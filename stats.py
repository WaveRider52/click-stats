#!/usr/bin/env python3
"""Click statistics for the redirect paths /go/github and /go/linkedin.

Reads the access log of the web server container, classifies each click and
stores one row per click (time, target, class, a page count). It stores no
address and no browser identification: the user agent is used in memory only.

Sub-commands: init, import-old, collect, compare, export, backup, rollup,
probe (read-only dry run), migrate, backfill.
Per click it stores three counts of requests by the same browser identification
in the 30 s around the click: pages30 (distinct pages answered with 200),
maxps30 (most page requests in one second, 200 or 304) and files30 (file
requests). Output is counts only, never log content.
"""
import argparse
import datetime as dt
import glob
import json
import os
import re
import sqlite3
import subprocess
import sys
import time

BASE = os.environ.get("STATS_BASE", os.path.expanduser("~/stats"))
DB = os.path.join(BASE, "db", "clicks.db")
PUBLIC = os.path.join(BASE, "public")
BACKUPS = os.path.join(BASE, "backup")
OLD = os.path.join(BASE, "clicks.txt")
DOCKER = os.environ.get("STATS_DOCKER", "docker")
CONTAINER = os.environ.get("STATS_CONTAINER", "nginx-odabas")

TARGETS = ("github", "linkedin")
CLASSES = ("mensch", "bot_erkannt", "bot_verdacht")
BOT_RE = re.compile(r"bot|spider|crawl", re.I)
REQUIRE_STATUS = os.environ.get("STATS_STATUS", "302")  # "any" counts every status
WINDOW = 15      # seconds before and after a click (30 s in total)
SUSPECT_MIN_PAGES = None  # automatic class bot_verdacht is switched off (v2)
RULE3 = (5, 1)            # preview only in probe: pages30 >= 5 and maxps30 <= 1
FILE_EXT = {"css", "js", "woff", "woff2", "png", "jpg", "jpeg", "svg", "ico", "webp", "avif", "gif"}
V1_MIN_PAGES = 8          # the v1 rule, shown by probe for comparison
LAG = 30         # seconds: the newest clicks wait for the next run (context)
KEEP_BACKUPS = 14
RAW_DAYS = 365

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
TIME_RE = re.compile(r"^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
LINE_RE = re.compile(
    r'^\[(?P<t>[^\]]+)\] "(?P<m>[A-Z]+) (?P<p>\S+) [^"]*" (?P<s>\d{3}) \d+ "(?P<ua>.*)"$')
CLICK_RE = re.compile(r"^/go/(github|linkedin)$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS clicks(
  id INTEGER PRIMARY KEY,
  ts_utc TEXT NOT NULL,
  target TEXT NOT NULL,
  seq INTEGER NOT NULL DEFAULT 0,
  class TEXT NOT NULL CHECK(class IN ('mensch','bot_erkannt','bot_verdacht')),
  pages30 INTEGER,
  maxps30 INTEGER,
  files30 INTEGER,
  source TEXT NOT NULL CHECK(source IN ('log','import')),
  UNIQUE(ts_utc, target, seq));
CREATE TABLE IF NOT EXISTS daily(
  date TEXT NOT NULL, target TEXT NOT NULL, class TEXT NOT NULL, n INTEGER NOT NULL,
  PRIMARY KEY(date, target, class));
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY, run_ts TEXT, w_from TEXT, e_to TEXT,
  lines_seen INTEGER, clicks_new INTEGER, container_started TEXT, gap INTEGER);
"""


def now_ep():
    return int(os.environ.get("STATS_NOW") or time.time())


def iso(ep):
    return dt.datetime.fromtimestamp(ep, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ep_of(s):
    return int(dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp())


def stamp_ep(s):  # "2026-10-20 18:00" (UTC) from the old counter file
    return int(dt.datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=dt.timezone.utc).timestamp())


def parse_time(t):
    m = TIME_RE.match(t)
    if not m or m.group(2) not in MONTHS:
        return None
    d, mon, y, hh, mm, ss, sign, oh, om = m.groups()
    off = (int(oh) * 3600 + int(om) * 60) * (1 if sign == "+" else -1)
    base = dt.datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=dt.timezone.utc)
    return int(base.timestamp()) - off


def connect(create=False):
    os.umask(0o077)
    if create:
        os.makedirs(os.path.dirname(DB), mode=0o700, exist_ok=True)
    if not os.path.exists(DB) and not create:
        sys.exit("no database; run init first")
    con = sqlite3.connect(DB)
    con.executescript(SCHEMA)
    ensure_columns(con)
    return con


def ensure_columns(con):
    have = {r[1] for r in con.execute("PRAGMA table_info(clicks)")}
    added = []
    for col in ("maxps30", "files30"):
        if col not in have:
            con.execute("ALTER TABLE clicks ADD COLUMN %s INTEGER" % col)
            added.append(col)
    if added:
        con.commit()
    return added


def st_get(con, key):
    r = con.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return r[0] if r else None


def st_set(con, key, value):
    con.execute("INSERT INTO state(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def is_page(path):
    p = path.split("?")[0]
    if p.startswith(("/_astro/", "/go/", "/stats/")):
        return False
    return p.endswith("/") or "." not in p.rsplit("/", 1)[-1]


def parse_log(out):
    entries = []
    for line in out.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        ts = parse_time(m.group("t"))
        if ts is None:
            continue
        entries.append((ts, m.group("m"), m.group("p"), m.group("s"), m.group("ua")))
    return entries


def ua_index(entries):
    by_ua = {}
    for ts, meth, path, status, ua in entries:
        if meth == "GET":
            by_ua.setdefault(ua, []).append((ts, path.split("?")[0], status))
    return by_ua


def is_file(path):
    """Page assets only: everything under /_astro/ and the listed extensions.
    rss.xml, robots.txt and sitemaps count neither as page nor as file."""
    if path.startswith("/_astro/"):
        return True
    last = path.rsplit("/", 1)[-1]
    return "." in last and last.rsplit(".", 1)[1].lower() in FILE_EXT


def metrics(reqs, ts):
    """(pages30, maxps30, files30) for one browser identification around ts."""
    pages, per_sec, files = set(), {}, 0
    for t, p, s in reqs:
        if not (ts - WINDOW <= t <= ts + WINDOW) or p.startswith(("/go/", "/stats/")):
            continue
        if is_page(p):
            if s == "200":
                pages.add(p)
            if s in ("200", "304"):
                per_sec[t] = per_sec.get(t, 0) + 1
        elif is_file(p):
            files += 1
    return len(pages), max(per_sec.values(), default=0), files


def classify(ua, pages):
    if BOT_RE.search(ua):
        return "bot_erkannt"
    if SUSPECT_MIN_PAGES and pages >= SUSPECT_MIN_PAGES:
        return "bot_verdacht"
    return "mensch"


def click_lines(entries):
    """Yield (ts, target, seq, status, ua) for every counted click line, in log order."""
    seqs = {}
    for ts, meth, path, status, ua in entries:
        c = CLICK_RE.match(path)
        if not c or meth != "GET":
            continue
        if REQUIRE_STATUS != "any" and status != REQUIRE_STATUS:
            continue
        key = (ts, c.group(1))
        seqs[key] = seqs.get(key, -1) + 1
        yield ts, c.group(1), seqs[key], status, ua


def run_docker(args):
    r = subprocess.run([DOCKER] + args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       text=True, errors="replace")
    if r.returncode != 0:
        sys.exit("docker %s failed (%d)" % (args[0], r.returncode))
    return r.stdout


def container_started():
    out = run_docker(["inspect", "-f", "{{.State.StartedAt}}", CONTAINER]).strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", out)
    return ep_of(m.group(1) + "Z") if m else 0


# ---------------------------------------------------------------- commands
def cmd_init(a):
    con = connect(create=True)
    if st_get(con, "watermark"):
        sys.exit("already initialised")
    st_set(con, "watermark", str(ep_of(a.at)))
    st_set(con, "init_at", a.at)
    st_set(con, "since", a.since)
    con.commit()
    print("init ok: watermark %s, since %s" % (a.at, a.since))


def cmd_import_old(a):
    con = connect()
    since, until = ep_of(a.since), ep_of(a.until)
    bots = {s.strip() for s in a.bot_stamps.split(",") if s.strip()}
    n_rows = 0
    for line in open(OLD):
        f = line.split()
        if len(f) != 4 or f[2] not in TARGETS or not f[3].isdigit():
            continue
        stamp = "%s %s" % (f[0], f[1])
        ep, n = stamp_ep(stamp), int(f[3])
        if n == 0 or ep - 3600 < since or ep > until:
            continue
        cls = "bot_verdacht" if stamp in bots else "mensch"
        for i in range(n):
            con.execute("INSERT OR IGNORE INTO clicks(ts_utc,target,seq,class,pages30,source) "
                        "VALUES(?,?,?,?,NULL,'import')", (iso(ep - 3600), f[2], i, cls))
        n_rows += n
        print("import %s %s n=%d class=%s" % (stamp, f[2], n, cls))
    con.commit()
    print("import done: %d rows" % n_rows)


def cmd_collect(a):
    con = connect()
    w = int(st_get(con, "watermark"))
    now = now_ep()
    e = now - LAG
    if e <= w:
        print("nothing to do")
        return
    out = run_docker(["logs", "--since", iso(w - WINDOW - 60), "--until", iso(e + WINDOW + 60), CONTAINER])
    entries = parse_log(out)
    by_ua = ua_index(entries)
    new = 0
    for ts, target, seq, status, ua in click_lines(entries):
        if not (w <= ts < e):
            continue
        pages, maxps, files = metrics(by_ua.get(ua, []), ts)
        cur = con.execute("INSERT OR IGNORE INTO clicks(ts_utc,target,seq,class,pages30,maxps30,files30,source) "
                          "VALUES(?,?,?,?,?,?,?,'log')",
                          (iso(ts), target, seq, classify(ua, pages), pages, maxps, files))
        new += cur.rowcount
    started = container_started()
    gap = 1 if started > w else 0
    con.execute("INSERT INTO runs(run_ts,w_from,e_to,lines_seen,clicks_new,container_started,gap) "
                "VALUES(?,?,?,?,?,?,?)", (iso(now), iso(w), iso(e), len(entries), new, iso(started), gap))
    st_set(con, "watermark", str(e))
    con.commit()
    print("collect ok: %s .. %s, lines %d, new clicks %d, gap %d" % (iso(w), iso(e), len(entries), new, gap))
    if a.export:
        cmd_export(a)


def cmd_probe(a):
    """Read-only dry run: metrics per click in the available log. Nothing is written."""
    args = ["logs"]
    if a.since:
        args += ["--since", a.since]
    if a.until:
        args += ["--until", a.until]
    entries = parse_log(run_docker(args + [CONTAINER]))
    by_ua = ua_index(entries)
    n = 0
    for ts, target, seq, status, ua in click_lines(entries):
        pages, maxps, files = metrics(by_ua.get(ua, []), ts)
        n304 = sum(1 for t, p, s in by_ua.get(ua, [])
                   if ts - WINDOW <= t <= ts + WINDOW and s == "304" and not p.startswith(("/go/", "/stats/")))
        v1 = "bot_erkannt" if BOT_RE.search(ua) else ("bot_verdacht" if pages >= V1_MIN_PAGES else "mensch")
        r3 = "ja" if (not BOT_RE.search(ua) and pages >= RULE3[0] and maxps <= RULE3[1]) else "nein"
        print("%s %s seq=%d pages30=%d maxps30=%d files30=%d n304=%d klasse_v1=%s klasse_v2=%s regel3=%s"
              % (iso(ts), target, seq, pages, maxps, files, n304, v1, classify(ua, pages), r3))
        n += 1
    print("probe: %d clicks, %d log lines, nothing written" % (n, len(entries)))


def cmd_migrate(a):
    if not os.path.exists(DB):
        sys.exit("no database")
    con = sqlite3.connect(DB)
    added = ensure_columns(con)
    cols = [r[1] for r in con.execute("PRAGMA table_info(clicks)")]
    print("migrate ok: added %s; columns now: %s" % (added or "nothing", ",".join(cols)))


def cmd_backfill(a):
    """Fill maxps30/files30 for log rows collected before the migration, from the log."""
    con = connect()
    rows = con.execute("SELECT id,ts_utc,target,seq,pages30 FROM clicks "
                       "WHERE source='log' AND maxps30 IS NULL AND pages30 IS NOT NULL").fetchall()
    if not rows:
        print("backfill: nothing to do")
        return
    entries = parse_log(run_docker(["logs", CONTAINER]))
    by_ua = ua_index(entries)
    uas = {(iso(ts), t, seq): ua for ts, t, seq, st, ua in click_lines(entries)}
    done = missing = mismatch = 0
    for rid, ts_utc, target, seq, pages30 in rows:
        ua = uas.get((ts_utc, target, seq))
        if ua is None:
            missing += 1
            continue
        pages, maxps, files = metrics(by_ua.get(ua, []), ep_of(ts_utc))
        if pages != pages30:
            mismatch += 1
            continue
        con.execute("UPDATE clicks SET maxps30=?, files30=? WHERE id=? AND maxps30 IS NULL",
                    (maxps, files, rid))
        done += 1
    con.commit()
    print("backfill: rows %d, updated %d, not in log %d, pages mismatch %d" % (len(rows), done, missing, mismatch))


def cmd_compare(a):
    con = connect()
    init = ep_of(st_get(con, "init_at"))
    mark = int(st_get(con, "watermark"))
    old = {}
    for line in open(OLD):
        f = line.split()
        if len(f) == 4 and f[2] in TARGETS and f[3].isdigit():
            ep = stamp_ep("%s %s" % (f[0], f[1]))
            if ep - 3600 >= init and ep <= mark:
                old[(ep, f[2])] = int(f[3])
    stamps = sorted({k[0] for k in old})
    mism, s_old, s_new = [], 0, 0
    for ep in stamps:
        for t in TARGETS:
            o = old.get((ep, t), 0)
            n = con.execute("SELECT COUNT(*) FROM clicks WHERE source='log' AND target=? "
                            "AND class IN ('mensch','bot_verdacht') AND ts_utc>=? AND ts_utc<?",
                            (t, iso(ep - 3600), iso(ep))).fetchone()[0]
            s_old, s_new = s_old + o, s_new + n
            if o != n:
                mism.append("%s %s old=%d new=%d" % (iso(ep), t, o, n))
    ber = con.execute("SELECT COUNT(*) FROM clicks WHERE source='log' AND class='bot_erkannt' "
                      "AND ts_utc>=? AND ts_utc<?", (iso(init), iso(mark))).fetchone()[0]
    print("compare: hours %d, old %d, new(mensch+bot_verdacht) %d, bot_erkannt (not in old) %d, mismatches %d"
          % (len(stamps), s_old, s_new, ber, len(mism)))
    for m in mism:
        print("MISMATCH", m)
    sys.exit(1 if mism else 0)


def cmd_export(a):
    con = connect()
    since = st_get(con, "since")
    first = dt.datetime.strptime(since[:10], "%Y-%m-%d").date()
    today = dt.datetime.fromtimestamp(now_ep(), dt.timezone.utc).date()
    counts = {}
    for d, t, c, n in con.execute("SELECT substr(ts_utc,1,10),target,class,COUNT(*) FROM clicks "
                                  "WHERE ts_utc>=? GROUP BY 1,2,3", (since,)):
        counts[(d, t, c)] = n
    for d, t, c, n in con.execute("SELECT date,target,class,n FROM daily WHERE date>=?", (since[:10],)):
        counts[(d, t, c)] = counts.get((d, t, c), 0) + n
    days, d = [], first
    while d <= today:
        ds = d.isoformat()
        row = {"date": ds}
        for t in TARGETS:
            row[t] = {c: counts.get((ds, t, c), 0) for c in CLASSES}
        days.append(row)
        d += dt.timedelta(days=1)
    doc = {"generated": iso(now_ep()), "since": since, "tz": "UTC", "days": days}
    os.makedirs(PUBLIC, exist_ok=True)
    os.chmod(PUBLIC, 0o755)
    tmp = os.path.join(PUBLIC, ".klicks.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(doc, fh, separators=(",", ":"))
        fh.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(PUBLIC, "klicks.json"))
    print("export ok: %d days" % len(days))


def cmd_backup(a):
    con = connect()
    os.makedirs(BACKUPS, mode=0o700, exist_ok=True)
    dest = os.path.join(BACKUPS, "clicks-%s.db" % dt.datetime.fromtimestamp(now_ep(), dt.timezone.utc).strftime("%Y%m%d"))
    if os.path.exists(dest):
        os.remove(dest)
    out = sqlite3.connect(dest)
    con.backup(out)
    res = out.execute("PRAGMA integrity_check").fetchone()[0]
    out.close()
    os.chmod(dest, 0o600)
    files = sorted(glob.glob(os.path.join(BACKUPS, "clicks-*.db")))
    for f in files[:-KEEP_BACKUPS]:
        os.remove(f)
    print("backup ok: %s, integrity %s, kept %d" % (os.path.basename(dest), res, min(len(files), KEEP_BACKUPS)))


def cmd_rollup(a):
    con = connect()
    today = dt.datetime.fromtimestamp(now_ep(), dt.timezone.utc).date()
    cutoff = (today - dt.timedelta(days=RAW_DAYS)).isoformat()
    rows = con.execute("SELECT substr(ts_utc,1,10),target,class,COUNT(*) FROM clicks "
                       "WHERE substr(ts_utc,1,10)<? GROUP BY 1,2,3", (cutoff,)).fetchall()
    with con:
        for d, t, c, n in rows:
            con.execute("INSERT INTO daily(date,target,class,n) VALUES(?,?,?,?) "
                        "ON CONFLICT(date,target,class) DO UPDATE SET n=n+excluded.n", (d, t, c, n))
        cur = con.execute("DELETE FROM clicks WHERE substr(ts_utc,1,10)<?", (cutoff,))
    print("rollup ok: cutoff %s, %d day-rows written, %d click rows removed" % (cutoff, len(rows), cur.rowcount))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("init")
    s.add_argument("--at", required=True, help="watermark, full hour, e.g. 2026-10-21T18:00:00Z")
    s.add_argument("--since", required=True, help="counting start, e.g. 2026-10-19T21:00:00Z")
    s.set_defaults(f=cmd_init)
    s = sub.add_parser("import-old")
    s.add_argument("--since", required=True)
    s.add_argument("--until", required=True)
    s.add_argument("--bot-stamps", default="")
    s.set_defaults(f=cmd_import_old)
    s = sub.add_parser("collect")
    s.add_argument("--export", action="store_true")
    s.set_defaults(f=cmd_collect)
    s = sub.add_parser("probe")
    s.add_argument("--since", help="optional, passed to docker logs, e.g. 2026-10-22T00:00:00Z")
    s.add_argument("--until")
    s.set_defaults(f=cmd_probe)
    for name, fn in (("compare", cmd_compare), ("export", cmd_export),
                     ("backup", cmd_backup), ("rollup", cmd_rollup),
                     ("migrate", cmd_migrate), ("backfill", cmd_backfill)):
        sub.add_parser(name).set_defaults(f=fn)
    a = p.parse_args()
    a.f(a)


if __name__ == "__main__":
    main()
