# click-stats

A small, dependency-free click counter for the two outgoing links (`/go/github`, `/go/linkedin`) of my portfolio site [odabas.ch](https://odabas.ch). It runs as a single Python script on my self-hosted VPS and replaces an older hourly shell counter.

The goal: count how often the links are clicked, tell people apart from programs as well as the data allows, and publish only daily totals. No cookies, no JavaScript on the page, no visitor addresses in the database.

## How it works

```
browser -> Traefik (TCP passthrough) -> nginx container -> access log
                                                              |
                          cron, every 15 min:  stats.py collect --export
                                                              |
                                     SQLite (one row per click)  ->  klicks.json (daily totals)
                                                                          |
                                                          served by nginx at /stats/klicks.json
```

- `/go/<target>` answers with a `302` redirect. The script reads the nginx container log (`docker logs`) and counts only `GET` requests with status `302`. `HEAD` requests do not count.
- The log format contains no client address (nginx only sees the reverse proxy's address anyway). The script reads the user agent only to classify a click and never stores it in the database. (The web server's own access log still contains it.)
- One row per click: time (UTC), target, classification and three numbers about the 30 seconds around the click.
- Public output is `klicks.json` with daily totals per target and classification, written atomically.

### Classification

| Class | Meaning |
|---|---|
| `mensch` | not recognised as a program (an estimate, not a certainty) |
| `bot_erkannt` | user agent contains `bot`, `spider` or `crawl` (case-insensitive) |
| `bot_verdacht` | suspected program; not assigned automatically, only by hand for old hourly data |

The three numbers stored per click, all for the same user agent within ±15 s of the click:

- `pages30`: distinct pages answered with `200`
- `maxps30`: highest number of page requests in a single second (`200` or `304`)
- `files30`: number of asset requests (`/_astro/*` and common static extensions)

They exist to find a rule that separates humans from programs later (for example many pages, but never more than one per second). No rule is applied yet, because no method is 100 % reliable: headers can be forged and browser-driven bots look like browsers.

## Design decisions

- **Watermark and lag.** A run reads from the last watermark to `now - 30 s`. The log is read with a ±60 s margin so that the context of a click is complete. `UNIQUE(ts_utc, target, seq)` with `INSERT OR IGNORE` makes reruns idempotent.
- **Gap detection.** Docker logs vanish when the container is recreated. Every run records the container start time in the `runs` table and sets a `gap` flag if the container was recreated after the watermark. Clicks can only be computed while the log exists, so a collect run precedes every deploy.
- **Retention.** Single clicks are kept for 365 days, then `rollup` folds them into daily totals. `backup` keeps 14 consistent SQLite backups (`integrity_check` after each).
- **Verification.** `compare` checks the new database against the old hourly counter hour by hour. `probe` is a read-only dry run that prints the metrics per click without writing anything.
- **Privacy.** Counts only, never log content in any output. Database 0600, backups 0600, public folder contains only the totals file.

## Commands

```
stats.py init --at <UTC hour> --since <UTC>   # create the database and set the watermark
stats.py import-old --since .. --until ..     # import hourly counts of the old counter
stats.py collect [--export]                   # read new clicks from the log
stats.py export                               # write the public daily totals (JSON)
stats.py compare                              # check against the old counter
stats.py probe [--since .. --until ..]        # read-only dry run
stats.py migrate | backfill                   # schema upgrade and filling new columns
stats.py backup | rollup                      # daily maintenance
```

Example crontab:

```
0,15,30,45 * * * * flock -n ~/stats/.lock python3 -I ~/projects/stats/stats.py collect --export >> ~/stats/collect.log 2>&1
10 3 * * *         python3 -I ~/projects/stats/stats.py backup >> ~/stats/collect.log 2>&1
10 4 * * *         python3 -I ~/projects/stats/stats.py rollup >> ~/stats/collect.log 2>&1
```

## Configuration

Environment variables, all optional:

| Variable | Default | Purpose |
|---|---|---|
| `STATS_BASE` | `~/stats` | folder for database, backups and public output |
| `STATS_CONTAINER` | `nginx-odabas` | container whose log is read |
| `STATS_DOCKER` | `docker` | docker binary |
| `STATS_STATUS` | `302` | `any` counts every status |

## Requirements

Python 3 (standard library only, SQLite included) and access to `docker logs` for the web server container.

## Limits

The classification is an estimate. "Not recognised as a program" can include programs that present themselves as browsers, and a human can be misclassified too. The script is built for one site and one log format; paths, targets and class names are constants at the top of `stats.py`.

## Context

Part of a self-hosted platform on an Infomaniak VPS (Ubuntu 24.04): Traefik as edge router, one nginx per site, MariaDB, Docker Compose. The script was written step by step with Claude (Anthropic) as a reviewer; I ran and verified every step on the server myself.
