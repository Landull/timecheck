# timecheck

A forensic timeline builder. Give it an evidence folder plus whatever else you've collected (browser history, document metadata, event log exports, bodyfiles, logs) and it merges every timestamp into one sorted timeline, with the suspicious parts flagged and browser downloads linked to the files they left on disk.

No dependencies. Just Python 3.8+ and the standard library. It reads the output of [histcheck](https://github.com/Landull/histcheck) and [metacheck](https://github.com/Landull/metacheck), and pairs with [hashcheck](https://github.com/Landull/hashcheck) and [iocheck](https://github.com/Landull/iocheck).

## What it reads

| Input | How to give it | Events |
|---|---|---|
| A folder or mounted image | the folder | modified, accessed, changed and born times for every file and folder |
| Sleuth Kit / MFTECmd bodyfile | `fls -m` or `MFTECmd --body` output | the same, including `$FILE_NAME` times and deleted entries |
| histcheck output | its CSV or JSON | page visits, downloads, searches |
| metacheck output | its CSV or JSON | dates stored inside documents and photos (created, modified, taken, printed) |
| CSV exports | any CSV with a time column, like EvtxECmd, PECmd, MFTECmd or a spreadsheet | one event per row per time column |
| Text logs | syslog, `auth.log`, Apache/nginx access logs, anything with ISO timestamps | one event per line |
| timecheck output | its own CSV or JSON | everything, so timelines can be built in pieces and merged |

Files are recognized by what's inside them, not their name. Times with the same value on one file are grouped the way `mactime` does it, so `m..b` means modified and born at that moment. CSV exports in UTF-16 or with `;` or tab separators work too, and US-style dates like `10/18/2026 2:03:15 PM` are understood.

Every file it reads gets its SHA-256 hash, event count and first/last time for your case notes.

## What it flags

- **Executables and scripts in user-writable folders** like Downloads, Temp, AppData, ProgramData and `/tmp`
- **Timestomping signs**: a `$STANDARD_INFORMATION` created time earlier than `$FILE_NAME`, an executable modified before it was created, and a modified time on an exact whole second when nearly every other file on the volume has fractions
- **Deleted entries** still listed in a bodyfile
- **Timestamps in the future**
- **Log lines** for failed logins, accepted remote logins, `sudo` commands, account changes, and web requests that look like path traversal, injection or webshell use
- **Everything histcheck and metacheck already flagged**, carried through

When a browser download from histcheck matches a file in the folder you walked, both events get a `~` line linking them, so you can see the download and the file it created side by side.

## How it handles evidence

- **Walking a folder never opens a file.** It only reads timestamps, so the access times of the evidence aren't changed by timecheck. I checked by recording every file's times before and after a run.
- **Times are kept in UTC.** Anything that carries its own time zone is converted. Anything that doesn't (syslog, many CSV exports, camera EXIF) is read as UTC unless you say otherwise with `--tz`, and is marked with `*` so you know it was assumed.

## Usage

```
python3 timecheck.py /Volumes/Evidence/Users
```

Some real uses:

```
# File times, browser history and document metadata in one timeline
python3 timecheck.py /Volumes/Evidence/Users history.csv metadata.json

# A full NTFS timeline from a bodyfile, plus Windows event logs from EvtxECmd
python3 timecheck.py body.txt evtx.csv

# What happened in the 10 minutes either side of a moment, in your own time zone
python3 timecheck.py /Volumes/Evidence/Users history.csv --around "2026-10-18 14:02" --window 10m --local

# Only file creations, or only the red flags
python3 timecheck.py /Volumes/Evidence/Users --macb b
python3 timecheck.py /Volumes/Evidence/Users body.txt history.csv --flagged

# Everything mentioning an IP address, from the logs only
python3 timecheck.py auth.log access.log -s log -g 185.220.101.7 --year 2026

# A server log written in US Central time
python3 timecheck.py auth.log --tz=-05:00 --year 2026

# Skip noise when walking
python3 timecheck.py /Volumes/Evidence -x '$Recycle.Bin' -x '*.tmp'

# Spreadsheet for case notes, or JSON for scripts
python3 timecheck.py /Volumes/Evidence/Users history.csv -f csv -o timeline.csv
python3 timecheck.py /Volumes/Evidence/Users history.csv -f json -o timeline.json
```

When sources were written in different time zones, build each one with its own `--tz` and merge the results:

```
python3 timecheck.py auth.log --tz=-05:00 --year 2026 -f csv -o auth.csv
python3 timecheck.py auth.csv evtx.csv history.csv body.txt
```

On Windows, use `python` instead of `python3`.

## Options

| Flag | Description |
|---|---|
| `--since DATE` | only events on or after `YYYY-MM-DD` or `YYYY-MM-DD HH:MM` |
| `--until DATE` | only events on or before DATE (a bare date covers that whole day) |
| `--around DATE` | only events within `--window` of DATE, with DATE marked `>>>` in the table |
| `--window SPAN` | span either side of `--around`, like `90s`, `15m`, `2h` or `1d` (default `15m`) |
| `-s, --source` | only `fs`, `bodyfile`, `browser`, `metadata`, `log` or `csv` events (repeatable) |
| `-g, --grep TEXT` | only events whose detail, path or flags contain TEXT (repeatable) |
| `--macb LETTERS` | file events only if they include one of these letters, like `b` or `mb` |
| `--flagged` | only events with findings |
| `-x, --exclude GLOB` | skip files and folders matching GLOB when walking (repeatable) |
| `-n, --no-recurse` | don't descend into subfolders |
| `--time-col NAME` | for CSV input, use this column as the time instead of guessing (repeatable) |
| `--tz ZONE` | zone for times that don't carry one: `UTC` (default), `local`, or an offset like `--tz=-05:00` |
| `--year YEAR` | year for syslog lines, which don't include one (default: the log file's modified year) |
| `--local` | show and filter times in this computer's time zone instead of UTC |
| `--summary` | only the per-source summary and busiest hours |
| `--full` | don't shorten long lines in the table |
| `-f, --format` | `table` (default), `csv` or `json` |
| `-o, --output FILE` | write output to a file |

## Example

```
TIME (UTC)                SOURCE          WHAT         DETAIL
2026-10-18 19:01:10Z      Chrome:Default  search       "free invoice template" (www.google.com)
2026-10-18 19:01:10Z      Chrome:Default  visit        https://www.google.com/search?q=free+invoice+template "free invoice template - Google Search" [keyword search, address bar]
2026-10-18 19:01:30Z      Chrome:Default  visit        https://invoice-templates.example.net/download "Free Invoice Templates" [link, on page 41s]
2026-10-18 19:02:05Z      Chrome:Default  download    !http://185.220.101.7/files/Invoice_0412.exe -> C:\Users\bob\Downloads\Invoice_0412.exe (1.8 MB, complete, opened, application/x-msdownload)
                                                      ! kept despite warning
                                                      ! executable/script file type (.exe)
                                                      ! downloaded from an IP address
                                                      ~ file on disk: Users/bob/Downloads/Invoice_0412.exe
2026-10-18 19:02:05Z      Chrome:Default  visit       !http://185.220.101.7/files/Invoice_0412.exe [link, server redirect]
                                                      ! IP address instead of hostname
2026-10-18 19:02:07Z      fs              ma.. file   !Users/bob/Downloads/Invoice_0412.exe (1.8 MB)
                                                      ! executable/script in a user-writable folder (.exe)
                                                      ~ downloaded by Chrome:Default at 2026-10-18 19:02:05Z from http://185.220.101.7/files/Invoice_0412.exe
2026-10-18 19:03:12Z      fs              ma.. file   !Users/bob/AppData/Local/Temp/update.ps1 (2.1 KB)
                                                      ! executable/script in a user-writable folder (.ps1)
2026-10-18 19:06:50Z*     csv:events.csv  TimeCreated  MapDescription=Successful logon EventId=4624 Provider=Microsoft-Windows-Security-Auditing Channel=Security UserName=DESKTOP-BOB\bob PayloadData1=LogonType 10...
2026-10-18 19:07:30Z*     csv:events.csv  TimeCreated  MapDescription=A service was installed EventId=7045 Provider=Service Control Manager Channel=System PayloadData1=Name: winupdate Computer=DESKTOP-BOB RecordN...
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Timestamped events found |
| `1` | No timestamped events found |
| `2` | Bad input (missing path, bad date or time zone) |

## Forensic notes

- **Work on copies.** Walking only reads timestamps, but listing a folder can still update the folder's own access time on some systems, and reading a log or CSV can update that file's. Run it against a forensic image or a write-blocked copy, and record the SHA-256 it reports.
- **Know your time zones.** A wrong `--tz` shifts a whole source by hours. Check the `*` marks and line sources up against an event you know the true time of.
- **Timestamps are easy to change.** Treat flags as leads to corroborate, not proof. Archives, installers and copy tools also set whole-second and older-than-created times for innocent reasons.
- **Limits.** Python can't read birth times on Linux, so use a bodyfile from `fls` there. On Windows, folder walks don't include the MFT change time or `$FILE_NAME` times, so use `MFTECmd --body` for a full NTFS timeline. `.evtx`, registry hives and prefetch files aren't parsed directly; export them with EvtxECmd, RECmd or PECmd and give timecheck the CSV. For deep work, compare against Plaso (log2timeline).

## License

MIT, see [LICENSE](LICENSE).

---

Part of [Landull](https://github.com/Landull)'s forensics toolkit.
