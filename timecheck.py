#!/usr/bin/env python3
"""
timecheck - forensic timeline builder.

Merges everything with a timestamp into one sorted timeline: file system
times (modified, accessed, changed, born) from a folder or mounted image,
Sleuth Kit / MFTECmd bodyfiles, histcheck browser history, metacheck
document and photo metadata, CSV exports from other tools (EvtxECmd,
MFTECmd, PECmd and the like), and text logs (syslog, auth.log, web server
access logs, anything with ISO timestamps).

Walking a folder only reads timestamps, never file contents. Suspicious
patterns are flagged, and browser downloads are linked to the files they
created on disk.

Standard library only. Python 3.8+.

https://github.com/Landull/timecheck
"""

import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
import re
import stat
import sys
from collections import Counter

__version__ = "1.0.0"

UTC = dt.timezone.utc
EPOCH = dt.datetime(1970, 1, 1, tzinfo=UTC)
NOW = dt.datetime.now(UTC)

SOURCES = ("fs", "bodyfile", "browser", "metadata", "log", "csv")
SOURCE_ORDER = {s: i for i, s in enumerate(SOURCES)}

RISKY_EXT = {
    ".exe", ".msi", ".msix", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".lnk", ".jar", ".dll", ".cpl", ".iso", ".img",
    ".vhd", ".vhdx", ".dmg", ".pkg", ".app", ".command", ".sh", ".apk", ".appx",
    ".docm", ".xlsm", ".pptm", ".one", ".reg", ".url", ".library-ms",
}

# Folders any user (or malware running as one) can write to.
WRITABLE_DIRS = (
    "/downloads/", "/temp/", "/tmp/", "/appdata/", "/users/public/", "/programdata/",
    "/var/tmp/", "/dev/shm/", "/$recycle.bin/", "/library/caches/", "/windows/temp/",
)

MONTHS = {m: i for i, m in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}

# --------------------------------------------------------------------------
# Time helpers
# --------------------------------------------------------------------------

TZ_RE = re.compile(r"^(?:(Z|UTC|GMT)|([+-])(\d{2})'?:?(\d{2})?'?)$", re.I)
ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?"
                    r"\s*(Z|UTC|GMT|[+-]\d{2}(?::?\d{2})?)?$", re.I)
EXIF_RE = re.compile(r"^(\d{4}):(\d{2}):(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
                     r"\s*(Z|[+-]\d{2}:?\d{2})?$")
PDF_RE = re.compile(r"^D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{2}'?\d{2}'?)?")
US_RE = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4}),? (\d{1,2}):(\d{2})(?::(\d{2}))?(?:\.(\d{1,9}))?"
                   r"\s*([AP]M)?$", re.I)
CLF_RE = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})$")


def from_epoch(secs):
    try:
        secs = float(secs)
    except (TypeError, ValueError):
        return None
    if secs <= 0:
        return None
    try:
        return EPOCH + dt.timedelta(seconds=secs)
    except OverflowError:
        return None


def from_ns(ns):
    if not ns or ns <= 0:
        return None
    try:
        return EPOCH + dt.timedelta(microseconds=ns // 1000)
    except OverflowError:
        return None


def parse_offset(text):
    m = TZ_RE.match(text.strip())
    if not m:
        return None
    if m.group(1):
        return UTC
    mins = int(m.group(3)) * 60 + int(m.group(4) or 0)
    if mins > 14 * 60:
        return None
    return dt.timezone(dt.timedelta(minutes=-mins if m.group(2) == "-" else mins))


def attach_tz(t, tz):
    """Give a time with no zone the zone the user said to assume, then convert to UTC."""
    try:
        if tz == "local":
            return t.astimezone().astimezone(UTC)
        return t.replace(tzinfo=tz).astimezone(UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _build(y, mo, d, h, mi, s, frac, zone, tz):
    try:
        t = dt.datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0),
                        int(((frac or "") + "000000")[:6]))
    except (TypeError, ValueError):
        return None, False
    if not 1970 <= t.year <= 2100:
        return None, False
    if zone:
        off = parse_offset(zone)
        if off is None:
            return None, False
        return t.replace(tzinfo=off).astimezone(UTC), False
    return attach_tz(t, tz), True


def parse_ts(text, tz=UTC):
    """Read a timestamp in any common format. Returns (UTC time, had_no_zone)."""
    text = (text or "").strip().strip('"')
    if not text or len(text) > 40 or not (text[0].isdigit() or text.startswith("D:")):
        return None, False
    m = ISO_RE.match(text) or EXIF_RE.match(text)
    if m:
        return _build(*m.groups(), tz=tz)
    m = PDF_RE.match(text)
    if m:
        y, mo, d, h, mi, s, zone = m.groups()
        return _build(y, mo, d, h, mi, s, None, zone, tz)
    m = US_RE.match(text)
    if m:
        mo, d, y, h, mi, s, frac, ampm = m.groups()
        h = int(h)
        if ampm:
            if not 1 <= h <= 12:
                return None, False
            h = h % 12 + (12 if ampm.upper() == "PM" else 0)
        return _build(y, mo, d, h, mi, s, frac, None, tz)
    m = CLF_RE.match(text)
    if m:
        d, mon, y, h, mi, s, zone = m.groups()
        mo = MONTHS.get(mon.lower())
        if not mo:
            return None, False
        return _build(y, mo, d, h, mi, s, None, zone, tz)
    return None, False


def fmt_time(t, local=False, precise=False):
    if t is None:
        return ""
    if local:
        t = t.astimezone()
    s = t.strftime("%Y-%m-%d %H:%M:%S")
    if precise and t.microsecond:
        s += f".{t.microsecond:06d}"
    return s + (t.strftime("%z") if local else "Z")


def parse_when(text, local, end=False):
    """YYYY-MM-DD or YYYY-MM-DD HH:MM[:SS]. A bare --until date covers the whole day."""
    text = text.strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            t = dt.datetime.strptime(text, fmt)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d" and end:
            t += dt.timedelta(days=1) - dt.timedelta(microseconds=1)
        if local:
            return t.astimezone().astimezone(UTC)
        return t.replace(tzinfo=UTC)
    raise ValueError(f"can't read date '{text}' (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM')")


def parse_window(text):
    m = re.match(r"^\s*(\d+)\s*([smhd]?)\s*$", text.lower())
    if not m:
        raise ValueError(f"can't read window '{text}' (use e.g. 90s, 15m, 2h, 1d)")
    unit = {"s": "seconds", "": "minutes", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    return dt.timedelta(**{unit: int(m.group(1))})


def fmt_size(n):
    if n is None or n < 0:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n} B"


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def event(time, source, label, what, detail, path="", macb="", flags=None, artifact="",
          line=None, naive=False, extra=None):
    return {
        "time": time, "source": source, "label": label, "what": what, "macb": macb,
        "detail": detail, "path": path or "", "flags": list(flags or []), "links": [],
        "tz_assumed": naive, "artifact": artifact, "line": line, **(extra or {}),
    }


def path_key(path):
    """Last two path parts, lowercased, so C:\\Users\\bob\\Downloads\\x.exe matches
    /Volumes/Evidence/Users/bob/Downloads/x.exe."""
    parts = [p for p in path.replace("\\", "/").lower().split("/") if p]
    return "/".join(parts[-2:]) if parts else ""


def file_flags(path, kind, times, exact_second):
    flags = []
    norm = "/" + path.replace("\\", "/").lower().lstrip("/")
    ext = os.path.splitext(norm.rsplit("/", 1)[-1])[1]
    risky = kind == "file" and ext in RISKY_EXT
    if risky and any(d in norm for d in WRITABLE_DIRS):
        flags.append(f"executable/script in a user-writable folder ({ext})")
    m, b = times.get("m"), times.get("b")
    if risky and m and b and m < b - dt.timedelta(seconds=2):
        flags.append("modified before it was created (copied, extracted or timestomped)")
    if exact_second:
        flags.append("modified time is a whole second while most files here have fractions "
                     "(set by a tool, an archive, or timestomping)")
    if any(t and t > NOW + dt.timedelta(days=1) for t in times.values()):
        flags.append("timestamp in the future")
    return flags


def entries_to_events(entries, source, label, artifact=""):
    """Turn file entries (path + m/a/c/b times) into mactime-style grouped events."""
    plain = [e for e in entries if e["kind"] == "file" and not e.get("fn") and e["times"].get("m")]
    with_frac = sum(1 for e in plain if e["frac"])
    # Only call out whole-second times when the volume normally records fractions.
    check_exact = len(plain) >= 20 and with_frac >= 0.9 * len(plain)
    fn_births = {e["base"]: e["times"].get("b") for e in entries if e.get("fn")}

    events = []
    for e in entries:
        times = {k: v for k, v in e["times"].items() if v is not None}
        if not times:
            continue
        flags = [] if e.get("fn") else file_flags(
            e["path"], e["kind"], times, check_exact and e["kind"] == "file" and not e["frac"])
        if e.get("deleted"):
            flags.append("deleted entry (still listed in the file system metadata)")
        fn_b, si_b = fn_births.get(e.get("base")), times.get("b")
        if not e.get("fn") and fn_b and si_b and si_b < fn_b - dt.timedelta(seconds=1):
            flags.append("$STANDARD_INFORMATION created time is earlier than $FILE_NAME "
                         "(classic timestomping sign)")
        groups = {}
        for letter in "macb":
            if letter in times:
                groups.setdefault(times[letter], set()).add(letter)
        shown = e["path"] + ("/" if e["kind"] == "dir" and not e["path"].endswith(("/", "\\")) else "")
        if e["kind"] == "file" and e.get("size") is not None:
            shown += f"  ({fmt_size(e['size'])})"
        for t, letters in sorted(groups.items()):
            macb = "".join(c if c in letters else "." for c in "macb")
            events.append(event(t, source, label, f"{macb} {e['kind']}", shown, path=e["path"],
                                macb=macb, flags=flags,
                                artifact=artifact, line=e.get("line"),
                                extra={"has_b": "b" in times}))
    return events


# --------------------------------------------------------------------------
# File system walk (timestamps only - file contents are never read)
# --------------------------------------------------------------------------


def stat_entry(path, warnings):
    try:
        st = os.lstat(path)
    except OSError as exc:
        warnings.append(f"{path}: {exc.strerror or exc}")
        return None
    if stat.S_ISDIR(st.st_mode):
        kind = "dir"
    elif stat.S_ISLNK(st.st_mode):
        kind = "link"
    else:
        kind = "file"
    times = {"m": from_ns(st.st_mtime_ns), "a": from_ns(st.st_atime_ns)}
    birth = getattr(st, "st_birthtime_ns", None)
    b = from_ns(birth) if birth else from_epoch(getattr(st, "st_birthtime", None))
    if os.name == "nt":
        # On Windows st_ctime is the creation time, and there's no inode change time.
        times["b"] = b or from_ns(st.st_ctime_ns)
    else:
        times["c"] = from_ns(st.st_ctime_ns)
        times["b"] = b
    return {"path": path, "kind": kind, "size": st.st_size if kind == "file" else None,
            "times": times, "frac": st.st_mtime_ns % 1_000_000_000 != 0}


def walk_fs(target, recursive, excludes, warnings):
    def excluded(path):
        low = path.lower()
        name = os.path.basename(low.rstrip("/\\"))
        return any(fnmatch.fnmatchcase(name, g) or fnmatch.fnmatchcase(low, g) for g in excludes)

    entries = []
    root_entry = stat_entry(target, warnings)
    if root_entry:
        entries.append(root_entry)
    if not os.path.isdir(target) or os.path.islink(target):
        return entries

    def onerror(exc):
        warnings.append(f"{exc.filename}: {exc.strerror or exc}")

    for root, dirs, files in os.walk(target, onerror=onerror):
        dirs[:] = sorted(d for d in dirs if not excluded(os.path.join(root, d)))
        for name in dirs + sorted(files):
            path = os.path.join(root, name)
            if name in files and excluded(path):
                continue
            entry = stat_entry(path, warnings)
            if entry:
                entries.append(entry)
        if not recursive:
            dirs[:] = []
    return entries


# --------------------------------------------------------------------------
# Reading artifact files
# --------------------------------------------------------------------------


def read_text(path, limit=None):
    with open(path, "rb") as fh:
        raw = fh.read() if limit is None else fh.read(limit)
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    if b"\x00" in raw[:8192]:
        return None
    return raw.decode("utf-8-sig", errors="replace")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --- bodyfile (Sleuth Kit fls -m / mactime, MFTECmd --body) ----------------

NUM_RE = re.compile(r"^-?\d+(?:\.\d+)?$")


def looks_like_bodyfile(lines):
    seen = 0
    for ln in lines[:20]:
        if not ln.strip():
            continue
        parts = ln.split("|")
        if len(parts) < 11 or not all(NUM_RE.match(p.strip()) for p in parts[-4:]):
            return False
        seen += 1
    return seen > 0


def parse_bodyfile(text, path, label):
    entries = []
    for n, ln in enumerate(text.splitlines(), 1):
        if not ln.strip() or "|" not in ln:
            continue
        try:
            _md5, rest = ln.split("|", 1)
            name, _inode, mode, _uid, _gid, size, a, m, c, cr = rest.rsplit("|", 9)
        except ValueError:
            continue
        fn = name.endswith(" ($FILE_NAME)")
        base = name[: -len(" ($FILE_NAME)")] if fn else name
        deleted = "(deleted" in name
        mode = mode.strip()
        kind = "dir" if mode.startswith("d") else "link" if mode.startswith("l") else "file"
        frac = "." in m and m.split(".", 1)[1].strip("0") != ""
        try:
            size = int(float(size))
        except ValueError:
            size = None
        entries.append({
            "path": name, "base": base, "fn": fn, "deleted": deleted, "kind": kind,
            "size": size, "frac": frac, "line": n,
            "times": {"m": from_epoch(m), "a": from_epoch(a), "c": from_epoch(c),
                      "b": from_epoch(cr)},
        })
    return entries_to_events(entries, "bodyfile", label, path)


# --- histcheck -------------------------------------------------------------

HIST_FIELDS = {"time", "type", "browser", "profile", "url", "title", "detail"}


def hist_event(r, path, line, tz):
    t, naive = parse_ts(str(r.get("time") or ""), tz)
    if t is None:
        return None
    rtype = r.get("type") or "visit"
    who = f"{r.get('browser')}:{r.get('profile')}" if r.get("profile") else (r.get("browser") or "browser")
    url, title, detail = r.get("url") or "", r.get("title") or "", r.get("detail") or ""
    if rtype == "search":
        shown = f'"{title}"  ({detail})'
    elif rtype == "download":
        shown = f"{url}  -> {detail}"
    else:
        shown = url + (f'  "{title}"' if title else "") + (f"  [{detail}]" if detail else "")
    flags = r.get("flags") or []
    if isinstance(flags, str):
        flags = [f for f in flags.split("; ") if f]
    return event(t, "browser", who, rtype, shown, path=url, flags=flags, artifact=path,
                 line=line, naive=naive, extra={"download_path": r.get("path") or ""})


# --- metacheck -------------------------------------------------------------

DATE_FIELD = re.compile(r"date|time|created|creat|modif|saved|printed|taken|digitiz|original|stamp",
                        re.I)


def meta_events(records, path, tz):
    """records: [(file, file_path, [(section, field, value)], findings)]"""
    events = []
    for name, full, fields, findings in records:
        mine = []
        for section, field, value in fields:
            if section == "File" or not isinstance(value, str) or not DATE_FIELD.search(field):
                continue
            t, naive = parse_ts(value, tz)
            if t is None:
                continue
            mine.append(event(t, "metadata", "metadata", clip(field, 18),
                              f"{name}  [{section}]", path=full or name,
                              artifact=path, naive=naive))
        if mine and findings:
            min(mine, key=lambda e: e["time"])["flags"] = list(findings)
        events += mine
    return events


def meta_from_json(doc, path, tz):
    records = []
    for item in doc:
        sections = item.get("sections") or {}
        fields = [(s, k, v) for s, kv in sections.items() if isinstance(kv, dict)
                  for k, v in kv.items()]
        full = (sections.get("File") or {}).get("Path", "")
        records.append((item.get("file", ""), full, fields, item.get("findings") or []))
    return meta_events(records, path, tz)


def meta_from_csv(rows, path, tz):
    grouped = {}
    for r in rows:
        g = grouped.setdefault(r.get("file", ""), {"full": "", "fields": [], "findings": []})
        if r.get("section") == "File" and r.get("field") == "Path":
            g["full"] = r.get("value", "")
        elif r.get("section") == "Findings":
            g["findings"].append(r.get("value", ""))
        else:
            g["fields"].append((r.get("section", ""), r.get("field", ""), r.get("value", "")))
    return meta_events([(k, g["full"], g["fields"], g["findings"]) for k, g in grouped.items()],
                       path, tz)


# --- timecheck's own output (so timelines can be merged) -------------------

OWN_FIELDS = ["time", "source", "label", "what", "macb", "detail", "path", "flags", "links",
              "tz_assumed", "artifact", "line"]


def own_event(r, tz):
    t, naive = parse_ts(str(r.get("time") or ""), tz)
    if t is None:
        return None

    def as_list(v):
        return [x for x in v.split("; ") if x] if isinstance(v, str) else list(v or [])

    source = r.get("source") if r.get("source") in SOURCES else "csv"
    e = event(t, source, r.get("label") or source, r.get("what") or "", r.get("detail") or "",
              path=r.get("path") or "", macb=r.get("macb") or "", flags=as_list(r.get("flags")),
              artifact=r.get("artifact") or "", line=r.get("line") or None,
              naive=naive or str(r.get("tz_assumed")).lower() in ("true", "1"))
    e["links"] = as_list(r.get("links"))
    e["has_b"] = "b" in e["macb"]
    return e


# --- generic CSV (EvtxECmd, MFTECmd, PECmd, spreadsheets...) ---------------

TIME_COL = re.compile(r"time|date|created|modified|accessed|changed|written|stamp|when|_utc|"
                      r"lastrun|firstrun|first|last", re.I)
PREFER = ["MapDescription", "Description", "Message", "EventId", "Event ID", "EventID",
          "Provider", "Channel", "UserName", "User", "ExecutableName", "Executable",
          "FileName", "Name", "Path", "FullPath", "ParentPath", "SourceFile", "Command",
          "CommandLine", "Url", "PayloadData1", "PayloadData2", "PayloadData3",
          "RemoteHost", "Computer"]
PATH_COLS = ("FullPath", "Path", "FileName", "ExecutableName", "Executable", "SourceFile", "Url")


def read_csv(text):
    sample = text[:65536]
    try:
        dialect = csv.Sniffer().sniff(sample.split("\n", 1)[0], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    return reader.fieldnames or [], list(reader)


def generic_csv_events(header, rows, path, label, tz, forced):
    if forced:
        want = {f.lower() for f in forced}
        tcols = [h for h in header if h and h.lower() in want]
    else:
        tcols = []
        for h in header:
            if not h or not TIME_COL.search(h):
                continue
            vals = [r.get(h) for r in rows[:200] if r.get(h)]
            if vals and sum(1 for v in vals if parse_ts(v, tz)[0]) >= 0.5 * len(vals):
                tcols.append(h)
    if not tcols:
        return None
    lower = {h.lower(): h for h in header if h}
    order = []
    for h in [lower[p.lower()] for p in PREFER if p.lower() in lower] + [h for h in header if h]:
        if h not in order:
            order.append(h)
    order = [h for h in order if h not in tcols]
    pathcol = next((lower[c.lower()] for c in PATH_COLS if c.lower() in lower), None)

    events = []
    for n, r in enumerate(rows, 2):
        parts = [f"{h}={' '.join(str(r[h]).split())}" for h in order
                 if r.get(h) not in (None, "")][:8]
        detail = "  ".join(parts)
        for h in tcols:
            t, naive = parse_ts(r.get(h) or "", tz)
            if t is None:
                continue
            events.append(event(t, "csv", label, h, detail,
                                path=(r.get(pathcol) or "") if pathcol else "",
                                artifact=path, line=n, naive=naive))
    return events


# --- text logs -------------------------------------------------------------

ISO_LINE = re.compile(r"^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?"
                      r"(?:\s?(?:Z|UTC|[+-]\d{2}:?\d{2}))?)\]?[\s,|:-]*(.*)$")
SYSLOG_LINE = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (.*)$")
CLF_LINE = re.compile(r"^(\S+) \S+ \S+ \[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] (.*)$")

LOG_RULES = [
    (re.compile(r"Failed password|Failed publickey|authentication failure|Invalid user", re.I),
     "failed login"),
    (re.compile(r"Accepted (?:password|publickey|keyboard-interactive)", re.I),
     "remote login accepted"),
    (re.compile(r"sudo(?:\[\d+\])?: .*COMMAND=", re.I), "sudo command"),
    (re.compile(r"\b(?:useradd|userdel|usermod|groupadd)\b|new user:|password changed", re.I),
     "account change"),
    (re.compile(r"\.\./|/etc/passwd|cmd=|union(?:\s|%20|\+)+select|<script|wget(?:\s|%20|\+)|"
                r"curl(?:\s|%20|\+)|base64_decode|\.php\?.*=(?:http|ftp)", re.I),
     "suspicious web request"),
]


def log_flags(text):
    return [name for rx, name in LOG_RULES if rx.search(text)]


def looks_like_log(lines):
    sample = [ln for ln in lines[:50] if ln.strip()]
    if not sample:
        return False
    hits = sum(1 for ln in sample if ISO_LINE.match(ln) or SYSLOG_LINE.match(ln) or CLF_LINE.match(ln))
    return hits >= max(1, 0.6 * len(sample))


def parse_log(text, path, label, tz, year):
    events = []
    try:
        mtime = from_ns(os.stat(path).st_mtime_ns)
    except OSError:
        mtime = NOW
    base_year = year or mtime.year
    for n, ln in enumerate(text.splitlines(), 1):
        t = naive = None
        m = ISO_LINE.match(ln)
        if m:
            t, naive = parse_ts(m.group(1).replace(",", "."), tz)
            body = m.group(2)
        elif CLF_LINE.match(ln):
            m = CLF_LINE.match(ln)
            t, naive = parse_ts(m.group(2), tz)
            body = f"{m.group(1)}  {m.group(3)}"
        else:
            m = SYSLOG_LINE.match(ln)
            if m and m.group(1).lower() in MONTHS:
                mon = MONTHS[m.group(1).lower()]
                t, naive = _build(base_year, mon, m.group(2), m.group(3), m.group(4), m.group(5),
                                  None, None, tz)
                # syslog has no year: a line dated after the file was last written is last year's
                if t and not year and t > mtime + dt.timedelta(days=1):
                    t, naive = _build(base_year - 1, mon, m.group(2), m.group(3), m.group(4),
                                      m.group(5), None, None, tz)
                body = m.group(6)
        if t is None:
            continue
        body = body.strip()
        events.append(event(t, "log", label, "log", body, path=path,
                            flags=log_flags(body), artifact=path, line=n, naive=naive))
    return events


# --- dispatcher ------------------------------------------------------------


def read_artifact(path, args, tz, warnings):
    """Work out what a named file is and read it. Returns (kind, events, entries)."""
    name = os.path.basename(path)
    try:
        head = read_text(path, 262144)
    except OSError as exc:
        warnings.append(f"{path}: {exc.strerror or exc}")
        return None, [], []
    if head is None:
        return "file system", [], walk_fs(path, False, [], warnings)

    stripped = head.lstrip()
    lines = head.splitlines()

    if stripped[:1] in ("{", "["):
        try:
            doc = json.loads(read_text(path))
        except (ValueError, OSError):
            doc = None
        if isinstance(doc, dict) and doc.get("tool") == "histcheck":
            evs = [hist_event(r, path, i, tz) for i, r in enumerate(doc.get("records") or [], 1)]
            return "histcheck JSON", [e for e in evs if e], []
        if isinstance(doc, dict) and doc.get("tool") == "timecheck":
            evs = [own_event(r, tz) for r in doc.get("events") or []]
            return "timecheck JSON", [e for e in evs if e], []
        if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "sections" in doc[0]:
            return "metacheck JSON", meta_from_json(doc, path, tz), []

    if looks_like_bodyfile(lines):
        return "bodyfile", parse_bodyfile(read_text(path), path, f"body:{name}"), []

    first = lines[0] if lines else ""
    if any(sep in first for sep in (",", "\t", ";")):
        header, rows = read_csv(read_text(path))
        hset = {h.strip().lower() for h in header if h}
        if HIST_FIELDS <= hset:
            evs = [hist_event(r, path, i, tz) for i, r in enumerate(rows, 2)]
            return "histcheck CSV", [e for e in evs if e], []
        if {"time", "source", "label", "what", "macb", "detail"} <= hset:
            evs = [own_event(r, tz) for r in rows]
            return "timecheck CSV", [e for e in evs if e], []
        if hset == {"file", "type", "section", "field", "value"}:
            return "metacheck CSV", meta_from_csv(rows, path, tz), []
        if not looks_like_log(lines):
            evs = generic_csv_events(header, rows, path, f"csv:{name}", tz, args.time_col)
            if evs is not None:
                return "CSV", evs, []

    if looks_like_log(lines):
        return "log", parse_log(read_text(path), path, f"log:{name}", tz, args.year), []

    warnings.append(f"{path}: no timestamps recognized inside, using its file system times")
    return "file system", [], walk_fs(path, False, [], warnings)


# --------------------------------------------------------------------------
# Linking browser downloads to files on disk
# --------------------------------------------------------------------------


def link_downloads(events, local):
    downloads = {}
    for e in events:
        if e["source"] == "browser" and e["what"] == "download" and e.get("download_path"):
            key = path_key(e["download_path"])
            if key and "/" in key:
                downloads.setdefault(key, e)
    if not downloads:
        return
    born = {path_key(e["path"]) for e in events
            if e["source"] in ("fs", "bodyfile") and e.get("has_b")}
    for e in events:
        if e["source"] not in ("fs", "bodyfile") or not e["macb"]:
            continue
        key = path_key(e["path"])
        d = downloads.get(key)
        if not d:
            continue
        if "b" in e["macb"] or (key not in born and "m" in e["macb"]):
            e["links"].append(f"downloaded by {d['label']} at {fmt_time(d['time'], local)} "
                              f"from {d['path']}")
            note = f"file on disk: {e['path']}"
            if note not in d["links"]:
                d["links"].append(note)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def clip(text, n):
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 3] + "..."


def render_summary(sources, events, local):
    lines = ["", "Sources:"]
    for s in sources:
        span = ""
        if s["first"]:
            span = f"  {fmt_time(s['first'], local)} -> {fmt_time(s['last'], local)}"
        lines.append(f"  {s['label']}  [{s['kind']}]  {s['events']} event(s){span}")
        lines.append(f"    {s['path']}")
        if s.get("sha256"):
            lines.append(f"    sha256 {s['sha256']}")
    hours = Counter((e["time"].astimezone() if local else e["time"])
                    .replace(minute=0, second=0, microsecond=0) for e in events)
    if len(hours) > 1:
        busiest = hours.most_common(8)
        top = busiest[0][1]
        lines += ["", "Busiest hours:"]
        for h, n in sorted(busiest):
            bar = "#" * max(1, round(30 * n / top))
            lines.append(f"  {fmt_time(h, local)}  {bar} {n}")
    flagged = sum(1 for e in events if e["flags"])
    linked = sum(1 for e in events if e["links"] and e["source"] != "browser")
    naive = sum(1 for e in events if e["tz_assumed"])
    notes = []
    if flagged:
        notes.append(f"{flagged} event(s) flagged with !")
    if linked:
        notes.append(f"{linked} file event(s) linked to a browser download with ~")
    if naive:
        notes.append(f"{naive} event(s) marked * had no time zone in the source and were read "
                     f"as {sources_tz_name()} (change with --tz)")
    if notes:
        lines += [""] + notes
    return "\n".join(lines) + "\n"


_TZ_NAME = ["UTC"]


def sources_tz_name():
    return _TZ_NAME[0]


def render_table(events, sources, local, summary_only, full, pivot=None):
    out = []
    if not summary_only and events:
        w = max([len("SOURCE")] + [len(e["label"]) for e in events])
        ww = max([len("WHAT")] + [len(e["what"]) for e in events])
        tz = "local" if local else "UTC"
        out.append(f"{'TIME (' + tz + ')':<24}  {'SOURCE':<{w}}  {'WHAT':<{ww}}  DETAIL")
        pad = " " * (24 + 2 + w + 2 + ww + 1)
        pivot_done = pivot is None
        for e in events:
            if not pivot_done and e["time"] >= pivot:
                out.append(f">>> {fmt_time(pivot, local)}  (--around)")
                pivot_done = True
            stamp = fmt_time(e["time"], local) + ("*" if e["tz_assumed"] else "")
            mark = "!" if e["flags"] else " "
            detail = e["detail"] if full else clip(e["detail"], 160)
            out.append(f"{stamp:<24}  {e['label']:<{w}}  {e['what']:<{ww}} {mark}{detail}")
            for f in e["flags"]:
                out.append(f"{pad}! {f}")
            for link in e["links"]:
                out.append(f"{pad}~ {link if full else clip(link, 160)}")
        if not pivot_done:
            out.append(f">>> {fmt_time(pivot, local)}  (--around)")
    return "\n".join(out) + ("\n" if out else "") + render_summary(sources, events, local)


def render_csv(events, local):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=OWN_FIELDS, extrasaction="ignore")
    w.writeheader()
    for e in events:
        row = dict(e)
        row["time"] = fmt_time(e["time"], local, precise=True)
        row["flags"] = "; ".join(e["flags"])
        row["links"] = "; ".join(e["links"])
        w.writerow(row)
    return buf.getvalue()


def render_json(events, sources, warnings, local):
    def clean(obj):
        return {k: (fmt_time(v, local, precise=True) if isinstance(v, dt.datetime) else v)
                for k, v in obj.items() if k not in ("has_b", "download_path")}
    doc = {
        "tool": "timecheck", "version": __version__,
        "generated": fmt_time(dt.datetime.now(UTC), local),
        "sources": [clean(s) for s in sources],
        "events": [clean(e) for e in events],
        "warnings": warnings,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="timecheck",
        description="Forensic timeline builder: file system times, bodyfiles, browser history, "
                    "metadata, CSV exports and logs merged into one sorted timeline.")
    p.add_argument("targets", nargs="+", metavar="target",
                   help="folder to walk for file times, or a file to read events from "
                        "(bodyfile, histcheck/metacheck output, CSV, log)")
    p.add_argument("--since", metavar="DATE", help="only events on/after DATE (YYYY-MM-DD[ HH:MM])")
    p.add_argument("--until", metavar="DATE", help="only events on/before DATE")
    p.add_argument("--around", metavar="DATE",
                   help="only events within --window of DATE, with DATE marked in the table")
    p.add_argument("--window", metavar="SPAN", default="15m",
                   help="span either side of --around (e.g. 90s, 15m, 2h, 1d; default 15m)")
    p.add_argument("-s", "--source", action="append", choices=SOURCES,
                   help="only events from this kind of source (repeatable)")
    p.add_argument("-g", "--grep", metavar="TEXT", action="append",
                   help="only events whose detail, path or flags contain TEXT (repeatable)")
    p.add_argument("--macb", metavar="LETTERS",
                   help="file events only if they include one of these letters, e.g. b or mb")
    p.add_argument("--flagged", action="store_true", help="only events with findings (!)")
    p.add_argument("-x", "--exclude", metavar="GLOB", action="append", default=[],
                   help="skip files/folders matching GLOB when walking (repeatable)")
    p.add_argument("-n", "--no-recurse", action="store_true",
                   help="don't descend into subfolders")
    p.add_argument("--time-col", metavar="NAME", action="append",
                   help="CSV input: use this column as the time (repeatable)")
    p.add_argument("--tz", metavar="ZONE", default="UTC",
                   help="zone for timestamps that don't carry one: UTC (default), local, "
                        "or an offset like -05:00")
    p.add_argument("--year", type=int, help="year for syslog lines (they don't include one)")
    p.add_argument("--local", action="store_true",
                   help="show and filter times in this computer's time zone instead of UTC")
    p.add_argument("--summary", action="store_true",
                   help="table format: only the per-source summary and busiest hours")
    p.add_argument("--full", action="store_true", help="table format: don't shorten long lines")
    p.add_argument("-f", "--format", choices=("table", "csv", "json"), default="table")
    p.add_argument("-o", "--output", metavar="FILE", help="write output to a file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def keep(e, args, since, until, grep):
    if args.source and e["source"] not in args.source:
        return False
    if since and e["time"] < since:
        return False
    if until and e["time"] > until:
        return False
    if args.flagged and not e["flags"]:
        return False
    if args.macb and e["macb"] and not any(c in e["macb"] for c in args.macb.lower()):
        return False
    if grep:
        hay = "\n".join([e["detail"], e["path"], e["what"], e["label"]] + e["flags"]
                        + e["links"]).lower()
        if not any(g in hay for g in grep):
            return False
    return True


def main(argv=None):
    args = parse_args(argv)
    try:
        if args.tz.lower() == "local":
            tz = "local"
            _TZ_NAME[0] = "this computer's local time"
        else:
            zone = args.tz.strip()
            if len(zone) > 3 and zone[:3].upper() in ("UTC", "GMT"):
                zone = zone[3:]          # UTC-05:00 -> -05:00
            if re.fullmatch(r"[+-]\d{1,2}", zone):
                zone = zone[0] + zone[1:].zfill(2)   # -5 -> -05
            tz = parse_offset(zone)
            if tz is None:
                raise ValueError(f"can't read --tz '{args.tz}' (use UTC, local, or e.g. -05:00)")
            _TZ_NAME[0] = "UTC" if tz is UTC else f"UTC{zone}"
        since = parse_when(args.since, args.local) if args.since else None
        until = parse_when(args.until, args.local, end=True) if args.until else None
        pivot = None
        if args.around:
            pivot = parse_when(args.around, args.local)
            span = parse_window(args.window)
            since, until = pivot - span, pivot + span
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2

    excludes = [g.lower() for g in args.exclude]
    sources, events, warnings, seen = [], [], [], set()
    for target in args.targets:
        if not os.path.lexists(target):
            print(f"[!] Not found: {target}", file=sys.stderr)
            return 2
        real = os.path.realpath(target)
        if real in seen:
            continue
        seen.add(real)
        info = {"label": "", "kind": "", "path": target, "events": 0, "first": None,
                "last": None, "sha256": ""}
        if os.path.isdir(target):
            entries = walk_fs(target, not args.no_recurse, excludes, warnings)
            label = "fs"
            evs = entries_to_events(entries, "fs", label)
            info.update(label=label, kind="file system")
        else:
            kind, evs, entries = read_artifact(target, args, tz, warnings)
            if kind is None:
                continue
            if kind == "file system":
                evs = entries_to_events(entries, "fs", "fs")
                info.update(label="fs", kind=kind)
            else:
                info.update(label=evs[0]["label"] if evs and kind in ("log", "CSV", "bodyfile")
                            else kind.split()[0], kind=kind)
                try:
                    info["sha256"] = sha256_file(target)
                except OSError:
                    pass
            if kind not in ("file system",) and not evs:
                warnings.append(f"{target}: read as {kind} but no usable timestamps found")
        info["events"] = len(evs)
        if evs:
            info["first"] = min(e["time"] for e in evs)
            info["last"] = max(e["time"] for e in evs)
        sources.append(info)
        events += evs

    if not events:
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
        print("[!] No timestamped events found", file=sys.stderr)
        return 1

    link_downloads(events, args.local)
    grep = [g.lower() for g in args.grep] if args.grep else None
    events = [e for e in events if keep(e, args, since, until, grep)]
    events.sort(key=lambda e: (e["time"], SOURCE_ORDER[e["source"]], e["detail"]))

    if args.format == "csv":
        text = render_csv(events, args.local)
    elif args.format == "json":
        text = render_json(events, sources, warnings, args.local)
    else:
        text = render_table(events, sources, args.local, args.summary, args.full, pivot)

    if args.output:
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        print(f"[*] {len(events)} event(s) from {len(sources)} source(s) written to "
              f"{args.output}", file=sys.stderr)
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            sys.stderr.close()

    if args.format != "json":
        for w in warnings:
            print(f"[!] {w}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
