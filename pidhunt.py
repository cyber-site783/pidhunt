#!/usr/bin/env python3
"""PidHunt - Your Own Process Memory Scanner.

PidHunt reads the memory of a running process you own and hunts for byte
patterns - injected markers, leaked secrets, suspicious strings - using
rules you write yourself.

It only ever READS memory. It never writes to another process, and it
refuses to scan any process owned by another user.

How it works (the six steps from the project brief):
    1. Check the target process is owned by the current user, refuse otherwise.
    2. Parse /proc/<pid>/maps and collect every readable region.
    3. Load the rule file and compile each pattern into its matcher.
    4. Read each region in chunks from /proc/<pid>/mem, keeping an overlap
       window so a pattern split across chunks is never missed.
    5. Match every chunk against every rule and record each hit with region,
       offset and context bytes.
    6. Print and save the report of all hits.

Usage:
    python3 pidhunt.py --rules rules.txt <pid>
    python3 pidhunt.py --rules rules.txt --output report.txt <pid>
    python3 pidhunt.py --rules rules.txt --entropy --strings <pid>
    python3 pidhunt.py --rules rules.txt --watch 5 <pid>

Exit codes:
    0 - scan finished, no hits
    1 - hits found
    2 - error (bad PID, wrong owner, bad rule file, unreadable memory)

Lab only: scan only processes you started yourself, on your own machine.
Reading another person's process memory without permission is unauthorised
access (PECA 2016, Pakistan).
"""

import argparse
import json
import math
import os
import re
import sys
import time

VERSION = "1.0.0"
CHUNK_SIZE = 1024 * 1024          # 1 MiB read per chunk
CONTEXT_SIZE = 16                 # context bytes shown on each side of a hit
ENTROPY_THRESHOLD = 7.0           # bits per byte; above this a region is HIGH
ENTROPY_SAMPLE_SIZE = 64 * 1024   # bytes sampled per region for entropy
STRING_MIN_LEN = 4
STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")


class ScanError(Exception):
    """A clean, user-facing error. Printed without a traceback."""


class Region:
    """One readable region from /proc/<pid>/maps."""

    def __init__(self, start, end, perms, pathname):
        self.start = start
        self.end = end
        self.perms = perms
        self.pathname = pathname or "[anonymous]"

    @property
    def size(self):
        return self.end - self.start

    def label(self):
        return f"{self.pathname} ({self.start:#x}-{self.end:#x})"


class Rule:
    """One rule from the rule file: a plain string, hex bytes or regex."""

    def __init__(self, name, kind, pattern_text, matcher):
        self.name = name
        self.kind = kind
        self.pattern_text = pattern_text
        self.matcher = matcher          # bytes (string/hex) or compiled regex

    def fixed_length(self):
        """Length in bytes, for string and hex rules. None for regex."""
        if self.kind == "regex":
            return None
        return len(self.matcher)

    def find_all(self, data):
        """Yield (offset, length) of every match in data."""
        if self.kind == "regex":
            for match in self.matcher.finditer(data):
                yield match.start(), match.end() - match.start()
        else:
            start = 0
            while True:
                pos = data.find(self.matcher, start)
                if pos < 0:
                    return
                yield pos, len(self.matcher)
                start = pos + 1         # allow overlapping matches


class Hit:
    """One pattern match, with its region, address and context bytes."""

    def __init__(self, rule, region, address, length, matched,
                 context_before, context_after):
        self.rule = rule
        self.region = region
        self.address = address
        self.length = length
        self.matched = matched
        self.context_before = context_before
        self.context_after = context_after

    @property
    def offset_in_region(self):
        return self.address - self.region.start

    def key(self):
        return (self.rule.name, self.address)


def parse_maps(pid):
    """Read /proc/<pid>/maps and return every readable region."""
    regions = []
    try:
        with open(f"/proc/{pid}/maps", "r") as maps_file:
            for line in maps_file:
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                address, perms = parts[0], parts[1]
                pathname = parts[5].strip() if len(parts) == 6 else ""
                if "r" not in perms:
                    continue
                start_s, end_s = address.split("-")
                regions.append(Region(int(start_s, 16), int(end_s, 16),
                                      perms, pathname))
    except FileNotFoundError:
        raise ScanError(f"no process with PID {pid}")
    except OSError as exc:
        raise ScanError(f"cannot read /proc/{pid}/maps: {exc}")
    return regions


def check_ownership(pid):
    """Refuse any process not owned by the current user."""
    try:
        owner_uid = os.stat(f"/proc/{pid}").st_uid
    except FileNotFoundError:
        raise ScanError(f"no process with PID {pid}")
    if owner_uid != os.getuid():
        raise ScanError(
            f"PID {pid} is owned by UID {owner_uid}, not by you "
            f"(UID {os.getuid()}). PidHunt only scans your own processes.")


def process_name(pid):
    """Short name of the process, from /proc/<pid>/comm."""
    try:
        with open(f"/proc/{pid}/comm", "r") as comm_file:
            return comm_file.read().strip()
    except OSError:
        return "?"


def make_rule(kind, pattern_text, name, path, line_no):
    """Compile one rule line into a Rule. Raises ValueError on bad input."""
    where = f"{path}:{line_no}"
    if kind == "string":
        return Rule(name, kind, pattern_text, pattern_text.encode("utf-8"))
    if kind == "hex":
        try:
            matcher = bytes.fromhex(pattern_text)
        except ValueError:
            raise ValueError(f"{where}: bad hex pattern '{pattern_text}'")
        if not matcher:
            raise ValueError(f"{where}: empty hex pattern")
        return Rule(name, kind, pattern_text, matcher)
    if kind == "regex":
        try:
            matcher = re.compile(pattern_text.encode("utf-8"))
        except re.error as exc:
            raise ValueError(f"{where}: bad regex '{pattern_text}': {exc}")
        return Rule(name, kind, pattern_text, matcher)
    raise ValueError(f"{where}: unknown rule type '{kind}' "
                     "(use string, hex or regex)")


def load_rules(path):
    """Load a rule file. One rule per line: TYPE PATTERN NAME.

    TYPE is string, hex or regex. Lines starting with # are comments.
    Blank lines are skipped.
    """
    rules = []
    try:
        rule_file = open(path, "r")
    except OSError as exc:
        raise ScanError(f"cannot open rule file {path}: {exc}")
    with rule_file:
        for line_no, raw in enumerate(rule_file, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 2)
            if len(parts) != 3:
                raise ScanError(
                    f"{path}:{line_no}: expected 'TYPE PATTERN NAME', "
                    f"got: {raw.strip()}")
            kind, pattern_text, name = parts
            try:
                rules.append(make_rule(kind, pattern_text, name, path, line_no))
            except ValueError as exc:
                raise ScanError(str(exc))
    if not rules:
        raise ScanError(f"{path}: no rules found")
    return rules


def compute_overlap(rules, chunk_size):
    """Overlap window between chunks, in bytes.

    At least as large as the longest fixed pattern, so a pattern split
    across a chunk boundary is never missed. Never more than half a chunk.
    """
    longest = 0
    for rule in rules:
        length = rule.fixed_length()
        if length is not None:
            longest = max(longest, length)
    overlap = max(4096, longest)
    return min(overlap, chunk_size // 2)


def shannon_entropy(data):
    """Shannon entropy of bytes, in bits per byte (0 to 8)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    size = len(data)
    for count in counts:
        if count:
            p = count / size
            entropy -= p * math.log2(p)
    return entropy


def extract_strings(data, min_len=STRING_MIN_LEN):
    """Printable ASCII strings of at least min_len bytes."""
    return [m.group().decode("ascii")
            for m in STRING_RE.finditer(data)
            if len(m.group()) >= min_len]


def format_context(data):
    """Bytes as 'hex | ascii', non-printable bytes shown as dots."""
    hex_part = " ".join(f"{b:02x}" for b in data)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{hex_part}  |  {ascii_part}"


def scan_region(mem_file, region, rules, chunk_size, overlap, want_entropy):
    """Read one region in chunks and return (hits, bytes_read, bytes_skipped, entropy).

    A guarded or unmapped page never crashes the scan: the failed chunk is
    counted as skipped and the scan moves on.
    """
    hits = []
    seen = set()
    bytes_read = 0
    bytes_skipped = 0
    entropy_sample = bytearray()
    offset = 0
    while offset < region.size:
        take = min(chunk_size, region.size - offset)
        read_start = region.start + offset
        try:
            mem_file.seek(read_start)
            data = mem_file.read(take)
        except OSError:
            bytes_skipped += take
            offset += chunk_size - overlap
            continue
        if not data:
            bytes_skipped += take
            offset += chunk_size - overlap
            continue
        if len(data) < take:
            bytes_skipped += take - len(data)
        bytes_read += len(data)
        if want_entropy and len(entropy_sample) < ENTROPY_SAMPLE_SIZE:
            room = ENTROPY_SAMPLE_SIZE - len(entropy_sample)
            entropy_sample += data[:room]
        for rule in rules:
            for pos, length in rule.find_all(data):
                address = read_start + pos
                key = (rule.name, address)
                if key in seen:
                    continue        # same hit, seen in the overlap window
                seen.add(key)
                hits.append(Hit(
                    rule, region, address, length,
                    matched=data[pos:pos + length],
                    context_before=data[max(0, pos - CONTEXT_SIZE):pos],
                    context_after=data[pos + length:pos + length + CONTEXT_SIZE]))
        if take < chunk_size:
            break
        offset += chunk_size - overlap
    entropy = shannon_entropy(bytes(entropy_sample)) if want_entropy else None
    return hits, bytes_read, bytes_skipped, entropy


class ScanResult:
    """Everything one scan pass found."""

    def __init__(self, pid, name, regions, hits, bytes_read, bytes_skipped,
                 entropies):
        self.pid = pid
        self.name = name
        self.regions = regions
        self.hits = hits
        self.bytes_read = bytes_read
        self.bytes_skipped = bytes_skipped
        self.entropies = entropies      # {region: entropy} or None


def scan_pid(pid, rules, chunk_size, want_entropy, want_strings):
    """One full scan pass over a process. Returns a ScanResult."""
    check_ownership(pid)
    regions = parse_maps(pid)
    overlap = compute_overlap(rules, chunk_size)
    try:
        mem_file = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except OSError as exc:
        raise ScanError(
            f"cannot open /proc/{pid}/mem: {exc}. "
            "Try running with sudo, or check kernel.yama.ptrace_scope.")
    hits = []
    bytes_read = 0
    bytes_skipped = 0
    entropies = {} if want_entropy else None
    with mem_file:
        for region in regions:
            region_hits, read, skipped, entropy = scan_region(
                mem_file, region, rules, chunk_size, overlap, want_entropy)
            hits.extend(region_hits)
            bytes_read += read
            bytes_skipped += skipped
            if want_entropy:
                entropies[region] = entropy
    return ScanResult(pid, process_name(pid), regions, hits,
                      bytes_read, bytes_skipped, entropies)


def hit_to_dict(hit, want_strings):
    """One hit as a JSON-ready dict."""
    out = {
        "rule": hit.rule.name,
        "type": hit.rule.kind,
        "pattern": hit.rule.pattern_text,
        "region": hit.region.pathname,
        "region_range": f"{hit.region.start:#x}-{hit.region.end:#x}",
        "address": f"{hit.address:#x}",
        "offset_in_region": f"{hit.offset_in_region:#x}",
        "matched_hex": hit.matched.hex(),
        "matched_ascii": "".join(chr(b) if 32 <= b < 127 else "."
                                for b in hit.matched),
        "context_hex": (hit.context_before + hit.matched +
                        hit.context_after).hex(),
        "context_ascii": "".join(
            chr(b) if 32 <= b < 127 else "." for b in
            hit.context_before + hit.matched + hit.context_after),
    }
    if want_strings:
        out["strings_around_hit"] = extract_strings(
            hit.context_before + hit.matched + hit.context_after)
    return out


def build_report_text(pid, name, rules_path, result, want_strings):
    """The human-readable report, as text."""
    lines = [
        "PidHunt scan report",
        f"Target PID: {pid} ({name})",
        f"Rules file: {rules_path}",
        f"Readable regions scanned: {len(result.regions)}",
        f"Bytes read: {result.bytes_read}",
        f"Bytes skipped (unreadable): {result.bytes_skipped}",
        f"Hits: {len(result.hits)}",
        "",
    ]
    if result.entropies is not None:
        lines.append("Region entropy (HIGH means over "
                     f"{ENTROPY_THRESHOLD} bits per byte):")
        for region, entropy in result.entropies.items():
            flag = "HIGH" if entropy >= ENTROPY_THRESHOLD else "ok"
            lines.append(f"  {entropy:5.2f}  {flag:4}  {region.label()}")
        lines.append("")
    if not result.hits:
        lines.append("No hits.")
        return "\n".join(lines) + "\n"
    for hit in result.hits:
        lines.append(f"[{hit.rule.name}] {hit.rule.kind}: {hit.rule.pattern_text}")
        lines.append(f"  Region: {hit.region.label()}")
        lines.append(f"  Offset: {hit.offset_in_region:#x} "
                     f"(absolute {hit.address:#x})")
        lines.append(f"  Matched: {format_context(hit.matched)}")
        context = hit.context_before + hit.matched + hit.context_after
        lines.append(f"  Context: {format_context(context)}")
        if want_strings:
            strings = extract_strings(context)
            if strings:
                lines.append(f"  Strings: {', '.join(strings)}")
        lines.append("")
    return "\n".join(lines) + "\n"


def build_report_json(pid, name, rules_path, result, want_strings):
    """The same report, as JSON."""
    report = {
        "tool": f"PidHunt {VERSION}",
        "pid": pid,
        "process": name,
        "rules_file": rules_path,
        "regions_scanned": len(result.regions),
        "bytes_read": result.bytes_read,
        "bytes_skipped": result.bytes_skipped,
        "hits": [hit_to_dict(h, want_strings) for h in result.hits],
    }
    if result.entropies is not None:
        report["entropy"] = [
            {"region": region.label(), "entropy": round(entropy, 2),
             "high": entropy >= ENTROPY_THRESHOLD}
            for region, entropy in result.entropies.items()
        ]
    return json.dumps(report, indent=2) + "\n"


def print_hits(hits, want_strings):
    """Print hits to the screen, in short form."""
    for hit in hits:
        print(f"[{hit.rule.name}] {hit.rule.kind} "
              f"@ {hit.region.pathname} +{hit.offset_in_region:#x} "
              f"(absolute {hit.address:#x})")
        print(f"  Matched: {format_context(hit.matched)}")
        if want_strings:
            strings = extract_strings(
                hit.context_before + hit.matched + hit.context_after)
            if strings:
                print(f"  Strings: {', '.join(strings)}")


def save_report(path, text):
    try:
        with open(path, "w") as report_file:
            report_file.write(text)
    except OSError as exc:
        raise ScanError(f"cannot write report {path}: {exc}")


def run_once(args, rules):
    """One scan pass: print a summary, save the report, return exit code."""
    result = scan_pid(args.pid, rules, args.chunk_size,
                      args.entropy, args.strings)
    print(f"PidHunt {VERSION} - PID {args.pid} ({result.name})")
    print(f"Scanned {len(result.regions)} readable regions, "
          f"{result.bytes_read} bytes read, "
          f"{result.bytes_skipped} bytes skipped.")
    if result.entropies is not None:
        print("Region entropy:")
        for region, entropy in result.entropies.items():
            flag = "HIGH" if entropy >= ENTROPY_THRESHOLD else "ok"
            print(f"  {entropy:5.2f}  {flag:4}  {region.label()}")
    if result.hits:
        print(f"Found {len(result.hits)} hit(s):")
        print_hits(result.hits, args.strings)
    else:
        print("No hits.")
    if args.json:
        report = build_report_json(args.pid, result.name, args.rules,
                                   result, args.strings)
    else:
        report = build_report_text(args.pid, result.name, args.rules,
                                   result, args.strings)
    save_report(args.output, report)
    print(f"Report saved to {args.output}")
    return 1 if result.hits else 0


def run_watch(args, rules):
    """Rescan every N seconds and report only new hits."""
    seen = set()
    print(f"PidHunt {VERSION} - watching PID {args.pid} "
          f"every {args.watch} second(s). Ctrl+C to stop.")
    try:
        while True:
            result = scan_pid(args.pid, rules, args.chunk_size,
                              args.entropy, args.strings)
            new_hits = [h for h in result.hits if h.key() not in seen]
            for hit in new_hits:
                seen.add(hit.key())
            if new_hits:
                print(f"[{time.strftime('%H:%M:%S')}] "
                      f"{len(new_hits)} new hit(s):")
                print_hits(new_hits, args.strings)
            else:
                print(f"[{time.strftime('%H:%M:%S')}] No new hits.")
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print("\nWatch stopped.")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PidHunt - scan a process you own for byte patterns "
                    "from a rule file. Read-only; never writes to the process.")
    parser.add_argument("pid", type=int, help="process ID to scan")
    parser.add_argument("-r", "--rules", required=True,
                        help="rule file (one rule per line: TYPE PATTERN NAME)")
    parser.add_argument("-o", "--output", default="pidhunt-report.txt",
                        help="report file (default: pidhunt-report.txt)")
    parser.add_argument("--json", action="store_true",
                        help="save the report as JSON instead of text")
    parser.add_argument("--entropy", action="store_true",
                        help="flag high-entropy regions (packed or encrypted data)")
    parser.add_argument("--strings", action="store_true",
                        help="print readable strings around each hit")
    parser.add_argument("--watch", type=float, metavar="SECONDS",
                        help="rescan every N seconds, report only new hits")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE,
                        metavar="BYTES",
                        help=f"bytes read per chunk (default: {CHUNK_SIZE})")
    parser.add_argument("--version", action="version",
                        version=f"PidHunt {VERSION}")
    args = parser.parse_args(argv)

    if args.pid <= 0:
        print("error: PID must be a positive number", file=sys.stderr)
        return 2
    if args.chunk_size <= 0:
        print("error: --chunk-size must be positive", file=sys.stderr)
        return 2
    try:
        rules = load_rules(args.rules)
        if args.watch is not None:
            if args.watch <= 0:
                print("error: --watch needs a positive number of seconds",
                      file=sys.stderr)
                return 2
            return run_watch(args, rules)
        return run_once(args, rules)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
