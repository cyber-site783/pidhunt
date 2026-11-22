# PidHunt — Your Own Process Memory Scanner

PidHunt is a command-line tool, written in Python, that reads the memory of
a running process you own and hunts for byte patterns — injected markers,
leaked secrets, suspicious strings — using rules you write yourself.

You give it a process ID. It reads the memory map from the process
information filesystem (`/proc/<pid>/maps`), selects the readable regions,
reads each region in chunks from the process memory file
(`/proc/<pid>/mem`), and matches every chunk against a rule file of
patterns: plain strings, hex byte sequences and regular expressions. It
reports each hit with the region name, offset and surrounding context bytes,
and saves a report.

It only ever **reads** memory. It never writes to another process, and it
refuses to scan any process owned by another user.

## Name

The PNY Trainings brief for this project calls the tool **MemScope**. That
name is already used by other projects, so this tool is published as
**PidHunt**:

- MemScope (akketix/memscope) — a Windows RAM/VRAM pressure monitor
- memscope (090type/memscope) — a real-time heap memory visualiser for C++
- memscope-mcp — a Windows process-memory MCP server
- memscope-rs — a Rust memory analyser
- Memscope in Perfetto — a live memory monitor

PidHunt does exactly what the brief asks for, under a name that was free on
both Google and GitHub when checked.

## How it works

1. Check the target process is owned by the current user, refuse otherwise.
2. Parse the memory map and collect every readable region with its address
   range and name.
3. Load the rule file and compile each pattern into its matcher.
4. Read each region in chunks from the process memory file, keeping an
   overlap window so a pattern split across chunks is never missed.
5. Match every chunk against every rule and record each hit with region,
   offset and context bytes.
6. Print and save the report of all hits.

## Requirements

- Linux (the tool reads `/proc/<pid>/maps` and `/proc/<pid>/mem`)
- Python 3, no extra packages — standard library only
- `gcc` only if you want to build the example marker program

## Quick demo (one command)

```bash
bash demo.sh
```

This builds the example marker program, runs it, scans it with PidHunt and
shows the report. The marker program holds three planted markers (a plain
string, a hex byte sequence and a password line matched by regex) plus a
high-entropy region, so the demo exercises every feature.

## Usage

```bash
python3 pidhunt.py --rules rules.txt <pid>
python3 pidhunt.py --rules rules.txt --output report.txt <pid>
python3 pidhunt.py --rules rules.txt --entropy --strings <pid>
python3 pidhunt.py --rules rules.txt --json --output report.json <pid>
python3 pidhunt.py --rules rules.txt --watch 5 <pid>
```

Options:

| Option | What it does |
| --- | --- |
| `-r, --rules FILE` | Rule file (required) |
| `-o, --output FILE` | Report file (default: `pidhunt-report.txt`) |
| `--json` | Save the report as JSON instead of text |
| `--entropy` | Flag high-entropy regions (packed or encrypted data) |
| `--strings` | Print readable strings around each hit |
| `--watch SECONDS` | Rescan every N seconds, report only new hits (Ctrl+C stops) |
| `--chunk-size BYTES` | Bytes read per chunk (default: 1048576) |

Exit codes: `0` — scan finished, no hits; `1` — hits found;
`2` — error (bad PID, wrong owner, bad rule file, unreadable memory).

## Rule file format

One rule per line: `TYPE PATTERN NAME`

```text
# Lines starting with # are comments. Blank lines are skipped.
string PIDHUNT_SECRET_MARKER_12345 secret-marker
hex DEADBEEF01020304 hex-marker
regex password=[A-Za-z0-9!]+ password-pattern
```

- `string` — a plain string, matched exactly (UTF-8).
- `hex` — a byte sequence, written as an even-length hex string.
- `regex` — a regular expression, matched against the raw bytes.

The `NAME` is shown in the report; keep it short, with no spaces. A very
long regex match that spans more than the overlap window (4096 bytes by
default) could be missed — keep regex matches short.

## What a hit looks like

```text
[secret-marker] string: PIDHUNT_SECRET_MARKER_12345
  Region: /home/user/marker_program (0x...-0x...)
  Offset: 0xc0 (absolute 0x...)
  Matched: 50 49 44 ...  |  PIDHUNT_SECRET_MARKER_12345
  Context: ...  |  ...PIDHUNT_SECRET_MARKER_12345...
```

One marker can appear in more than one region, and every copy is reported.
In the demo, the three planted markers produce 8 hits: each marker sits in
two read-only mappings of the binary (the loader maps the same file offset
twice), and the secret marker and password line also appear in the heap —
copies left in `printf`'s stdout buffer. That duplication is real, and it is
the defensive lesson below.

## Defensive lesson: secrets do not stay in one place

The demo proves it. A password that exists once in a program's source ends
up in several places in memory: the read-only mapping of the binary, a
second mapping of the same data, and the heap, where library buffers copy
it while printing. Deleting the variable does not delete the copies.

That is why secrets must never sit in process memory in plaintext. Programs
that handle secrets properly keep them encrypted in memory and decrypt them
only for the moment of use (and wipe the buffer right after), or they hand
the secret to the operating system's key store and never hold it themselves.
If a secret is in memory in plaintext, anyone who can read that process —
or its crash dump, or its swap — can read the secret too.

## Lab only

Scan only processes you started yourself, on your own machine. Never scan a
process owned by another user or on a machine you do not own. Reading
another person's process memory without permission is unauthorised access —
a criminal offence under the Prevention of Electronic Crimes Act, 2016
(Pakistan).

## Troubleshooting

- `error: cannot open /proc/<pid>/mem: Permission denied` — the kernel
  only lets a process read another process's memory if it is allowed to
  trace it. Run with `sudo`, or check
  `/proc/sys/kernel/yama/ptrace_scope` (value `1` means only a parent
  process may trace its child).
- `error: PID ... is owned by UID ...` — PidHunt only scans your own
  processes. This is deliberate.
- `error: no process with PID ...` — the process exited, or the PID is
  wrong. Check with `ps -p <pid>`.
- `No hits.` — the rules did not match anything. Check the rule file
  format (`TYPE PATTERN NAME`) and that the marker is really in the
  target's memory.

## Files

```text
pidhunt.py                  The tool (standard library only)
README.md                   This file
LICENSE                     MIT licence
examples/rules.txt          Example rule file (one rule of each type)
examples/marker_program.c   Lab program holding planted markers
examples/sample-report.txt  Real report from a demo scan
demo.sh                     One-command demo
```
