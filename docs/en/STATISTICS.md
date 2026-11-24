# Project statistics

English summary of `docs/STATISTIK.md`, state at publication (24 November 2026, 05:18). Times and
commit counts come from the version history of the development PC, which is not published. The
German file additionally lists every milestone, the duration of each development step and every
test run in Windows Sandbox.

## Period and time spent

| Item | Value |
|---|---|
| Project start | 13 November 2026, 09:59 |
| Last change | 24 November 2026, 05:18 |
| Calendar time | 259.3 h |
| Active working time (estimate) | 59.2 h in 53 working blocks |
| Commits | 242 |

How the active time is estimated: commits and milestones are grouped into working blocks; a pause
of more than 60 minutes starts a new block. Work before the first event of a block is not
included.

## Test PC

Every measurement and test in the manual and in the test report comes from a single PC (as of
23 November 2026, read from Windows).

| Component | Details |
|---|---|
| Processor | AMD Ryzen Threadripper 3960X, 24 cores, 48 logical processors |
| Mainboard | Gigabyte TRX40 AORUS XTREME (BIOS F7f of 24 September 2025) |
| Memory | 64 GB |
| Graphics card | NVIDIA GeForce RTX 3090 (24 GB) |
| Drives | four NVMe SSDs of about 2 TB each (Samsung SSD 990, three Seagate FireCuda), one 10 TB hard disk (WD) |
| Operating system | Windows 11 Pro, version 25H2, build 26200.9974 |
| Antivirus next to K9 | Trend Micro Maximum Security |
| Windows protection features | virtualisation (SVM) on; Secure Boot off; memory integrity off until 23 November 2026, on since then |

## AI usage: tokens and cost

K9 was developed entirely in conversation with Claude (Claude Code). The table shows what the
session logs on the test PC recorded: 891 requests from 8 sessions between 16 and
23 November 2026 (counted on 23 November 2026, 08:54). The cost is converted to
**Claude Fable 5.2** at the list prices of the Anthropic API per million tokens (price list as of
3 November 2026). Part of the requests actually ran on the cheaper Claude Opus 5.5.

| Kind | Tokens | Price per million | Cost |
|---|---:|---:|---:|
| Output (written by Claude, including thinking) | 758,736 | 40.00 USD | 30.35 USD |
| Input without cache | 2,114 | 8.00 USD | 0.02 USD |
| Input read from the cache | 370,633,730 | 0.20 USD | 74.13 USD |
| Input written to the cache (5 minutes) | 1,144,655 | 10.00 USD | 11.45 USD |
| Input written to the cache (1 hour) | 3,868,328 | 16.00 USD | 61.89 USD |
| **Total of the recorded sessions** | | | **177.83 USD** |

**Extrapolation to the whole project (estimate):** the recorded sessions cover 16.8 hours of
active work (counted the same way as above). That is about 10.60 USD per hour. Applied to the
59.2 hours of active working time of the whole project, this gives about **626 USD**.

**What this number is not:** it is not an invoice. The first three days (13 to 15 November),
several later working blocks and the conversations outside these sessions are not recorded on the
PC; for them the hourly rate of the recorded sessions is assumed. The project was not billed per
token at this price list.

## Size of the program

| Crate | Lines (Rust) |
|---|---:|
| k9-core | 30,623 |
| k9-dienst | 5,463 |
| k9-agent | 4,715 |
| k9-cli | 2,365 |
| k9-doc | 433 |
| k9-res | 140 |
| k9-testsim | 212 |
| **total** | **43,951** |

| Item | Value |
|---|---:|
| Automated unit tests | 389 |
| Checks in the end-to-end test | 45 |
| PowerShell scripts (lines) | 4,514 |
| Documentation (Markdown lines) | 6,271 |
| Pages of the German manual | 111 |

## Detection data on the test PC

| Item | Count |
|---|---:|
| Detection sources active / up to date | 15 / 15 |
| YARA rules | 10,848 |
| ClamAV signatures | 3,642,950 |
| Malware hashes | 1,227,362 |
| Malicious and phishing addresses | 212,016 |
| CISA KEV entries | 1,790 |

## Measurements (from the German test report)

| Measurement | Result |
|---|---|
| Agent when idle | 0.08 % CPU (all cores), 28 MB memory |
| Agent during a game | 0.01 % CPU |
| Service after installation (10 min, with driver check) | 1.70 % of one core, 505 file opens/s, 42 % of them checked |
| Service during a game (3 × 10 min) | 0.57–0.82 % of one core (with 48 cores about 0.01 % of the CPU), 397–576 file opens/s, 37–52 % checked |
| Service in the sandbox (10 min) | 0.21 % of one core, 62 file opens/s, 3 % checked |
| Scan of the Downloads folder (99 files, 882 MB) | 4.6 s (about 190 MB/s); second run 0.0 s |
| Autostarts, browser history, hosts file | 12.3 s for 178 autostart entries |
| ClamAV real-time check | about 10 s loading time once, about 1 GB of memory only while active |
| Drivers | 568 checked, 0 on a block list (after cleaning up 9 drivers/services) |
| Lookalike domains against the 1 million most popular domains | 53 hits, almost all real imitations |
| Ransomware test program (400 files, 40 per second), suspending on | unknown program: 382 to 383 of 400 files intact; known program: 400 of 400 (392 if it starts at once); suspending off: 0 |

Tests with real ransomware samples in Windows Sandbox, the comparison runs and every failed run
are described in `docs/TESTBERICHT.md` (German).
