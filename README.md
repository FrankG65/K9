# K9 – a companion scanner for Windows PCs that are also used for gaming

*Deutsche Fassung: [README.de.md](README.de.md)*

K9 runs **alongside** your existing antivirus and reports what it notices: malware, ransomware
behaviour, credential stealers, phishing addresses, suspicious program starts, new autostart
entries, vulnerable programs and drivers. It never changes the settings of other security
products, never adds exclusions there and never switches anything off. K9 is written in Rust and
needs no further runtime packages once it is built.

K9 was developed and tested on one Windows 11 PC next to Trend Micro Maximum Security.

> **Language:** K9 speaks **English and German**. It follows the display language of Windows
> (German Windows: German, any other language: English); the switch “Language: Deutsch English”
> at the top right of the dashboard changes it at once, or run `k9 sprache en`. In English you get
> the whole dashboard, the alert windows, the findings with their advice, the confirmation
> windows and the notifications. Still German: the console output of the `k9` command and the
> command names, the log and the full manual. This page and the documents listed under
> "Documentation in English" are translations.

## Principles

- **Nothing happens automatically.** Every new detection is reported and waits for your decision:
  quarantine, delete/disable, or allow. Programs are never updated and files are never deleted
  without you.
- **Decisions are remembered.** The same finding does not come back. Every decision can be
  reviewed and revoked.
- **Gaming comes first.** Agent and service run at low priority. While a game is running,
  scheduled checks and updates wait and no windows appear – only critical alarms (ransomware,
  credential theft) get through.
- **Everything stays on the PC.** K9 downloads detection data but uploads nothing. The dashboard
  listens on `127.0.0.1` only and requires a random access key.
- **Protection against tampering.** Decisions and settings that weaken protection need a
  confirmation in a separate window of the service; decisions are signed by the service.

## What K9 checks

| Area | How |
|---|---|
| Files | YARA rules (YARA Forge), ClamAV, hash lists (MalwareBazaar, ThreatFox), malicious and phishing addresses inside `.url`/`.html`/`.eml`/`.svg` |
| Real time: new files | Downloads, Desktop, Documents, TEMP, Startup folders, removable drives when plugged in |
| Program starts | every start via Windows event tracing (ETW): suspicious command lines and process chains, PowerShell scripts before they run, unsigned programs and scripts from the internet, attack chains; optionally Sigma and LOLBAS rules |
| Ransomware | canary files and detection of many encrypted files in a short time; optionally the suspicious program is suspended until you decide |
| Credential theft | foreign programs opening stored passwords and cookies of browsers, Steam, Discord, Telegram or wallets |
| Autostarts | Run keys, Startup folders, scheduled tasks, services, native-messaging hosts of browser extensions, hidden WMI autostarts |
| Browser extensions | new extensions, new permissions after an update, known malicious extensions |
| Network and DNS | connections and DNS queries to malicious and phishing addresses, lookalike domains of well-known brands, new inbound firewall rules |
| Accounts and sign-ins | new user accounts and administrators, Remote Desktop sign-ins, many wrong passwords |
| Drivers | vulnerable and malicious kernel drivers (Microsoft block list, LOLDrivers), fitness for memory integrity |
| Vulnerable software | installed programs against actively exploited vulnerabilities (CISA KEV, NVD, EPSS) |
| Security check | traffic lights in the dashboard: antivirus, firewall, Windows updates, Secure Boot, User Account Control, Remote Desktop, memory integrity, LSA protection, backup, outdated programs |

Every feature with its switch and default is listed in the manual, part 3. Interventions such as
suspending suspicious programs, the firewall block list or shadow copies are off after
installation and are switched on by you.

## Components

| Program | Role |
|---|---|
| `k9-dienst.exe` | Windows service (LocalSystem): program starts, DNS and file access via ETW, driver check, watchdog for the agent, protected database of decisions |
| `k9-agent.exe` | Agent in the user account: real-time file checks, schedules, game detection, alert windows, dashboard in the browser |
| `k9.exe` | Commands for PowerShell: scan, decide, sources, switch features, install and update |

## Requirements

Windows 10 or 11 (64-bit). To build: Rust (stable, `x86_64-pc-windows-msvc`), Visual Studio Build
Tools (C++) and Git. Optional: ClamAV (`winget install Cisco.ClamAV`), a free abuse.ch key
(MalwareBazaar, URLhaus, ThreatFox) and an NVD key.

## Build and set up

```powershell
cd "C:\K9-Quelltext"
cargo build --release
& ".\target\release\k9.exe" dienst installieren
& "C:\Program Files\K9\k9.exe" quellen aktualisieren
& "C:\Program Files\K9\k9.exe" dashboard
```

`dienst installieren` asks for administrator rights, copies the programs to
`C:\Program Files\K9` and sets up service and agent. A new version is installed with
`& ".\target\release\k9.exe" dienst aktualisieren`; K9 is removed with
`& "C:\Program Files\K9\k9.exe" dienst deinstallieren`. The commands are German words:
`dienst` = service, `quellen aktualisieren` = update sources, `funktion` = feature.

The programs are not code-signed. An antivirus may therefore object to freshly built programs or
to the downloaded signature files (they contain malware patterns). You add exclusions there
yourself; K9 never does that for you.

## Documentation in English

| Document | Content |
|---|---|
| [docs/en/ARCHITECTURE.md](docs/en/ARCHITECTURE.md) | structure of the programs and data flows |
| [docs/en/SECURITY.md](docs/en/SECURITY.md) | protection against tampering, assumptions, limits |
| [docs/en/SOURCES.md](docs/en/SOURCES.md) | every detection source with address, licence and attribution |
| [docs/en/STATISTICS.md](docs/en/STATISTICS.md) | test PC, time spent, AI usage and cost, size of the code, test runs |

## Documentation in German

| Document | Content |
|---|---|
| [docs/ANLEITUNG.md](docs/ANLEITUNG.md) and [PDF](docs/Anleitung-K9.pdf) | the full manual: quick start, operation, all features, command reference, installation, troubleshooting, change log |
| [docs/TESTBERICHT.md](docs/TESTBERICHT.md) | every test with setup, result and limits, including the failed ones |
| [docs/SANDBOX-TESTPLAN.md](docs/SANDBOX-TESTPLAN.md) | tests in Windows Sandbox |

## Testing

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
powershell -ExecutionPolicy Bypass -File scripts\e2e-test.ps1
```

The automated tests (`cargo test`, `e2e-test.ps1`) never use EICAR or real malware; the project
has its own harmless test signature. Risky behaviour tests and the comparison runs with real
malware happen only inside Windows Sandbox (`scripts\sandbox`); the scripts refuse to run outside
it. The `.wsb` files and scripts contain example paths (`C:\K9-Quelltext`, `C:\Users\anna`) that
you adapt to your PC.

## Limits

- K9 is a private project and **no replacement for an antivirus**. It complements one.
- K9 is published freely. No commercial use is planned; there are no ready-made installers, no
  support and no warranty (see the licence).
- It has been tested on a single PC. What was measured and what was not is in the test report.
- K9 works without its own kernel driver. A program with administrator rights can do more than
  K9 can prevent; the manual names these limits for every feature.
- Behaviour rules cause false alarms. That is why a human always decides.

## How it was built

K9 was developed entirely in conversation with Claude (Claude Code) between 13 and
23 November 2026. Time spent, token usage and an estimate of the cost are in
[docs/en/STATISTICS.md](docs/en/STATISTICS.md).

## Detection sources and licences

Detection data is downloaded by the program on your PC and is not redistributed. Every source
with licence and attribution is listed in [docs/en/SOURCES.md](docs/en/SOURCES.md) and shown by
`k9 quellen`. The Public Suffix List (MPL-2.0) is shipped unchanged.

## Licence

MIT, see [LICENSE](LICENSE).
