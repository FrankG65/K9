# Architecture

State: version 0.50.3 (24 November 2026). The module tables below are taken from the one-line
descriptions at the top of each source file.

## Overview

K9 consists of three programs that are installed, and four helper crates.

```
crates/
  k9-core/     library – all of the detection and decision logic
  k9-dienst/   Windows service "K9-Dienst" (LocalSystem)
  k9-agent/    agent in the user account (dashboard, alert windows, schedules)
  k9-cli/      command line "k9"
  k9-doc/      helper: turns the German manual (Markdown) into printable HTML for the PDF
  k9-res/      build helper: embeds the program icon as a Windows resource
  k9-testsim/  test tool, never installed: behaves like ransomware on sham files
scripts/       end-to-end test, PDF generation, Windows Sandbox tests
```

Language: **Rust** (memory safety, no runtime environment, very low resource use). The C runtime
is linked statically. Dependencies are widely used, maintained crates (`windows`, `tokio`, `axum`,
`rusqlite` with bundled SQLite, `yara-x`, `sha2`, `serde`/`toml`, `lettre` and `reqwest` with
rustls, `keyring`, `tracing`, `chrono`). `cargo audit` is part of the check chain before every
commit.

### Who does what

| Program | Runs as | Role |
|---|---|---|
| `k9-dienst.exe` | LocalSystem | Sees what a normal user cannot: every program start, DNS query and access to credential stores through Windows event tracing (ETW). Owns the protected database of detections and decisions, signs decisions, shows the confirmation window for anything that weakens protection, watches the agent and its own files. |
| `k9-agent.exe` | the signed-in user | Real-time checks of new files, schedules, game detection, alert windows, tray icon, the dashboard on `127.0.0.1`. Receives the service's findings and forwards the user's decisions. |
| `k9.exe` | the signed-in user (asks for administrator rights only to install, update or remove the service) | Scans, decisions, sources, feature switches, restoring files from shadow copies. |

The split follows one rule: **a program running with the user's rights must not be able to reach
more through the service than it could without it.** The service treats everything a normal user
can change as untrusted (see [SECURITY.md](SECURITY.md)).

### Where data lives

| Location | Content | Who may write |
|---|---|---|
| `C:\Program Files\K9` | the three programs | administrators |
| `C:\ProgramData\K9` | protected database (detections, decisions, quarantine entries), quarantine, source data, service log, baseline of the program files | the service |
| `%APPDATA%\K9\config.toml` | configuration | the user; changes that weaken protection take effect only after confirmation |
| `%LOCALAPPDATA%\K9` | the agent's own bookkeeping, agent log, security check report | the user |
| Windows Credential Manager | keys and passwords (dashboard key, abuse.ch, NVD, SMTP, ntfy) | the user |

## Data flow

```
 file checks (agent, CLI)          behaviour (service, via ETW)
 schedule / k9 scan / dashboard    program starts, DNS, credential stores,
 new files, removable drives       scripts, ransomware, drivers, accounts
            │                                   │
            ▼                                   ▼
   Scanner reads each file once        rules, chains, Sigma (optional)
   → engines: hash lists, patterns,             │
     YARA-X, ClamAV, address lists              │
            └───────────────┬───────────────────┘
                            ▼
      Finding { kind, path, fingerprint, rule id, name, severity, details }
                            ▼
        quiet? (work folder / work program, known side effect of an update)
                            ▼
        remembered decision for (fingerprint, rule id), signed by the service?
           ├─ allow         → ignored silently (recorded as "automatisch")
           ├─ quarantine    → applied again silently + log entry
           ├─ delete        → applied again silently + log entry
           └─ none          → stored as open
                                 │  (already open? → no second message)
                                 ▼
                    is a game running?
                      ├─ yes → queued; delivered after the game
                      │        (critical alarms get through)
                      └─ no  → alert window, dashboard, optional e-mail / phone
                                 ▼
             the user decides (alert window, dashboard or `k9 entscheiden`)
                                 ▼
          decisions that weaken protection: confirmation window of the service
                                 ▼
          action is carried out (only if the file still has the same SHA-256)
          and remembered → the same finding never reports again
```

**Fingerprints.** A file is identified by its SHA-256 plus the rule id; a process finding by the
rule, the parent program and the command line; software by name, version and the list of CVEs;
an autostart by entry and target. A decision therefore applies to exactly one case. The one
exception is deliberate and chosen by the user: a rule can be allowed for everything a signed
work program starts (see the manual, chapter "Arbeitsordner").

**Revoking.** A revoked decision is deleted; the next finding asks again. Restoring a file from
quarantine removes the quarantine decision (otherwise the next scan would silently move the file
again).

**Agent and service.** They talk over two named pipes: one carries the service's findings to the
agent, the other carries requests from agent and `k9` to the service. The agent attaches the
service's database read-only. Callers of the request pipe are checked: only K9's own programs
from the installation folder are accepted.

## Modules in `k9-core`

### Foundation

| Module | Purpose |
|---|---|
| `app` | shared start-up for agent and CLI: paths, configuration, database, engines |
| `paths` | location of configuration and data folders |
| `config` | configuration (`config.toml`), commented default file |
| `funktion` | `k9 funktion`: switching single features on or off without breaking the file |
| `model` | data model of detections, actions and kinds |
| `store` | SQLite store for detections, decisions, quarantine entries, log and queues |
| `pipeline` | finding → remembered decision → apply silently or store as open; applying a decision |
| `schutz` | protection of security-relevant state against programs with the user's rights (signed decisions, confirmed settings) |
| `dienst` | shared parts for service, agent and CLI (pipe protocol) |
| `secrets` | secrets in the Windows Credential Manager |
| `term` | console output without umlauts |
| `sprache` | language of every text (German or English, setting `sprache`), macros `t!`/`tf!`/`tw!`; fingerprints of findings stay independent of the language |
| `winreg` | small registry helpers |
| `priority` | low process priority so that checks never compete with games |
| `gaming` | game detection and idle time |
| `schedule` | schedules: at once, always, daily, weekly, once, idle |
| `umzug` | move from the old installation name ("Virenscanner") to K9 |

### File checks

| Module | Purpose |
|---|---|
| `scanner` | reads every file once in chunks, computes SHA-256, feeds all engines |
| `engine` | engine interface, hash-list and byte-pattern engines, the project's own test signature |
| `yara` | YARA engine (yara-x, pure Rust), rules from YARA Forge |
| `clamav` | the official ClamAV for Windows (clamd + freshclam), local only |
| `sources` | detection sources: download, verify and store signatures, rules and indicator lists |
| `sperrlisten` | two large optional block lists for the network checks |
| `quarantine` | obfuscated quarantine with checksum control, restore, delete |
| `herkunft` | origin of downloaded files ("Mark of the Web") |
| `virustotal` | optional lookup of a program's SHA-256 (nothing is uploaded) |

### Behaviour

| Module | Purpose |
|---|---|
| `realtime` | building blocks of real-time protection in user mode: folder watching, process, network and DNS queries, ransomware heuristics, suspending and ending processes |
| `ransom` | ransomware detection in the service: who wrote the files that suddenly look encrypted |
| `anhalten` | suspending a suspicious process until the user decides (opt-in) |
| `ketten` | attack chains: single steps are often harmless, together they are not |
| `skripte` | PowerShell script blocks, checked before they run |
| `sigma` | Sigma rules (SigmaHQ) for program starts, optional |
| `infostealer` | which files hold logins, and who may open them |
| `speicher` | memory scan while the PC is idle, optional |
| `arbeitsordner` | work folders and work programs: behaviour findings from there are stored quietly |
| `sofort` | wake-up signals from Windows instead of polling |

### Inventory and system state

| Module | Purpose |
|---|---|
| `autostart` | Run keys, Startup folders, scheduled tasks, services; signature check; disable and re-enable |
| `wmi_autostart` | hidden autostarts through WMI event subscriptions |
| `nativehost` | helper programs of browser extensions ("native messaging") |
| `erweiterungen` | browser extensions: inventory, policies, known malicious extensions |
| `treiber` | kernel drivers: inventory, vulnerable and malicious drivers, fitness for memory integrity |
| `software` | installed programs against actively exploited vulnerabilities; outdated programs (winget) |
| `luecken` | new vulnerabilities (CVE) of installed programs, with EPSS |
| `nachladen` | downloading an installer from the official site when winget cannot, with a same-publisher signature check |
| `anmeldungen` | accounts and sign-ins from the Security event log |
| `eingang` | watch over inbound firewall rules |
| `firewall` | blocking known botnet command servers in the Windows firewall (opt-in) |
| `heimnetz` | new devices in the home network |
| `urls` | malicious and phishing addresses: files, browser history (from a copy), hosts file |
| `phishing` | lookalike domains of well-known brands |
| `sicherheit` | the security check: traffic lights for the basic protection of the PC |
| `basis` | baseline of the installed program files for the tamper alarm |
| `wiederherstellung` | getting files back out of a shadow copy after a ransomware attack |

### Messages

| Module | Purpose |
|---|---|
| `notify` | channels: alert window, toast, dashboard, e-mail, phone (ntfy); queue during a game |
| `window` | K9's own alert window (native TaskDialog) |
| `wochenbericht` | weekly summary |
| `verknuepfung` | shortcuts to the dashboard |

## Modules in `k9-dienst`

| Module | Purpose |
|---|---|
| `main` | service entry; refuses stop requests that were not announced by `k9` |
| `etw` | ETW real-time session: program starts, DNS queries, PowerShell script blocks, access to credential stores |
| `server` | the two named pipes: findings to the agent, requests from agent and `k9` |
| `bestaetigung` | confirmation window for decisions that weaken protection |
| `einstellungen` | watches the security settings in `config.toml`; weakening changes wait for confirmation |
| `selbstschutz` | tamper alarm: program files changed, service stopped, event tracing ended from outside |
| `wache` | keeps the agent running in the user's session |
| `ransom_wache` | ransomware detection on the document folders |
| `treiber_wache` | driver check every 6 hours and when a driver appears |
| `konten_wache` | accounts and sign-ins |
| `eingang_wache` | inbound firewall rules |
| `wmi_wache` | hidden WMI autostarts |
| `aufraeumen` | closes findings whose cause is gone |
| `quellen` | source data in the protected folder |
| `sperre` | firewall block list (opt-in) |
| `schattenkopie` | shadow copies as a way back after ransomware (opt-in) |
| `vt` | VirusTotal lookups (opt-in) |
| `stoerungen` | reports when something K9 relies on fails: a source, ClamAV, a scheduled job |

## Modules in `k9-agent`

| Module | Purpose |
|---|---|
| `main` | agent entry |
| `scheduler` | loop: game detection, due schedules, queued notifications |
| `realtime` | real-time protection in the user's session (new files, programs, autostarts, network, removable drives) |
| `dienst_client` | connection to the service: receives its findings |
| `dashboard` | local browser dashboard (`127.0.0.1` only) |
| `pflege` | background care while no game runs: security check, home network, weekly report, new vulnerabilities |
| `tray` | icon in the notification area |

## Quarantine

A file is read in chunks, XOR-obfuscated with a random 32-byte key (one per file, kept in the
database) and stored as `*.vsq` in the quarantine folder. Only when the copy is complete and its
checksum matches the finding is the original removed. The stored file is neither executable nor
visible to other scanners as active malware. A protected access list of the original is saved and
set again on restore; the checksum is verified again when restoring.

## Game mode

- **Detection:** Direct3D full screen, full-screen applications and presentation mode
  (`SHQueryUserNotificationState`), plus running programs from game folders (Steam, Epic, GOG, EA,
  Ubisoft, Battle.net, Riot, Xbox) or with configured names. Helper programs that live in game
  folders but are no games (overlays, wallpaper tools) are excluded by a list.
- **Effect:** scheduled checks and updates wait; a running scheduled scan pauses between two
  files; messages are collected and delivered afterwards. Only critical alarms open a window.
- **Base load:** agent and service run below normal priority with low I/O and memory priority and
  Windows efficiency mode. Measured on the test PC: about 1.4 % of one processor core for both
  together during a game (see [STATISTICS.md](STATISTICS.md) and the German test report).

## The dashboard

Binds to `127.0.0.1` only. Every request carries a random 256-bit key (compared in constant
time); the Host header must be `127.0.0.1` or `localhost` (protection against DNS rebinding);
changes only by POST, foreign origins are rejected; strict Content-Security-Policy,
`X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`; all output is
HTML-escaped.

## What K9 deliberately does not have

- **No kernel driver of its own.** Everything works in user mode and through ETW. The price: a
  program with administrator rights can do more than K9 can prevent. The manual names this limit
  for every feature it affects.
- **No automatic intervention on a first finding.** Suspending a process is the strongest thing
  K9 does by itself, it is opt-in, and it is undone with one click.
- **No changes to other security products.**
- **No uploads.** Even the optional VirusTotal lookup sends only a checksum.
