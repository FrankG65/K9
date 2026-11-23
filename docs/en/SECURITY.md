# K9 – security review of the Windows service

Translation of `docs/SICHERHEIT.md`. State: 14 November 2026 (hardening stage 3), with the rows
added for later features.

The service "K9-Dienst" runs as **LocalSystem**. Everything a program with normal user rights can
change is **untrusted** for it. A malicious program with your rights must never reach more through
the service than it could without it.

## Ground rules

1. **Run and load only from protected folders.** The service starts programs only from
   `C:\Program Files\…` or `C:\Windows\System32`. It loads DLLs only from System32 and its own
   program folder (`SetDefaultDllDirectories`, current directory removed).
2. **In user folders only with user rights.** Every request over the pipe runs with the rights of
   the caller (`ImpersonateNamedPipeClient`). Background work in your folders runs with your logon
   token (`WTSQueryUserToken`). System rights are used only for the service's own protected
   folders (`as_system`). A redirection (junction, symlink, hard link) in your folder therefore
   cannot steer the service into system folders. Without a user token, access to user paths is
   refused (`ensure_user_context`).
3. **Own data only in `C:\ProgramData\K9`** (owner SYSTEM, users read-only or no access at all):
   log, temporary files, keys, quarantine, detection data, confirmed settings.
4. **Values from the database are only hints.** For actions with system rights the service uses
   only the values it reported itself and kept in memory.

## Review table

| Input (changeable by user programs) | Use in the service | Risk before | Measure |
|---|---|---|---|
| `config.toml` → `clamav_programmordner` | path of `freshclam.exe` | **code with system rights** (enter your own program) | the service starts freshclam only below `%ProgramFiles%` (`is_under_program_files`) |
| `config.toml` → `quellen.ordner` | folder of the detection data | service writes into any folder | the service always uses `C:\ProgramData\K9\quellen`; the setting is ignored |
| `config.toml` → `yara_paket` | part of the download address | foreign address | fixed values only (`core`/`extended`/`full`); the addresses are fixed in the program |
| `config.toml` (whole file) | settings, security check | the service created the file as SYSTEM; error messages containing file content | read only, with user rights; never created or written; if broken → defaults |
| `config.toml` → protection switches and lists | switching off checks, exclusions, game lists | a malicious program with user rights switches protection off | one rule table (`schutz::SCHALTER`/`LISTEN`, unit test: every switch is classified) for service, agent and k9; weakening takes effect only after confirmation in the confirmation window, also at service start; tightening becomes the confirmed state at once; the confirmed state is read only from a file owned by SYSTEM/administrators, without write access for others and without a reparse point |
| service keys (VirusTotal, abuse.ch, NVD) | API keys | an invalid key silently switches lookups off | first key without asking, replacing or deleting only after confirmation |
| `%LOCALAPPDATA%\K9\logs` | service log | **writing a file into any folder** (junction to `C:\Windows\System32`) | log goes to `C:\ProgramData\K9\logs` |
| `%TEMP%` (of the user) | temporary files during downloads | as above | service TEMP = `C:\ProgramData\K9\temp` (SYSTEM/admins only) |
| database `k9.db` (user folder) | findings, decisions, quarantine list | writing as SYSTEM through a redirection; forged paths | access only with user rights; `trusted_schema=OFF`; decisions valid only with the service's signature. Stage 3 moves the database into the service entirely |
| quarantine list → `stored_file` | restoring reads this file with system rights | **reading any file** (e.g. registry hives) | only a regular file *inside* the protected quarantine folder, without redirection, path resolved (`safe_inside`) |
| quarantine list → `original_path` / target | restoring writes there | **writing any file** (e.g. a DLL into System32) | writing only with user rights |
| finding → file path | moving into quarantine, deleting | **deleting or reading any file** | reading and deleting only with user rights; only the write into the protected quarantine uses system rights |
| finding → process ID / program | "end process" | **ending any process** (e.g. Trend Micro) | findings of the agent: with user rights. Findings of the service: with system rights, but only with the PID and program path from the service's memory; the program path is checked first |
| finding → autostart details | disabling/re-enabling (services, Run keys) | switching off foreign services | only with user rights (HKLM and services are then not changeable) |
| quarantine migration (old user folder) | copying and deleting | redirection → reading/deleting system files | reading and deleting with user rights, only `*.vsq` files in the old folder |
| detection data migration | copying into the protected folder | redirection → copying system files into a readable folder | reading with user rights, redirections are skipped, intermediate folder, active only after the copy is complete |
| game mode (agent) | postponing updates and the driver check | suppressing updates | comes over the pipe (`Spielmodus`), accepted only from the installed agent; invalid after 5 minutes without a new message. No file in the user folder any more. Worst case: a later update |
| `HKLM\SOFTWARE\K9` → `Datenordner` | the service's own data folder | the service works in a user folder | the service accepts only `C:\ProgramData\K9` (path resolved, no junctions or links); otherwise a warning and still the protected folder. The installer always enters this folder. The user folder is read only for the one-time takeover, with user rights |
| tamper alarm | protection is switched off or replaced | false alarms during K9's own updates and at shutdown; an attacker stops the service, swaps a file and starts it again | baseline (checksums) in the protected database, written **only** by `k9 dienst aktualisieren` with administrator rights, never by a service start; compared at every start and every 10 minutes; a restart outside of Windows start and update is reported (medium); "service not running" only after 2 minutes and not at shutdown; only reported, never repaired. **Limit:** an attacker with administrator rights can use the update path himself ("update" his own files) or change the protected database; without code signing of the programs this cannot be prevented completely. At the first installation the state found at the first service start counts. |
| attack chains (service) | one critical message instead of many single ones | false alarms with installers; confusion through reused process IDs | a chain only starts at an unsigned program from the internet; members by process ID **and** start time; 30 minutes only; a script host alone reports nothing; bookkeeping in memory only, no intervention |
| suspending critical programs (off) | stopping damage before you decide | harmless program frozen; game or anti-cheat suspended (account ban); reused process ID | only critical findings of kind process; process ID, start time and path checked; never games, anti-cheat, Windows folders, programs signed by Microsoft or Trend Micro, K9; only suspend, never end, never resume automatically; resuming through the service only for the same process |
| VirusTotal (off) | second opinion on new programs | privacy (checksum goes to Google); key | only the SHA-256, never the file; key only in the service's protected store, only in the header of the HTTPS request; 4/min, 500/day; cached for 7 days. Real keys only through the invisible input of `k9 geheimnis`; `--aus-eingabe` only for tests – with full PowerShell logging a key passed by command or script would appear in plain text in the event log |
| shadow copies (off) | way back after ransomware | disk space; conflict with the rule "deleting shadow copies" | only create, never delete, never change the storage size (Windows rotates by itself); only when idle, never during a game |
| firewall block (off) | preventing connections to botnet command servers | blocking harmless shared servers; blocking in the home network; too many rules | only the Feodo recommendation and ThreatFox "botnet_cc" with confidence 100, ≤ 30 days; public IPv4 only; exactly address and port; at most 1000; only rules with K9's own name, removable at any time; never updated during a game |
| origin mark (Zone.Identifier) at program start | message "unsigned program from the internet" | manipulated mark; access keys in download addresses | only the small data stream is read (at most 64 KB), never changed; address without the part after "?"/"#"; signature via WinVerifyTrust; every program file checked only once |
| ETW Microsoft-Windows-PowerShell (event 4104, script blocks) | message "suspicious script" | scripts contain passwords; false alarms with admin scripts; deceiving the program through the command line | script checked in memory only; stored are only rule, SHA-256 and a shortened excerpt with masked strings and encodings; parts of at most 1 MB; program only from kernel data; an allowance only for exactly this script; the Windows policy is set only by the user (`k9 powershell-protokoll`) |
| ETW Kernel-File (file access to credential stores) | message "credential stealer" | false alarms against real programs; floods; evasion through upper/lower case or a forged command line; reused process IDs | all file opens without a kernel filter (it compared case-sensitively in the sandbox), selection in the service ignoring case; program only from kernel data (Kernel-Process image path, running process with matching start time), life histories per process ID with start and end, otherwise "program cannot be assigned reliably"; text only (path, PID); an owner only with a valid publisher signature **and** the publisher's folder; Windows components only by name with a Microsoft signature and a fixed folder (never "signed by Microsoft" in general: PowerShell, cmd, esentutl and others stay reportable); at most one message per program and store in 10 minutes; an allowance only for exactly program + store + signature or checksum |
| browser settings, extension manifests, policies, shortcuts | inventory and assessment of the extensions | manipulated JSON files | read only (agent, user rights), never written; JSON as data only; extensions are never removed or switched off |
| list of malicious extensions (download) | recognising malicious extensions | manipulated list | HTTPS only, fixed address; valid IDs only; discarded below 100 entries; updated only by the service into the protected folder |
| phishing list "phishing-filter" (download) | recognising phishing domains | manipulated list, an entry for a whole suffix (flood of false alarms) | HTTPS only, fixed address; valid host names only; public suffixes (Public Suffix List, shipped) are discarded, also when loading; discarded below 1,000 entries; severity only medium; updated only by the service |
| check for lookalike domains | reporting imitation domains | false alarms, load with many DNS queries | only the name before the suffix; official domains as a list; typos only for long names; tested against 1 million Tranco domains; every name is checked only once (cache of up to 20,000 names; service at low priority) |
| pipe messages | all commands | foreign commands | ACL (SYSTEM, admins, the user the service was set up for), version, sizes, fixed list of actions; the caller must be agent/k9 from `C:\Program Files\K9`; execution with the caller's rights |
| pipe → `GeheimnisSetzen` | storing API keys | overwriting keys | only from `k9.exe` in `C:\Program Files`, only two known names, size limited |
| API keys | downloads abuse.ch/NVD | theft from the Credential Manager | service copy with DPAPI (SYSTEM) in `…\geheim`; the abuse.ch copy in the user's store is removed. The NVD key also stays with the user (the agent's software check needs it; low value) |
| downloads (YARA Forge, abuse.ch, OpenPhish, CISA, NVD, ClamAV) | detection data | manipulated data | HTTPS only with fixed addresses; YARA Forge with a checksum; ClamAV verifies signatures itself (freshclam); processing is memory-safe (Rust, yara-x) |
| ETW events (process names, command lines, DNS names) | rules, finding texts | – | text only, never executed |
| environment variables | folder paths | – | set at start from `HKLM\SOFTWARE\K9` (writable by admins only); `SystemRoot` comes from the service control manager |
| `HKLM\SOFTWARE\K9` → agent path | starting the agent | foreign program | writable by admins only; in addition the path must lie in `C:\Program Files\K9`; always started with the user's token (never SYSTEM) |
| agent restart | `conhost.exe` | – | from `%SystemRoot%\System32`, user's token |

## Stage 3: database in the service, confirmation window

| Topic | Implementation |
|---|---|
| findings, decisions, quarantine list, events, disabled autostarts | live in `C:\ProgramData\K9\geschuetzt.db` (owner SYSTEM, users read-only). Agent and k9 attach it read-only; their old copies are renamed to `alt_*` and no longer used |
| new findings | go over the pipe to the service; the service checks decisions and stores. A program with your rights cannot delete a finding there or mark it as done |
| service not reachable | findings are buffered in the user folder with a running number and delivered later. If numbers are missing, the service reports "buffered findings have disappeared" |
| decisions | are carried out by the service (quarantine, delete, end with your rights); it remembers and signs them |
| weakening decisions (allow, only this once, seen/ignore, restore, re-enable an autostart, accept a setting, pause the agent) | need a **confirmation window** that the service starts with your *elevated* token in your session (`k9.exe bestaetigen` from `C:\Program Files\K9`). Programs with normal rights cannot operate it (Windows UIPI). The window shows only fixed text from the service's database (threat, location, rule, action) and "Ja"/"Nein" (preselected: Nein), no links, no help, no file dialogs. Without an answer after 2 minutes, "Nein" applies |
| HKCU in the service | under impersonation the service opens the user's registry branch (`RegOpenCurrentUser`), not that of SYSTEM |

## Remaining limits

- **Caller check by program path:** a program with your rights could inject itself into the
  running agent (same user). Without a driver there is no complete protection against that.
  Weakening decisions, however, need the confirmation window, and everything else runs with your
  own rights.
- **Confirmation window without an administrator account:** if the user is not an administrator,
  there is no elevated token and the window runs with normal rights (then without UIPI
  protection). On the test PC the user is an administrator.
- **Local buffers** (alert window queue, scan cache, schedule state) stay in the user folder. A
  program can at most delay an alert window there; the finding stays open in the service and
  appears in the dashboard.
- **No kernel driver.** A program with administrator rights can do more than K9 can prevent:
  it can end the service by force (Windows restarts it within a second, and K9 reports the
  restart), and it can replace files. K9 reports what it sees and repairs nothing by itself.

## Tests

- A forged or subsequently changed allowance is ignored (`self_made_allowance_without_signature_is_ignored`).
- Only programs in `C:\Program Files\K9` count as trusted (`only_programs_in_program_files_are_trusted`).
- The agent can only read the service's database; takeover of old data; renaming of the old
  copies (`service_database_is_read_only_for_the_agent_and_takes_over_old_data`).
- Gaps in the numbering of buffered findings are recognised (`sequence_gaps_are_detected`).
- Text in the confirmation window cannot leave the command line (`text_cannot_break_out_of_the_command_line`).
- Unit tests and portable agents never read `C:\ProgramData\K9` and never talk to the installed
  service. Test files never lie in `%TEMP%`.
