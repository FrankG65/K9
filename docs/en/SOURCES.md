# Detection sources

Translation of `docs/QUELLEN.md`.

All sources are used **locally**: only lists and rules are downloaded, **nothing is uploaded**
(no files, no hashes, no visited addresses). Downloads use HTTPS only. Storage: with the Windows
service `C:\ProgramData\K9\quellen` (only the service writes), without the service
`%LOCALAPPDATA%\K9\quellen`. Due sources are updated automatically, but never during a game; by
hand: `k9 quellen aktualisieren`.

> **Licences:** the licences below are the state of research in November 2026. K9 distributes
> **no** detection data – every installation downloads it directly from the provider. If you
> redistribute the program or the data, check the current terms of each source again. Two sources
> are free for non-commercial use only (OpenPhish Community, the VirusTotal lookup).

| Source (key) | Content | Address | Interval (default) | Check of the data | Licence / terms |
|---|---|---|---|---|---|
| YARA Forge (`yara_forge`) | YARA rules, package "core" (5,078 rules, default) or "extended" (10,848 rules, switch `yara-erweitert`; as of 22 Nov 2026) | https://github.com/YARAHQ/yara-forge/releases (GitHub API `releases/latest`) | 24 h | SHA-256 checksum from the GitHub release (`digest`); the rules are compiled completely before they replace the old ones | Collection: GPL-3.0. Every rule has its own licence in the metadata field `license` (e.g. DRL 1.1, MIT, CC-BY-NC). The distribution of rule licences is shown in `status.json` and in the dashboard after every download. |
| SigmaHQ Sigma rules (`sigma`, only with `sigma_aktiv`) | Package "core": rules of the levels high and critical (status test/stable); K9 uses the rules for Windows process creation (554 of 558 can be evaluated, as of r2026-07-01). Since 0.44.0 also the add-on "Emerging Threats" of the same release, again only high and critical (158 more rules, 712 together) | https://github.com/SigmaHQ/sigma/releases (`sigma_core.zip`, `sigma_emerging_threats_addon.zip`) | 24 h | SHA-256 from the release; the package is read completely before it replaces the old one | Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License): use, modification and redistribution allowed; **every message names the author of the rule** |
| LOLBAS with the matching Sigma rules (`lolbas`, only with `lolbas_aktiv`) | The LOLBAS list (246 Windows programs that attackers abuse, as of 22 Nov 2026) is used for selection only: K9 loads the Sigma rules for Windows process creation of level "medium" that it points to – 81 rules for 201 of the 246 programs (as of r2026-07-01). A program name alone is never a message | https://lolbas-project.github.io/api/lolbas.json and https://github.com/SigmaHQ/sigma/releases (`sigma_all_rules.zip`) | 24 h | SHA-256 of the Sigma package from the release; only the selected rule texts are stored; without a rule that can be evaluated the old state stays | List: LOLBAS project, GPL-3.0 – read only, not shipped with K9; rules: Detection Rule License 1.1 – **every message names the author of the rule** |
| HaGeZi Threat Intelligence Feeds (`hagezi_tif`, only with `hagezi_tif_aktiv`) | Malware, phishing and scam domains, medium list (about 390,000 entries, as of 20 Nov 2026); stored locally as 64-bit keys (3 MB) | https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt | 24 h (the list is republished every 8 to 12 h) | at least 50,000 valid entries, otherwise the old state stays; whole shared suffixes are never taken over | GPL-3.0 (https://github.com/hagezi/dns-blocklists); downloaded when updating, not shipped with K9 |
| Spamhaus DROP (`spamhaus_drop`, only with `spamhaus_drop_aktiv`) | IPv4 networks that are hijacked or run by criminals (1,751 networks, as of 21 Nov 2026) | https://www.spamhaus.org/drop/drop_v4.json | 24 h (Spamhaus asks not to download more often than hourly) | every line readable, no network larger than /8, at least 100 networks | free to use (https://www.spamhaus.org/drop/terms/); source: The Spamhaus Project – the file is stored unchanged including its copyright line |
| abuse.ch MalwareBazaar (`malwarebazaar`) | SHA-256 of known malware: full export once a day, in between every hour the export of the last 48 hours (`sha256_recent.txt`, about 1,000 hashes), merged into the full list | https://bazaar.abuse.ch/export/txt/sha256/full/ and https://bazaar.abuse.ch/export/txt/sha256/recent/ | 1 h (recent), 24 h (full) | format and content check (only valid 64-character hashes) | abuse.ch terms of use; according to abuse.ch the data is free to use (CC0). **A free Auth-Key is required** (https://auth.abuse.ch/). |
| abuse.ch URLhaus (`urlhaus`) | Active malicious addresses (malware distribution) | https://urlhaus.abuse.ch/downloads/text_online/ | 24 h (recommended 6 h) | not empty, URLs only | as above (CC0, Auth-Key) |
| abuse.ch Feodo Tracker (only with `firewall_sperre`) | Botnet command servers, recommended list (address, port, last online) | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json | daily | public IPv4 only, port > 0, last online ≤ 30 days; as of 15 Nov 2026: 1 entry, last active in March → currently empty | abuse.ch terms of use (Feodo Tracker: free to use) |
| VirusTotal (only with `virustotal_aktiv`) | Result for one checksum | https://www.virustotal.com/api/v3/files/<SHA-256> | on demand (4/min, 500/day) | lookup by checksum only, no upload | free key for private, non-commercial use only; the checksum is transmitted to VirusTotal (Google) |
| abuse.ch ThreatFox (`threatfox`) | Indicators of the last 48 h (SHA-256, URLs, domains); collected locally for 180 days | https://threatfox.abuse.ch/export/json/recent/ | 24 h | JSON format checked, only the types sha256/url/domain | as above (CC0, Auth-Key) |
| OpenPhish Community (`openphish`) | Current phishing addresses | https://openphish.com/feed.txt | 24 h (the feed changes every 12 h) | not empty, http(s) lines only | OpenPhish Community Feed – according to the provider **for non-commercial use only**. |
| CISA KEV (`cisa_kev`) | Catalogue of actively exploited vulnerabilities | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | 24 h | JSON format, catalogue version | US government work, public domain (CC0) |
| NIST NVD CVE API 2.0 (no download package) | Version ranges for the KEV candidates | https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=… | on demand, cached for 30 days (`quellen\nvd`) | JSON format; retry on server errors | public domain; NVD terms of use: rate limit 5 requests/30 s without a key, 50 with a free key (https://nvd.nist.gov/developers/request-an-api-key). Notice required by NVD: "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| FIRST.org EPSS (no download package) | Estimated probability that a vulnerability is exploited within the next 30 days – only for the CVEs that affect installed programs | https://api.first.org/data/v1/epss?cve=… | with every check for new vulnerabilities (once a day) | values between 0 and 1, otherwise discarded; without an answer the message comes without the estimate | free, no registration; source: FIRST.org, Exploit Prediction Scoring System (https://www.first.org/epss) |
| LOLDrivers (`loldrivers`) | Known vulnerable (588) and malicious (125) Windows drivers: file hashes (SHA-1/SHA-256) and Authenticode hashes, CVE numbers | https://www.loldrivers.io/api/drivers.json | 24 h | JSON format, valid hashes only; a condensed index is stored (`quellen\treiber\loldrivers.json`) | **Apache-2.0** (project magicsword-io/LOLDrivers on GitHub, checked 14 Nov 2026) |
| Microsoft driver block list (`ms_treiber`) | "Microsoft recommended driver block rules": Authenticode hashes (SHA-1/SHA-256) and file name/version rules | https://aka.ms/VulnerableDriverBlockList (ZIP, file `DriverPolicy_Enforced.xml`) | 24 h | ZIP/XML format, Authenticode hashes only (page hashes are ignored); condensed index `quellen\treiber\microsoft.json` | Published by Microsoft in the Download Center and on Microsoft Learn; the Microsoft terms of use for the website apply. The list is evaluated locally only and **not redistributed**. |
| MalExt Sentry (`malext`) | IDs of known malicious browser extensions (Chrome/Edge), about 8,600 | https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv | 24 h | valid extension IDs only (32 characters a–p); fewer than 100 entries → not taken over; stored as `quellen\erweiterungen\malext-ids.txt` | **Data CC BY 4.0** (attribution: toborrm9, "Malicious Extension Sentry", https://github.com/toborrm9/malicious_extension_sentry), code MIT; checked 14 Nov 2026 |
| malware-filter phishing-filter (`phishing_filter`) | Phishing domains from OpenPhish, IPThreat and PhishTank, without popular domains (Tranco, Umbrella, Cloudflare Radar – filtered by the provider), about 18,000 | https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt | 24 h (the list changes every 12 h; e.g. `intervall_stunden = { phishing_filter = 12 }`) | valid host names only, no IP addresses, **no public suffixes** according to the Public Suffix List (e.g. `github.io`, `blogspot.com`); fewer than 1,000 entries → not taken over; stored as `quellen\phishing\phishing-filter-hosts.txt` | **Data CC BY-SA 4.0** (attribution: curben, "phishing-filter", https://gitlab.com/malware-filter/phishing-filter; modified as described in the column before), code CC0/MIT; used locally only, not redistributed; checked 14 Nov 2026 |
| ClamAV (`clamav`) | Signature databases main/daily/bytecode | via `freshclam` from https://database.clamav.net | 24 h | `freshclam` verifies the digital signatures of the databases itself | ClamAV is GPL-2.0; the signature databases are provided by Cisco Talos (use according to the ClamAV terms). ClamAV is **not shipped**; it is installed separately (`winget install Cisco.ClamAV`). |

## Different intervals

```toml
[quellen]
aktualisieren_stunden = 24
intervall_stunden = { urlhaus = 6, openphish = 12 }
```

MalwareBazaar is the exception to `aktualisieren_stunden`: without its own entry it is reloaded
every hour. With `intervall_stunden = { malwarebazaar = 24 }` K9 downloads only once a day.

## Protection of the data

* New data replaces the old only after a successful check (checksum, format, for YARA:
  compilation); on an error the previous state stays active.
* For every stored file the SHA-256 is recorded in `quellen\status.json`. If a file is missing or
  was changed (for example because another antivirus deleted the YARA rules or signatures),
  `k9 status`, `k9 quellen` and the dashboard say so clearly – with the hint to add the folder as
  an exclusion in the other antivirus.
* Keys (abuse.ch, NVD) are kept only in the Windows Credential Manager.

## Data shipped with the source code

| Data | Purpose | Licence |
|---|---|---|
| Public Suffix List (`crates/k9-core/data/public_suffix_list.dat`, unchanged, as of 14 Nov 2026, https://publicsuffix.org/list/) | Determines the actual domain name (e.g. `example.co.uk`, `user.github.io`): entries of phishing lists never cover a whole public suffix; lookalike domains are compared only by the name before the suffix | Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/); the file is in the source code unchanged |
| Tranco list of the most popular domains (https://tranco-list.eu/) | Development only: false-alarm test of the lookalike-domain check; not shipped | MIT |

## Program icon and typeface

The "paw" icon (`pictures\k9-pfote.svg` and the files derived from it) was designed for K9. The
letters "K9" in it are converted to paths; they come from the typeface **Archivo Black**
(Omnibus-Type), licence **SIL Open Font License 1.1** – converting to paths is allowed, the
typeface itself is not shipped and need not be installed.

The PNG and ICO files are generated by the developer tool `tools\k9-bilder` (uses the library
resvg, MPL-2.0/Apache-2.0); it is not part of the installation.
