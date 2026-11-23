//! Accounts and logons (checked by the Windows service in the Security event log, read only):
//! a new local user account, an account added to the Administrators or Remote Desktop Users
//! group, a disabled account switched on again, a remote desktop logon and many failed
//! logons in a short time. These are typical signs that someone else is on the PC.
//! Windows records these events by default; K9 changes no audit setting.

use std::collections::VecDeque;
use std::path::PathBuf;

use crate::model::{Finding, Kind, Severity};

/// Administrators and Remote Desktop Users (well-known SIDs, independent of the language).
const ADMINS: &str = "S-1-5-32-544";
const RDP_USERS: &str = "S-1-5-32-555";

/// Failed logons in `FAIL_WINDOW` minutes that count as an attack.
pub const FAIL_THRESHOLD: usize = 10;
pub const FAIL_WINDOW_MIN: i64 = 10;

/// One event of the Security log (only the fields K9 needs).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Event {
    pub id: u32,
    pub record: u64,
    /// UTC, as written in the log ("2026-11-17T20:01:02.1234567Z").
    pub time: String,
    pub data: std::collections::BTreeMap<String, String>,
    /// The <UserData> part (event 1102 has no EventData).
    pub raw_user: String,
}

fn between_tags(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let s = xml.find(&open)? + open.len();
    let e = xml[s..].find(&format!("</{tag}>"))? + s;
    Some(unescape(&xml[s..e]))
}

impl Event {
    pub fn get(&self, name: &str) -> &str {
        self.data.get(name).map(String::as_str).unwrap_or("")
    }

    fn user(&self, name_key: &str, domain_key: &str) -> String {
        let (n, d) = (self.get(name_key), self.get(domain_key));
        if d.is_empty() || d == "-" {
            n.to_string()
        } else {
            format!("{d}\\{n}")
        }
    }

    /// Local time for the user.
    pub fn local_time(&self) -> String {
        chrono::DateTime::parse_from_rfc3339(&self.time)
            .map(|t| t.with_timezone(&chrono::Local).format("%d.%m.%Y %H:%M:%S").to_string())
            .unwrap_or_else(|_| self.time.clone())
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

/// Parses the XML of one event (EvtRenderEventXml).
pub fn parse(xml: &str) -> Option<Event> {
    let between = |open: &str, close: &str| -> Option<String> {
        let s = xml.find(open)? + open.len();
        let e = xml[s..].find(close)? + s;
        Some(xml[s..e].to_string())
    };
    let id_part = between("<EventID", "</EventID>")?;
    let id = id_part.rsplit('>').next()?.trim().parse().ok()?;
    let record = between("<EventRecordID>", "</EventRecordID>")?.trim().parse().ok()?;
    let time = xml.find("SystemTime='").and_then(|i| xml[i + 12..].split('\'').next().map(str::to_string)).unwrap_or_default();
    let mut data = std::collections::BTreeMap::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<Data Name='") {
        rest = &rest[i + 12..];
        let Some(q) = rest.find('\'') else { break };
        let name = rest[..q].to_string();
        let after = &rest[q..];
        if let Some(r) = after.strip_prefix("'/>") {
            data.insert(name, String::new());
            rest = r;
            continue;
        }
        let Some(gt) = after.find('>') else { break };
        let body = &after[gt + 1..];
        let Some(end) = body.find("</Data>") else { break };
        data.insert(name, unescape(&body[..end]));
        rest = &body[end..];
    }
    let raw_user = between("<UserData>", "</UserData>").unwrap_or_default();
    Some(Event { id, record, time, data, raw_user })
}

/// Private, link-local or loopback address (or none at all, e.g. a local console logon).
pub fn is_local_address(ip: &str) -> bool {
    let ip = ip.trim();
    if ip.is_empty() || ip == "-" {
        return true;
    }
    match ip.trim_start_matches("::ffff:").parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(a)) => a.is_private() || a.is_loopback() || a.is_link_local(),
        Ok(std::net::IpAddr::V6(a)) => a.is_loopback() || (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80,
        Err(_) => false,
    }
}

fn finding(ev: &Event, rule: &str, severity: Severity, title: String, hint: &str, extra: serde_json::Value) -> Finding {
    let mut details = serde_json::json!({
        "hinweis": hint,
        "ereignis": ev.id,
        "zeit": ev.local_time(),
    });
    if let (Some(d), Some(x)) = (details.as_object_mut(), extra.as_object()) {
        d.extend(x.clone());
    }
    Finding {
        path: PathBuf::from(format!("{title} ({})", ev.local_time())),
        // Every event once: the record number is unique in the log.
        sha256: crate::sha256_hex(format!("anmeldung|{rule}|{}|{}", ev.record, ev.time).as_bytes()),
        size: 0,
        rule_id: rule.into(),
        threat_name: title,
        category: t!("Konten und Anmeldungen", "Accounts and sign-ins").into(),
        severity,
        engine: "dienst".into(),
        kind: Kind::Hinweis,
        details: Some(details),
    }
}

fn self_hint() -> &'static str {
    t!(
        "Warst du das selbst (oder ein Installationsprogramm, das du gestartet hast)? Dann „Gesehen“. Sonst: Konto in den Windows-Einstellungen → Konten prüfen und entfernen, Passwörter ändern und einen vollständigen Scan starten.",
        "Was that you (or a setup program you started)? Then “Seen”. Otherwise: check and remove the account in the Windows settings → Accounts, change passwords and start a full scan."
    )
}

/// The finding for one account/logon event (None: nothing to report). Failed logons
/// (4625) are counted by [`FailedLogons`] instead.
pub fn assess(ev: &Event) -> Option<Finding> {
    match ev.id {
        4720 => {
            let who = ev.user("TargetUserName", "TargetDomainName");
            let by = ev.user("SubjectUserName", "SubjectDomainName");
            Some(finding(
                ev,
                "KONTO:NEU",
                Severity::Hoch,
                tf!("Neues Benutzerkonto „{who}“ angelegt", "New user account “{who}” created"),
                self_hint(),
                serde_json::json!({ "konto": who, "von": by }),
            ))
        }
        4732 => {
            let group = ev.get("TargetSid");
            let (label, sev) = match group {
                ADMINS => (t!("Administratoren", "Administrators"), Severity::Hoch),
                RDP_USERS => (t!("Remotedesktopbenutzer", "Remote Desktop Users"), Severity::Hoch),
                _ => return None,
            };
            let member = match ev.get("MemberName") {
                "" | "-" => ev.get("MemberSid").to_string(),
                m => m.to_string(),
            };
            let by = ev.user("SubjectUserName", "SubjectDomainName");
            Some(finding(
                ev,
                "KONTO:GRUPPE",
                sev,
                tf!("Konto „{member}“ wurde zur Gruppe {label} hinzugefügt", "Account “{member}” was added to the group {label}"),
                self_hint(),
                serde_json::json!({ "konto": member, "gruppe": label, "von": by }),
            ))
        }
        4722 => {
            let who = ev.user("TargetUserName", "TargetDomainName");
            let sid = ev.get("TargetSid");
            // The built-in Administrator (RID 500) and Guest (RID 501) are off on a home PC.
            let builtin = sid.ends_with("-500") || sid.ends_with("-501");
            Some(finding(
                ev,
                "KONTO:AKTIVIERT",
                if builtin { Severity::Hoch } else { Severity::Mittel },
                tf!("Benutzerkonto „{who}“ wurde aktiviert{}", "User account “{who}” was enabled{}", if builtin { t!(" (eingebautes Konto)", " (built-in account)") } else { "" }),
                self_hint(),
                serde_json::json!({ "konto": who, "von": ev.user("SubjectUserName", "SubjectDomainName") }),
            ))
        }
        1102 => {
            let by = between_tags(&ev.raw_user, "SubjectUserName").unwrap_or_default();
            Some(finding(
                ev,
                "ANMELDUNG:PROTOKOLL-GELOESCHT",
                Severity::Hoch,
                t!("Das Windows-Sicherheitsprotokoll wurde gelöscht", "The Windows security log was cleared").into(),
                t!("Angreifer löschen das Protokoll, um ihre Spuren zu verwischen. Hast du es nicht selbst gelöscht (Ereignisanzeige → Sicherheit → Protokoll löschen): vollständigen Scan starten und Passwörter von einem anderen Gerät aus ändern.", "Attackers clear the log to cover their tracks. If you did not clear it yourself (Event Viewer → Security → Clear Log): start a full scan and change passwords from another device."),
                serde_json::json!({ "von": by }),
            ))
        }
        4624 if ev.get("LogonType") == "10" => {
            let who = ev.user("TargetUserName", "TargetDomainName");
            let ip = ev.get("IpAddress").to_string();
            let local = is_local_address(&ip);
            Some(finding(
                ev,
                "ANMELDUNG:FERNZUGRIFF",
                if local { Severity::Mittel } else { Severity::Hoch },
                tf!("Anmeldung per Remotedesktop als „{who}“ von {}", "Sign-in via Remote Desktop as “{who}” from {}", if ip.is_empty() || ip == "-" { t!("unbekannt", "unknown").to_string() } else { ip.clone() }),
                if local {
                    t!("Fernzugriff aus deinem eigenen Netz. Warst du das (z. B. von einem anderen PC)? Dann „Gesehen“.", "Remote access from your own network. Was that you (e.g. from another PC)? Then “Seen”.")
                } else {
                    t!("Fernzugriff aus dem Internet! Warst du das nicht: Netzwerkkabel ziehen bzw. WLAN aus, Remotedesktop in den Windows-Einstellungen ausschalten und alle Passwörter von einem anderen Gerät aus ändern.", "Remote access from the internet! If that was not you: pull the network cable or switch off Wi-Fi, switch off Remote Desktop in the Windows settings and change all passwords from another device.")
                },
                serde_json::json!({ "konto": who, "adresse": ip, "rechner": ev.get("WorkstationName") }),
            ))
        }
        _ => None,
    }
}

/// Counts failed logons (4625) and reports many in a short time once per window.
#[derive(Default)]
pub struct FailedLogons {
    seen: VecDeque<(chrono::DateTime<chrono::Utc>, Event)>,
    last_report: Option<chrono::DateTime<chrono::Utc>>,
}

impl FailedLogons {
    pub fn add(&mut self, ev: Event) -> Option<Finding> {
        let t = chrono::DateTime::parse_from_rfc3339(&ev.time).ok()?.with_timezone(&chrono::Utc);
        let window = chrono::Duration::minutes(FAIL_WINDOW_MIN);
        self.seen.push_back((t, ev));
        while self.seen.front().is_some_and(|(x, _)| t - *x > window) {
            self.seen.pop_front();
        }
        if self.seen.len() < FAIL_THRESHOLD || self.last_report.is_some_and(|r| t - r < window * 3) {
            return None;
        }
        self.last_report = Some(t);
        let mut users: Vec<String> = self.seen.iter().map(|(_, e)| e.user("TargetUserName", "TargetDomainName")).collect();
        users.sort();
        users.dedup();
        let mut ips: Vec<String> = self.seen.iter().map(|(_, e)| e.get("IpAddress").to_string()).filter(|i| !i.is_empty() && i != "-").collect();
        ips.sort();
        ips.dedup();
        let external = ips.iter().any(|i| !is_local_address(i));
        // The program that asked Windows to check the password (file name only): with it the
        // cause is visible at a glance when the attempts come from this PC.
        let mut programs: Vec<String> =
            self.seen.iter().map(|(_, e)| e.get("ProcessName").rsplit(['\\', '/']).next().unwrap_or("").to_string()).filter(|p| !p.is_empty() && p != "-").collect();
        programs.sort();
        programs.dedup();
        let local_only = ips.is_empty();
        let mut title = tf!(
            "{} fehlgeschlagene Anmeldungen in {FAIL_WINDOW_MIN} Minuten – Konto {}; {}", "{} failed sign-ins in {FAIL_WINDOW_MIN} minutes – account {}; {}",
            self.seen.len(),
            users.join(", "),
            if local_only { t!("von diesem PC, keine Netzwerkadresse", "from this PC, no network address").to_string() } else { tf!("von {}", "from {}", ips.join(", ")) }
        );
        if !programs.is_empty() {
            title.push_str(&tf!("; Programm {}", "; program {}", programs.join(", ")));
        }
        let last = &self.seen.back()?.1;
        let mut f = finding(
            last,
            "ANMELDUNG:FEHLVERSUCHE",
            if external { Severity::Hoch } else { Severity::Mittel },
            title,
            t!("Jemand probiert Passwörter aus. Kommt das aus dem Internet: Remotedesktop und Datei-/Druckerfreigabe ausschalten, Router-Portfreigaben prüfen. Hast du dich nur oft vertippt: „Gesehen“.", "Someone is trying passwords. If this comes from the internet: switch off Remote Desktop and file/printer sharing, check the port forwardings of the router. If you only mistyped often: “Seen”."),
            serde_json::json!({ "anzahl": self.seen.len(), "konten": users, "adressen": ips, "programme": programs }),
        );
        if local_only {
            if let Some(d) = f.details.as_mut() {
                d["hinweis"] = t!("Die Versuche kamen von einem Programm auf diesem PC, nicht aus dem Netz – ein Angriff von außen ist das nicht. \
                                Benutzt du das genannte Programm selbst (z. B. einen Browser, der das Windows-Kennwort prüft), genügt „Gesehen“. \
                                Kennst du es nicht: einen vollständigen Scan starten.", "The attempts came from a program on this PC, not from the network – this is not an attack from outside. \
                                If you use the named program yourself (e.g. a browser that checks the Windows password), “Seen” is enough. \
                                If you do not know it: start a full scan.")
                    .into();
            }
        }
        Some(f)
    }
}

/// Windows writes "account enabled" (4722) right after "account created" (4720) for every new
/// account: that second event is part of the creation and gets no finding of its own.
#[derive(Default)]
pub struct NeueKonten {
    created: Vec<(String, chrono::DateTime<chrono::Utc>)>,
}

impl NeueKonten {
    /// True if `ev` is the activation that belongs to an account created within the last 2 minutes.
    pub fn part_of_creation(&mut self, ev: &Event) -> bool {
        let Ok(t) = chrono::DateTime::parse_from_rfc3339(&ev.time).map(|t| t.with_timezone(&chrono::Utc)) else { return false };
        let sid = ev.get("TargetSid").to_string();
        self.created.retain(|(_, c)| (t - *c).num_seconds().abs() <= 120);
        match ev.id {
            4720 if !sid.is_empty() => {
                self.created.push((sid, t));
                false
            }
            4722 => !sid.is_empty() && self.created.iter().any(|(s, _)| *s == sid),
            _ => false,
        }
    }
}

/// Signal from Windows as soon as one of the watched events is written to a log (push
/// subscription: Windows calls us for every matching event; the callback only sets a wait
/// event) – the service then reads at once instead of once a minute.
pub struct Signal {
    sub: windows::Win32::System::EventLog::EVT_HANDLE,
    event: windows::Win32::Foundation::HANDLE,
}

// SAFETY: both handles are only used by the thread that owns the Signal (and by the
// callback, which only sets the event).
unsafe impl Send for Signal {}

unsafe extern "system" fn signal_callback(_action: windows::Win32::System::EventLog::EVT_SUBSCRIBE_NOTIFY_ACTION, context: *const core::ffi::c_void, _event: windows::Win32::System::EventLog::EVT_HANDLE) -> u32 {
    // SAFETY: the context is the event handle of the Signal, which outlives the subscription.
    unsafe {
        let _ = windows::Win32::System::Threading::SetEvent(windows::Win32::Foundation::HANDLE(context as *mut core::ffi::c_void));
    }
    0
}

impl Signal {
    /// The account and logon events of the Security log (needs the rights of the service).
    pub fn open() -> Option<Self> {
        let ids = EVENTS.iter().map(|e| format!("EventID={e}")).collect::<Vec<_>>().join(" or ");
        let rdp = "(*[System[EventID=4624]] and *[EventData[Data[@Name='LogonType']='10']])";
        Self::subscribe("Security", &format!("*[System[({ids})]] or {rdp}")).or_else(|| Self::subscribe("Security", &format!("*[System[({ids})]]")))
    }

    /// Subscribes to future events of a channel that match the XPath query.
    pub fn subscribe(channel: &str, query: &str) -> Option<Self> {
        use windows::core::HSTRING;
        use windows::Win32::System::EventLog::{EvtSubscribe, EvtSubscribeToFutureEvents};
        use windows::Win32::System::Threading::CreateEventW;
        // SAFETY: the event and the subscription are closed in Drop (subscription first).
        unsafe {
            let event = CreateEventW(None, false, false, None).ok()?;
            match EvtSubscribe(None, None, &HSTRING::from(channel), &HSTRING::from(query), None, Some(event.0 as *const core::ffi::c_void), Some(signal_callback), EvtSubscribeToFutureEvents.0) {
                Ok(sub) => Some(Self { sub, event }),
                Err(_) => {
                    let _ = windows::Win32::Foundation::CloseHandle(event);
                    None
                }
            }
        }
    }

    /// Waits up to `ms` for a new event. True: something was written (the caller reads the
    /// log itself with [`read_since`]).
    pub fn wait(&self, ms: u32) -> bool {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        // SAFETY: valid event handle.
        unsafe { windows::Win32::System::Threading::WaitForSingleObject(self.event, ms) == WAIT_OBJECT_0 }
    }
}

impl Drop for Signal {
    fn drop(&mut self) {
        // SAFETY: handles created in subscribe(); closing the subscription waits for a running callback.
        unsafe {
            let _ = windows::Win32::System::EventLog::EvtClose(self.sub);
            let _ = windows::Win32::Foundation::CloseHandle(self.event);
        }
    }
}

/// Event ids the service reads.
pub const EVENTS: &[u32] = &[4720, 4722, 4732, 4625, 1102];

/// Events of the Security log after `after` (oldest first, at most `max`). `None` when the
/// log can't be read (no rights, service not running as SYSTEM).
pub fn read_since(after: u64, max: usize) -> Option<Vec<Event>> {
    let ids = EVENTS.iter().map(|e| format!("EventID={e}")).collect::<Vec<_>>().join(" or ");
    let mut out = query(&format!("*[System[({ids}) and EventRecordID>{after}]]"), max, false)?;
    // Remote desktop logons only (4624 is written for every logon).
    out.extend(query(&format!("*[System[EventID=4624 and EventRecordID>{after}]] and *[EventData[Data[@Name='LogonType']='10']]"), max, false)?);
    out.sort_by_key(|e| e.record);
    out.truncate(max);
    Some(out)
}

/// Newest record number of the Security log (the baseline at the very first start).
pub fn newest_record() -> Option<u64> {
    Some(query("*", 1, true)?.first().map(|e| e.record).unwrap_or(0))
}

fn query(xpath: &str, max: usize, newest_first: bool) -> Option<Vec<Event>> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtQueryReverseDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
    };
    let channel = HSTRING::from("Security");
    let query = HSTRING::from(xpath);
    let dir = if newest_first { EvtQueryReverseDirection.0 } else { EvtQueryForwardDirection.0 };
    let mut out = Vec::new();
    // SAFETY: event log query; every handle is closed, the buffer is sized by the API.
    unsafe {
        let q = EvtQuery(None, PCWSTR(channel.as_ptr()), PCWSTR(query.as_ptr()), EvtQueryChannelPath.0 | dir).ok()?;
        while out.len() < max {
            let mut ev = [0isize; 16];
            let mut got = 0u32;
            if EvtNext(q, &mut ev, 2000, 0, &mut got).is_err() || got == 0 {
                break;
            }
            for raw in ev.iter().take(got as usize) {
                let h = EVT_HANDLE(*raw);
                let mut used = 0u32;
                let mut props = 0u32;
                let _ = EvtRender(None, h, EvtRenderEventXml.0, 0, None, &mut used, &mut props);
                let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
                if EvtRender(None, h, EvtRenderEventXml.0, (buf.len() * 2) as u32, Some(buf.as_mut_ptr().cast()), &mut used, &mut props).is_ok() {
                    let xml = String::from_utf16_lossy(&buf[..(used as usize / 2).min(buf.len())]);
                    if let Some(e) = parse(&xml) {
                        out.push(e);
                    }
                }
                let _ = EvtClose(h);
            }
        }
        let _ = EvtClose(q);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(id: u32, record: u64, time: &str, data: &[(&str, &str)]) -> String {
        let d: String = data.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>\
             <EventID>{id}</EventID><TimeCreated SystemTime='{time}'/><EventRecordID>{record}</EventRecordID></System><EventData>{d}<Data Name='Leer'/></EventData></Event>"
        )
    }

    #[test]
    fn parses_events_and_reports_new_accounts_and_admins() {
        let e = parse(&xml(4720, 77, "2026-11-17T20:01:02.1234567Z", &[("TargetUserName", "hacker"), ("TargetDomainName", "PC"), ("SubjectUserName", "anna")])).unwrap();
        assert_eq!((e.id, e.record, e.get("TargetUserName"), e.get("Leer")), (4720, 77, "hacker", ""));
        let f = assess(&e).unwrap();
        assert_eq!((f.rule_id.as_str(), f.severity, f.kind), ("KONTO:NEU", Severity::Hoch, Kind::Hinweis));
        assert!(f.threat_name.contains("PC\\hacker"));
        let admin = parse(&xml(4732, 78, "2026-11-17T20:01:03Z", &[("TargetSid", ADMINS), ("MemberSid", "S-1-5-21-1-2-3-1005"), ("MemberName", "-")])).unwrap();
        assert!(assess(&admin).unwrap().threat_name.contains("Administratoren"));
        let other = parse(&xml(4732, 79, "2026-11-17T20:01:03Z", &[("TargetSid", "S-1-5-32-545")])).unwrap();
        assert!(assess(&other).is_none(), "normale Gruppe Benutzer: keine Meldung");
        assert_ne!(assess(&e).unwrap().sha256, assess(&admin).unwrap().sha256);
    }

    #[test]
    fn activation_right_after_creation_is_not_reported_twice() {
        let ev = |id: u32, rec: u64, time: &str, sid: &str| parse(&xml(id, rec, time, &[("TargetSid", sid), ("TargetUserName", "k9test")])).unwrap();
        let mut n = NeueKonten::default();
        assert!(!n.part_of_creation(&ev(4720, 1, "2026-11-18T12:17:06.1Z", "S-1-5-21-1-1005")));
        assert!(n.part_of_creation(&ev(4722, 2, "2026-11-18T12:17:06.2Z", "S-1-5-21-1-1005")), "gehoert zum Anlegen");
        assert!(!n.part_of_creation(&ev(4722, 3, "2026-11-18T12:17:07Z", "S-1-5-21-1-500")), "anderes Konto: melden");
        assert!(!n.part_of_creation(&ev(4722, 4, "2026-11-18T12:30:00Z", "S-1-5-21-1-1005")), "spaeter eingeschaltet: melden");
    }

    #[test]
    fn cleared_log_is_reported() {
        let x = "<Event><System><EventID>1102</EventID><TimeCreated SystemTime='2026-11-17T20:01:03Z'/><EventRecordID>1</EventRecordID></System>\
                 <UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>anna</SubjectUserName></LogFileCleared></UserData></Event>";
        let f = assess(&parse(x).unwrap()).unwrap();
        assert_eq!(f.rule_id, "ANMELDUNG:PROTOKOLL-GELOESCHT");
        assert_eq!(f.details.unwrap()["von"], "anna");
    }

    #[test]
    fn remote_desktop_from_the_internet_is_high() {
        let rdp = |ip: &str| parse(&xml(4624, 9, "2026-11-17T20:01:03Z", &[("LogonType", "10"), ("TargetUserName", "anna"), ("IpAddress", ip)])).unwrap();
        assert_eq!(assess(&rdp("203.0.113.5")).unwrap().severity, Severity::Hoch);
        assert_eq!(assess(&rdp("192.168.178.20")).unwrap().severity, Severity::Mittel);
        let console = parse(&xml(4624, 10, "2026-11-17T20:01:03Z", &[("LogonType", "2")])).unwrap();
        assert!(assess(&console).is_none(), "normale Anmeldung am PC: nichts");
        assert!(is_local_address("fe80::1") && is_local_address("-") && !is_local_address("8.8.8.8"));
    }

    #[test]
    fn many_failed_logons_give_one_finding() {
        let mut f = FailedLogons::default();
        let mut found = Vec::new();
        for i in 0..25u64 {
            let t = format!("2026-11-17T20:{:02}:00Z", i / 4);
            let e = parse(&xml(4625, 100 + i, &t, &[("TargetUserName", "admin"), ("IpAddress", "198.51.100.7")])).unwrap();
            found.extend(f.add(e));
        }
        assert_eq!(found.len(), 1, "einmal je Zeitfenster");
        assert_eq!(found[0].severity, Severity::Hoch);
        assert_eq!(found[0].details.as_ref().unwrap()["anzahl"], 10);
        // A few typos spread over an hour: nothing.
        let mut g = FailedLogons::default();
        for i in 0..4u64 {
            let e = parse(&xml(4625, i, &format!("2026-11-17T2{i}:00:00Z"), &[])).unwrap();
            assert!(g.add(e).is_none());
        }
    }
}

#[cfg(test)]
mod live {
    #[test]
    fn signal_wakes_up_for_a_new_event() {
        // A channel every user may read and write to: Windows PowerShell logs each start.
        let Some(s) = super::Signal::subscribe("Windows PowerShell", "*") else {
            println!("Kanal nicht lesbar - uebersprungen");
            return;
        };
        // Other tests and programs start PowerShell too: wait for a quiet moment first.
        if !(0..40).any(|_| !s.wait(300)) {
            println!("Kanal kommt nicht zur Ruhe (andere PowerShell-Starts) - uebersprungen");
            return;
        }
        let script = crate::test_tmp().join("signal-test.ps1");
        std::fs::write(&script, "exit 0\r\n").unwrap();
        let _ = std::process::Command::new("powershell").args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(&script).status();
        assert!(s.wait(15_000), "Signal nach dem Start von PowerShell");
    }
}

#[cfg(test)]
mod failed_logon_text_tests {
    use super::*;

    fn event(i: u64, fields: &[(&str, &str)]) -> Event {
        let mut data = String::new();
        for (k, v) in fields {
            data.push_str(&format!("<Data Name='{k}'>{v}</Data>"));
        }
        let xml = format!(
            "<Event><System><EventID>4625</EventID><EventRecordID>{i}</EventRecordID><TimeCreated SystemTime='2026-11-20T19:20:{:02}Z'/></System><EventData>{data}</EventData></Event>",
            i % 60
        );
        parse(&xml).expect("Ereignis lesbar")
    }

    #[test]
    fn local_attempts_name_account_and_program_and_are_not_called_an_attack() {
        let mut f = FailedLogons::default();
        let mut found = Vec::new();
        for i in 0..12u64 {
            let e = event(i + 1, &[("TargetUserName", "anna"), ("TargetDomainName", "PC"), ("IpAddress", "-"), ("ProcessName", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")]);
            found.extend(f.add(e));
        }
        assert_eq!(found.len(), 1);
        let hit = &found[0];
        assert_eq!(hit.severity, Severity::Mittel);
        assert!(hit.threat_name.contains("anna") && hit.threat_name.contains("von diesem PC") && hit.threat_name.ends_with("Programm msedge.exe"), "{}", hit.threat_name);
        let d = hit.details.as_ref().unwrap();
        assert_eq!(d["programme"][0], "msedge.exe");
        assert!(d["hinweis"].as_str().unwrap().contains("nicht aus dem Netz"));
    }

    #[test]
    fn attempts_from_the_internet_keep_the_warning_and_name_the_address() {
        let mut f = FailedLogons::default();
        let mut found = Vec::new();
        for i in 0..12u64 {
            found.extend(f.add(event(i + 1, &[("TargetUserName", "admin"), ("IpAddress", "198.51.100.7")])));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, Severity::Hoch);
        assert!(found[0].threat_name.contains("von 198.51.100.7"), "{}", found[0].threat_name);
        assert!(found[0].details.as_ref().unwrap()["hinweis"].as_str().unwrap().starts_with("Jemand probiert"));
    }
}
