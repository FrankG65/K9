//! Windows service ("K9-Dienst") – shared parts for service, agent
//! and CLI: message protocol, validation, named pipes with restrictive ACL,
//! installation settings and service status.
//!
//! Two pipes (synchronous I/O on one handle would block reads against writes):
//! * `K9-Dienst-Meldungen`: service -> agent, one JSON line per finding.
//! * `K9-Dienst-Befehle`: agent/k9 -> service, one request, one answer.
//!
//! The pipe ACL allows only SYSTEM, Administrators and the installing user.
//! Every message is versioned and validated; a request can only reference a
//! finding the service reported itself (random token) – never a path or a
//! command line, so nothing arbitrary can be executed with service rights.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_NONE, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};

use crate::model::{Action, Finding, Kind, Severity};
use crate::winreg::{self, HKLM};

pub const SERVICE_NAME: &str = "K9-Dienst";
/// User-defined service control (128..=255) that `k9 dienst stoppen/aktualisieren/deinstallieren`
/// sends right before the stop request. Without it the service refuses to stop: ransomware
/// stops protection services through Windows first (Conti, test of 21.11.2026).
pub const STOP_CODE: u32 = 200;
/// How long the announcement is valid.
pub const STOP_VALID_SECS: u64 = 60;
pub const SERVICE_DISPLAY: &str = "K9 Schutzdienst";
pub const PIPE_MELDUNGEN: &str = r"\\.\pipe\K9-Dienst-Meldungen";
pub const PIPE_BEFEHLE: &str = r"\\.\pipe\K9-Dienst-Befehle";
pub const REG_KEY: &str = "SOFTWARE\\K9";
pub const PROTOCOL: u32 = 1;
const MAX_LINE: usize = 64 * 1024;

// =============================================================== protocol

/// A finding as transported over the pipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WireFinding {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub rule_id: String,
    pub threat_name: String,
    pub category: String,
    pub severity: Severity,
    pub engine: String,
    pub kind: Kind,
    pub details: Option<serde_json::Value>,
}

impl From<&Finding> for WireFinding {
    fn from(f: &Finding) -> Self {
        Self {
            path: f.path.to_string_lossy().to_string(),
            sha256: f.sha256.clone(),
            size: f.size,
            rule_id: f.rule_id.clone(),
            threat_name: f.threat_name.clone(),
            category: f.category.clone(),
            severity: f.severity,
            engine: f.engine.clone(),
            kind: f.kind,
            details: f.details.clone(),
        }
    }
}

impl WireFinding {
    /// The finding as reported (without a service token).
    pub fn into_plain(self) -> Finding {
        Finding {
            path: PathBuf::from(self.path),
            sha256: self.sha256,
            size: self.size,
            rule_id: self.rule_id,
            threat_name: self.threat_name,
            category: self.category,
            severity: self.severity,
            engine: self.engine,
            kind: self.kind,
            details: self.details,
        }
    }

    /// Finding for the agent's pipeline; `dienst_token` lets the agent ask the
    /// service to carry out actions that need administrator rights.
    pub fn into_finding(self, token: &str) -> Finding {
        let mut details = self.details.unwrap_or_else(|| serde_json::json!({}));
        if let Some(obj) = details.as_object_mut() {
            obj.insert("dienst_token".into(), token.into());
        }
        Finding {
            path: PathBuf::from(self.path),
            sha256: self.sha256,
            size: self.size,
            rule_id: self.rule_id,
            threat_name: self.threat_name,
            category: self.category,
            severity: self.severity,
            engine: self.engine,
            kind: self.kind,
            details: Some(details),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "typ", rename_all = "lowercase")]
#[allow(clippy::large_enum_variant)] // one message at a time, boxing brings nothing
pub enum Message {
    /// service -> agent: new finding
    Fund { v: u32, token: String, fund: WireFinding },
    /// service -> agent: keep-alive
    Ping { v: u32 },
    /// agent -> service: carry out the user's decision for a finding of the service
    Aktion { v: u32, token: String, detection_id: i64, aktion: Action },
    /// k9 -> service: the user stops the agent on purpose (no alarm, restart later)
    AgentStopp { v: u32, minuten: u32 },
    /// k9 -> service: end a pause early (strengthening, no confirmation); answer "beendet"/"keine"
    PauseBeenden { v: u32 },
    /// k9 -> service: remove the firewall block now and do not restore it until the next
    /// regular renewal (`k9 firewall entfernen`; with confirmation window)
    FirewallEntfernen { v: u32 },
    /// Agent -> service: a game is running (the service then postpones its updates and checks).
    Spielmodus { v: u32, aktiv: bool },
    /// Agent -> service: no keyboard/mouse input for this many minutes (for idle-only work).
    Leerlauf { v: u32, minuten: u32 },
    /// k9/agent -> service: status query
    Status { v: u32 },
    /// agent/k9 -> service: sign a remembered decision of the user
    Signieren { v: u32, entscheidung_id: i64 },
    /// agent/k9 -> service: carry out the user's decision for any open finding
    /// (e.g. quarantine into the protected folder)
    Ausfuehren { v: u32, detection_id: i64, aktion: Action },
    /// agent/k9 -> service: update the source data now (all or one source)
    QuellenAktualisieren { v: u32, quelle: Option<String> },
    /// k9 -> service: store an API key for the source updates (None = delete)
    GeheimnisSetzen { v: u32, name: String, wert: Option<String> },
    /// k9 -> service: which API keys does the service have? (names only)
    Geheimnisse { v: u32 },
    /// agent/k9 -> service: new findings (the service checks decisions and stores them)
    Funde { v: u32, seq: i64, funde: Vec<WireFinding> },
    /// agent/k9 -> service: the user's decision for an open finding
    Entscheiden { v: u32, detection_id: i64, aktion: Action, notiz: Option<String> },
    /// agent/k9 -> service: the same decision for several open findings (one confirmation for
    /// all; the answer lists the result per finding as JSON)
    EntscheidenMehrere { v: u32, ids: Vec<i64>, aktion: Action, notiz: Option<String> },
    /// agent/k9 -> service: remember a decision (e.g. after restoring)
    EntscheidungSpeichern { v: u32, sha256: String, rule_id: String, threat_name: String, aktion: Action, notiz: Option<String> },
    /// agent/k9 -> service: forget a decision (by id or fingerprint)
    EntscheidungWiderrufen { v: u32, id: Option<i64>, sha256: Option<String>, rule_id: Option<String> },
    /// agent/k9 -> service: switch a disabled autostart on again
    Reaktivieren { v: u32, id: i64 },
    /// agent/k9 -> service: entry for the event log
    Ereignis { v: u32, stufe: String, text: String },
    /// agent/k9 -> service: restore a file from the protected quarantine
    Wiederherstellen { v: u32, quarantaene_id: i64, freigeben: bool, ziel: Option<String> },
    /// service -> caller
    Ergebnis { v: u32, ok: bool, text: String },
    StatusAntwort {
        v: u32,
        version: String,
        etw_prozesse: bool,
        etw_dns: bool,
        agent_wache: bool,
        /// State of the shadow copies (only when switched on).
        #[serde(default)]
        schattenkopien: Option<String>,
        /// Self-test at the start (JSON, k9_core::umzug::Gesundheit).
        #[serde(default)]
        gesundheit: Option<String>,
    },
}

fn is_token(t: &str) -> bool {
    t.len() == 32 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

fn short(s: &str, max: usize) -> bool {
    s.len() <= max
}

/// Checks version, sizes and the meaning of a message.
pub fn validate(msg: &Message) -> Result<()> {
    let v = match msg {
        Message::Fund { v, .. }
        | Message::Ping { v }
        | Message::Aktion { v, .. }
        | Message::AgentStopp { v, .. }
        | Message::PauseBeenden { v }
        | Message::FirewallEntfernen { v }
        | Message::Spielmodus { v, .. }
        | Message::Leerlauf { v, .. }
        | Message::Status { v }
        | Message::Signieren { v, .. }
        | Message::Ausfuehren { v, .. }
        | Message::QuellenAktualisieren { v, .. }
        | Message::GeheimnisSetzen { v, .. }
        | Message::Geheimnisse { v }
        | Message::Funde { v, .. }
        | Message::Entscheiden { v, .. }
        | Message::EntscheidenMehrere { v, .. }
        | Message::EntscheidungSpeichern { v, .. }
        | Message::EntscheidungWiderrufen { v, .. }
        | Message::Reaktivieren { v, .. }
        | Message::Ereignis { v, .. }
        | Message::Wiederherstellen { v, .. }
        | Message::Ergebnis { v, .. }
        | Message::StatusAntwort { v, .. } => *v,
    };
    if v != PROTOCOL {
        bail!("Protokollversion {v} wird nicht unterstützt (erwartet {PROTOCOL})");
    }
    let fund_ok = |fund: &WireFinding| -> Result<()> {
        let details_len = fund.details.as_ref().map(|d| d.to_string().len()).unwrap_or(0);
        if !short(&fund.path, 2048)
            || !short(&fund.rule_id, 256)
            || !short(&fund.threat_name, 512)
            || !short(&fund.category, 128)
            || !short(&fund.engine, 64)
            || fund.sha256.len() != 64
            || !fund.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || details_len > 16 * 1024
        {
            bail!("Fund mit ungültigen Feldern abgelehnt");
        }
        Ok(())
    };
    let is_sha = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit());
    match msg {
        Message::Fund { token, fund, .. } => {
            if !is_token(token) {
                bail!("Ungültiges Token");
            }
            fund_ok(fund)?;
        }
        Message::Funde { seq, funde, .. } => {
            if *seq <= 0 || funde.is_empty() || funde.len() > 50 {
                bail!("Ungültige Fundliste");
            }
            funde.iter().try_for_each(fund_ok)?;
        }
        Message::Entscheiden { detection_id, notiz, .. } if *detection_id <= 0 || notiz.as_ref().is_some_and(|n| !short(n, 500)) => {
            bail!("Ungültige Entscheidung")
        }
        Message::EntscheidenMehrere { ids, notiz, .. }
            if ids.is_empty() || ids.len() > 200 || ids.iter().any(|i| *i <= 0) || notiz.as_ref().is_some_and(|n| !short(n, 500)) =>
        {
            bail!("Ungültige Sammelentscheidung")
        }
        Message::EntscheidungSpeichern { sha256, rule_id, threat_name, notiz, .. }
            if !is_sha(sha256) || !short(rule_id, 256) || !short(threat_name, 512) || notiz.as_ref().is_some_and(|n| !short(n, 500)) =>
        {
            bail!("Ungültige Entscheidung")
        }
        Message::EntscheidungWiderrufen { id, sha256, rule_id, .. }
            if !(id.is_some_and(|i| i > 0) || (sha256.as_deref().is_some_and(is_sha) && rule_id.as_ref().is_some_and(|r| short(r, 256)))) =>
        {
            bail!("Ungültiger Widerruf")
        }
        Message::Reaktivieren { id, .. } if *id <= 0 => bail!("Ungültiger Eintrag"),
        Message::Ereignis { stufe, text, .. } if !matches!(stufe.as_str(), "info" | "warnung" | "fehler") || !short(text, 2000) => {
            bail!("Ungültiges Ereignis")
        }
        Message::Aktion { token, detection_id, aktion, .. } => {
            if !is_token(token) || *detection_id <= 0 {
                bail!("Ungültige Aktionsanfrage");
            }
            // Passive decisions need the service only to confirm a settings change.
            if aktion.is_passive() && *aktion != Action::Freigabe {
                bail!("Passive Entscheidungen braucht der Dienst nicht");
            }
        }
        Message::AgentStopp { minuten, .. } => {
            if *minuten == 0 || *minuten > 240 {
                bail!("Pause muss zwischen 1 und 240 Minuten liegen");
            }
        }
        Message::Ergebnis { text, .. } if !short(text, 4096) => bail!("Antwort zu lang"),
        Message::Signieren { entscheidung_id, .. } if *entscheidung_id <= 0 => bail!("Ungültige Entscheidung"),
        Message::QuellenAktualisieren { quelle: Some(q), .. } if !short(q, 64) => bail!("Ungültige Quelle"),
        Message::GeheimnisSetzen { name, wert, .. }
            if !crate::schutz::SERVICE_SECRETS.contains(&name.as_str()) || wert.as_ref().is_some_and(|w| w.is_empty() || !short(w, 1024)) =>
        {
            bail!("Ungültiges Geheimnis")
        }
        Message::Ausfuehren { detection_id, aktion, .. } if *detection_id <= 0 || aktion.is_passive() => {
            bail!("Ungültige Ausführungsanfrage")
        }
        Message::Wiederherstellen { quarantaene_id, ziel, .. } if *quarantaene_id <= 0 || ziel.as_ref().is_some_and(|z| !short(z, 1024)) => {
            bail!("Ungültige Wiederherstellungsanfrage")
        }
        _ => {}
    }
    Ok(())
}

pub fn encode(msg: &Message) -> Result<String> {
    let mut s = serde_json::to_string(msg)?;
    if s.len() > MAX_LINE {
        bail!("Nachricht zu groß");
    }
    s.push('\n');
    Ok(s)
}

pub fn decode(line: &str) -> Result<Message> {
    if line.len() > MAX_LINE {
        bail!("Nachricht zu groß");
    }
    let msg: Message = serde_json::from_str(line.trim()).context("Ungültige Nachricht")?;
    validate(&msg)?;
    Ok(msg)
}

pub fn new_token() -> String {
    hex::encode(crate::random_bytes(16))
}

// ================================================================== pipes

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// DACL: SYSTEM and Administrators full access, the given user read/write.
pub fn pipe_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{user_sid})")
}

/// Owns a security descriptor created from SDDL.
pub struct SecDesc(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is an immutable heap allocation owned by this value.
unsafe impl Send for SecDesc {}
unsafe impl Sync for SecDesc {}

impl SecDesc {
    pub fn from_sddl(sddl: &str) -> Result<Self> {
        let w = wide(sddl);
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: valid NUL-terminated string; freed in Drop.
        unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), SDDL_REVISION_1, &mut sd, None)? };
        Ok(Self(sd))
    }

    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for SecDesc {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0 .0)));
        }
    }
}

pub struct Pipe(HANDLE);

// SAFETY: a pipe handle may be used from another thread (one user at a time).
unsafe impl Send for Pipe {}

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: handle owned by us.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

impl Pipe {
    /// Server side: creates one pipe instance with the given ACL and waits for a client.
    pub fn serve(name: &str, sd: &SecDesc) -> Result<Self> {
        let w = wide(name);
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: valid name and security attributes.
        let h = unsafe {
            CreateNamedPipeW(
                PCWSTR(w.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                4,
                64 * 1024,
                64 * 1024,
                0,
                Some(&sa),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_invalid() {
            bail!("Pipe {name} kann nicht angelegt werden");
        }
        let pipe = Pipe(h);
        // SAFETY: blocking wait for a client; "already connected" is fine.
        unsafe {
            if let Err(e) = ConnectNamedPipe(pipe.0, None) {
                if e.code() != windows::Win32::Foundation::ERROR_PIPE_CONNECTED.to_hresult() {
                    bail!("Verbindung fehlgeschlagen: {e}");
                }
            }
        }
        Ok(pipe)
    }

    /// Client side: connects (waits up to `timeout` for a free instance).
    pub fn connect(name: &str, timeout: Duration) -> Result<Self> {
        let w = wide(name);
        let start = Instant::now();
        loop {
            // SAFETY: valid name.
            let h = unsafe {
                CreateFileW(
                    PCWSTR(w.as_ptr()),
                    (GENERIC_READ | GENERIC_WRITE).0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
            };
            match h {
                Ok(h) => return Ok(Pipe(h)),
                Err(e) if start.elapsed() < timeout => {
                    // SAFETY: valid name.
                    unsafe {
                        let _ = WaitNamedPipeW(PCWSTR(w.as_ptr()), 500);
                    }
                    if e.code() == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.to_hresult() {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
                Err(e) => bail!("Dienst nicht erreichbar ({name}): {e}"),
            }
        }
    }

    pub fn write_msg(&self, msg: &Message) -> Result<()> {
        let line = encode(msg)?;
        let mut written = 0u32;
        // SAFETY: valid handle and buffer.
        unsafe {
            WriteFile(self.0, Some(line.as_bytes()), Some(&mut written), None)?;
            let _ = FlushFileBuffers(self.0);
        }
        if written as usize != line.len() {
            bail!("Nachricht unvollständig gesendet");
        }
        Ok(())
    }

    /// Reads one line (blocking).
    pub fn read_msg(&self) -> Result<Message> {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let mut n = 0u32;
            // SAFETY: valid handle and buffer.
            unsafe { ReadFile(self.0, Some(&mut byte), Some(&mut n), None)? };
            if n == 0 {
                bail!("Verbindung geschlossen");
            }
            if byte[0] == b'\n' {
                break;
            }
            buf.push(byte[0]);
            if buf.len() > MAX_LINE {
                bail!("Nachricht zu groß");
            }
        }
        decode(&String::from_utf8_lossy(&buf))
    }

    /// Process id of the connected client (server side, for the log).
    pub fn client_pid(&self) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: valid handle.
        unsafe { windows::Win32::System::Pipes::GetNamedPipeClientProcessId(self.0, &mut pid).ok()? };
        Some(pid)
    }

    /// Token of the connected client (server side) for impersonation.
    /// The caller closes it with `CloseHandle`.
    pub fn client_token(&self) -> Option<HANDLE> {
        use windows::Win32::Security::{RevertToSelf, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY};
        use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;
        use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
        // SAFETY: impersonate only to take the token, revert right away.
        unsafe {
            ImpersonateNamedPipeClient(self.0).ok()?;
            let mut tok = HANDLE::default();
            let r = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, true, &mut tok);
            let _ = RevertToSelf();
            r.ok()?;
            Some(tok)
        }
    }

    pub fn disconnect(&self) {
        // SAFETY: valid handle.
        unsafe {
            let _ = DisconnectNamedPipe(self.0);
        }
    }
}

/// One request/answer on the command pipe.
pub fn request(msg: &Message) -> Result<Message> {
    // Unit tests and portable/test agents never talk to the installed service.
    if cfg!(test) || std::env::var_os(crate::paths::HOME_ENV).is_some_and(|v| !v.is_empty()) {
        bail!("Test-/portabler Modus: kein Kontakt zum installierten Dienst");
    }
    let p = Pipe::connect(PIPE_BEFEHLE, Duration::from_secs(5))?;
    p.write_msg(msg)?;
    p.read_msg()
}

fn expect_ok(answer: Message) -> Result<()> {
    match answer {
        Message::Ergebnis { ok: true, .. } => Ok(()),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
    }
}

/// Asks the service to carry out the user's decision for an open finding.
pub fn request_execute(detection_id: i64, aktion: Action) -> Result<()> {
    expect_ok(request(&Message::Ausfuehren { v: PROTOCOL, detection_id, aktion })?)
}

/// Asks the service to update the source data (runs in the background there).
pub fn request_source_update(quelle: Option<&str>) -> Result<String> {
    match request(&Message::QuellenAktualisieren { v: PROTOCOL, quelle: quelle.map(str::to_string) })? {
        Message::Ergebnis { ok: true, text, .. } => Ok(text),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
    }
}

/// Names of the API keys the service holds.
pub fn service_secret_names() -> Result<Vec<String>> {
    match request(&Message::Geheimnisse { v: PROTOCOL })? {
        Message::Ergebnis { ok: true, text, .. } => Ok(text.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
    }
}

pub fn request_set_secret(name: &str, wert: Option<&str>) -> Result<()> {
    expect_ok(request(&Message::GeheimnisSetzen { v: PROTOCOL, name: name.into(), wert: wert.map(str::to_string) })?)
}

fn ok_text(answer: Message) -> Result<String> {
    match answer {
        Message::Ergebnis { ok: true, text, .. } => Ok(text),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
    }
}

/// Sends findings to the service; answer: JSON summary (see k9-dienst).
pub fn request_findings(seq: i64, funde: Vec<WireFinding>) -> Result<String> {
    ok_text(request(&Message::Funde { v: PROTOCOL, seq, funde })?)
}

/// The user's decision, carried out by the service; answer: JSON summary.
pub fn request_decide(detection_id: i64, aktion: Action, notiz: Option<&str>) -> Result<String> {
    ok_text(request(&Message::Entscheiden { v: PROTOCOL, detection_id, aktion, notiz: notiz.map(str::to_string) })?)
}

pub fn request_decide_many(ids: &[i64], aktion: Action, notiz: Option<&str>) -> Result<String> {
    ok_text(request(&Message::EntscheidenMehrere { v: PROTOCOL, ids: ids.to_vec(), aktion, notiz: notiz.map(str::to_string) })?)
}

pub fn request_save_decision(sha256: &str, rule_id: &str, threat_name: &str, aktion: Action, notiz: Option<&str>) -> Result<()> {
    expect_ok(request(&Message::EntscheidungSpeichern {
        v: PROTOCOL,
        sha256: sha256.into(),
        rule_id: rule_id.into(),
        threat_name: threat_name.chars().take(500).collect(),
        aktion,
        notiz: notiz.map(str::to_string),
    })?)
}

pub fn request_revoke(id: Option<i64>, fingerprint: Option<(&str, &str)>) -> Result<()> {
    expect_ok(request(&Message::EntscheidungWiderrufen {
        v: PROTOCOL,
        id,
        sha256: fingerprint.map(|f| f.0.to_string()),
        rule_id: fingerprint.map(|f| f.1.to_string()),
    })?)
}

pub fn request_reenable(id: i64) -> Result<String> {
    ok_text(request(&Message::Reaktivieren { v: PROTOCOL, id })?)
}

pub fn request_event(stufe: &str, text: &str) -> Result<()> {
    let stufe = if matches!(stufe, "info" | "warnung" | "fehler") { stufe } else { "info" };
    expect_ok(request(&Message::Ereignis { v: PROTOCOL, stufe: stufe.into(), text: text.chars().take(1900).collect() })?)
}

/// Asks the service to restore a file from the protected quarantine.
pub fn request_restore(quarantaene_id: i64, freigeben: bool, ziel: Option<&std::path::Path>) -> Result<()> {
    let ziel = ziel.map(|z| z.display().to_string());
    expect_ok(request(&Message::Wiederherstellen { v: PROTOCOL, quarantaene_id, freigeben, ziel })?)
}

/// Asks the service to carry out an action for one of its findings.
pub fn request_action(token: &str, detection_id: i64, aktion: Action) -> Result<()> {
    match request(&Message::Aktion { v: PROTOCOL, token: token.into(), detection_id, aktion })? {
        Message::Ergebnis { ok: true, .. } => Ok(()),
        Message::Ergebnis { ok: false, text, .. } => bail!("Dienst: {text}"),
        other => bail!("Unerwartete Antwort des Dienstes: {other:?}"),
    }
}

// ======================================================= settings / state

/// Written at installation (HKLM\SOFTWARE\K9, admin-only).
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub user_sid: String,
    pub profile: String,
    pub appdata: String,
    pub localappdata: String,
    pub temp: String,
    pub data_dir: String,
    pub agent_path: String,
}

pub fn read_settings() -> Option<Settings> {
    let r = |n: &str| winreg::read_string(HKLM, REG_KEY, n);
    Some(Settings {
        user_sid: r("BenutzerSid")?,
        profile: r("Benutzerprofil")?,
        appdata: r("AppData")?,
        localappdata: r("LocalAppData")?,
        temp: r("Temp")?,
        data_dir: r("Datenordner")?,
        agent_path: r("AgentPfad")?,
    })
}

pub fn write_settings(s: &Settings) -> Result<()> {
    winreg::create_key(HKLM, REG_KEY)?;
    for (n, v) in [
        ("BenutzerSid", &s.user_sid),
        ("Benutzerprofil", &s.profile),
        ("AppData", &s.appdata),
        ("LocalAppData", &s.localappdata),
        ("Temp", &s.temp),
        ("Datenordner", &s.data_dir),
        ("AgentPfad", &s.agent_path),
    ] {
        winreg::set_string(HKLM, REG_KEY, n, v)?;
    }
    Ok(())
}

/// SID of the current user (works in elevated processes too: same user).
pub fn current_user_sid() -> Result<String> {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    // SAFETY: token and buffers are valid for the duration of the calls.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), len, &mut len);
        let _ = CloseHandle(token);
        r?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut s)?;
        let sid = s.to_string()?;
        let _ = LocalFree(Some(HLOCAL(s.0 as _)));
        Ok(sid)
    }
}

/// "läuft", "gestoppt", ... or `None` if the service is not installed.
pub fn service_state() -> Option<String> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    };
    let name = wide(SERVICE_NAME);
    // SAFETY: handles closed below.
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT).ok()?;
        let svc = OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_QUERY_STATUS);
        let res = match svc {
            Ok(svc) => {
                let mut st = SERVICE_STATUS::default();
                let r = QueryServiceStatus(svc, &mut st);
                let _ = CloseServiceHandle(svc);
                r.ok().map(|_| match st.dwCurrentState {
                    s if s == SERVICE_RUNNING => "läuft".to_string(),
                    s if s == SERVICE_STOPPED => "gestoppt".to_string(),
                    s if s == SERVICE_START_PENDING => "startet".to_string(),
                    s if s == SERVICE_STOP_PENDING => "wird gestoppt".to_string(),
                    _ => "unbekannt".to_string(),
                })
            }
            Err(_) => None,
        };
        let _ = CloseServiceHandle(scm);
        res
    }
}

/// Installation folder of the runtime programs (admin-only writable).
pub fn install_dir() -> PathBuf {
    let pf = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
    PathBuf::from(pf).join("K9")
}

/// True if `path` is a program directly in the installation folder. The
/// service only starts or trusts programs there – never from a folder the
/// user (or malware running as the user) can change.
pub fn is_installed_program(path: &std::path::Path) -> bool {
    let dir = install_dir();
    path.parent().is_some_and(|p| p.to_string_lossy().eq_ignore_ascii_case(&dir.to_string_lossy()))
        && !path.to_string_lossy().contains("..")
}

/// Development folder (with scripts\anleitung-pdf.ps1), written at installation.
pub fn dev_dir() -> Option<PathBuf> {
    winreg::read_string(HKLM, REG_KEY, "Entwicklungsordner").map(PathBuf::from).filter(|p| p.is_dir())
}

pub fn service_running() -> bool {
    service_state().as_deref() == Some("läuft")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding() -> WireFinding {
        WireFinding {
            path: "Prozess x".into(),
            sha256: "ab".repeat(32),
            size: 0,
            rule_id: "PROZESSKETTE:winword.exe>powershell.exe".into(),
            threat_name: "Test".into(),
            category: "Test".into(),
            severity: Severity::Hoch,
            engine: "dienst".into(),
            kind: Kind::Prozess,
            details: Some(serde_json::json!({ "pid": 4711 })),
        }
    }

    #[test]
    fn only_programs_in_program_files_are_trusted() {
        let dir = install_dir();
        assert!(is_installed_program(&dir.join("k9-agent.exe")));
        assert!(!is_installed_program(std::path::Path::new(r"C:\K9-Quelltext\target\release\k9-agent.exe")));
        assert!(!is_installed_program(&dir.join("sub").join("k9-agent.exe")));
        assert!(!is_installed_program(&dir.join("..").join("x.exe")));
    }

    #[test]
    fn roundtrip_and_validation() {
        let t = new_token();
        let m = Message::Fund { v: PROTOCOL, token: t.clone(), fund: finding() };
        let line = encode(&m).unwrap();
        assert!(line.ends_with('\n'));
        assert_eq!(decode(&line).unwrap(), m);
        let f = finding().into_finding(&t);
        assert_eq!(f.details.unwrap()["dienst_token"], t);

        // wrong version, bad token, bad hash, oversized details, unknown action
        assert!(decode(&line.replace("\"v\":1", "\"v\":2")).is_err());
        assert!(validate(&Message::Fund { v: 1, token: "x".into(), fund: finding() }).is_err());
        let mut bad = finding();
        bad.sha256 = "zz".into();
        assert!(validate(&Message::Fund { v: 1, token: t.clone(), fund: bad }).is_err());
        let mut big = finding();
        big.details = Some(serde_json::json!({ "x": "a".repeat(20000) }));
        assert!(validate(&Message::Fund { v: 1, token: t.clone(), fund: big }).is_err());
        assert!(decode(r#"{"typ":"aktion","v":1,"token":"00","detection_id":1,"aktion":"loeschen"}"#).is_err());
        assert!(decode(&format!(r#"{{"typ":"aktion","v":1,"token":"{t}","detection_id":1,"aktion":"rm -rf"}}"#)).is_err());
        assert!(validate(&Message::Aktion { v: 1, token: t.clone(), detection_id: 5, aktion: Action::Gesehen }).is_err());
        assert!(validate(&Message::Signieren { v: 1, entscheidung_id: 0 }).is_err());
        assert!(validate(&Message::Aktion { v: 1, token: t.clone(), detection_id: 5, aktion: Action::Quarantaene }).is_ok());
        assert!(validate(&Message::AgentStopp { v: 1, minuten: 0 }).is_err());
        assert!(decode(&"x".repeat(70_000)).is_err());
        assert!(decode("{ kein json").is_err());
    }

    #[test]
    fn pipe_acl_allows_user_and_blocks_others() {
        let sid = current_user_sid().unwrap();
        assert!(sid.starts_with("S-1-5-"));
        // Allowed: our own user.
        let name = format!(r"\\.\pipe\K9-Test-{}", new_token());
        let sd = SecDesc::from_sddl(&pipe_sddl(&sid)).unwrap();
        let n2 = name.clone();
        let server = std::thread::spawn(move || {
            let p = Pipe::serve(&n2, &sd).unwrap();
            let m = p.read_msg().unwrap();
            p.write_msg(&Message::Ergebnis { v: 1, ok: true, text: format!("{m:?}") }).unwrap();
            let _ = p.read_msg(); // wait until the client is done
        });
        let c = Pipe::connect(&name, Duration::from_secs(5)).unwrap();
        c.write_msg(&Message::Status { v: 1 }).unwrap();
        assert!(matches!(c.read_msg().unwrap(), Message::Ergebnis { ok: true, .. }));
        drop(c);
        server.join().unwrap();

        // Blocked: ACL only for SYSTEM, Administrators (not elevated here) and another SID.
        if !crate::paths::is_elevated() {
            let name = format!(r"\\.\pipe\K9-Test-{}", new_token());
            let sd = SecDesc::from_sddl(&pipe_sddl("S-1-5-21-1-2-3-1000")).unwrap();
            let n2 = name.clone();
            std::thread::spawn(move || {
                let _ = Pipe::serve(&n2, &sd);
            });
            std::thread::sleep(Duration::from_millis(300));
            assert!(Pipe::connect(&name, Duration::from_millis(800)).is_err(), "fremder Benutzer darf nicht verbinden");
        }
    }

    #[test]
    fn service_state_query_works_without_admin() {
        // Installed or not – the query itself must not fail or panic.
        let _ = service_state();
    }
}
