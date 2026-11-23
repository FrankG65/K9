//! Notification channels: Windows popup (toast), browser dashboard, e-mail
//! (SMTP over TLS) and phone push (ntfy). Several channels can be active.
//!
//! While a game runs, notifications are queued in the database and delivered
//! when the game ends; critical ones may still go out via e-mail/phone.

use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::config::{Channel, Config, EmailConfig, HandyConfig};
use crate::gaming::GamingState;
use crate::model::{Action, Detection, Severity};
use crate::secrets;
use crate::store::Store;

/// Link to the local dashboard (agent must be running).
#[derive(Debug, Clone)]
pub struct DashboardLink {
    pub port: u16,
    pub token: String,
}

impl DashboardLink {
    pub fn home(&self) -> String {
        format!("http://127.0.0.1:{}/?t={}", self.port, self.token)
    }
    pub fn decide(&self, detection_id: i64, action: Action) -> String {
        format!(
            "http://127.0.0.1:{}/entscheiden?t={}&id={}&aktion={}",
            self.port,
            self.token,
            detection_id,
            action.as_str()
        )
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub title: String,
    pub body: String,
    pub detections: Vec<Detection>,
    pub critical: bool,
}

impl Message {
    pub fn for_detections(detections: Vec<Detection>) -> Self {
        let critical = detections.iter().any(|d| d.severity >= Severity::Hoch);
        let (title, body) = if detections.len() == 1 {
            let d = &detections[0];
            (
                tf!("K9: Bedrohung erkannt ({})", "K9: threat detected ({})", d.severity.label()),
                tf!("{}\n{}\nBitte entscheiden: Quarantäne, Löschen/Deaktivieren oder Freigabe.", "{}\n{}\nPlease decide: quarantine, delete/disable or allow.", d.threat_name, d.path),
            )
        } else {
            let mut body = tf!("{} neue Erkennungen warten auf Ihre Entscheidung:\n", "{} new findings are waiting for your decision:\n", detections.len());
            for d in detections.iter().take(10) {
                body.push_str(&format!("• {} – {}\n", d.threat_name, d.path));
            }
            if detections.len() > 10 {
                body.push_str(&tf!("… und {} weitere\n", "… and {} more\n", detections.len() - 10));
            }
            (tf!("K9: {} Bedrohungen erkannt", "K9: {} threats detected", detections.len()), body)
        };
        Self { title, body, detections, critical }
    }

    pub fn test(channel: Channel) -> Self {
        Self {
            title: t!("K9: Testmeldung", "K9: test alert").into(),
            body: tf!("Dies ist eine Testmeldung über den Kanal „{}“. Alles funktioniert.", "This is a test alert via the channel “{}”. Everything works.", channel.label()),
            detections: Vec::new(),
            critical: false,
        }
    }

    /// Text for external channels: no dashboard token, no local links.
    fn external_text(&self) -> String {
        let mut text = self.body.clone();
        if !self.detections.is_empty() {
            text.push_str(t!("\n\nEntscheiden Sie am PC im Dashboard (Befehl: k9 dashboard).", "\n\nDecide at the PC in the dashboard (command: k9 dashboard)."));
        }
        text
    }
}

pub trait Notifier {
    fn channel(&self) -> Channel;
    fn send(&self, msg: &Message) -> Result<()>;
}

pub fn notifier_for(channel: Channel, cfg: &Config, link: Option<DashboardLink>) -> Box<dyn Notifier> {
    match channel {
        Channel::Fenster => Box::new(WindowNotifier),
        Channel::Popup => Box::new(toast::ToastNotifier { link }),
        Channel::Dashboard => Box::new(DashboardNotifier),
        Channel::Email => Box::new(EmailNotifier { cfg: cfg.email.clone() }),
        Channel::Handy => Box::new(NtfyNotifier { cfg: cfg.handy.clone() }),
    }
}

/// Own notification window. Real detections are queued by [`dispatch`] and
/// shown by the agent; `send` itself only shows the harmless sample window
/// (test message) and blocks until it is closed.
pub struct WindowNotifier;

impl Notifier for WindowNotifier {
    fn channel(&self) -> Channel {
        Channel::Fenster
    }
    fn send(&self, msg: &Message) -> Result<()> {
        if !msg.detections.is_empty() {
            bail!("Meldefenster für Funde werden vom Agent angezeigt");
        }
        crate::window::show(&crate::window::WindowContent::sample()).map(|_| ())
    }
}

/// Hint when Windows popups cannot work, pointing to the Meldefenster.
pub fn popup_hint(cfg: &Config) -> Option<String> {
    if !cfg.meldungen.kanaele.contains(&Channel::Popup) {
        return None;
    }
    let reason = popup_blocked_reason()?;
    Some(if cfg.meldungen.kanaele.contains(&Channel::Fenster) {
        tf!("Windows-Popups werden nicht angezeigt ({reason}); das Meldefenster ist aktiv und übernimmt", "Windows pop-ups are not shown ({reason}); the alert window is active and takes over")
    } else {
        tf!(
            "Windows-Popups werden nicht angezeigt ({reason}). Alternative: Kanal \"fenster\" (Meldefenster) in config.toml unter [meldungen] kanaele eintragen", "Windows pop-ups are not shown ({reason}). Alternative: enter the channel \"fenster\" (alert window) in config.toml under [meldungen] kanaele"
        )
    })
}

/// The dashboard shows pending detections itself; nothing to push.
pub struct DashboardNotifier;

impl Notifier for DashboardNotifier {
    fn channel(&self) -> Channel {
        Channel::Dashboard
    }
    fn send(&self, _msg: &Message) -> Result<()> {
        Ok(())
    }
}

// ------------------------------------------------------------------ e-mail

pub struct EmailNotifier {
    cfg: EmailConfig,
}

impl Notifier for EmailNotifier {
    fn channel(&self) -> Channel {
        Channel::Email
    }
    fn send(&self, msg: &Message) -> Result<()> {
        use lettre::message::header::ContentType;
        use lettre::transport::smtp::authentication::Credentials;
        use lettre::{SmtpTransport, Transport};

        let c = &self.cfg;
        if c.smtp_server.is_empty() || c.absender.is_empty() || c.empfaenger.is_empty() {
            bail!("E-Mail ist nicht konfiguriert ([email] smtp_server, absender, empfaenger in config.toml)");
        }
        let mut builder = lettre::Message::builder()
            .from(c.absender.parse().context("Ungültiger Absender")?)
            .subject(&msg.title)
            .header(ContentType::TEXT_PLAIN);
        for to in &c.empfaenger {
            builder = builder.to(to.parse().with_context(|| format!("Ungültiger Empfänger {to}"))?);
        }
        let mail = builder.body(msg.external_text())?;
        let transport = match c.verschluesselung.to_lowercase().as_str() {
            "starttls" => SmtpTransport::starttls_relay(&c.smtp_server)?,
            "tls" | "" => SmtpTransport::relay(&c.smtp_server)?,
            other => bail!("Unbekannte Verschlüsselung '{other}' (tls oder starttls)"),
        };
        let mut transport = transport.port(c.smtp_port).timeout(Some(Duration::from_secs(20)));
        if !c.benutzer.is_empty() {
            let pass = secrets::get(secrets::SMTP_PASSWORD)?
                .context("SMTP-Passwort fehlt – bitte mit 'k9 geheimnis smtp-passwort' hinterlegen")?;
            transport = transport.credentials(Credentials::new(c.benutzer.clone(), pass));
        }
        transport.build().send(&mail).context("E-Mail-Versand fehlgeschlagen")?;
        Ok(())
    }
}

// ------------------------------------------------------------- phone (ntfy)

pub struct NtfyNotifier {
    cfg: HandyConfig,
}

impl Notifier for NtfyNotifier {
    fn channel(&self) -> Channel {
        Channel::Handy
    }
    fn send(&self, msg: &Message) -> Result<()> {
        let c = &self.cfg;
        if c.thema.trim().is_empty() {
            bail!("Handy-Meldungen sind nicht konfiguriert ([handy] thema in config.toml)");
        }
        let server = c.server.trim_end_matches('/');
        if !server.starts_with("https://") && !server.starts_with("http://127.0.0.1") && !server.starts_with("http://localhost") {
            bail!("ntfy-Server muss https:// verwenden");
        }
        // JSON publishing keeps umlauts intact (HTTP headers would not).
        let body = serde_json::json!({
            "topic": c.thema.trim(),
            "title": msg.title,
            "message": msg.external_text(),
            "priority": if msg.critical { 5 } else { c.prioritaet.clamp(1, 5) },
            "tags": [if msg.detections.is_empty() { "white_check_mark" } else { "warning" }],
        });
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15)).build()?;
        let mut req = client
            .post(server)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string());
        if let Some(token) = secrets::get(secrets::NTFY_TOKEN)? {
            req = req.bearer_auth(token);
        }
        let resp = req.send().context("ntfy-Server nicht erreichbar")?;
        if !resp.status().is_success() {
            bail!("ntfy-Server antwortet mit {}", resp.status());
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ dispatch

#[derive(Debug, Default)]
pub struct DispatchReport {
    pub sent: Vec<Channel>,
    pub failed: Vec<(Channel, String)>,
    pub queued: usize,
}

fn send_on(
    channels: &[Channel],
    cfg: &Config,
    store: &Store,
    link: &Option<DashboardLink>,
    msg: &Message,
    report: &mut DispatchReport,
) {
    for ch in channels {
        let res = if *ch == Channel::Fenster {
            // The agent shows queued windows one at a time (never while gaming).
            let now = crate::now_string();
            msg.detections.iter().try_for_each(|d| store.enqueue_window(d.id, &now, false))
        } else {
            notifier_for(*ch, cfg, link.clone()).send(msg)
        };
        match res {
            Ok(()) => report.sent.push(*ch),
            Err(e) => {
                tracing::warn!("Meldung über {} fehlgeschlagen: {e:#}", ch.label());
                report.failed.push((*ch, format!("{e:#}")));
            }
        }
    }
}

/// Delivers notifications for new detections, or queues them while gaming.
pub fn dispatch(
    cfg: &Config,
    store: &Store,
    detections: Vec<Detection>,
    gaming: &GamingState,
    link: Option<DashboardLink>,
) -> Result<DispatchReport> {
    let mut report = DispatchReport::default();
    if detections.is_empty() {
        return Ok(report);
    }
    let msg = Message::for_detections(detections);
    if gaming.active {
        for d in &msg.detections {
            store.enqueue_notification(d.id)?;
        }
        report.queued = msg.detections.len();
        if msg.critical && cfg.gaming.kritische_sofort_extern {
            let external: Vec<Channel> = cfg.meldungen.kanaele.iter().copied().filter(|c| c.is_external()).collect();
            send_on(&external, cfg, store, &link, &msg, &mut report);
        }
        return Ok(report);
    }
    send_on(&cfg.meldungen.kanaele, cfg, store, &link, &msg, &mut report);
    Ok(report)
}

/// Sends everything that was queued during a gaming session.
pub fn flush_queue(cfg: &Config, store: &Store, link: Option<DashboardLink>) -> Result<DispatchReport> {
    let pending = store.take_queued()?;
    dispatch(cfg, store, pending, &GamingState::default(), link)
}

// -------------------------------------------------------------------- toast

pub use toast::blocked_reason as popup_blocked_reason;

mod toast {
    use anyhow::Result;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegGetValueW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE,
        REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_DWORD,
    };
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    use super::{DashboardLink, Message, Notifier};
    use crate::config::Channel;
    use crate::model::Action;

    const AUMID: &str = "K9.Agent";

    fn read_dword(subkey: &str, value: &str) -> Option<u32> {
        let k: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let v: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut data = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        // SAFETY: NUL-terminated strings, buffer size matches.
        let err = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                PCWSTR(k.as_ptr()),
                PCWSTR(v.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut data as *mut u32 as *mut _),
                Some(&mut size),
            )
        };
        err.is_ok().then_some(data)
    }

    /// Windows silently drops toasts when notifications are switched off.
    /// Returns a German explanation in that case.
    pub fn blocked_reason() -> Option<&'static str> {
        if read_dword("Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications", "ToastEnabled") == Some(0) {
            return Some(t!("Windows-Benachrichtigungen sind ausgeschaltet (Einstellungen → System → Benachrichtigungen)", "Windows notifications are switched off (Settings → System → Notifications)"));
        }
        let app_key = format!("Software\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\{AUMID}");
        if read_dword(&app_key, "Enabled") == Some(0) {
            return Some(t!("Benachrichtigungen für „K9“ sind in Windows ausgeschaltet (Einstellungen → System → Benachrichtigungen)", "notifications for “K9” are switched off in Windows (Settings → System → Notifications)"));
        }
        None
    }
    /// Fallback: Windows PowerShell's AUMID (always registered).
    const FALLBACK_AUMID: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";

    pub struct ToastNotifier {
        pub link: Option<DashboardLink>,
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
    }

    /// Registers a display name for our AUMID under HKCU (no admin needed,
    /// no autostart, only affects how the toast sender is shown).
    fn register_aumid() -> bool {
        let key_path: Vec<u16> = format!("Software\\Classes\\AppUserModelId\\{AUMID}\0").encode_utf16().collect();
        let name: Vec<u16> = "DisplayName\0".encode_utf16().collect();
        let value: Vec<u16> = "K9\0".encode_utf16().collect();
        // SAFETY: NUL-terminated buffers; key closed below.
        unsafe {
            let mut key = HKEY::default();
            if RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(key_path.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
            .is_err()
            {
                return false;
            }
            let bytes = std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
            let ok = RegSetValueExW(key, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes)).is_ok();
            let _ = RegCloseKey(key);
            ok
        }
    }

    impl ToastNotifier {
        fn build_xml(&self, msg: &Message) -> String {
            let mut lines = msg.body.lines();
            let first = lines.next().unwrap_or_default();
            let rest: Vec<&str> = lines.collect();
            let mut xml = String::new();
            let launch = self.link.as_ref().map(|l| l.home()).unwrap_or_default();
            if launch.is_empty() {
                xml.push_str("<toast>");
            } else {
                xml.push_str(&format!(r#"<toast activationType="protocol" launch="{}""#, xml_escape(&launch)));
                if !msg.detections.is_empty() {
                    // Keeps the toast visible until the user reacts.
                    xml.push_str(r#" scenario="reminder""#);
                }
                xml.push('>');
            }
            xml.push_str(r#"<visual><binding template="ToastGeneric">"#);
            xml.push_str(&format!("<text>{}</text>", xml_escape(&msg.title)));
            xml.push_str(&format!("<text>{}</text>", xml_escape(first)));
            if !rest.is_empty() {
                xml.push_str(&format!("<text>{}</text>", xml_escape(&rest.join("\n"))));
            }
            xml.push_str("</binding></visual>");
            if let Some(link) = &self.link {
                xml.push_str("<actions>");
                if msg.detections.len() == 1 {
                    let id = msg.detections[0].id;
                    for a in Action::ALL {
                        let label = if a == Action::Loeschen { t!("Löschen", "Delete") } else { a.label() };
                        xml.push_str(&format!(
                            r#"<action content="{}" activationType="protocol" arguments="{}"/>"#,
                            xml_escape(label),
                            xml_escape(&link.decide(id, a))
                        ));
                    }
                } else {
                    xml.push_str(&format!(
                        r#"<action content="{}" activationType="protocol" arguments="{}"/>"#,
                        t!("Dashboard öffnen", "Open dashboard"),
                        xml_escape(&link.home())
                    ));
                }
                xml.push_str("</actions>");
            }
            xml.push_str("</toast>");
            xml
        }
    }

    impl Notifier for ToastNotifier {
        fn channel(&self) -> Channel {
            Channel::Popup
        }

        fn send(&self, msg: &Message) -> Result<()> {
            if let Some(reason) = blocked_reason() {
                anyhow::bail!("{reason} – das Popup würde nicht angezeigt");
            }
            let doc = XmlDocument::new()?;
            doc.LoadXml(&HSTRING::from(self.build_xml(msg)))?;
            let toast = ToastNotification::CreateToastNotification(&doc)?;
            let aumid = if register_aumid() { AUMID } else { FALLBACK_AUMID };
            let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))?;
            notifier.Show(&toast)?;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn toast_xml_is_well_formed() {
            let n = ToastNotifier { link: Some(DashboardLink { port: 1, token: "abc".into() }) };
            let mut msg = Message::test(Channel::Popup);
            msg.title = "<&\">".into();
            let xml = n.build_xml(&msg);
            let doc = XmlDocument::new().unwrap();
            doc.LoadXml(&HSTRING::from(xml)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DetectionStatus, Finding};
    use crate::store::Upsert;

    fn pending(store: &Store, sev: Severity) -> Detection {
        let f = Finding {
            path: "C:\\x".into(),
            sha256: "cd".repeat(32),
            size: 1,
            rule_id: "R".into(),
            threat_name: "T".into(),
            category: "Test".into(),
            severity: sev,
            engine: "muster".into(),
            kind: crate::model::Kind::Datei,
            details: None,
        };
        match store.upsert_pending(&f).unwrap() {
            Upsert::New(d) => d,
            Upsert::AlreadyPending(d) => d,
        }
    }

    #[test]
    fn gaming_queues_and_flush_delivers() {
        let store = Store::open_in_memory().unwrap();
        let mut cfg = Config::default();
        cfg.meldungen.kanaele = vec![Channel::Dashboard];
        let d = pending(&store, Severity::Niedrig);
        let gaming = GamingState { active: true, reason: Some("Test".into()) };
        let r = dispatch(&cfg, &store, vec![d.clone()], &gaming, None).unwrap();
        assert_eq!(r.queued, 1);
        assert!(r.sent.is_empty());
        let r2 = flush_queue(&cfg, &store, None).unwrap();
        assert_eq!(r2.sent, vec![Channel::Dashboard]);
        assert_eq!(store.queued_count().unwrap(), 0);
        // Decided detections are not delivered after the game.
        store.enqueue_notification(d.id).unwrap();
        store.mark_detection(d.id, DetectionStatus::Entschieden, Some(Action::Freigabe)).unwrap();
        assert!(flush_queue(&cfg, &store, None).unwrap().sent.is_empty());
    }

    #[test]
    fn window_channel_is_deferred_while_gaming() {
        let store = Store::open_in_memory().unwrap();
        let mut cfg = Config::default();
        cfg.meldungen.kanaele = vec![Channel::Fenster];
        let d = pending(&store, Severity::Kritisch);
        let gaming = GamingState { active: true, reason: Some("Test".into()) };
        // Critical + gaming: the window is NOT queued (it is not an external channel).
        let r = dispatch(&cfg, &store, vec![d.clone()], &gaming, None).unwrap();
        assert_eq!(r.queued, 1);
        assert_eq!(store.window_queue_count().unwrap(), 0);
        // After the game the window is queued for the agent.
        let r2 = flush_queue(&cfg, &store, None).unwrap();
        assert_eq!(r2.sent, vec![Channel::Fenster]);
        let (next, more) = store.next_window(&crate::now_string()).unwrap().unwrap();
        assert_eq!((next.id, more), (d.id, 0));
    }

    #[test]
    fn unconfigured_external_channels_fail_cleanly() {
        let cfg = Config::default();
        assert!(notifier_for(Channel::Email, &cfg, None).send(&Message::test(Channel::Email)).is_err());
        assert!(notifier_for(Channel::Handy, &cfg, None).send(&Message::test(Channel::Handy)).is_err());
    }
}
