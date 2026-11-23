//! Local browser dashboard (127.0.0.1 only).
//!
//! Security: every request needs the random access token; the Host header
//! must be 127.0.0.1/localhost (DNS-rebinding protection); state-changing
//! requests are POST only and their Origin (if sent) must be the dashboard
//! itself. Strict CSP, no external resources, no referrer.

use std::fmt::Write as _;
use std::sync::Arc;

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use k9_core::{t, tf, tw};
use k9_core::config::Channel;
use k9_core::app::Check;
use k9_core::model::{Action, Detection, Kind, Severity};
use k9_core::sources::SourceId;
use k9_core::notify::{self, Message};
use k9_core::pipeline;

use crate::scheduler;
use crate::Shared;

pub fn router(shared: Arc<Shared>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/entscheiden", get(confirm))
        .route("/aktion", post(decide))
        .route("/aktion-mehrere", post(decide_many))
        .route("/widerrufen", post(revoke))
        .route("/wiederherstellen", post(restore))
        .route("/scan", post(scan_now))
        .route("/scan-voll", post(scan_full))
        .route("/scan-abbrechen", post(scan_cancel))
        .route("/test", post(test_message))
        .route("/quellen", post(update_sources))
        .route("/sicherheitscheck", post(security_check_now))
        .route("/sprache", post(set_language))
        .route("/autostart", post(reenable_autostart))
        .route("/beenden", post(stop_agent))
        .route("/programm", post(program_action))
        .route("/api/status", get(api_status))
        .route("/api/scan", get(api_scan))
        .route("/favicon.ico", get(favicon_ico))
        .route("/favicon.svg", get(favicon_svg))
        .with_state(shared)
}

// --------------------------------------------------------------------- guard

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn guard(s: &Shared, headers: &HeaderMap, token: &str, is_post: bool) -> Result<(), (StatusCode, &'static str)> {
    let port = s.port();
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    if !allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
        return Err((StatusCode::FORBIDDEN, t!("Ungültiger Host", "Invalid host")));
    }
    if is_post {
        // Browsers mark cross-site requests; only our own pages may post.
        if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
            if !matches!(site, "same-origin" | "none") {
                return Err((StatusCode::FORBIDDEN, t!("Ungültige Herkunft", "Invalid origin")));
            }
        }
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|o| o.to_str().ok()) {
            if !allowed_hosts.iter().any(|h| origin.eq_ignore_ascii_case(&format!("http://{h}"))) {
                return Err((StatusCode::FORBIDDEN, t!("Ungültige Herkunft", "Invalid origin")));
            }
        }
    }
    if !constant_time_eq(token.as_bytes(), s.token.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, t!("Zugriff verweigert – bitte den Link aus 'k9 dashboard' verwenden", "Access denied – please use the link from 'k9 dashboard'")));
    }
    Ok(())
}

fn with_security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    // "same-origin": no referrer (with token) leaves the dashboard, but the
    // browser still sends a real Origin for our own forms. With "no-referrer"
    // browsers send `Origin: null`, which the POST check rightly rejects.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

/// K9 icon for the browser tab (static, no data: served without the token).
const FAVICON_ICO: &[u8] = include_bytes!("../../../pictures/favicon.ico");
const FAVICON_SVG: &str = include_str!("../../../pictures/favicon.svg");
/// Header: the program icon with the "K9" lettering (legible from about 40 px).
const HEADER_SVG: &str = include_str!("../../../pictures/k9-pfote.svg");

async fn favicon_ico() -> Response {
    with_security_headers(([(header::CONTENT_TYPE, "image/x-icon"), (header::CACHE_CONTROL, "max-age=86400")], FAVICON_ICO).into_response())
}

async fn favicon_svg() -> Response {
    with_security_headers(([(header::CONTENT_TYPE, "image/svg+xml"), (header::CACHE_CONTROL, "max-age=86400")], FAVICON_SVG).into_response())
}

fn html_page(title: &str, body: &str) -> Response {
    // Only our own inline script (random nonce per page) may run.
    let nonce = hex_nonce();
    let html = format!(
        "<!doctype html><html lang=\"{lang}\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\"><link rel=\"icon\" href=\"/favicon.ico\" sizes=\"16x16 32x32 48x48\"><style>{CSS}</style></head><body><main>{body}</main><div id=\"toast\" class=\"msg toast\" hidden></div>\
         <script nonce=\"{nonce}\">{SCRIPT}</script></body></html>",
        esc(title),
        lang = t!("de", "en")
    );
    let mut resp = with_security_headers(([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response());
    if let Ok(v) = HeaderValue::from_str(&format!(
        "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    )) {
        resp.headers_mut().insert(header::CONTENT_SECURITY_POLICY, v);
    }
    resp
}

fn hex_nonce() -> String {
    k9_core::random_bytes(16).iter().map(|b| format!("{b:02x}")).collect()
}

fn redirect_home(s: &Shared, msg: &str) -> Response {
    redirect_to(s, msg, None)
}

/// Back to the dashboard at a section/row (without JavaScript the browser
/// would otherwise jump to the top); the message is shown in that section.
fn redirect_to(s: &Shared, msg: &str, at: Option<(&str, String)>) -> Response {
    let loc = match at {
        Some((section, anchor)) => format!("/?t={}&meldung={}&bereich={section}#{anchor}", s.token, url_encode(msg)),
        None => format!("/?t={}&meldung={}", s.token, url_encode(msg)),
    };
    with_security_headers((StatusCode::SEE_OTHER, [(header::LOCATION, loc)]).into_response())
}

/// Hint in the section "Sicherheits-Check" while a program action waits for the "Ja" in the
/// confirmation window (`asking`) or is being worked on. Every name in it is exactly what the
/// dashboard shows.
fn program_hint(asking: bool) -> &'static str {
    if asking {
        t!(
            "Bitte im Bestätigungsfenster „Ja“ wählen („Nein“ bricht ab). Dieser Hinweis verschwindet von selbst.",
            "Please choose “Yes” in the confirmation window (“No” cancels; on a German Windows the buttons read “Ja” and “Nein”). This hint disappears by itself."
        )
    } else {
        t!(
            "K9 arbeitet die gewählten Programme nacheinander ab. In der Liste darunter steht hinter jedem Programm „… läuft …“ oder „… wartet …“. \
             Braucht ein Programm Administratorrechte, fragt Windows in einem eigenen Fenster danach – dort „Ja“ wählen. \
             Das Ergebnis steht danach hier im Bereich „Sicherheits-Check“ unter „Letzte Aktionen“, direkt unter der Liste der Programme. \
             Dieser Hinweis verschwindet von selbst, sobald alles erledigt ist.",
            "K9 works through the chosen programs one after the other. In the list below, each program shows “… running …” or “… waiting …”. \
             If a program needs administrator rights, Windows asks in a window of its own – choose “Yes” there. \
             The result then appears here in the section “Security check” under “Last actions”, directly below the list of programs. \
             This hint disappears by itself as soon as everything is done."
        )
    }
}

/// Sections whose buttons work without reloading the page.
const LIVE_SECTIONS: [&str; 4] = ["offen", "entscheidungen", "quarantaene", "autostarts"];

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> anyhow::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(|e| anyhow::anyhow!(tf!("Interner Fehler: {e}", "Internal error: {e}")))?
}

fn error_page(e: anyhow::Error) -> Response {
    html_page(t!("Fehler", "Error"), &format!("<h1>{}</h1><p class=\"err\">{}</p>", t!("Fehler", "Error"), esc(&format!("{e:#}"))))
}

// ------------------------------------------------------------------- handlers

#[derive(Deserialize)]
struct TokenQuery {
    t: String,
    meldung: Option<String>,
    bereich: Option<String>,
}

async fn index(State(s): State<Arc<Shared>>, headers: HeaderMap, Query(q): Query<TokenQuery>) -> Response {
    if let Err(r) = guard(&s, &headers, &q.t, false) {
        return r.into_response();
    }
    let s2 = s.clone();
    match blocking(move || render_index(&s2, q.meldung.as_deref(), q.bereich.as_deref())).await {
        Ok(body) => html_page("K9 – Dashboard", &body),
        Err(e) => error_page(e),
    }
}

/// The sample of affected files a ransomware suspicion carries ("dateien"), as a list.
fn affected_files_html(v: &serde_json::Value) -> String {
    let files: Vec<&str> = v["dateien"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect()).unwrap_or_default();
    if files.is_empty() {
        return String::new();
    }
    format!(
        "<small>{}</small><ul>{}</ul>",
        t!("Betroffene Dateien (Beispiele):", "Affected files (examples):"),
        files.iter().map(|f| format!("<li><small><code>{}</code></small></li>", esc(f))).collect::<String>()
    )
}

/// 1234567 -> "1.234.567"
fn thousands(v: u64) -> String {
    let digits = v.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(c);
    }
    out
}

/// The text of the line "Scan läuft" while a scan runs: which scan, how many files it has
/// reached, where it is.
fn scan_line(kind: &str, seen: u64, dir: &str, cancelling: bool) -> String {
    tf!(
        "ja – {kind}: {} Dateien erreicht{}{}",
        "yes – {kind}: {} files reached{}{}",
        thousands(seen),
        if dir.is_empty() { String::new() } else { tf!(", gerade in {dir}", ", currently in {dir}") },
        if cancelling { t!(" – wird abgebrochen …", " – being cancelled …") } else { "" }
    )
}

/// `None` when no scan runs.
fn scan_text(s: &Shared) -> Option<String> {
    use std::sync::atomic::Ordering::Relaxed;
    s.scan_running.load(Relaxed).then(|| {
        scan_line(&s.scan_kind.lock().unwrap(), s.scan_seen.load(Relaxed), &s.scan_current.lock().unwrap(), s.scan_cancel.load(Relaxed))
    })
}

/// Line "Scan läuft" of the status box. While a scan runs the page script refreshes just this
/// line every two seconds (`/api/scan`) – a scan of all drives takes hours, and reloading the whole
/// page all the time would throw away what the user is doing in the dashboard.
fn scan_state(s: &Shared) -> String {
    match scan_text(s) {
        Some(text) => format!("<span id=\"scanstand\">{}</span>", esc(&text)),
        None => t!("nein", "no").into(),
    }
}

/// The scan buttons of the status box with their explanation; while a scan runs only "Scan abbrechen".
fn scan_buttons(s: &Shared) -> String {
    let t = hidden_token(s);
    if s.scan_running.load(std::sync::atomic::Ordering::Relaxed) {
        return tf!(
            "<form method=\"post\" action=\"/scan-abbrechen\">{t}<button>Scan abbrechen</button></form>\
             <p><small>Der Scan endet nach der Datei, die gerade geprüft wird. Was bis dahin gefunden wurde, bleibt als Meldung erhalten.</small></p>",
            "<form method=\"post\" action=\"/scan-abbrechen\">{t}<button>Cancel scan</button></form>\
             <p><small>The scan ends after the file that is being checked right now. What was found until then stays as a finding.</small></p>"
        );
    }
    let inline = "style=\"display:inline-block;margin:0 .5em .5em 0\"";
    tf!(
        "<form method=\"post\" action=\"/scan\" {inline}>{t}<button>Schnellscan (Standardordner)</button></form>\
         <form method=\"post\" action=\"/scan-voll\" {inline}>{t}<input type=\"hidden\" name=\"art\" value=\"schonend\"><button>Vollständiger Scan (schonend)</button></form>\
         <form method=\"post\" action=\"/scan-voll\" {inline}>{t}<input type=\"hidden\" name=\"art\" value=\"schnell\"><button>Vollständiger Scan (schnell)</button></form>\
         <p><small><b>Schnellscan:</b> die Standardordner (Downloads, Desktop, Dokumente, Temp), dazu Programme, Adressen und Autostarts – der kürzeste Lauf.<br>\
         <b>Vollständig (schonend):</b> alle eingebauten Laufwerke und eingesteckten USB-Datenträger mit {} Prüfsträngen – du kannst dabei weiterarbeiten, es dauert am längsten.<br>\
         <b>Vollständig (schnell):</b> dasselbe mit {} Prüfsträngen – für die Nacht oder wenn du nicht am PC sitzt; der PC reagiert in dieser Zeit träger.<br>\
         Beide vollständigen Scans pausieren, solange ein Spiel läuft. Jeder Scan lässt sich mit „Scan abbrechen“ beenden. K9 meldet nur – nichts wird automatisch verschoben oder gelöscht.</small></p>",
        "<form method=\"post\" action=\"/scan\" {inline}>{t}<button>Quick scan (standard folders)</button></form>\
         <form method=\"post\" action=\"/scan-voll\" {inline}>{t}<input type=\"hidden\" name=\"art\" value=\"schonend\"><button>Full scan (gentle)</button></form>\
         <form method=\"post\" action=\"/scan-voll\" {inline}>{t}<input type=\"hidden\" name=\"art\" value=\"schnell\"><button>Full scan (fast)</button></form>\
         <p><small><b>Quick scan:</b> the standard folders (Downloads, Desktop, Documents, Temp), plus programs, addresses and autostarts – the shortest run.<br>\
         <b>Full (gentle):</b> all built-in drives and plugged-in USB drives with {} worker threads – you can keep working, it takes the longest.<br>\
         <b>Full (fast):</b> the same with {} worker threads – for the night or when you are away from the PC; the PC reacts more slowly during that time.<br>\
         Both full scans pause while a game is running. Every scan can be ended with “Cancel scan”. K9 only reports – nothing is moved or deleted automatically.</small></p>",
        s.app.config.scan.max_threads.clamp(1, 8),
        scheduler::fast_threads()
    )
}

fn hidden_token(s: &Shared) -> String {
    format!("<input type=\"hidden\" name=\"t\" value=\"{}\">", esc(&s.token))
}

/// Date above time, neither part wraps – for every date/time in tables and details.
/// Also turns the firewall log's UTC times (RFC 3339) into local time.
/// "2026-11-18 06:51:29" -> "18.11.2026 06:51" (one line, for running text).
fn short_time(ts: &str) -> String {
    chrono::NaiveDateTime::parse_from_str(ts.trim(), "%Y-%m-%d %H:%M:%S").map(|t| t.format("%d.%m.%Y %H:%M").to_string()).unwrap_or_else(|_| esc(ts))
}

fn dt(ts: &str) -> String {
    let ts = ts.trim();
    let local = chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S").to_string());
    let s = local.as_deref().unwrap_or(ts);
    match s.split_once(' ') {
        Some((d, t)) if d.len() == 10 && d.as_bytes().get(4) == Some(&b'-') => {
            format!("<span class=\"dt\"><span>{}</span><span>{}</span></span>", esc(d), esc(t.trim()))
        }
        _ => format!("<span class=\"nw\">{}</span>", esc(s)),
    }
}

/// Last column of an open finding: tick box (with the actions this finding allows, for the
/// selection bar) and "gleiche" (tick all findings of the same kind and content/program).
fn select_cell(d: &Detection) -> String {
    let actions: Vec<(String, String)> = pipeline::allowed_actions(d)
        .into_iter()
        .map(|a| (a.as_str().to_string(), pipeline::action_label(d, a)))
        .collect();
    // Only in debug builds (screenshots of the isolated test instance): preselected findings.
    let pre = cfg!(debug_assertions) && std::env::var("K9_TEST_VORAUSWAHL").is_ok_and(|v| v.split(',').any(|x| x.trim() == d.id.to_string()));
    format!(
        "<label class=\"nw\"><input type=\"checkbox\" class=\"wahl\" name=\"id\" value=\"{id}\" form=\"sammel\" data-aktionen=\"{}\" data-gruppe=\"{g}\"{} \
         aria-label=\"{aria} {id}\"></label><br><button type=\"button\" class=\"gleiche\" data-gruppe=\"{g}\" \
         title=\"{title}\">{same}</button>",
        esc(&serde_json::to_string(&actions).unwrap_or_default()),
        if pre { " checked" } else { "" },
        id = d.id,
        g = esc(&pipeline::same_group(d)),
        aria = t!("Meldung auswählen:", "Select finding"),
        title = t!(
            "Alle offenen Meldungen derselben Art mit derselben Datei bzw. demselben Programm auswählen",
            "Select all open findings of the same kind with the same file or the same program"
        ),
        same = t!("gleiche", "same")
    )
}

/// `application/x-www-form-urlencoded` with repeated keys (several "id").
fn form_pairs(body: &[u8]) -> Vec<(String, String)> {
    fn decode(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'+' => out.push(b' '),
                b'%' if i + 2 < b.len() => {
                    match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16) {
                        Ok(v) => {
                            out.push(v);
                            i += 2;
                        }
                        Err(_) => out.push(b'%'),
                    }
                }
                c => out.push(c),
            }
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

/// A button label: breaks only between words or after "/", never inside a word.
fn button_label(label: &str) -> String {
    esc(label).replace('/', "/<wbr>")
}

fn decision_buttons(s: &Shared, d: &Detection) -> String {
    let mut out = String::new();
    for a in &k9_core::pipeline::allowed_actions(d) {
        let class = match a {
            Action::Quarantaene | Action::Deaktivieren => "warn",
            Action::Loeschen | Action::Beenden => "danger",
            Action::Freigabe | Action::Gesehen | Action::Einmalig | Action::Regelfreigabe => "ok",
        };
        let label = k9_core::pipeline::action_label(d, *a);
        let _ = write!(
            out,
            "<form method=\"post\" action=\"/aktion\" class=\"inline\">{}<input type=\"hidden\" name=\"id\" value=\"{}\">\
             <input type=\"hidden\" name=\"aktion\" value=\"{}\"><button class=\"{class}\">{}</button></form>",
            hidden_token(s),
            d.id,
            a.as_str(),
            button_label(&label)
        );
    }
    out
}

/// Long path or command line: monospace block that wraps at any character;
/// very long texts are shortened with a "mehr anzeigen" toggle (no JavaScript).
fn long_code(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    const SHORT: usize = 240;
    if text.chars().count() <= SHORT {
        return format!("<code class=\"blk\">{}</code>", esc(text));
    }
    let head: String = text.chars().take(SHORT).collect();
    format!(
        "<details class=\"lang\"><summary><code class=\"blk\">{}…</code><span class=\"mehr\"></span></summary><code class=\"blk\">{}</code></details>",
        esc(&head),
        esc(text)
    )
}

/// Kind-specific details under the location column.
/// "Sicherheits-Check": traffic light of the basic protection (computed by the agent every
/// 6 hours, see k9_core::sicherheit) and the outdated programs.
fn security_check_html(b: &mut String, s: &Shared) {
    let app = &s.app;
    use k9_core::sicherheit::{Ampel, Bericht};
    let _ = tw!(b, "<section id=\"sicherheitscheck\"><h2>Sicherheits-Check</h2>", "<section id=\"sicherheitscheck\"><h2>Security check</h2>");
    let Some(r) = Bericht::load(&app.paths.data_dir) else {
        let _ = tw!(b, "<p class=\"muted\">Noch nicht geprüft – der Agent prüft wenige Minuten nach dem Start (nie während eines Spiels).</p></section>", "<p class=\"muted\">Not checked yet – the agent checks a few minutes after its start (never during a game).</p></section>");
        return;
    };
    let _ = tw!(b, "<table class=\"kompakt ampel\"><tr><th></th><th>Punkt</th><th>Zustand</th><th>Was tun?</th></tr>", "<table class=\"kompakt ampel\"><tr><th></th><th>Item</th><th>State</th><th>What to do?</th></tr>");
    for p in &r.punkte {
        let cls = match p.ampel {
            Ampel::Gruen => "a-gruen",
            Ampel::Gelb => "a-gelb",
            Ampel::Rot => "a-rot",
            Ampel::Grau => "a-grau",
        };
        let _ = write!(
            b,
            "<tr><td><span class=\"punkt {cls}\" title=\"{}\" aria-label=\"{}\"></span></td><td class=\"nw\">{}</td><td>{}</td><td><small>{}</small></td></tr>",
            p.ampel.label(),
            p.ampel.label(),
            esc(&p.name),
            esc(&p.text),
            esc(&p.tipp)
        );
    }
    let _ = write!(b, "</table>");
    if let Some(list) = r.updates.as_ref().filter(|l| !l.is_empty()) {
        let asking = PROGRAM_ASKING.load(std::sync::atomic::Ordering::SeqCst);
        let busy = program_jobs_active() || asking;
        if busy {
            // The script reloads the page every 3 seconds while this marker is there (keeps the
            // scroll position); it starts while the confirmation window is still open.
            let _ = write!(b, "<span data-neuladen hidden></span>");
            // The hint belongs to the state, not to the address of the page: it is gone by
            // itself as soon as nothing waits or runs any more. (Until 0.45.0 it was part of
            // the address and came back with every reload - also long after the work was done.)
            let _ = write!(b, "<p class=\"msg\">{}</p>", esc(program_hint(asking)));
        }
        // Once the user worked with the list it stays open (until the agent restarts).
        let busy = busy || PROGRAM_LIST_OPEN.load(std::sync::atomic::Ordering::Relaxed);
        let _ = tw!(
            b,
            "<details class=\"liste\"{}><summary>{} Programme mit neuerer Version anzeigen</summary><p><small>K9 aktualisiert nichts von selbst. Jede Aktion öffnet zuerst ein Bestätigungsfenster; nach „Ja“ \
             erledigt winget die Programme nacheinander im Hintergrund (Installationsprogramme können eigene Fenster zeigen oder nach Administratorrechten fragen). \
             Trend Micro und K9 werden nie deinstalliert.</small></p>\
             <form method=\"post\" action=\"/programm\">{}\
             <p class=\"knoepfe\"><button name=\"aktion\" value=\"aktualisieren-alle\">Alle aktualisieren</button> <button name=\"aktion\" value=\"deinstallieren-alle\" class=\"warn\">Alle deinstallieren</button> \
             · <button name=\"aktion\" value=\"aktualisieren\">Ausgewählte aktualisieren</button> <button name=\"aktion\" value=\"deinstallieren\" class=\"warn\">Ausgewählte deinstallieren</button></p>\
             <table class=\"kompakt\"><tr><th>Programm</th><th>Installiert</th><th>Neu</th><th>Befehl</th><th>Aktion</th><th>Auswahl</th></tr>", "<details class=\"liste\"{}><summary>Show {} programs with a newer version</summary><p><small>K9 updates nothing by itself. Every action first opens a confirmation window; after “Yes” \
             winget handles the programs one after the other in the background (setup programs may show their own windows or ask for administrator rights). \
             Trend Micro and K9 are never uninstalled.</small></p>\
             <form method=\"post\" action=\"/programm\">{}\
             <p class=\"knoepfe\"><button name=\"aktion\" value=\"aktualisieren-alle\">Update all</button> <button name=\"aktion\" value=\"deinstallieren-alle\" class=\"warn\">Uninstall all</button> \
             · <button name=\"aktion\" value=\"aktualisieren\">Update selected</button> <button name=\"aktion\" value=\"deinstallieren\" class=\"warn\">Uninstall selected</button></p>\
             <table class=\"kompakt\"><tr><th>Program</th><th>Installed</th><th>New</th><th>Command</th><th>Action</th><th>Select</th></tr>",
            if busy { " open" } else { "" },
            list.len(),
            hidden_token(s)
        );
        for u in list {
            let id = esc(&u.id);
            let state = match program_job_state(&u.id) {
                None if asking && program_asked(&u.id) => t!("<span class=\"laeuft\"><span class=\"kreis\"></span>wartet auf dein „Ja“ im Bestätigungsfenster …</span>", "<span class=\"laeuft\"><span class=\"kreis\"></span>waiting for your “Yes” in the confirmation window …</span>").to_string(),
                Some((a, true)) => tf!(
                    "<span class=\"laeuft\"><span class=\"kreis\"></span>{} läuft …</span>{}", "<span class=\"laeuft\"><span class=\"kreis\"></span>{} running …</span>{}",
                    a.label(),
                    if matches!(a, k9_core::sicherheit::ProgrammAktion::Aktualisieren | k9_core::sicherheit::ProgrammAktion::Deinstallieren) {
                        tf!(" <button name=\"einzeln\" value=\"abbrechen:{id}\" title=\"winget für dieses Programm beenden\">Abbrechen</button>", " <button name=\"einzeln\" value=\"abbrechen:{id}\" title=\"end winget for this program\">Cancel</button>")
                    } else {
                        String::new()
                    }
                ),
                Some((a, false)) => tf!("<span class=\"laeuft wartet\"><span class=\"kreis\"></span>{} wartet …</span>", "<span class=\"laeuft wartet\"><span class=\"kreis\"></span>{} waiting …</span>", a.label()),
                None => {
                    let remove = if k9_core::sicherheit::protected_program(u) {
                        t!(" <small class=\"muted\">(nicht über K9)</small>", " <small class=\"muted\">(not via K9)</small>").to_string()
                    } else {
                        tf!(" <button name=\"einzeln\" value=\"deinstallieren:{id}\" class=\"warn\">Deinstallieren</button>", " <button name=\"einzeln\" value=\"deinstallieren:{id}\" class=\"warn\">Uninstall</button>")
                    };
                    tf!("<button name=\"einzeln\" value=\"aktualisieren:{id}\">Aktualisieren</button>{remove}", "<button name=\"einzeln\" value=\"aktualisieren:{id}\">Update</button>{remove}")
                }
            };
            let _ = tw!(
                b,
                "<tr><td>{}{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td class=\"nw\">{state}</td>\
                 <td class=\"wahl\"><input type=\"checkbox\" name=\"id\" value=\"{id}\" aria-label=\"{} auswählen\"></td></tr>", "<tr><td>{}{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td class=\"nw\">{state}</td>\
                 <td class=\"wahl\"><input type=\"checkbox\" name=\"id\" value=\"{id}\" aria-label=\"select {}\"></td></tr>",
                esc(&u.name),
                if u.hinweis.is_empty() {
                    String::new()
                } else {
                    let since = if u.fehler_seit.is_empty() { String::new() } else { tf!("Seit {}: ", "Since {}: ", esc(&u.fehler_seit)) };
                    let link = if u.seite.starts_with("https://") {
                        tf!(
                            "<br><small>{since}Die Download-Adresse im winget-Katalog stimmt nicht. Selbst laden von der offiziellen Seite: \
                             <a href=\"{0}\" target=\"_blank\" rel=\"noopener noreferrer\">{0}</a> – oder in 1–2 Tagen erneut „Aktualisieren“ (meist ist der Katalog dann berichtigt).</small>", "<br><small>{since}The download address in the winget catalogue is wrong. Download it yourself from the official page: \
                             <a href=\"{0}\" target=\"_blank\" rel=\"noopener noreferrer\">{0}</a> – or try “Update” again in 1–2 days (the catalogue is usually corrected by then).</small>",
                            esc(&u.seite)
                        )
                    } else {
                        String::new()
                    };
                    let install = if program_job_state(&u.id).is_some() {
                        String::new()
                    } else {
                        match downloaded_installer(s, u) {
                            Some(k) if k.abweichend.is_some() => tf!(
                                "<br><button name=\"einzeln\" value=\"installieren:{id}\" class=\"warn\">Trotzdem installieren</button> <small class=\"err\">Achtung, Herstellername weicht ab:</small> \
                                 <small>geladene Datei {} ist gültig signiert von „{}“, die installierte Version von „{}“. Firmen ändern manchmal ihren Namen – nur installieren, wenn du das für dieselbe Firma hältst.</small>", "<br><button name=\"einzeln\" value=\"installieren:{id}\" class=\"warn\">Install anyway</button> <small class=\"err\">Attention, the publisher name differs:</small> \
                                 <small>the downloaded file {} is validly signed by “{}”, the installed version by “{}”. Companies sometimes change their name – only install if you believe this is the same company.</small>",
                                esc(&k.datei.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()),
                                esc(&k.signiert_von),
                                esc(k.abweichend.as_deref().unwrap_or(""))
                            ),
                            Some(k) => tf!(
                                "<br><button name=\"einzeln\" value=\"installieren:{id}\">Installieren</button>{} <small>geladene Datei {} – gültig signiert von {} (wie die installierte Version)</small>", "<br><button name=\"einzeln\" value=\"installieren:{id}\">Install</button>{} <small>downloaded file {} – validly signed by {} (like the installed version)</small>",
                                match k9_core::nachladen::silent_switches(&k.datei) {
                                    Some((kit, _)) => tf!(
                                        " <button name=\"einzeln\" value=\"still:{id}\" title=\"ohne Fenster, mit den Standardeinstellungen des Herstellers ({})\">Still installieren</button>", " <button name=\"einzeln\" value=\"still:{id}\" title=\"without a window, with the publisher\'s default settings ({})\">Install silently</button>",
                                        esc(kit)
                                    ),
                                    None => String::new(),
                                },
                                esc(&k.datei.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()),
                                esc(&k.signiert_von)
                            ),
                            None if !link.is_empty() => tf!(
                                "<br><button name=\"einzeln\" value=\"laden:{id}\">Suchen und Laden</button> <small class=\"muted\">K9 sucht das Installationsprogramm auf der offiziellen Seite und unter der Adresse aus dem winget-Katalog (64 Bit, keine portable Version) und lädt es nach „Downloads“ – es bleibt nur, \
                                 wenn es gültig signiert ist und vom selben Hersteller stammt wie die installierte Version. Danach erscheint hier „Installieren“ (auch wenn du die Datei selbst lädst).</small>", "<br><button name=\"einzeln\" value=\"laden:{id}\">Search and download</button> <small class=\"muted\">K9 looks for the setup program on the official page and at the address from the winget catalogue (64 bit, no portable version) and downloads it to “Downloads” – it only stays \
                                 if it is validly signed and comes from the same publisher as the installed version. After that “Install” appears here (also if you download the file yourself).</small>"
                            ),
                            None => String::new(),
                        }
                    };
                    format!("<br><small class=\"err\">{}</small>{link}{install}", esc(&k9_core::sprache::stored(&u.hinweis)))
                },
                esc(&u.installiert),
                esc(&u.verfuegbar),
                esc(&u.command()),
                esc(&u.name)
            );
        }
        let _ = write!(b, "</table></form></details>");
    }
    if !r.aktionen.is_empty() {
        let _ = tw!(b, "<p><small><b>Letzte Aktionen:</b><br>{}</small></p>", "<p><small><b>Last actions:</b><br>{}</small></p>", r.aktionen.iter().take(5).map(|a| esc(&k9_core::sprache::stored(a))).collect::<Vec<_>>().join("<br>"));
    }
    let _ = tw!(
        b,
        "<p><small>Stand: {}{}. K9 prüft alle 6 Stunden von selbst und ändert keine dieser Einstellungen. \
         Hast du gerade etwas umgestellt, zeigt „Jetzt neu prüfen“ sofort den neuen Stand.</small></p>\
         <form method=\"post\" action=\"/sicherheitscheck\">{}<button>Jetzt neu prüfen</button></form></section>", "<p><small>As of: {}{}. K9 checks every 6 hours by itself and changes none of these settings. \
         If you have just changed something, “Check again now” shows the new state at once.</small></p>\
         <form method=\"post\" action=\"/sicherheitscheck\">{}<button>Check again now</button></form></section>",
        short_time(&r.zeit),
        r.updates_zeit.as_deref().map(|t| tf!(" · Programme geprüft: {}", " · programs checked: {}", short_time(t))).unwrap_or_default(),
        hidden_token(s)
    );
}

/// Under the threat name: what the finding is about, in plain words ("Betrifft: …").
fn subject_note(d: &Detection) -> String {
    match k9_core::pipeline::subject(d) {
        Some(s) => tf!("<br><small class=\"betrifft\"><b>Betrifft:</b> {}</small>", "<br><small class=\"betrifft\"><b>Concerns:</b> {}</small>", esc(&s)),
        None => String::new(),
    }
}

/// Quiet finding (work folder): why it opened no Meldefenster.
fn quiet_note(d: &Detection) -> String {
    match k9_core::arbeitsordner::reason_of(d.details.as_ref()) {
        Some(why) => tf!("<div class=\"leise\"><small><b>Leise</b> (nur im Dashboard, kein Meldefenster): {}</small></div>", "<div class=\"leise\"><small><b>Quiet</b> (dashboard only, no alert window): {}</small></div>", esc(&why)),
        None => String::new(),
    }
}

/// File finding: which programs held the file open when it was found.
fn holder_note(d: &Detection) -> String {
    match d.details.as_ref().and_then(|v| v[k9_core::arbeitsordner::OFFEN_BEI].as_str()) {
        Some(who) => tf!("<div class=\"leise\"><small><b>Beim Fund geöffnet von:</b> {}</small></div>", "<div class=\"leise\"><small><b>Opened by when found:</b> {}</small></div>", esc(who)),
        None => String::new(),
    }
}

fn detail_html(d: &Detection) -> String {
    let v = d.details.clone().unwrap_or_default();
    let s = |k: &str| esc(v[k].as_str().unwrap_or(""));
    match d.kind {
        Kind::Datei => format!(
            "<small>SHA-256 {}</small>{}",
            esc(&d.sha256),
            if k9_core::pipeline::file_missing(d) { t!("<div><small><b>Datei nicht mehr vorhanden.</b></small></div>", "<div><small><b>File no longer exists.</b></small></div>") } else { "" }
        ),
        Kind::Software => {
            let mut out = String::from("<small>");
            for c in v["cves"].as_array().into_iter().flatten() {
                let _ = write!(
                    out,
                    "{} ({}{}){}{}<br>",
                    esc(c["cve"].as_str().unwrap_or("?")),
                    esc(c["schwere"].as_str().unwrap_or("?")),
                    if c["ransomware"].as_bool() == Some(true) { ", Ransomware" } else { "" },
                    c["behoben_ab"].as_str().map(|f| tf!(" – behoben ab {}", " – fixed from {}", esc(f))).unwrap_or_default(),
                    esc(c["epss_text"].as_str().unwrap_or(""))
                );
            }
            let _ = tw!(out, "Treffersicherheit: {} – {}<br><b>Lösung:</b> <code>{}</code></small>", "Confidence: {} – {}<br><b>Solution:</b> <code>{}</code></small>", s("konfidenz"), s("hinweis"), s("loesung"));
            out
        }
        Kind::Url | Kind::Hinweis | Kind::Einstellung => format!("<small>{}</small>", s("hinweis")),
        Kind::Erweiterung => {
            let list = |k: &str| v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            let mut out = String::from("<small>");
            let raw = |k: &str| v[k].as_str().unwrap_or("").to_string();
            for (label, val) in [(t!("Rechte", "Permissions"), list("rechte")), (t!("Webseiten", "Websites"), list("seiten")), (t!("Quelle", "Source"), raw("update_url")), ("Registry", raw("schluessel"))] {
                if !val.is_empty() {
                    let _ = write!(out, "{label}: {}<br>", esc(&val));
                }
            }
            let _ = write!(out, "{}</small>", s("hinweis"));
            out
        }
        Kind::Firewall => {
            let mut out = String::from("<small>");
            let tamper = d.rule_id == k9_core::firewall::TAMPER_RULE;
            let by = if tamper { t!("Geändert von", "Changed by") } else { t!("Angelegt von", "Created by") };
            let at = if tamper { t!("Geändert am", "Changed on") } else { t!("Angelegt am", "Created on") };
            for (label, key) in [
                (t!("Regel", "Rule"), "name"),
                (t!("Erlaubt", "Allows"), "protokoll"),
                ("Ports", "ports"),
                (t!("Von", "From"), "von"),
                (t!("Profile", "Profiles"), "profile"),
                (t!("Für", "For"), "programm"),
                (by, "ersteller"),
                (t!("Signiert von", "Signed by"), "ersteller_signatur"),
                (t!("Benutzer", "User"), "benutzer"),
                (at, "erstellt"),
                (t!("Vorfälle", "Incidents"), "vorfaelle"),
                (t!("Zuletzt", "Last"), "zuletzt"),
            ] {
                let val = match &v[key] {
                    serde_json::Value::String(t) => t.clone(),
                    serde_json::Value::Null => if key == "ersteller" { t!("unbekannt (nicht mehr im Firewall-Protokoll)", "unknown (no longer in the firewall log)").into() } else { String::new() },
                    other => other.to_string(),
                };
                if val.is_empty() {
                    continue;
                }
                if key == "erstellt" || key == "zuletzt" {
                    let _ = write!(out, "{label}: {}<br>", dt(&val));
                } else {
                    let _ = write!(out, "{label}: {}<br>", esc(&val));
                }
            }
            if let Some(n) = v["anzahl"].as_u64().filter(|n| *n > 1) {
                let _ = tw!(out, "Gleiche Regel {n}-mal vorhanden<br>", "Same rule exists {n} times<br>");
            }
            let _ = write!(out, "{}</small>", s("hinweis"));
            out
        }
        Kind::Treiber => {
            let parts: Vec<String> = k9_core::treiber::summary_parts(&v).iter().map(|p| esc(p)).collect();
            tf!("<small>{}<br><b>Empfehlung:</b> {}</small>", "<small>{}<br><b>Recommendation:</b> {}</small>", parts.join(" · "), s("hinweis"))
        }
        Kind::Autostart => tf!(
            "<small>Befehl:</small>{}<small>Programm:</small>{}", "<small>Command:</small>{}<small>Program:</small>{}",
            long_code(v["befehl"].as_str().unwrap_or("")),
            long_code(v["ziel"].as_str().unwrap_or(""))
        ),
        Kind::Prozess => {
            let befehl = v["befehl"].as_str().unwrap_or("");
            tf!(
                "<small>Programm (Prozess-ID {}):</small>{}{}{}<div><small>{}</small></div>", "<small>Program (process ID {}):</small>{}{}{}<div><small>{}</small></div>",
                v["pid"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                long_code(v["ziel"].as_str().unwrap_or("")),
                if befehl.is_empty() { String::new() } else { tf!("<small>Befehlszeile:</small>{}", "<small>Command line:</small>{}", long_code(befehl)) }
                    + &v["skript"].as_str().filter(|x| !x.is_empty()).map(|x| tf!("<small>Skript (Ausschnitt, Zeichenketten maskiert):</small>{}", "<small>Script (excerpt, strings masked):</small>{}", long_code(x))).unwrap_or_default()
                    + &affected_files_html(&v)
                    + &v["schritte"]
                        .as_array()
                        .filter(|a| !a.is_empty())
                        .map(|a| tf!("<small>Schritte der Kette:</small><ol>{}</ol>", "<small>Steps of the chain:</small><ol>{}</ol>", a.iter().filter_map(|x| x.as_str()).map(|x| format!("<li><small>{}</small></li>", esc(x))).collect::<String>()))
                        .unwrap_or_default(),
                if k9_core::pipeline::process_running(d) { "" } else { t!("<div><small><b>Prozess läuft nicht mehr.</b></small></div>", "<div><small><b>The process is no longer running.</b></small></div>") },
                s("hinweis")
            )
        }
    }
}

fn render_index(s: &Shared, msg: Option<&str>, section: Option<&str>) -> anyhow::Result<String> {
    let mut b = render_body(s, msg.filter(|_| section.is_none_or(|x| !LIVE_SECTIONS.contains(&x))))?;
    // Message next to the button that was used (see redirect_to).
    if let (Some(m), Some(sec)) = (msg.filter(|m| !m.is_empty()), section.filter(|x| LIVE_SECTIONS.contains(x))) {
        let start = format!("<section id=\"{sec}\">");
        if let Some(i) = b.find(&start) {
            if let Some(j) = b[i..].find("</h2>") {
                b.insert_str(i + j + 5, &format!("<p class=\"msg\">{}</p>", esc(m)));
            }
        }
    }
    Ok(b)
}

/// Header: the paw with "K9" (the program icon, inline, larger than the text) and the version number;
/// own tooltip (on hover and keyboard focus) with build time and – only for a build of exactly
/// one commit – that commit. No native `title`: it shows late and not over the inline SVG.
fn header() -> String {
    let svg = HEADER_SVG;
    let svg = &svg[svg.find("<svg").unwrap_or(0)..];
    let svg = svg
        .replacen(r#"width="256" height="256""#, r#"class="logo" role="img" aria-label="K9" focusable="false""#, 1)
        .replacen("<title>K9</title>", "", 1);
    format!(
        "<h1 class=\"titel\" tabindex=\"0\" aria-describedby=\"k9-version\">{svg}<span class=\"ver\">{}</span>\
         <span id=\"k9-version\" class=\"tip\" role=\"tooltip\">{}</span></h1>",
        env!("CARGO_PKG_VERSION"),
        esc(&version_tooltip())
    )
}

/// Language switch at the top right: the active language is shown as text, the other one as
/// a button.
fn language_switch(s: &Shared) -> String {
    let en = k9_core::sprache::en();
    let item = |code: &str, label: &str, active: bool| {
        if active {
            format!("<b aria-current=\"true\">{label}</b>")
        } else {
            format!("<button name=\"sprache\" value=\"{code}\" lang=\"{code}\">{label}</button>")
        }
    };
    format!(
        "<form method=\"post\" action=\"/sprache\" class=\"sprache\">{}<span>{}</span> {} {}</form>",
        hidden_token(s),
        t!("Sprache:", "Language:"),
        item("de", "Deutsch", !en),
        item("en", "English", en)
    )
}

fn version_tooltip() -> String {
    let commit = env!("K9_COMMIT");
    let mut t = tf!("Version {}, gebaut am {}", "Version {}, built on {}", env!("CARGO_PKG_VERSION"), env!("K9_BUILD_TIME"));
    if !commit.is_empty() {
        t.push_str(&format!(", Commit {commit}"));
    }
    t
}

fn render_body(s: &Shared, msg: Option<&str>) -> anyhow::Result<String> {
    let app = &s.app;
    let store = app.store()?;
    let counts = store.counts()?;
    let gaming = s.gaming.lock().unwrap().clone();
    let mut b = String::new();
    b.push_str(&language_switch(s));
    b.push_str(&header());
    if let Some(m) = msg.filter(|m| !m.is_empty()) {
        let _ = write!(b, "<p class=\"msg\">{}</p>", esc(m));
    }
    if let Some(hint) = notify::popup_hint(&app.config) {
        let _ = write!(b, "<p class=\"msg err\">{}.</p>", esc(&hint));
    }

    security_check_html(&mut b, s);

    // Detection data overview
    if let Ok(src) = app.sources() {
        use k9_core::sources::fmt_num as n;
        let st = src.stats(&app.config.quellen);
        let tile = |value: String, label: &str, sub: String| {
            format!("<div class=\"tile\"><div class=\"num\">{value}</div><div class=\"lbl\">{}</div><div class=\"sub\">{}</div></div>", esc(label), esc(&sub))
        };
        let _ = tw!(
            b,
            "<section class=\"daten\" id=\"erkennungsdaten\"><h2>Erkennungsdaten</h2><div class=\"tiles\">{}{}{}{}{}{}{}</div>", "<section class=\"daten\" id=\"erkennungsdaten\"><h2>Detection data</h2><div class=\"tiles\">{}{}{}{}{}{}{}</div>",
            tile(format!("{} / {}", st.quellen_ok, st.quellen_aktiv), t!("Quellen aktuell", "Sources up to date"), t!("aktiv und ohne Fehler", "active and without errors").into()),
            tile(n(st.schadsoftware_hashes), t!("Schadsoftware-Hashes", "Malware hashes"), format!("MalwareBazaar {} · ThreatFox {}", n(st.malwarebazaar_hashes), n(st.threatfox_hashes))),
            tile(
                n(st.schad_adressen),
                t!("Schad-/Phishing-Adressen", "Malicious/phishing addresses"),
                format!(
                    "URLhaus {} · OpenPhish {} · Phishing-Filter {} · ThreatFox {}",
                    n(st.urlhaus_adressen),
                    n(st.openphish_adressen),
                    n(st.phishing_filter_domains),
                    n(st.threatfox_adressen)
                )
            ),
            tile(n(st.threatfox_iocs), t!("ThreatFox-IOCs", "ThreatFox IOCs"), t!("Hashes, Adressen, Domains", "hashes, addresses, domains").into()),
            tile(n(st.yara_regeln), t!("YARA-Regeln", "YARA rules"), "YARA Forge".into()),
            tile(n(st.clamav_signaturen), t!("ClamAV-Signaturen", "ClamAV signatures"), "main · daily · bytecode".into()),
            tile(n(st.kev_eintraege), t!("CISA-KEV-Einträge", "CISA KEV entries"), t!("aktiv ausgenutzte Lücken", "actively exploited vulnerabilities").into()),
        );
        let _ = tw!(b, "<table class=\"kompakt\"><tr><th>Quelle</th><th>Einträge</th><th>Aktualisiert</th><th></th></tr>", "<table class=\"kompakt\"><tr><th>Source</th><th>Entries</th><th>Updated</th><th></th></tr>");
        for q in &st.quellen {
            let state = if !q.aktiv {
                t!("<span class=\"muted\">deaktiviert</span>", "<span class=\"muted\">disabled</span>").to_string()
            } else if q.ok {
                "<span class=\"okc\">OK</span>".to_string()
            } else {
                format!("<span class=\"err\">{}</span>", esc(q.fehler.as_deref().unwrap_or(t!("noch nicht geladen", "not loaded yet"))))
            };
            let _ = write!(
                b,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{state}</td></tr>",
                esc(&q.name),
                n(q.eintraege),
                dt(q.aktualisiert.as_deref().unwrap_or("–"))
            );
        }
        let _ = tw!(b, "</table><p><small>Stand der Übersicht: {}</small></p></section>", "</table><p><small>Overview as of: {}</small></p></section>", esc(&st.stand));
    }

    // Status
    let _ = tw!(
        b,
        "<section><h2>Status</h2><ul class=\"status\"><li>Offene Erkennungen: <b>{}</b></li><li>Gespeicherte Entscheidungen: {}</li>\
         <li>In Quarantäne: {}</li><li>Gaming-Modus: {}</li><li>Scan läuft: {}</li><li>Letzter Scan: {}</li><li>Windows-Dienst: {}</li></ul>\
         {}</section>", "<section><h2>Status</h2><ul class=\"status\"><li>Open findings: <b>{}</b></li><li>Saved decisions: {}</li>\
         <li>In quarantine: {}</li><li>Gaming mode: {}</li><li>Scan running: {}</li><li>Last scan: {}</li><li>Windows service: {}</li></ul>\
         {}</section>",
        counts.pending,
        counts.decisions,
        counts.quarantined,
        if !app.config.gaming.aktiv {
            t!("aus", "off").to_string()
        } else if gaming.active {
            tf!("Spiel erkannt ({}) – Scans pausiert, Meldungen werden gesammelt", "game detected ({}) – scans paused, findings are collected", esc(gaming.reason.as_deref().unwrap_or("-")))
        } else {
            t!("bereit (kein Spiel erkannt)", "ready (no game detected)").into()
        },
        scan_state(s),
        esc(s.last_scan.lock().unwrap().as_deref().unwrap_or("–")),
        esc(&s.dienst_text.lock().unwrap()),
        scan_buttons(s)
    );

    // Pending detections (quiet ones from work folders at the end)
    let mut pending = store.pending_detections()?;
    pending.sort_by_key(k9_core::arbeitsordner::is_quiet);
    let _ = tw!(b, "<section id=\"offen\"><h2>Offene Erkennungen <small class=\"muted\">– nach Nummer geordnet, Lücken und alte Nummern sind normal</small></h2>", "<section id=\"offen\"><h2>Open findings <small class=\"muted\">– ordered by number, gaps and old numbers are normal</small></h2>");
    if pending.is_empty() {
        let _ = tw!(b, "<p>Keine offenen Erkennungen.</p>", "<p>No open findings.</p>");
    } else {
        let _ = tw!(b, "<p>Nichts wird automatisch verschoben oder gelöscht – bitte je Fund entscheiden. Die Entscheidung wird gespeichert, derselbe Fund wird danach nicht mehr gemeldet. \
                           Mehrere gleiche Meldungen: rechts ankreuzen (oder „gleiche“) und unten die Aktion für alle wählen.</p>\
                           <p><small><b>Warum die Nummern nicht fortlaufend sind:</b> Jede Meldung behält ihre Nummer für immer. Hier fehlen die Nummern, die du schon entschieden hast. \
                           Tritt dieselbe Sache später noch einmal auf (gleiche Regel, gleiches Programm, gleiche Befehlszeile oder Datei), legt K9 keine neue Meldung an, \
                           sondern öffnet die alte wieder – deshalb können sehr alte Nummern neben ganz neuen stehen. In der Spalte „Erkannt“ steht dann darunter „erneut: …“ mit dem letzten Auftreten. \
                           Leise Meldungen stehen am Ende der Liste.</small></p>\
                           <p class=\"wahl-alle\"><label><input type=\"checkbox\" id=\"wahl-alle\"> Alle auswählen</label></p>", "<p>Nothing is moved or deleted automatically – please decide for each finding. The decision is saved, the same finding is not reported again afterwards. \
                           Several identical findings: tick them on the right (or “same”) and choose the action for all of them at the bottom.</p>\
                           <p><small><b>Why the numbers are not consecutive:</b> Every finding keeps its number for ever. The numbers you have already decided are missing here. \
                           If the same thing happens again later (same rule, same program, same command line or file), K9 does not create a new finding \
                           but reopens the old one – that is why very old numbers can stand next to brand-new ones. The column “Detected” then shows “again: …” with the last occurrence below. \
                           Quiet findings are at the end of the list.</small></p>\
                           <p class=\"wahl-alle\"><label><input type=\"checkbox\" id=\"wahl-alle\"> Select all</label></p>");
        let _ = tw!(
            b,
            "<table class=\"funde\"><colgroup><col class=\"c-nr\"><col class=\"c-bed\"><col class=\"c-ort\"><col class=\"c-sev\"><col class=\"c-dat\"><col class=\"c-akt\"><col class=\"c-wahl\"></colgroup>\n             <thead><tr><th>#</th><th>Bedrohung</th><th>Fundort</th><th>Schwere</th><th>Erkannt</th><th>Entscheidung</th><th class=\"nw\">Auswahl</th></tr></thead>", "<table class=\"funde\"><colgroup><col class=\"c-nr\"><col class=\"c-bed\"><col class=\"c-ort\"><col class=\"c-sev\"><col class=\"c-dat\"><col class=\"c-akt\"><col class=\"c-wahl\"></colgroup>\n             <thead><tr><th>#</th><th>Threat</th><th>Location</th><th>Severity</th><th>Detected</th><th>Decision</th><th class=\"nw\">Select</th></tr></thead>"
        );
        for d in &pending {
            // Drivers: one readable line instead of kind · category · rule · engine.
            let meta = if d.kind == Kind::Treiber {
                k9_core::treiber::category_line(&d.details.clone().unwrap_or_default(), &d.rule_id)
            } else {
                format!("{} · {} · {} · {}", d.kind.label(), k9_core::sprache::tr(&d.category), d.rule_id, d.engine)
            };
            let _ = write!(
                b,
                "<tr id=\"erkennung-{id}\"><td class=\"nr\">{id}</td><td>{}{}<br><small>{}</small></td><td class=\"path\">{}<br>{}</td>\
                 <td class=\"nw\">{}</td><td>{}</td><td class=\"actions\">{}</td><td class=\"wahl\">{}</td></tr>",
                esc(&d.threat_name),
                subject_note(d),
                esc(&meta),
                long_code(&d.path),
                quiet_note(d) + &holder_note(d) + &detail_html(d),
                d.severity.label(),
                dt(&d.first_seen) + &if d.last_seen != d.first_seen { tf!("<br><small class=\"muted\">erneut:<br>{}</small>", "<br><small class=\"muted\">again:<br>{}</small>", dt(&d.last_seen)) } else { String::new() },
                decision_buttons(s, d),
                select_cell(d),
                id = d.id
            );
        }
        let neutral: serde_json::Map<String, serde_json::Value> =
            Action::ALL.iter().map(|a| (a.as_str().to_string(), serde_json::Value::from(pipeline::neutral_label(*a)))).collect();
        let _ = tw!(
            b,
            "</table><form id=\"sammel\" class=\"sammel\" method=\"post\" action=\"/aktion-mehrere\" data-neutral=\"{}\" hidden>{}\
             <span class=\"anzahl\"></span><span class=\"knoepfe\"></span><button type=\"button\" class=\"aufheben\">Auswahl aufheben</button></form>", "</table><form id=\"sammel\" class=\"sammel\" method=\"post\" action=\"/aktion-mehrere\" data-neutral=\"{}\" hidden>{}\
             <span class=\"anzahl\"></span><span class=\"knoepfe\"></span><button type=\"button\" class=\"aufheben\">Clear selection</button></form>",
            esc(&serde_json::Value::Object(neutral).to_string()),
            hidden_token(s)
        );
    }
    let _ = write!(b, "</section>");

    // Decisions
    let decisions = store.list_decisions()?;
    let _ = tw!(b, "<section id=\"entscheidungen\"><h2>Gespeicherte Entscheidungen</h2>", "<section id=\"entscheidungen\"><h2>Saved decisions</h2>");
    if decisions.is_empty() {
        let _ = tw!(b, "<p>Noch keine Entscheidungen.</p>", "<p>No decisions yet.</p>");
    } else {
        let _ = tw!(b, "<table><tr><th class=\"nr\">#</th><th class=\"nw\">Aktion</th><th>Bedrohung</th><th>Fingerabdruck</th><th>Datum</th><th></th></tr>", "<table><tr><th class=\"nr\">#</th><th class=\"nw\">Action</th><th>Threat</th><th>Fingerprint</th><th>Date</th><th></th></tr>");
        let public_key = k9_core::schutz::public_key();
        for d in &decisions {
            // With the service only signed decisions count.
            let unsigned = public_key.as_deref().is_some_and(|pk| !k9_core::schutz::verify(pk, d));
            let warn = if unsigned { t!("<br><small class=\"err\">nicht vom Dienst unterschrieben – gilt nicht</small>", "<br><small class=\"err\">not signed by the service – does not apply</small>") } else { "" };
            let _ = tw!(
                b,
                "<tr><td class=\"nr\">{}</td><td><span class=\"nw\">{}</span>{warn}</td><td>{}{}</td><td class=\"path\"><small>{}<br>{}</small></td><td>{}</td>\
                 <td class=\"nw\"><form method=\"post\" action=\"/widerrufen\">{}<input type=\"hidden\" name=\"id\" value=\"{}\"><button>Widerrufen</button></form></td></tr>", "<tr><td class=\"nr\">{}</td><td><span class=\"nw\">{}</span>{warn}</td><td>{}{}</td><td class=\"path\"><small>{}<br>{}</small></td><td>{}</td>\
                 <td class=\"nw\"><form method=\"post\" action=\"/widerrufen\">{}<input type=\"hidden\" name=\"id\" value=\"{}\"><button>Revoke</button></form></td></tr>",
                d.id,
                esc(d.action.label()),
                esc(&d.threat_name),
                d.note.as_deref().map(|n| format!("<br><small>{}</small>", esc(n))).unwrap_or_default(),
                esc(&d.rule_id),
                esc(&d.sha256),
                dt(&d.decided_at),
                hidden_token(s),
                d.id
            );
        }
        let _ = write!(b, "</table>");
    }
    let _ = write!(b, "</section>");

    // Quarantine
    let quarantine = store.list_quarantine()?;
    let _ = tw!(b, "<section id=\"quarantaene\"><h2>Quarantäne</h2>", "<section id=\"quarantaene\"><h2>Quarantine</h2>");
    if quarantine.is_empty() {
        let _ = tw!(b, "<p>Quarantäne ist leer.</p>", "<p>The quarantine is empty.</p>");
    } else {
        let _ = tw!(b, "<table><tr><th class=\"nr\">#</th><th>Bedrohung</th><th>Originalpfad</th><th>Größe</th><th>Seit</th><th></th></tr>", "<table><tr><th class=\"nr\">#</th><th>Threat</th><th>Original path</th><th>Size</th><th>Since</th><th></th></tr>");
        for q in &quarantine {
            let form = |allow: bool, label: &str| {
                format!(
                    "<form method=\"post\" action=\"/wiederherstellen\" class=\"inline\">{}<input type=\"hidden\" name=\"id\" value=\"{}\">{}<button>{}</button></form>",
                    hidden_token(s),
                    q.id,
                    if allow { "<input type=\"hidden\" name=\"freigeben\" value=\"1\">" } else { "" },
                    label
                )
            };
            let _ = write!(
                b,
                "<tr><td class=\"nr\">{}</td><td>{}</td><td class=\"path\">{}</td><td class=\"nw\">{} B</td><td>{}</td><td class=\"stack\">{}{}</td></tr>",
                q.id,
                esc(&q.threat_name),
                esc(&q.original_path),
                q.size,
                dt(&q.quarantined_at),
                form(false, t!("Wiederherstellen", "Restore")),
                form(true, t!("Wiederherstellen + Freigeben", "Restore + allow"))
            );
        }
        let _ = tw!(b, "</table><p><small>„Wiederherstellen“ setzt die Entscheidung zurück (beim nächsten Fund wird wieder gefragt), „+ Freigeben“ merkt sich die Freigabe.</small></p>", "</table><p><small>“Restore” resets the decision (you are asked again at the next finding), “+ allow” remembers the release.</small></p>");
    }
    let _ = write!(b, "</section>");

    // Disabled autostarts
    let disabled = store.list_disabled()?;
    if !disabled.is_empty() {
        let _ = tw!(b, "<section id=\"autostarts\"><h2>Deaktivierte Autostarts</h2><table><tr><th class=\"nr\">#</th><th>Eintrag</th><th>Seit</th><th></th></tr>", "<section id=\"autostarts\"><h2>Disabled autostarts</h2><table><tr><th class=\"nr\">#</th><th>Entry</th><th>Since</th><th></th></tr>");
        for (id, label, at) in &disabled {
            let _ = tw!(
                b,
                "<tr><td class=\"nr\">{id}</td><td class=\"path\">{}</td><td>{}</td><td class=\"nw\"><form method=\"post\" action=\"/autostart\">{}<input type=\"hidden\" name=\"id\" value=\"{id}\"><button>Wieder einschalten</button></form></td></tr>", "<tr><td class=\"nr\">{id}</td><td class=\"path\">{}</td><td>{}</td><td class=\"nw\"><form method=\"post\" action=\"/autostart\">{}<input type=\"hidden\" name=\"id\" value=\"{id}\"><button>Switch on again</button></form></td></tr>",
                esc(label),
                dt(at),
                hidden_token(s)
            );
        }
        let _ = write!(b, "</table></section>");
    }

    // Browser extensions (read only; removing happens in the browser)
    {
        use k9_core::erweiterungen as ext;
        let list = ext::inventory();
        let malicious = app.sources().map(|s| ext::load_malicious(&s.dir)).unwrap_or_default();
        let _ = tw!(b, "<section id=\"erweiterungen\"><h2>Browser-Erweiterungen ({})</h2>", "<section id=\"erweiterungen\"><h2>Browser extensions ({})</h2>", list.len());
        for (browser, profile) in ext::developer_mode() {
            let _ = tw!(
                b,
                "<p class=\"msg\">Hinweis: Entwicklermodus für Erweiterungen ist an ({}, Profil {}). Damit lassen sich ungeprüfte Erweiterungen laden – ausschalten, wenn du ihn nicht brauchst.</p>", "<p class=\"msg\">Note: developer mode for extensions is on ({}, profile {}). It allows loading unchecked extensions – switch it off if you do not need it.</p>",
                esc(&browser),
                esc(&profile)
            );
        }
        if !list.is_empty() {
            let _ = tw!(b, "<details><summary>Liste anzeigen</summary><table><tr><th>Browser</th><th>Erweiterung</th><th>Herkunft</th><th>Einschätzung</th></tr>", "<details><summary>Show list</summary><table><tr><th>Browser</th><th>Extension</th><th>Origin</th><th>Assessment</th></tr>");
            for e in &list {
                let (sev, why) = ext::assess(e, &malicious, None, None).unwrap_or((Severity::Info, String::new()));
                let _ = write!(
                    b,
                    "<tr><td>{} <small>({})</small></td><td>{}<br><small>{} · v{}{}</small></td><td>{}</td><td>{}<br><small>{}</small></td></tr>",
                    esc(e.browser),
                    esc(&e.profile),
                    esc(if e.name.is_empty() { &e.id } else { &e.name }),
                    esc(&e.id),
                    esc(&e.version),
                    if e.enabled { "" } else { t!(" · ausgeschaltet", " · switched off") },
                    match e.source {
                        ext::Source::Store => "Store",
                        ext::Source::Outside => t!("außerhalb des Stores", "outside the store"),
                        ext::Source::Policy => t!("Richtlinie", "policy"),
                    },
                    esc(sev.label()),
                    esc(&why)
                );
            }
            let _ = write!(b, "</table></details>");
        }
        let _ = write!(b, "</section>");
    }

    // Sources
    if let Ok(src) = app.sources() {
        let _ = tw!(
            b,
            "<section id=\"quellen\"><h2>Erkennungsquellen</h2><table><tr><th>Quelle</th><th>Stand</th><th>Einträge</th><th>Aktualisiert</th></tr>", "<section id=\"quellen\"><h2>Detection sources</h2><table><tr><th>Source</th><th>State</th><th>Entries</th><th>Updated</th></tr>"
        );
        for id in SourceId::ALL {
            let st = src.get(id);
            let state = if !id.enabled(&app.config.quellen) {
                t!("deaktiviert", "disabled").to_string()
            } else if let Some(e) = &st.error {
                format!("<span class=\"err\">{}</span>", esc(e))
            } else {
                esc(&k9_core::sprache::stored(st.version.as_deref().unwrap_or(t!("noch nie geladen", "never loaded"))))
            };
            let _ = write!(
                b,
                "<tr><td>{}<br><small>{}</small></td><td>{state}</td><td>{}</td><td>{}</td></tr>",
                esc(id.label()),
                esc(&st.license.clone().unwrap_or_else(|| id.license().to_string())),
                st.entries,
                dt(st.last_update.as_deref().unwrap_or("–"))
            );
        }
        let _ = write!(b, "</table>");
        for w in src.integrity_warnings() {
            let _ = write!(b, "<p class=\"msg err\">{}</p>", esc(&w));
        }
        let _ = tw!(
            b,
            "<form method=\"post\" action=\"/quellen\">{}<button>Quellen jetzt aktualisieren</button></form>{}</section>", "<form method=\"post\" action=\"/quellen\">{}<button>Update sources now</button></form>{}</section>",
            hidden_token(s),
            if s.updating.load(std::sync::atomic::Ordering::Relaxed) { t!("<p>Aktualisierung läuft …</p>", "<p>Update is running …</p>") } else { "" }
        );
    }

    // Recent detections
    let recent = store.recent_detections(15)?;
    let _ = tw!(b, "<section><h2>Letzte Erkennungen</h2>", "<section><h2>Latest findings</h2>");
    if recent.is_empty() {
        let _ = tw!(b, "<p>Keine.</p>", "<p>None.</p>");
    } else {
        let _ = tw!(b, "<table><tr><th class=\"nr\">#</th><th>Status</th><th>Bedrohung</th><th>Datei</th><th>Zuletzt</th></tr>", "<table><tr><th class=\"nr\">#</th><th>Status</th><th>Threat</th><th>File</th><th>Last</th></tr>");
        for d in &recent {
            let _ = write!(
                b,
                "<tr><td class=\"nr\">{}</td><td>{}{}</td><td>{}{}</td><td class=\"path\">{}</td><td>{}</td></tr>",
                d.id,
                d.status.label(),
                d.action.map(|a| format!(" ({})", a.label())).unwrap_or_default(),
                esc(&d.threat_name),
                subject_note(d),
                esc(&d.path),
                dt(&d.last_seen)
            );
        }
        let _ = write!(b, "</table>");
    }
    let _ = write!(b, "</section>");

    // Settings
    let cfg = &app.config;
    let _ = tw!(
        b,
        "<section id=\"einstellungen\"><h2>Einstellungen</h2><ul class=\"status\"><li>Konfigurationsdatei: <code>{}</code></li>\
         <li>Datenordner: <code>{}</code></li><li>Meldekanäle: {}</li><li>Gaming-Modus: {} (Vollbild-Erkennung {})</li>\
         <li>Standardpfade: {}</li><li>Ausnahmen: {}</li><li>Max. Dateigröße: {} MB</li></ul><h3>Zeitpläne</h3><ul>", "<section id=\"einstellungen\"><h2>Settings</h2><ul class=\"status\"><li>Configuration file: <code>{}</code></li>\
         <li>Data folder: <code>{}</code></li><li>Alert channels: {}</li><li>Gaming mode: {} (full-screen detection {})</li>\
         <li>Standard paths: {}</li><li>Exclusions: {}</li><li>Max. file size: {} MB</li></ul><h3>Schedules</h3><ul>",
        esc(&app.paths.config_file().display().to_string()),
        esc(&app.paths.data_dir.display().to_string()),
        esc(&cfg.meldungen.kanaele.iter().map(|c| c.label()).collect::<Vec<_>>().join(", ")),
        if cfg.gaming.aktiv { t!("an", "on") } else { t!("aus", "off") },
        if cfg.gaming.vollbild_erkennen { t!("an", "on") } else { t!("aus", "off") },
        esc(&cfg.scan.standard_pfade.join(", ")),
        if cfg.scan.ausnahmen.is_empty() { t!("keine", "none").to_string() } else { esc(&cfg.scan.ausnahmen.join(", ")) },
        cfg.scan.max_dateigroesse_mb
    );
    if cfg.zeitplan.is_empty() {
        let _ = tw!(b, "<li>keine</li>", "<li>none</li>");
    }
    for e in &cfg.zeitplan {
        let last = store.last_run(&e.key())?.unwrap_or_else(|| t!("nie", "never").into());
        let _ = tw!(b, "<li>{} – zuletzt: {}</li>", "<li>{} – last: {}</li>", esc(&e.label()), esc(&last));
    }
    let _ = tw!(b, "</ul><p>Änderungen bitte in der Konfigurationsdatei vornehmen und den Agent neu starten.</p><h3>Testmeldungen</h3>", "</ul><p>Please make changes in the configuration file and restart the agent.</p><h3>Test alerts</h3>");
    for ch in [Channel::Fenster, Channel::Popup, Channel::Email, Channel::Handy] {
        let _ = write!(
            b,
            "<form method=\"post\" action=\"/test\" class=\"inline\">{}<input type=\"hidden\" name=\"kanal\" value=\"{}\"><button>{}</button></form>",
            hidden_token(s),
            match ch {
                Channel::Fenster => "fenster",
                Channel::Popup => "popup",
                Channel::Email => "email",
                _ => "handy",
            },
            esc(ch.label())
        );
    }
    let _ = write!(b, "</section>");

    // Event log
    let events = store.recent_events(20)?;
    let _ = tw!(b, "<section><h2>Protokoll</h2><table><tr><th>Zeit</th><th>Stufe</th><th>Ereignis</th></tr>", "<section><h2>Log</h2><table><tr><th>Time</th><th>Level</th><th>Event</th></tr>");
    for (ts, level, m) in events {
        let level = match level.as_str() {
            "warnung" => t!("warnung", "warning").to_string(),
            "fehler" => t!("fehler", "error").to_string(),
            _ => level,
        };
        let _ = write!(b, "<tr><td>{}</td><td class=\"nw\">{}</td><td>{}</td></tr>", dt(&ts), esc(&level), esc(&m));
    }
    let _ = write!(b, "</table></section>");
    Ok(b)
}

#[derive(Deserialize)]
struct ConfirmQuery {
    t: String,
    id: i64,
    aktion: String,
}

/// Target of the toast buttons: shows a confirmation page with a POST form
/// (a GET link alone never changes anything).
async fn confirm(State(s): State<Arc<Shared>>, headers: HeaderMap, Query(q): Query<ConfirmQuery>) -> Response {
    if let Err(r) = guard(&s, &headers, &q.t, false) {
        return r.into_response();
    }
    let action: Action = match q.aktion.parse() {
        Ok(a) => a,
        Err(e) => return error_page(anyhow::anyhow!(e)),
    };
    let s2 = s.clone();
    let det = match blocking(move || s2.app.store()?.detection(q.id)).await {
        Ok(Some(d)) => d,
        Ok(None) => return error_page(anyhow::anyhow!(tf!("Erkennung {} existiert nicht", "Finding {} does not exist", q.id))),
        Err(e) => return error_page(e),
    };
    let body = tf!(
        "<h1>Entscheidung bestätigen</h1><p><b>{}</b><br><span class=\"path\">{}</span></p><p>Aktion: <b>{}</b></p>\
         <form method=\"post\" action=\"/aktion\">{}<input type=\"hidden\" name=\"id\" value=\"{}\"><input type=\"hidden\" name=\"aktion\" value=\"{}\">\
         <label>Notiz (optional): <input name=\"notiz\" maxlength=\"200\"></label> <button class=\"warn\">Bestätigen</button></form>\
         <p><a href=\"/?t={}\">Zurück zum Dashboard</a></p>", "<h1>Confirm decision</h1><p><b>{}</b><br><span class=\"path\">{}</span></p><p>Action: <b>{}</b></p>\
         <form method=\"post\" action=\"/aktion\">{}<input type=\"hidden\" name=\"id\" value=\"{}\"><input type=\"hidden\" name=\"aktion\" value=\"{}\">\
         <label>Note (optional): <input name=\"notiz\" maxlength=\"200\"></label> <button class=\"warn\">Confirm</button></form>\
         <p><a href=\"/?t={}\">Back to the dashboard</a></p>",
        esc(&det.threat_name),
        esc(&det.path),
        esc(det.kind.normalize(action).map(|a| det.kind.action_label(a)).unwrap_or(action.label())),
        hidden_token(&s),
        det.id,
        action.as_str(),
        esc(&s.token)
    );
    html_page(t!("Entscheidung bestätigen", "Confirm decision"), &body)
}

#[derive(Deserialize)]
struct DecideForm {
    t: String,
    id: i64,
    aktion: String,
    notiz: Option<String>,
}

async fn decide(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<DecideForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let action: Action = match f.aktion.parse() {
        Ok(a) => a,
        Err(e) => return error_page(anyhow::anyhow!(e)),
    };
    let s2 = s.clone();
    let note = f.notiz.filter(|n| !n.trim().is_empty());
    let id = f.id;
    let res = blocking(move || {
        let store = s2.app.store()?;
        // The row that takes the place of the decided one (for the anchor).
        let ids: Vec<i64> = store.pending_detections()?.iter().map(|d| d.id).collect();
        let pos = ids.iter().position(|x| *x == id);
        let r = pipeline::apply_decision(&store, &s2.app.paths.quarantine_dir(), id, action, note.as_deref())?;
        let still: Vec<i64> = store.pending_detections()?.iter().map(|d| d.id).collect();
        let next = pos.and_then(|p| ids[p + 1..].iter().chain(ids[..p].iter().rev()).find(|x| still.contains(x)).copied());
        Ok((r, next))
    })
    .await;
    let anchor = |next: Option<i64>| Some(("offen", next.map(|n| format!("erkennung-{n}")).unwrap_or_else(|| "offen".into())));
    match res {
        Ok((r, next)) => redirect_to(
            &s,
            &tf!("Entscheidung „{}“ für {} gespeichert.", "Decision “{}” for {} saved.", r.action.label(), r.detection.threat_name),
            anchor(next),
        ),
        Err(e) => redirect_to(&s, &tf!("Fehler: {e:#}", "Error: {e:#}"), Some(("offen", format!("erkennung-{id}")))),
    }
}

/// Several ticked findings with one action. Same protection as a single click (host, origin,
/// token); the service checks every finding again and shows one confirmation for the batch.
async fn decide_many(State(s): State<Arc<Shared>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    let pairs = form_pairs(&body);
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    if let Err(r) = guard(&s, &headers, &get("t"), true) {
        return r.into_response();
    }
    let action: Action = match get("aktion").parse() {
        Ok(a) => a,
        Err(e) => return error_page(anyhow::anyhow!(e)),
    };
    let mut ids: Vec<i64> = pairs.iter().filter(|(n, _)| n == "id").filter_map(|(_, v)| v.parse().ok()).filter(|i| *i > 0).collect();
    ids.dedup();
    if ids.is_empty() {
        return redirect_to(&s, t!("Keine Meldung ausgewählt.", "No finding selected."), Some(("offen", "offen".into())));
    }
    if ids.len() > pipeline::BATCH_MAX {
        return redirect_to(&s, &tf!("Höchstens {} Meldungen auf einmal.", "At most {} findings at once.", pipeline::BATCH_MAX), Some(("offen", "offen".into())));
    }
    let s2 = s.clone();
    let res = blocking(move || pipeline::apply_batch(&s2.app.store()?, &s2.app.paths.quarantine_dir(), &ids, action, None)).await;
    match res {
        Ok(items) => redirect_to(&s, &pipeline::batch_summary(&items), Some(("offen", "offen".into()))),
        Err(e) => redirect_to(&s, &tf!("Nichts ausgeführt: {e:#}", "Nothing carried out: {e:#}"), Some(("offen", "offen".into()))),
    }
}

#[derive(Deserialize)]
struct IdForm {
    t: String,
    id: i64,
    freigeben: Option<String>,
}

async fn revoke(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<IdForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let s2 = s.clone();
    let res = blocking(move || {
        let store = s2.app.store()?;
        let d = store.revoke_decision(f.id)?;
        if let Some(d) = &d {
            store.log_event("info", &format!("Entscheidung widerrufen: {} ({})", d.threat_name, d.action.label()))?;
        }
        Ok(d)
    })
    .await;
    match res {
        Ok(Some(d)) => redirect_to(
            &s,
            &tf!("Entscheidung für {} widerrufen – wird beim nächsten Fund wieder gemeldet.", "Decision for {} revoked – it will be reported again at the next finding.", d.threat_name),
            Some(("entscheidungen", "entscheidungen".into())),
        ),
        Ok(None) => redirect_to(&s, t!("Entscheidung nicht gefunden.", "Decision not found."), Some(("entscheidungen", "entscheidungen".into()))),
        Err(e) => redirect_to(&s, &tf!("Fehler: {e:#}", "Error: {e:#}"), Some(("entscheidungen", "entscheidungen".into()))),
    }
}

async fn restore(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<IdForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let allow = f.freigeben.is_some();
    let s2 = s.clone();
    let res = blocking(move || pipeline::restore_from_quarantine(&s2.app.store()?, f.id, None, allow)).await;
    match res {
        Ok(p) => redirect_to(
            &s,
            &tf!("Wiederhergestellt: {}{}", "Restored: {}{}", p.display(), if allow { t!(" (dauerhaft freigegeben)", " (allowed permanently)") } else { "" }),
            Some(("quarantaene", "quarantaene".into())),
        ),
        Err(e) => redirect_to(&s, &tf!("Fehler: {e:#}", "Error: {e:#}"), Some(("quarantaene", "quarantaene".into()))),
    }
}

#[derive(Deserialize)]
struct TokenForm {
    t: String,
}

async fn scan_now(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    if s.scan_running.load(std::sync::atomic::Ordering::Relaxed) {
        return redirect_home(&s, t!("Es läuft bereits ein Scan.", "A scan is already running."));
    }
    scheduler::start_scan(
        s.clone(),
        s.app.config.default_scan_paths().into_iter().filter(|p| p.exists()).collect(),
        Check::ALL.to_vec(),
        scheduler::ScanArt::Schnell,
    );
    redirect_home(&s, t!("Schnellscan gestartet. Der Fortschritt steht im Kasten „Status“.", "Quick scan started. The progress is shown in the box “Status”."))
}

#[derive(Deserialize)]
struct FullScanForm {
    t: String,
    #[serde(default)]
    art: String,
}

/// Full scan of all local drives, started by one of the two buttons of the status box.
async fn scan_full(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<FullScanForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    if s.scan_running.load(std::sync::atomic::Ordering::Relaxed) {
        return redirect_home(&s, t!("Es läuft bereits ein Scan.", "A scan is already running."));
    }
    let art = if f.art == "schnell" { scheduler::ScanArt::VollSchnell } else { scheduler::ScanArt::VollSchonend };
    let roots = k9_core::realtime::local_drives();
    if roots.is_empty() {
        return redirect_home(&s, t!("Kein Laufwerk gefunden – es wurde nichts gestartet.", "No drive found – nothing was started."));
    }
    scheduler::start_scan(s.clone(), roots, Check::ALL.to_vec(), art);
    redirect_home(&s, &tf!("{} gestartet. Fortschritt und „Scan abbrechen“ stehen im Kasten „Status“.", "{} started. The progress and “Cancel scan” are in the box “Status”.", art.label()))
}

async fn scan_cancel(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    if !s.scan_running.load(std::sync::atomic::Ordering::Relaxed) {
        return redirect_home(&s, t!("Es läuft kein Scan.", "No scan is running."));
    }
    s.scan_cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    redirect_home(&s, t!("Der Scan wird abgebrochen. Bereits gefundene Meldungen bleiben erhalten.", "The scan is being cancelled. Findings already made are kept."))
}

/// "Jetzt neu prüfen" in the section "Sicherheits-Check": reads the settings of Windows again
/// (changes nothing).
async fn security_check_now(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let s2 = s.clone();
    let msg = match blocking(move || crate::pflege::security_check_now(&s2)).await {
        Ok(()) => t!("Sicherheits-Check neu geprüft – der Stand unten ist von jetzt.", "Security check done again – the state below is from now.").to_string(),
        Err(e) => tf!("Sicherheits-Check fehlgeschlagen: {e:#}", "Security check failed: {e:#}"),
    };
    redirect_to(&s, &msg, Some(("sicherheitscheck", "sicherheitscheck".into())))
}

#[derive(Deserialize)]
struct LanguageForm {
    t: String,
    sprache: String,
}

/// Language switch of the dashboard: writes `sprache` into config.toml (like `k9 sprache`) and
/// switches this agent at once - dashboard, Meldefenster and tray. Nothing else is changed.
async fn set_language(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<LanguageForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let Some(lang) = k9_core::sprache::parse(&f.sprache) else {
        return redirect_home(&s, t!("Unbekannte Sprache.", "Unknown language."));
    };
    let s2 = s.clone();
    let value = f.sprache.to_lowercase();
    let res = blocking(move || {
        let file = s2.app.paths.config_file();
        let text = std::fs::read_to_string(&file)?;
        let new = k9_core::funktion::set_language(&text, &value)?;
        if new != text {
            std::fs::write(&file, new)?;
        }
        k9_core::sprache::set(lang);
        // The security check stores its texts: write them again in the new language.
        if let Err(e) = crate::pflege::security_check_now(&s2) {
            tracing::warn!("Sicherheits-Check nach dem Sprachwechsel: {e:#}");
        }
        Ok(())
    })
    .await;
    match res {
        Ok(()) => {
            tracing::info!("Sprache umgestellt: {}", f.sprache);
            redirect_home(
                &s,
                t!(
                    "Sprache: Deutsch. Dashboard, Meldefenster und Symbol im Infobereich sind sofort umgestellt.",
                    "Language: English. Dashboard, alert windows and the tray icon are switched at once."
                ),
            )
        }
        Err(e) => redirect_home(&s, &tf!("Sprache nicht umgestellt: {e:#}", "Language not changed: {e:#}")),
    }
}

async fn update_sources(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    if s.updating.load(std::sync::atomic::Ordering::Relaxed) {
        return redirect_home(&s, t!("Die Aktualisierung läuft bereits.", "The update is already running."));
    }
    scheduler::update_sources_if_due(&s, true);
    redirect_home(&s, t!("Quellen werden im Hintergrund aktualisiert (niedrige Priorität). Seite später neu laden.", "Sources are being updated in the background (low priority). Reload the page later."))
}

/// Update/uninstall jobs of the list of outdated programs: done one after the other by one
/// worker thread; the dashboard shows "läuft …" (turning circle) or "wartet …" per program.
struct ProgramJobs {
    queue: std::collections::VecDeque<(k9_core::sicherheit::ProgrammAktion, k9_core::sicherheit::Update)>,
    current: Option<(k9_core::sicherheit::ProgrammAktion, String)>,
    worker: bool,
}

static PROGRAM_JOBS: std::sync::Mutex<ProgramJobs> = std::sync::Mutex::new(ProgramJobs { queue: std::collections::VecDeque::new(), current: None, worker: false });
/// A confirmation window is open (one at a time).
static PROGRAM_ASKING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The user started an action in the list: it stays open from then on.
static PROGRAM_LIST_OPEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Programs named in the open confirmation window.
static PROGRAM_ASKED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Checked downloaded installers: confirmed ones for the worker, and a short cache for the list.
static PROGRAM_FILES: std::sync::Mutex<Vec<(String, k9_core::nachladen::Kandidat)>> = std::sync::Mutex::new(Vec::new());
type InstallerCache = Vec<(String, std::time::Instant, Option<k9_core::nachladen::Kandidat>)>;
static INSTALLER_CACHE: std::sync::Mutex<InstallerCache> = std::sync::Mutex::new(Vec::new());

/// K9 has an open finding for this file.
fn has_open_finding(s: &Shared, file: &std::path::Path) -> bool {
    let f = file.display().to_string();
    s.app.store().and_then(|st| st.pending_detections()).map(|l| l.iter().any(|d| d.path.eq_ignore_ascii_case(&f))).unwrap_or(true)
}

/// The self-downloaded installer for a program whose update failed (checked, cached 15 s).
fn downloaded_installer(s: &Shared, u: &k9_core::sicherheit::Update) -> Option<k9_core::nachladen::Kandidat> {
    let mut c = INSTALLER_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.retain(|(_, t, _)| t.elapsed() < std::time::Duration::from_secs(15));
    if let Some((_, _, k)) = c.iter().find(|(id, _, _)| *id == u.id) {
        return k.clone();
    }
    let k = k9_core::nachladen::find(u, &|f| has_open_finding(s, f));
    c.push((u.id.clone(), std::time::Instant::now(), k.clone()));
    k
}

/// Runs a confirmed self-downloaded installer and then asks winget again what is outdated.
fn install_downloaded(s: &Shared, u: &k9_core::sicherheit::Update, silent: bool) -> (bool, String) {
    use k9_core::nachladen;
    let taken = {
        let mut f = PROGRAM_FILES.lock().unwrap_or_else(|e| e.into_inner());
        f.iter().position(|(id, _)| *id == u.id).map(|i| f.remove(i).1)
    };
    let Some(k) = taken else { return (false, t!("keine bestätigte Datei", "no confirmed file").into()) };
    // Again right before the start: same file content, still signed by the same publisher.
    let signers = nachladen::installed_signers(u);
    match nachladen::check_file(u, &k.datei, &signers, &|f| has_open_finding(s, f)) {
        Ok(now) if now.sha256 == k.sha256 => {}
        Ok(_) => return (false, t!("die Datei wurde nach der Bestätigung verändert – nicht gestartet", "the file was changed after the confirmation – not started").into()),
        Err(e) => return (false, tf!("nicht gestartet: {e}", "not started: {e}")),
    }
    let switches = if silent {
        match nachladen::silent_switches(&k.datei) {
            Some((_, sw)) => Some(sw),
            None => return (false, t!("Art des Installationsprogramms nicht erkannt – bitte „Installieren“ nehmen", "type of the setup program not recognised – please use “Install”").into()),
        }
    } else {
        None
    };
    let code = match nachladen::run_installer_with(&k.datei, switches) {
        Ok(c) => c,
        Err(e) => return (false, e),
    };
    let dir = &s.app.paths.data_dir;
    let still = match k9_core::sicherheit::outdated_programs() {
        Some(list) => {
            let still = list.iter().any(|x| x.id == u.id);
            if let Some(mut b) = k9_core::sicherheit::Bericht::load(dir) {
                b.set_updates(list);
                let _ = b.save(dir);
            }
            still
        }
        None => true,
    };
    if still {
        (false, tf!("Installationsprogramm beendet (Code {code}), winget meldet aber weiter eine neuere Version", "setup program ended (code {code}), but winget still reports a newer version"))
    } else {
        (true, tf!("aus {} (signiert von {})", "from {} (signed by {})", k.datei.display(), k.signiert_von))
    }
}

fn program_asked(id: &str) -> bool {
    PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|x| x == id)
}

fn program_jobs() -> std::sync::MutexGuard<'static, ProgramJobs> {
    PROGRAM_JOBS.lock().unwrap_or_else(|e| e.into_inner())
}

fn program_jobs_active() -> bool {
    let j = program_jobs();
    j.worker || !j.queue.is_empty()
}

/// (action, running now) of a program that is queued or running.
fn program_job_state(id: &str) -> Option<(k9_core::sicherheit::ProgrammAktion, bool)> {
    let j = program_jobs();
    if let Some((a, cur)) = &j.current {
        if cur == id {
            return Some((*a, true));
        }
    }
    j.queue.iter().find(|(_, u)| u.id == id).map(|(a, _)| (*a, false))
}

fn program_worker(s: Arc<Shared>) {
    use k9_core::sicherheit;
    loop {
        let job = {
            let mut j = program_jobs();
            match j.queue.pop_front() {
                Some((a, u)) => {
                    j.current = Some((a, u.id.clone()));
                    (a, u)
                }
                None => {
                    j.current = None;
                    j.worker = false;
                    k9_core::arbeitsordner::end_update();
                    return;
                }
            }
        };
        let (a, u) = job;
        tracing::info!("Programm {}: {} ({})", a.as_str(), u.name, u.id);
        // Side effects of the installer (helper files, run-once autostarts) come quietly.
        k9_core::arbeitsordner::begin_update(&u.name);
        if a == sicherheit::ProgrammAktion::Laden {
            let res = k9_core::nachladen::fetch_installer(&u, &sicherheit::catalogue_installer_urls(&u.id), &|f| has_open_finding(&s, f));
            let (ok, text) = match &res {
                Ok(k) => (true, tf!("{} (signiert von {})", "{} (signed by {})", k.datei.display(), k.signiert_von)),
                Err(e) => (false, e.clone()),
            };
            tracing::info!("Programm laden: {} – {}", u.name, text);
            sicherheit::note_program_download(&s.app.paths.data_dir, &u, ok, &text);
            INSTALLER_CACHE.lock().unwrap_or_else(|e| e.into_inner()).clear();
            continue;
        }
        let (mut ok, mut out, mut impossible) = if matches!(a, sicherheit::ProgrammAktion::Installieren | sicherheit::ProgrammAktion::StillInstallieren) {
            let (ok, out) = install_downloaded(&s, &u, a == sicherheit::ProgrammAktion::StillInstallieren);
            (ok, out, false)
        } else {
            sicherheit::run_program_action(a, &u)
        };
        // A failed update (e.g. download address not found, 404): refresh winget's catalogue
        // and try once more; after that offer the official page from the catalogue.
        let mut page = None;
        // The package can only be installed by an administrator (seen with "Claude" on
        // 21.11.2026): the same winget run again through Windows' own question for
        // administrator rights. The user asked for this update and confirmed it; Windows asks
        // once more in its own window, K9 never sees a password.
        let admin = !ok && a == sicherheit::ProgrammAktion::Aktualisieren && sicherheit::needs_admin(&out);
        if admin {
            tracing::info!("Programm aktualisieren: {} braucht Administratorrechte ({out}) – Start über die Windows-Abfrage", u.name);
            (ok, out) = sicherheit::run_upgrade_elevated(&u);
            tracing::info!("Programm aktualisieren mit Administratorrechten: {} – {out}", u.name);
        }
        if !ok && !admin && !impossible && a == sicherheit::ProgrammAktion::Aktualisieren && out != sicherheit::ABGEBROCHEN {
            tracing::info!("Programm aktualisieren: {} fehlgeschlagen ({out}) – Katalog erneuern und zweiter Versuch", u.name);
            sicherheit::refresh_winget_sources();
            let (ok2, out2, imp2) = sicherheit::run_program_action(a, &u);
            if ok2 || imp2 {
                (ok, out, impossible) = (ok2, out2, imp2);
            } else {
                out = tf!("{out2} – auch der zweite Versuch nach dem Erneuern des winget-Katalogs", "{out2} – also at the second attempt after refreshing the winget catalogue");
                page = sicherheit::official_page(&u.id);
            }
        }
        sicherheit::note_program_action(&s.app.paths.data_dir, a, &u, ok, &out, impossible);
        if let Some(p) = &page {
            sicherheit::note_program_page(&s.app.paths.data_dir, &u.id, p);
        }
        if let Ok(store) = s.app.store() {
            let _ = store.log_event(if ok { "info" } else { "fehler" }, &format!("Programm {}: {} – {}", a.label(), u.name, if ok { "erledigt".to_string() } else { format!("fehlgeschlagen: {out}") }));
        }
    }
}

/// Buttons of the list of outdated programs: one program ("einzeln" = action:id), the ticked
/// ones (aktion + id …) or all ("…-alle"). Only programs of the stored list; nothing happens
/// before "Ja" in the confirmation window (one window for all chosen programs).
async fn program_action(State(s): State<Arc<Shared>>, headers: HeaderMap, body: axum::body::Bytes) -> Response {
    use k9_core::sicherheit::{self, Bericht, ProgrammAktion};
    let pairs = form_pairs(&body);
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap_or_default();
    if let Err(r) = guard(&s, &headers, &get("t"), true) {
        return r.into_response();
    }
    let list = Bericht::load(&s.app.paths.data_dir).and_then(|b| b.updates).unwrap_or_default();
    let einzeln = get("einzeln");
    // "Abbrechen" next to the running program: ends the winget run in progress (no window).
    if let Some(id) = einzeln.strip_prefix("abbrechen:") {
        let running = program_job_state(id).is_some_and(|(_, now)| now);
        if running {
            sicherheit::CANCEL.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        return redirect_to(&s, if running { t!("Wird abgebrochen …", "Being cancelled …") } else { t!("Dieses Programm wird gerade nicht bearbeitet.", "This program is not being processed right now.") }, Some(("sicherheitscheck", "sicherheitscheck".into())));
    }
    let (a, chosen): (ProgrammAktion, Vec<sicherheit::Update>) = if let Some((act, id)) = einzeln.split_once(':') {
        let Some(a) = ProgrammAktion::parse(act) else { return error_page(anyhow::anyhow!(t!("Unbekannte Aktion", "Unknown action"))) };
        (a, list.into_iter().filter(|u| u.id == id).collect())
    } else {
        let act = get("aktion");
        let (act, all) = match act.strip_suffix("-alle") {
            Some(x) => (x.to_string(), true),
            None => (act, false),
        };
        let Some(a) = ProgrammAktion::parse(&act).filter(|a| matches!(a, ProgrammAktion::Aktualisieren | ProgrammAktion::Deinstallieren)) else { return error_page(anyhow::anyhow!(t!("Unbekannte Aktion", "Unknown action"))) };
        let ids: Vec<String> = pairs.iter().filter(|(n, _)| n == "id").map(|(_, v)| v.clone()).collect();
        (a, list.into_iter().filter(|u| all || ids.contains(&u.id)).collect())
    };
    let mut chosen: Vec<sicherheit::Update> = chosen
        .into_iter()
        .filter(|u| sicherheit::valid_id(&u.id))
        .filter(|u| !(a == ProgrammAktion::Deinstallieren && sicherheit::protected_program(u)))
        .filter(|u| program_job_state(&u.id).is_none())
        .collect();
    chosen.dedup_by(|x, y| x.id == y.id);
    if chosen.is_empty() {
        return redirect_to(&s, t!("Kein Programm ausgewählt (oder schon in Arbeit).", "No program selected (or already in progress)."), Some(("sicherheitscheck", "sicherheitscheck".into())));
    }
    if PROGRAM_ASKING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return redirect_to(&s, t!("Es ist schon ein Bestätigungsfenster offen.", "A confirmation window is already open."), Some(("sicherheitscheck", "sicherheitscheck".into())));
    }
    PROGRAM_LIST_OPEN.store(true, std::sync::atomic::Ordering::Relaxed);
    *PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()) = chosen.iter().map(|u| u.id.clone()).collect();
    let n = chosen.len();
    let s2 = s.clone();
    std::thread::spawn(move || {
        let label = a.label();
        let verb = label.to_lowercase();
        let mut text = if n == 1 {
            let u = &chosen[0];
            match a {
                ProgrammAktion::Laden => tf!(
                    "Installationsprogramm für {} suchen und laden|Seite: {}|K9 sucht dort, auf deren Download-Unterseiten und unter der Adresse aus dem winget-Katalog, lädt die Datei nach „Downloads“ und behält sie nur, wenn sie gültig signiert ist und vom selben Hersteller stammt wie die installierte Version.|Es wird nichts gestartet.", "Search and download the setup program for {}|Page: {}|K9 searches there, on its download subpages and at the address from the winget catalogue, downloads the file to “Downloads” and only keeps it if it is validly signed and comes from the same publisher as the installed version.|Nothing is started.",
                    u.name, u.seite
                ),
                ProgrammAktion::Installieren | ProgrammAktion::StillInstallieren => {
                    // The file is checked now; the worker checks it again (same SHA-256) before the start.
                    let Some(k) = k9_core::nachladen::find(u, &|f| has_open_finding(&s2, f)) else {
                        PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).clear();
                        PROGRAM_ASKING.store(false, std::sync::atomic::Ordering::SeqCst);
                        tracing::info!("Installieren: keine geprüfte Datei mehr für {}", u.name);
                        return;
                    };
                    if k.abweichend.is_some() && a == ProgrammAktion::StillInstallieren {
                        PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).clear();
                        PROGRAM_ASKING.store(false, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                    let signed = match &k.abweichend {
                        None => tf!("Gültig signiert von: {} – derselbe Hersteller wie die installierte Version", "Validly signed by: {} – the same publisher as the installed version", k.signiert_von),
                        Some(old) => tf!(
                            "ACHTUNG – der Herstellername weicht ab:|Diese Datei ist gültig signiert von: {}|Die installierte Version stammt von: {old}|Nur mit „Ja“ bestätigen, wenn du das für dieselbe Firma hältst (Firmen ändern manchmal ihren Namen).", "ATTENTION – the publisher name differs:|This file is validly signed by: {}|The installed version comes from: {old}|Only confirm with “Yes” if you believe this is the same company (companies sometimes change their name).",
                            k.signiert_von
                        ),
                    };
                    let mut t = tf!(
                        "{} installieren (geladene Datei)|Datei: {}|{signed}|SHA-256: {}|K9 hat keine Meldung zu dieser Datei.", "Install {} (downloaded file)|File: {}|{signed}|SHA-256: {}|K9 has no finding for this file.",
                        u.name,
                        k.datei.display(),
                        k.sha256
                    );
                    if a == ProgrammAktion::StillInstallieren {
                        match k9_core::nachladen::silent_switches(&k.datei) {
                            Some((kit, sw)) => t.push_str(&tf!(
                                "|STILL: ohne Fenster und ohne Fragen, mit den Standardeinstellungen des Herstellers (Zielordner, Verknüpfungen, Lizenz).|Art: {kit}, Schalter: {sw}|Die Windows-Abfrage nach Administratorrechten kann trotzdem kommen.", "|SILENT: without a window and without questions, with the publisher\'s default settings (target folder, shortcuts, licence).|Type: {kit}, switches: {sw}|The Windows question for administrator rights may still appear."
                            )),
                            None => {
                                PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).clear();
                                PROGRAM_ASKING.store(false, std::sync::atomic::Ordering::SeqCst);
                                return;
                            }
                        }
                    }
                    let mut f = PROGRAM_FILES.lock().unwrap_or_else(|e| e.into_inner());
                    f.retain(|(id, _)| *id != u.id);
                    f.push((u.id.clone(), k));
                    t
                }
                ProgrammAktion::Aktualisieren => tf!("{} von {} auf {} aktualisieren|Befehl: {}", "Update {} from {} to {}|Command: {}", u.name, u.installiert, u.verfuegbar, u.command()),
                ProgrammAktion::Deinstallieren => tf!("{} (Version {}) deinstallieren|Befehl: winget uninstall --id {} -e", "Uninstall {} (version {})|Command: winget uninstall --id {} -e", u.name, u.installiert, u.id),
            }
        } else {
            let mut t = tf!("{n} Programme {verb}:", "{label} {n} programs:");
            for u in chosen.iter().take(15) {
                t.push_str(&format!("|- {} ({})", u.name, u.installiert));
            }
            if n > 15 {
                t.push_str(&tf!("|… und {} weitere", "|… and {} more", n - 15));
            }
            t
        };
        text.push_str(t!("|Die Programme werden nacheinander bearbeitet. Installationsprogramme können eigene Fenster zeigen oder nach Administratorrechten fragen.", "|The programs are handled one after the other. Setup programs may show their own windows or ask for administrator rights."));
        let title = if n == 1 { tf!("Programm {verb}?", "{label} program?") } else { tf!("{n} Programme {verb}?", "{label} {n} programs?") };
        let exe = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("k9.exe")));
        let yes = exe.is_some_and(|k9| {
            std::process::Command::new(k9).args(["bestaetigen", "--titel", &title, "--text", &text]).status().is_ok_and(|st| st.code() == Some(6))
        });
        if !yes {
            PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).clear();
            PROGRAM_ASKING.store(false, std::sync::atomic::Ordering::SeqCst);
            tracing::info!("Programme {verb}: abgelehnt ({n})");
            return;
        }
        let start = {
            let mut j = program_jobs();
            for u in chosen {
                if !j.queue.iter().any(|(_, x)| x.id == u.id) && j.current.as_ref().is_none_or(|(_, c)| *c != u.id) {
                    j.queue.push_back((a, u));
                }
            }
            !std::mem::replace(&mut j.worker, true)
        };
        // Only now (the jobs are queued): no moment without a running sign in between.
        PROGRAM_ASKED.lock().unwrap_or_else(|e| e.into_inner()).clear();
        PROGRAM_ASKING.store(false, std::sync::atomic::Ordering::SeqCst);
        if start {
            program_worker(s2);
        }
    });
    redirect_to(
        &s,
        "",
        Some(("sicherheitscheck", "sicherheitscheck".into())),
    )
}

/// Ends the agent (used by `k9 agent-beenden`, e.g. for the hidden autostart agent).
async fn stop_agent(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<TokenForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    s.stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    tracing::info!("Agent wird auf Anforderung beendet");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        std::process::exit(0);
    });
    (StatusCode::OK, "Agent wird beendet").into_response()
}

async fn reenable_autostart(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<IdForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let s2 = s.clone();
    match blocking(move || k9_core::autostart::restore(&s2.app.store()?, f.id)).await {
        Ok(label) => redirect_to(
            &s,
            &tf!("Wieder eingeschaltet: {label} (bei der nächsten Prüfung wird wieder gefragt).", "Switched on again: {label} (you are asked again at the next check)."),
            Some(("autostarts", "autostarts".into())),
        ),
        Err(e) => redirect_to(&s, &tf!("Fehler: {e:#}", "Error: {e:#}"), Some(("autostarts", "autostarts".into()))),
    }
}

#[derive(Deserialize)]
struct ChannelForm {
    t: String,
    kanal: String,
}

async fn test_message(State(s): State<Arc<Shared>>, headers: HeaderMap, Form(f): Form<ChannelForm>) -> Response {
    if let Err(r) = guard(&s, &headers, &f.t, true) {
        return r.into_response();
    }
    let Some(ch) = Channel::parse(&f.kanal) else {
        return redirect_home(&s, t!("Unbekannter Kanal.", "Unknown channel."));
    };
    if ch == Channel::Fenster {
        // The sample window blocks until closed – show it without holding the request.
        std::thread::spawn(|| {
            if let Err(e) = notify::notifier_for(Channel::Fenster, &Default::default(), None).send(&Message::test(Channel::Fenster)) {
                tracing::warn!("Beispiel-Meldefenster: {e:#}");
            }
        });
        return redirect_home(&s, t!("Beispiel-Meldefenster geöffnet (verändert nichts).", "Sample alert window opened (changes nothing)."));
    }
    let s2 = s.clone();
    let res = blocking(move || notify::notifier_for(ch, &s2.app.config, s2.app.dashboard_link()).send(&Message::test(ch))).await;
    match res {
        Ok(()) => redirect_home(&s, &tf!("Testmeldung über {} gesendet.", "Test alert sent via {}.", ch.label())),
        Err(e) => redirect_home(&s, &tf!("Testmeldung über {} fehlgeschlagen: {e:#}", "Test alert via {} failed: {e:#}", ch.label())),
    }
}

#[derive(Deserialize)]
struct ApiQuery {
    t: String,
}

/// State of the running scan for the page script: cheap, no database access.
async fn api_scan(State(s): State<Arc<Shared>>, headers: HeaderMap, Query(q): Query<ApiQuery>) -> Response {
    if let Err(r) = guard(&s, &headers, &q.t, false) {
        return r.into_response();
    }
    let text = scan_text(&s);
    with_security_headers(axum::Json(serde_json::json!({ "laeuft": text.is_some(), "text": text.unwrap_or_default() })).into_response())
}

/// JSON status for scripts and the end-to-end test.
async fn api_status(State(s): State<Arc<Shared>>, headers: HeaderMap, Query(q): Query<ApiQuery>) -> Response {
    if let Err(r) = guard(&s, &headers, &q.t, false) {
        return r.into_response();
    }
    let s2 = s.clone();
    let res = blocking(move || {
        let store = s2.app.store()?;
        Ok(serde_json::json!({
            "zaehler": store.counts()?,
            "offen": store.pending_detections()?,
            "entscheidungen": store.list_decisions()?,
            "quarantaene": store.list_quarantine()?,
            "gaming": *s2.gaming.lock().unwrap(),
            "scan_laeuft": s2.scan_running.load(std::sync::atomic::Ordering::Relaxed),
            "dienst": s2.dienst_text.lock().unwrap().clone(),
            "erkennungsdaten": s2.app.sources().ok().map(|src| src.stats(&s2.app.config.quellen)),
        }))
    })
    .await;
    match res {
        Ok(v) => with_security_headers(axum::Json(v).into_response()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

/// Buttons in the finding/decision/quarantine/autostart tables work without
/// reloading: the form is sent in the background, the affected sections are
/// replaced and the scroll position stays. Without JavaScript the forms still
/// work normally (redirect with anchor).
const SCRIPT: &str = r#"
(function(){
  // A message in the address is shown once: reloading the page must not bring it back.
  try{var u=new URL(location.href);if(u.searchParams.has('meldung')){u.searchParams.delete('meldung');u.searchParams.delete('bereich');history.replaceState(null,'',u.toString());}}catch(_){}
  if(document.querySelector('[data-neuladen]'))setTimeout(function(){location.reload();},3000);
  var scanstand=document.getElementById('scanstand');
  if(scanstand){
    var tk=document.querySelector('input[name=t]');
    var poll=function(){
      fetch('/api/scan?t='+encodeURIComponent(tk?tk.value:''),{credentials:'same-origin'})
        .then(function(r){return r.json();})
        .then(function(j){if(!j.laeuft){location.reload();return;}scanstand.textContent=j.text;setTimeout(poll,2000);})
        .catch(function(){setTimeout(poll,5000);});
    };
    setTimeout(poll,2000);
  }
  var LIVE=['offen','entscheidungen','quarantaene','autostarts'];
  var toast=document.getElementById('toast'),timer;
  function show(t){if(!t)return;toast.textContent=t;toast.hidden=false;clearTimeout(timer);timer=setTimeout(function(){toast.hidden=true},6000);}
  // Every click on a button shows at once that K9 is working: a turning circle on the button
  // that was clicked, and the buttons of this form cannot be clicked a second time.
  function busy(f,sb){
    sb=sb||f.querySelector('button');
    if(sb&&!sb.querySelector('.kreis')){var k=document.createElement('span');k.className='kreis';sb.insertBefore(k,sb.firstChild);sb.classList.add('arbeitet');}
  }
  // Back from another page: the browser may show the old page with its turning circle.
  window.addEventListener('pageshow',function(e){if(e.persisted)location.reload();});
  document.addEventListener('submit',function(e){
    var f=e.target,sec=f.closest('section[id]');
    busy(f,e.submitter);
    if(!sec||LIVE.indexOf(sec.id)<0||(f.method||'').toLowerCase()!=='post'){
      // Sent by the browser itself; lock the buttons only after it has read the form.
      setTimeout(function(){f.querySelectorAll('button').forEach(function(b){b.disabled=true})},0);
      return;
    }
    e.preventDefault();
    var data=new FormData(f);
    if(e.submitter&&e.submitter.name)data.append(e.submitter.name,e.submitter.value);
    var btns=f.querySelectorAll('button');btns.forEach(function(b){b.disabled=true});
    var y=window.scrollY;
    fetch(f.action,{method:'POST',body:new URLSearchParams(data),credentials:'same-origin'}).then(function(r){
      return r.text().then(function(html){return {url:r.url,html:html,ok:r.ok}});
    }).then(function(res){
      if(!res.ok){throw new Error('http');}
      var doc=new DOMParser().parseFromString(res.html,'text/html');
      if(!doc.getElementById('offen')){document.open();document.write(res.html);document.close();return;}
      LIVE.forEach(function(id){var n=doc.getElementById(id),o=document.getElementById(id);if(n&&o){o.replaceWith(n)}});
      var st=doc.querySelector('ul.status'),so=document.querySelector('ul.status');if(st&&so){so.replaceWith(st)}
      window.scrollTo(0,y);
      try{show(new URL(res.url).searchParams.get('meldung'))}catch(_){}
    }).catch(function(){btns.forEach(function(b){b.disabled=false});f.submit();});
  });
  // Several findings at once: the bar offers only actions every ticked finding allows.
  var CLS={quarantaene:'warn',deaktivieren:'warn',loeschen:'danger',beenden:'danger',freigabe:'ok',gesehen:'ok',einmalig:'ok',regelfreigabe:'ok'};
  function boxes(){return Array.prototype.slice.call(document.querySelectorAll('input.wahl'))}
  function update(){
    var f=document.getElementById('sammel');if(!f)return;
    var all=boxes(),sel=all.filter(function(b){return b.checked}),a=document.getElementById('wahl-alle');
    if(a){a.checked=sel.length>0&&sel.length===all.length;a.indeterminate=sel.length>0&&sel.length<all.length}
    f.hidden=sel.length===0;if(!sel.length)return;
    var neutral=JSON.parse(f.getAttribute('data-neutral')),lists=sel.map(function(b){return JSON.parse(b.getAttribute('data-aktionen'))});
    var common=lists[0].filter(function(p){return lists.every(function(l){return l.some(function(q){return q[0]===p[0]})})});
    var k=f.querySelector('.knoepfe');k.textContent='';
    f.querySelector('.anzahl').textContent=sel.length+(document.documentElement.lang==='en'?(sel.length===1?' finding':' findings')+' selected:':(sel.length===1?' Meldung':' Meldungen')+' ausgewählt:');
    if(!common.length){var m=document.createElement('span');m.className='muted';m.textContent=document.documentElement.lang==='en'?'No action is possible for all selected findings – please decide one at a time or change the selection.':'Keine Aktion ist für alle ausgewählten Meldungen möglich – bitte einzeln entscheiden oder die Auswahl ändern.';k.appendChild(m);return}
    common.forEach(function(p){
      var same=lists.every(function(l){return l.some(function(q){return q[0]===p[0]&&q[1]===p[1]})});
      var b=document.createElement('button');b.name='aktion';b.value=p[0];b.className=CLS[p[0]]||'';
      b.textContent=(same?p[1]:neutral[p[0]])+' ('+sel.length+')';k.appendChild(b);
    });
  }
  document.addEventListener('change',function(e){
    var t=e.target;
    if(t.id==='wahl-alle'){boxes().forEach(function(b){b.checked=t.checked})}
    if(t.id==='wahl-alle'||(t.classList&&t.classList.contains('wahl')))update();
  });
  document.addEventListener('click',function(e){
    var t=e.target;if(!t.classList)return;
    if(t.classList.contains('gleiche')){var g=t.getAttribute('data-gruppe');boxes().forEach(function(b){if(b.getAttribute('data-gruppe')===g)b.checked=true});update()}
    if(t.classList.contains('aufheben')){boxes().forEach(function(b){b.checked=false});update()}
  });
  update();
})();
"#;

const CSS: &str = r#"
:root{--bg:#f6f7f9;--fg:#1d2330;--card:#fff;--line:#d9dde5;--muted:#5d6675;--accent:#2457c5;--ok:#1d7a46;--warn:#b26a00;--danger:#b3261e}
@media (prefers-color-scheme: dark){:root{--bg:#14171c;--fg:#e6e9ef;--card:#1d2128;--line:#343a45;--muted:#9aa3b2;--accent:#7aa2ff;--ok:#5cc58b;--warn:#f0b357;--danger:#ff8a80}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 "Segoe UI",system-ui,sans-serif}
main{width:100%;max-width:1800px;margin:0 auto;padding:16px clamp(24px,2.5vw,48px)}
/* Width follows the window up to 1800 px (longer lines get hard to read); side gutters 24-48 px, 16 px on phones. */
@media (max-width:600px){main{padding:12px 16px}section{padding:12px}}h1{margin:.2em 0 .6em}.titel{display:flex;align-items:flex-end;gap:.5rem;line-height:1.2;position:relative;width:max-content;max-width:100%;cursor:help;border-radius:6px}.titel:focus-visible{outline:2px solid var(--accent);outline-offset:4px}.titel .tip{visibility:hidden;opacity:0;position:absolute;left:0;top:100%;margin-top:6px;z-index:5;width:max-content;max-width:min(36rem,calc(100vw - 32px));font-size:.9rem;font-weight:400;line-height:1.4;background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px;box-shadow:0 4px 14px rgba(0,0,0,.25);transition:opacity .12s;pointer-events:none}.titel:hover .tip,.titel:focus .tip{visibility:visible;opacity:1}.titel .logo{width:64px;height:64px;flex:none;display:block}.titel .ver{font-size:.8rem;line-height:1;margin-bottom:8.9px;font-variant-numeric:tabular-nums}@media (max-width:480px){.titel .logo{width:48px;height:48px}.titel .ver{font-size:.675rem;margin-bottom:6.6px}}h2{margin:0 0 .5em;font-size:1.15em}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 14px;overflow-x:auto}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;min-width:0;overflow-wrap:break-word;word-break:normal}
th{color:var(--muted);font-weight:600;font-size:.9em;overflow-wrap:normal;word-break:normal;hyphens:manual}small{color:var(--muted)}.path{word-break:break-all}
.status{margin:0 0 10px;padding-left:18px}.toast{position:fixed;left:50%;bottom:18px;transform:translateX(-50%);max-width:min(720px,92vw);z-index:9;box-shadow:0 4px 18px rgba(0,0,0,.25)}.msg{background:var(--card);border-left:4px solid var(--accent);padding:10px 12px;border-radius:6px}
.err{color:var(--danger)}form.inline{display:inline-block;margin:2px}.actions{white-space:nowrap}
.nw,td.nw,th.nw{white-space:nowrap;overflow-wrap:normal;word-break:normal}th.nr,td.nr{width:1%;white-space:nowrap;overflow-wrap:normal;word-break:normal;font-variant-numeric:tabular-nums}
.dt{display:inline-flex;flex-direction:column;white-space:nowrap;line-height:1.3;font-variant-numeric:tabular-nums}
td.stack{width:1%;white-space:nowrap}td.stack form,td.stack form.inline{display:block;margin:0 0 5px}td.stack button{width:100%;white-space:nowrap;text-align:left}
button{overflow-wrap:normal;word-break:normal;hyphens:manual}
table.funde{table-layout:fixed;width:100%}col.c-wahl{width:5.5em}td.wahl{text-align:center}td.wahl input{width:1.25em;height:1.25em;cursor:pointer}
button.gleiche{font-size:.8em;padding:2px 8px;margin-top:6px;color:var(--muted)}p.wahl-alle{margin:.2em 0 .6em}p.wahl-alle input{width:1.1em;height:1.1em;vertical-align:-2px}
form.sammel{position:sticky;bottom:0;z-index:4;display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:10px;padding:10px 12px;background:var(--card);border:2px solid var(--accent);border-radius:8px;box-shadow:0 -4px 14px rgba(0,0,0,.18)}
form.sammel[hidden]{display:none}form.sammel .anzahl{font-weight:600;margin-right:4px}form.sammel .knoepfe{display:flex;flex-wrap:wrap;gap:6px;flex:1 1 auto}
@media (max-width:820px){table.funde td.wahl{text-align:left}}
col.c-nr{width:3.8em}col.c-bed{width:24%}col.c-sev{width:5.5em}col.c-dat{width:7em}col.c-akt{width:14em}
code.blk{display:block;font-family:Consolas,"Cascadia Mono",monospace;font-size:.84em;background:rgba(127,127,127,.12);padding:4px 6px;border-radius:4px;margin:2px 0 6px;white-space:pre-wrap;overflow-wrap:anywhere}
details.lang summary{list-style:none;cursor:pointer}details.lang summary::-webkit-details-marker{display:none}details.lang[open]>summary code{display:none}
.mehr{color:var(--accent);font-size:.85em}.mehr::before{content:"mehr anzeigen"}details.lang[open] .mehr::before{content:"weniger anzeigen"}html[lang=en] .mehr::before{content:"show more"}html[lang=en] details.lang[open] .mehr::before{content:"show less"}
table.funde td.actions{white-space:normal;overflow-wrap:normal;word-break:normal}table.funde td.actions form{display:block;margin:0 0 5px}table.funde td.actions button{width:100%;white-space:normal;text-align:left}
.path{overflow-wrap:anywhere;word-break:normal}
@media (max-width:820px){table.funde,table.funde tbody,table.funde tr,table.funde td{display:block;width:100%}table.funde thead,table.funde colgroup{display:none}table.funde tr{border-bottom:2px solid var(--line);padding:6px 0}table.funde td{border:none;padding:3px 0}}
button{font:inherit;cursor:pointer;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:5px 10px}
button:hover{border-color:var(--accent)}button.ok{color:var(--ok);border-color:var(--ok)}button.warn{color:var(--warn);border-color:var(--warn)}
button.danger{color:var(--danger);border-color:var(--danger)}a{color:var(--accent)}code{font-size:.9em}
input{font:inherit;padding:4px 6px;border:1px solid var(--line);border-radius:5px;background:var(--card);color:var(--fg)}
.daten{border-color:var(--accent);border-width:2px}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:12px}
.tile{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.tile .num{font-size:1.6em;font-weight:700;color:var(--accent);font-variant-numeric:tabular-nums}
.tile .lbl{font-weight:600}.tile .sub{color:var(--muted);font-size:.85em}table.kompakt td,table.kompakt th{padding:3px 8px}.okc{color:var(--ok);font-weight:600}.punkt{display:inline-block;width:.9em;height:.9em;border-radius:50%;vertical-align:middle}.a-gruen{background:var(--ok)}.a-gelb{background:var(--warn)}.a-rot{background:var(--danger)}.a-grau{background:var(--muted)}.kreis{display:inline-block;width:.9em;height:.9em;margin-right:.35em;vertical-align:-.1em;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:dreh 1s linear infinite}@keyframes dreh{to{transform:rotate(360deg)}}
.sprache{float:right;font-size:.9em;margin:.2em 0 0 1em}.sprache button{padding:.15em .6em}button.arbeitet{cursor:progress}button:disabled{opacity:.65;cursor:progress}button .kreis{border-color:currentColor;border-top-color:transparent}@media (prefers-reduced-motion:reduce){.kreis{animation-duration:3s}}.laeuft{font-weight:600}.laeuft.wartet{font-weight:400;color:var(--muted)}.laeuft.wartet .kreis{animation-duration:2.5s}details.liste>summary{display:inline-block;cursor:pointer;margin:10px 0 4px;padding:10px 18px;font-size:1.05em;font-weight:600;border:1px solid var(--accent);border-radius:8px;background:var(--card);list-style:none}details.liste>summary::-webkit-details-marker{display:none}details.liste>summary::before{content:"▸ "}details.liste[open]>summary::before{content:"▾ "}details.liste>summary:hover,details.liste>summary:focus-visible{background:var(--line)}.muted{color:var(--muted)}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_with_several_ids() {
        let p = form_pairs(b"t=abc&aktion=freigabe&id=12&id=13&id=x&notiz=a+b%C3%A4%2F");
        let ids: Vec<&str> = p.iter().filter(|(k, _)| k == "id").map(|(_, v)| v.as_str()).collect();
        assert_eq!(ids, ["12", "13", "x"]);
        assert_eq!(p.iter().find(|(k, _)| k == "notiz").unwrap().1, "a bä/");
        assert_eq!(form_pairs(b"a=%zz&b=%4"), [("a".to_string(), "%zz".to_string()), ("b".to_string(), "%4".to_string())]);
    }

    #[test]
    fn selection_cell_carries_the_allowed_actions() {
        let d = Detection {
            id: 7,
            path: "C:\\x".into(),
            sha256: "aa".into(),
            rule_id: "R".into(),
            threat_name: "t".into(),
            category: "c".into(),
            severity: Severity::Mittel,
            engine: "e".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            status: k9_core::model::DetectionStatus::Offen,
            action: None,
            kind: Kind::Firewall,
            details: Some(serde_json::json!({"anzahl": 2})),
        };
        let c = select_cell(&d);
        assert!(c.contains(r#"value="7" form="sammel""#), "{c}");
        assert!(c.contains("Regel entfernen (alle 2 gleichen)"), "Beschriftung je Meldung: {c}");
        assert!(c.contains(r#"data-gruppe="R|aa""#), "{c}");
    }

    #[test]
    fn dates_and_button_labels() {
        assert_eq!(dt("2026-11-15 21:54:42"), "<span class=\"dt\"><span>2026-11-15</span><span>21:54:42</span></span>");
        assert!(dt("2026-11-16T05:52:23.86Z").starts_with("<span class=\"dt\"><span>2026-11-16</span>"), "UTC aus dem Firewall-Protokoll wird Ortszeit");
        assert_eq!(dt("–"), "<span class=\"nw\">–</span>");
        assert_eq!(button_label("Löschen/Deaktivieren"), "Löschen/<wbr>Deaktivieren");
        assert_eq!(button_label("a<b"), "a&lt;b");
    }

    #[test]
    fn header_shows_paw_and_version() {
        let h = header();
        assert!(h.starts_with(r#"<h1 class="titel" tabindex="0" aria-describedby="k9-version">"#), "{h}");
        assert!(h.contains(&format!(r#"<span id="k9-version" class="tip" role="tooltip">{}</span>"#, esc(&version_tooltip()))));
        assert!(!h.contains(" title="), "kein zusätzlicher nativer Tooltip");
        assert!(h.contains(r#"role="img" aria-label="K9""#));
        assert!(h.contains("#FF6B00"), "Pfote in Signalorange");
        assert!(h.contains(r##"<path fill="#15171C" d="##), "Schriftzug K9 in der Pfote");
        assert!(h.contains(&format!("<span class=\"ver\">{}</span>", env!("CARGO_PKG_VERSION"))));
        assert!(!h.contains("<?xml") && !h.contains("<title>") && !h.contains(">K9<"), "kein Text K9 mehr");
        let tip = version_tooltip();
        assert!(tip.starts_with(&format!("Version {}, gebaut am ", env!("CARGO_PKG_VERSION"))), "{tip}");
        assert_eq!(tip.contains("Commit"), !env!("K9_COMMIT").is_empty());
    }

    #[test]
    fn escaping_and_encoding() {
        assert_eq!(esc("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
        assert_eq!(url_encode("Ä b&c"), "%C3%84%20b%26c");
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}

#[cfg(test)]
mod scan_button_tests {
    use super::{affected_files_html, scan_line, thousands};

    #[test]
    fn a_ransomware_suspicion_lists_its_sample_files_escaped() {
        let v = serde_json::json!({ "dateien": ["C:\\Users\\x\\Temp\\a<b>.tmp", "D:\\y.docx"] });
        let html = affected_files_html(&v);
        assert!(html.starts_with("<small>Betroffene Dateien (Beispiele):</small><ul>"), "{html}");
        assert!(html.contains("a&lt;b&gt;.tmp") && html.contains("D:\\y.docx"), "{html}");
        assert_eq!(affected_files_html(&serde_json::json!({ "befehl": "x" })), "");
    }

    #[test]
    fn the_scan_line_names_kind_files_folder_and_a_pending_cancel() {
        assert_eq!(scan_line("Schnellscan (Standardordner)", 0, "", false), "ja – Schnellscan (Standardordner): 0 Dateien erreicht");
        assert_eq!(
            scan_line("Vollständiger Scan (schnell)", 1234567, "D:\\Spiele", true),
            "ja – Vollständiger Scan (schnell): 1.234.567 Dateien erreicht, gerade in D:\\Spiele – wird abgebrochen …"
        );
    }

    #[test]
    fn the_english_dashboard_has_english_texts() {
        use k9_core::sprache::{with, Sprache};
        let line = with(Sprache::En, || scan_line("Full scan (fast)", 1200, r"C:\Windows", true));
        assert_eq!(line, r"yes – Full scan (fast): 1.200 files reached, currently in C:\Windows – being cancelled …");
        assert_eq!(with(Sprache::En, || crate::scheduler::ScanArt::VollSchnell.label()), "Full scan (fast)");
        assert_eq!(with(Sprache::En, || crate::tray::State::Kritisch.tooltip()), "K9: critical finding");
        assert!(with(Sprache::En, || crate::dashboard::program_hint(true)).contains("confirmation window"));
        // German stays the default.
        assert!(crate::dashboard::program_hint(true).contains("Bestätigungsfenster"));
    }

    #[test]
    fn thousands_separates_groups_of_three() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1.000");
        assert_eq!(thousands(1234567), "1.234.567");
        assert_eq!(thousands(120000), "120.000");
    }
}
