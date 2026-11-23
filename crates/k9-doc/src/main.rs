//! k9-doc: Markdown -> printable HTML for the PDF guide (title page with logo, clickable table of
//! contents, page numbers in the footer; Edge adds PDF bookmarks from the headings).
//! Usage: k9-doc <eingabe.md> <ausgabe.html> [Stand-Text]

use pulldown_cmark::{html, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

const CSS: &str = r#"
@page { size: A4; margin: 16mm 15mm 18mm 15mm;
        @bottom-right { content: "Seite " counter(page) " von " counter(pages); font: 8.5pt "Segoe UI", Arial, sans-serif; color: #5d6675; }
        @bottom-left { content: "K9 – Anleitung"; font: 8.5pt "Segoe UI", Arial, sans-serif; color: #5d6675; } }
@page :first { @bottom-right { content: none; } @bottom-left { content: none; } }
body { font-family: "Segoe UI", Arial, sans-serif; font-size: 10.5pt; line-height: 1.45; color: #1d2330; }
h1 { font-size: 20pt; margin: 0 0 5mm; color: #15171C; border-bottom: 3px solid #FF6B00; padding-bottom: 2mm; page-break-before: always; }
h2 { font-size: 14pt; margin: 8mm 0 3mm; padding-bottom: 1mm; border-bottom: 1.5px solid #15171C; color: #15171C; page-break-after: avoid; }
h3 { font-size: 12pt; margin: 5mm 0 2mm; page-break-after: avoid; }
p, li { orphans: 3; widows: 3; }
code { font-family: Consolas, "Cascadia Mono", monospace; font-size: 9.5pt; background: #eef1f6; padding: 0 2px; border-radius: 2px; }
pre, .kasten { background: #f3f5f9; border: 1px solid #cfd6e3; border-left: 4px solid #FF6B00; padding: 3mm; border-radius: 3px;
      white-space: pre; overflow: hidden; page-break-inside: avoid; }
.kasten { margin: 1em 0; }
.kasten p { margin: 0; white-space: pre; line-height: 1.45; }
.kasten.umbruch p { white-space: pre-wrap; overflow-wrap: anywhere; }
pre code, .kasten code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 2mm 0 4mm; font-size: 9.5pt; page-break-inside: auto; }
th, td { border: 1px solid #cfd6e3; padding: 1.5mm 2mm; text-align: left; vertical-align: top; }
th { background: #f1f2f4; }
tr { page-break-inside: avoid; }
blockquote { margin: 3mm 0; padding: 2mm 4mm; background: #fff4ea; border-left: 4px solid #FF6B00; }
a { color: #b34a00; text-decoration: none; }
.titel { height: 250mm; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; }
.titel .kopf { display: flex; align-items: flex-end; gap: 7mm; }
.titel .kopf svg { width: 51mm; height: 51mm; display: block; flex: none; }
/* Version above the date, the date's baseline level with the bottom edge of the icon
   (the icon's square ends 3/64 above the bottom of its box). */
.titel .kopf .vd { display: flex; flex-direction: column; align-items: flex-start; text-align: left; color: #15171C;
                   line-height: 1; margin-bottom: calc(51mm * 3 / 64 - 0.105em); font-size: 22pt; }
.titel .kopf .ver { font-weight: 700; margin-bottom: 3mm; }
.titel .kopf .dat { font-size: 16pt; color: #3a4150; }
.titel .untertitel { font-size: 18pt; margin-top: 10mm; color: #15171C; }
.titel .stand { color: #5d6675; font-size: 10pt; margin-top: 6mm; }
.inhalt { page-break-before: always; }
.inhalt h1 { page-break-before: avoid; }
.inhalt ol { list-style: none; padding-left: 0; }
.inhalt li.teil { font-weight: 600; margin-top: 3mm; }
.inhalt li.kap { margin-left: 7mm; }
"#;

/// The program icon (paw with "K9" in it) – on the title page next to version and date.
const ICON: &str = include_str!("../../../pictures/k9-pfote.svg");

/// The icon as inline SVG for the title page.
fn icon() -> String {
    let svg = &ICON[ICON.find("<svg").unwrap_or(0)..];
    svg.replacen(r#"width="256" height="256""#, r#"role="img" aria-label="K9""#, 1).replacen("<title>K9</title>", "", 1)
}

/// The current program version: read at every run from the workspace `Cargo.toml` (searched
/// upwards from the guide's folder), so the title page never shows an old version even if this
/// helper was built earlier; otherwise the built-in one.
fn version_for(md_path: &std::path::Path) -> String {
    let start = std::fs::canonicalize(md_path).unwrap_or_else(|_| md_path.to_path_buf());
    start
        .ancestors()
        .filter_map(|d| std::fs::read_to_string(d.join("Cargo.toml")).ok())
        .find_map(|t| workspace_version(&t))
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
}

/// The version named in the newest row of the change log ("**Version x.y.z:**", first one).
fn newest_logged_version(md: &str) -> Option<String> {
    let rest = &md[md.find("**Version ")? + "**Version ".len()..];
    let v: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || ".-+".contains(*c)).collect();
    (!v.is_empty()).then_some(v)
}

/// `version = "…"` in the `[workspace.package]` section.
fn workspace_version(toml: &str) -> Option<String> {
    let mut in_section = false;
    for line in toml.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_section = l == "[workspace.package]";
            continue;
        }
        if in_section {
            if let Some(v) = l.strip_prefix("version").map(str::trim_start).and_then(|r| r.strip_prefix('=')) {
                let v = v.trim().trim_matches('"');
                if !v.is_empty() && v.chars().all(|c| c.is_ascii_alphanumeric() || ".-+".contains(c)) {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// The date of the guide ("16.11.2026") from the "Stand" text the script passes.
fn date_of(stand: &str) -> String {
    stand
        .split(|c: char| c.is_whitespace() || c == '·')
        .find(|w| w.len() == 10 && w.as_bytes()[2] == b'.' && w.as_bytes()[5] == b'.' && w.chars().filter(char::is_ascii_digit).count() == 8)
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Anchor of a heading: lower case letters/digits, umlauts spelled out, the rest as "-".
fn slug(text: &str, n: usize) -> String {
    let mut s = String::new();
    for c in text.to_lowercase().chars() {
        match c {
            'ä' => s.push_str("ae"),
            'ö' => s.push_str("oe"),
            'ü' => s.push_str("ue"),
            'ß' => s.push_str("ss"),
            c if c.is_ascii_alphanumeric() => s.push(c),
            _ if !s.ends_with('-') => s.push('-'),
            _ => {}
        }
    }
    format!("{}-{n}", s.trim_matches('-'))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// HTML body (without the first heading, which becomes the title page) and the table of contents.
/// Widest line (in characters) that fits a code box at the font size of 9.5 pt. The font is
/// never made smaller (tried on 20.11.2026: long commands became too small to read) – long
/// commands are written as short commands in ANLEITUNG.md where that reads well; a line that
/// is still longer wraps at a space, in the normal font size. A test keeps the configuration
/// samples within this width and the commands within `BOX_CHARS_MAX`.
const BOX_CHARS: usize = 92;
const BOX_FONT: f32 = 9.5;
const BOX_FONT_MIN: f32 = 9.5;
/// Longest command line the guide may contain (it then wraps once).
#[cfg(test)]
const BOX_CHARS_MAX: usize = 145;

/// Font size for a code box whose longest line has `longest` characters, and whether every
/// line fits then (false: longer than even the smallest font allows – such a box wraps).
fn box_font(longest: usize) -> (f32, bool) {
    if longest <= BOX_CHARS {
        return (BOX_FONT, true);
    }
    // Rounded down to tenths so the line surely fits.
    let pt = (BOX_FONT * BOX_CHARS as f32 / longest as f32 * 10.0).floor() / 10.0;
    if pt >= BOX_FONT_MIN { (pt, true) } else { (BOX_FONT_MIN, false) }
}

/// How the lines of a PowerShell command box begin (configuration samples begin with
/// `[abschnitt]` or `name = …` and are left alone).
const COMMAND_STARTS: &[&str] = &[
    "cd ", ".\\", "& ", "$", "claude ", "powershell", "git ", "cargo ", "winget ", "Get-", "Set-", "Remove-", "Start-", "Stop-", "New-", "Restart-",
    "Unblock-", "Copy-", "Test-", "Where-", "Select-", "ForEach-", "Sort-", "[Environment]", "k9 ", "k9-agent", "sc.exe", "sc ", "schtasks", "reg ", "icacls", "notepad", "explorer",
];

/// A box with several PowerShell commands, one per line.
fn is_command_box(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    lines.len() >= 2 && lines.iter().all(|l| COMMAND_STARTS.iter().any(|s| l.starts_with(s)))
}

/// Some PDF programs drop the line breaks when several lines are copied: the commands then
/// arrive glued together in one line and do not run. A semicolon at the end of each line
/// (PowerShell's separator between commands) keeps the box working both ways – pasted as
/// several lines or as one.
fn with_separators(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let last = lines.iter().rposition(|l| !l.trim().is_empty()).unwrap_or(0);
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            let t = l.trim_end();
            // No separator where PowerShell reads on by itself: the command goes on in the next line.
            if i < last && !t.is_empty() && !t.ends_with([';', '{', '|', '`', ',', '(', '+']) { format!("{t};") } else { t.to_string() }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn code_box(text: &str) -> String {
    let text = text.trim_end_matches(['\r', '\n']);
    let joined;
    let text = if is_command_box(text) {
        joined = with_separators(text);
        joined.as_str()
    } else {
        text
    };
    let longest = text.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    let (pt, fits) = box_font(longest);
    let class = if fits { "einzeilig" } else { "umbruch" };
    // Every line is a paragraph of its own: PDF programs put a line break between paragraphs
    // when text is copied, but often none between the lines of one preformatted block.
    let lines: String = text.lines().map(|l| if l.trim().is_empty() { "<p>&nbsp;</p>".to_string() } else { format!("<p><code>{}</code></p>", esc(l)) }).collect();
    format!("<div class=\"kasten {class}\" style=\"font-size:{pt}pt\">{lines}</div>\n")
}

fn convert(md: &str) -> (String, String, String) {
    let events: Vec<Event> = Parser::new_ext(md, Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH).collect();
    let mut out: Vec<Event> = Vec::new();
    let mut toc = String::new();
    let mut title = String::new();
    let mut i = 0;
    let mut n = 0;
    while i < events.len() {
        if let Event::Start(Tag::Heading { level, .. }) = &events[i] {
            let level = *level;
            let mut text = String::new();
            let mut j = i + 1;
            while !matches!(events[j], Event::End(TagEnd::Heading(_))) {
                if let Event::Text(t) | Event::Code(t) = &events[j] {
                    text.push_str(t);
                }
                j += 1;
            }
            n += 1;
            if n == 1 && level == HeadingLevel::H1 {
                title = text; // title page
                i = j + 1;
                continue;
            }
            let id = slug(&text, n);
            match level {
                HeadingLevel::H1 => toc.push_str(&format!("<li class=\"teil\"><a href=\"#{id}\">{}</a></li>", esc(&text))),
                HeadingLevel::H2 => toc.push_str(&format!("<li class=\"kap\"><a href=\"#{id}\">{}</a></li>", esc(&text))),
                _ => {}
            }
            let tag = match level {
                HeadingLevel::H1 => "h1",
                HeadingLevel::H2 => "h2",
                HeadingLevel::H3 => "h3",
                HeadingLevel::H4 => "h4",
                HeadingLevel::H5 => "h5",
                HeadingLevel::H6 => "h6",
            };
            out.push(Event::Html(CowStr::from(format!("<{tag} id=\"{id}\">"))));
            out.extend(events[i + 1..j].iter().cloned());
            out.push(Event::Html(CowStr::from(format!("</{tag}>"))));
            i = j + 1;
            continue;
        }
        // Code boxes (commands to copy): every line stays ONE line in the PDF. A line that is
        // wrapped in the PDF is copied as two lines – pasted into PowerShell the command breaks
        // apart. So the font of a box shrinks until its longest line fits.
        if let Event::Start(Tag::CodeBlock(_)) = &events[i] {
            let mut text = String::new();
            let mut j = i + 1;
            while !matches!(events[j], Event::End(TagEnd::CodeBlock)) {
                if let Event::Text(t) = &events[j] {
                    text.push_str(t);
                }
                j += 1;
            }
            out.push(Event::Html(CowStr::from(code_box(&text))));
            i = j + 1;
            continue;
        }
        out.push(events[i].clone());
        i += 1;
    }
    let mut body = String::new();
    html::push_html(&mut body, out.into_iter());
    (title, toc, body)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Aufruf: k9-doc <eingabe.md> <ausgabe.html> [Stand]");
        std::process::exit(2);
    }
    let md = std::fs::read_to_string(&args[1]).unwrap_or_else(|e| {
        eprintln!("{} nicht lesbar: {e}", args[1]);
        std::process::exit(1);
    });
    let stand = args.get(3).cloned().unwrap_or_default();
    // The guide must describe exactly this version: newest change-log row = workspace.
    let version = version_for(std::path::Path::new(&args[1]));
    if let Some(logged) = newest_logged_version(&md) {
        if logged != version {
            eprintln!("Änderungsverlauf: die neueste Zeile nennt Version {logged}, das Projekt hat Version {version} – bitte eine Zeile für {version} ergänzen.");
            std::process::exit(3);
        }
    }
    let (title, toc, body) = convert(&md);
    let page = format!(
        "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\"><title>{t}</title><style>{CSS}</style></head><body>\
         <section class=\"titel\"><div class=\"kopf\">{icon}<div class=\"vd\"><span class=\"ver\">Version {v}</span><span class=\"dat\">{d}</span></div></div>\
         <div class=\"untertitel\">{t}</div><div class=\"stand\">{s}</div></section>\
         <nav class=\"inhalt\"><h1>Inhalt</h1><ol>{toc}</ol></nav>{body}</body></html>",
        t = esc(&title),
        icon = icon(),
        v = esc(&version),
        d = esc(&date_of(&stand)),
        s = esc(&stand),
    );
    if let Err(e) = std::fs::write(&args[2], page) {
        eprintln!("{} nicht schreibbar: {e}", args[2]);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comes_from_the_workspace() {
        let toml = "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"9.8.7\"\nedition = \"2021\"\n\n[package]\nversion = \"1.0.0\"\n";
        assert_eq!(workspace_version(toml).as_deref(), Some("9.8.7"));
        assert_eq!(workspace_version("[package]\nversion = \"1.0.0\"\n"), None);
        // the real workspace next to docs/ANLEITUNG.md
        let md = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ANLEITUNG.md");
        assert_eq!(version_for(&md), env!("CARGO_PKG_VERSION"));
        // and from a copy in a sub folder of target (as the PDF script uses it)
        let sub = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/anleitung/x.md");
        assert_eq!(version_for(&sub), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn change_log_must_name_the_current_version() {
        let md = "| Datum | Änderung |\n|---|---|\n| 16.11.2026 | **Version 0.4.3:** neu |\n| 16.11.2026 | **Version 0.4.2:** alt |\n";
        assert_eq!(newest_logged_version(md).as_deref(), Some("0.4.3"));
        assert_eq!(newest_logged_version("ohne"), None);
        // the real guide matches the workspace
        let guide = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ANLEITUNG.md")).unwrap();
        assert_eq!(newest_logged_version(&guide).as_deref(), Some(env!("CARGO_PKG_VERSION")), "neueste Zeile im Änderungsverlauf = Projektversion");
    }

    #[test]
    fn code_boxes_keep_every_command_on_one_line() {
        assert_eq!(box_font(40), (9.5, true));
        assert_eq!(box_font(90), (9.5, true));
        assert_eq!(box_font(92), (9.5, true));
        assert_eq!(box_font(93), (9.5, false), "die Schrift wird nie kleiner: laengere Zeilen brechen um");
        assert_eq!(box_font(300), (9.5, false));
        let html = code_box("cd \"D:\\Projekte\"\r\n.\\k9.exe status\r\n");
        assert!(html.starts_with("<div class=\"kasten einzeilig\" style=\"font-size:9.5pt\"><p><code>cd &quot;D:"), "{html}");
        assert!(html.contains("status</code></p></div>"), "ohne Leerzeile am Ende: {html}");
        assert_eq!(html.matches("<p>").count(), 2, "jede Zeile ein eigener Absatz: {html}");
        let (_, _, body) = convert("# T\n\n## A\n\n```\n.\\k9.exe scan\n```\n");
        assert!(body.contains("<div class=\"kasten einzeilig\""), "{body}");
        assert!(body.contains("k9.exe scan</code>"), "ein einzelner Befehl bleibt unveraendert: {body}");
    }

    #[test]
    fn the_guide_has_no_code_line_that_is_too_long() {
        // Long commands are split by hand where PowerShell reads on by itself (after a comma
        // inside parentheses, after a pipe); long comments of settings go above the setting.
        let md = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/ANLEITUNG.md")).unwrap();
        let mut inside = false;
        let mut too_long = Vec::new();
        for (nr, line) in md.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                inside = !inside;
            } else if inside {
                // Settings (name = value # comment) must fit; a command may wrap once.
                let setting = line.contains(" = ") && !line.trim_start().starts_with(['$', '[', '&', '.']);
                let limit = if setting { BOX_CHARS } else { BOX_CHARS_MAX };
                if line.chars().count() > limit {
                    too_long.push(format!("Zeile {}: {} Zeichen (erlaubt {limit})", nr + 1, line.chars().count()));
                }
            }
        }
        assert!(too_long.is_empty(), "zu lange Zeilen in Befehlskaesten: {too_long:?}");
    }

    #[test]
    fn commands_split_over_lines_get_no_separator_inside() {
        let pipe = "Get-CimInstance -ClassName AntiVirusProduct |\n    Where-Object displayName -like 'X*' |\n    Remove-CimInstance\nGet-Date";
        assert!(is_command_box(pipe));
        assert_eq!(with_separators(pipe), "Get-CimInstance -ClassName AntiVirusProduct |\n    Where-Object displayName -like 'X*' |\n    Remove-CimInstance;\nGet-Date");
        // One command over three lines inside parentheses: not touched at all.
        let call = "[Environment]::SetEnvironmentVariable(\"Path\",\n    [Environment]::GetEnvironmentVariable(\"Path\",\"User\") + \";x\",\n    \"User\")";
        assert!(!code_box(call).contains(";</code>"), "{}", code_box(call));
        assert!(!code_box(call).contains(",;"));
    }

    #[test]
    fn several_commands_in_a_box_survive_copying_without_line_breaks() {
        let three = "cd \"C:\\K9-Quelltext\"\n$env:Path += \";$env:USERPROFILE\\.local\\bin\"\nclaude remote-control";
        assert!(is_command_box(three));
        assert_eq!(with_separators(three), "cd \"C:\\K9-Quelltext\";\n$env:Path += \";$env:USERPROFILE\\.local\\bin\";\nclaude remote-control");
        // Glued together (as some PDF programs copy it) it is still three commands.
        assert_eq!(with_separators(three).replace('\n', ""), "cd \"C:\\K9-Quelltext\";$env:Path += \";$env:USERPROFILE\\.local\\bin\";claude remote-control");
        // Configuration samples and single commands are not touched.
        assert!(!is_command_box("[meldungen]\nkanaele = [\"fenster\"]\nspaeter_minuten = 60"));
        assert!(!is_command_box(".\\k9.exe status"));
        assert!(is_command_box("winget install Cisco.ClamAV\ncd \"C:\\Program Files\\K9\"\n.\\k9.exe quellen aktualisieren clamav"));
        let html = code_box("[scan]\nausnahmen = []\n");
        assert!(!html.contains(';'), "{html}");
        let html = code_box("cd \"C:\\Program Files\\K9\"\n.\\k9.exe dashboard\n");
        assert!(html.contains("K9&quot;;</code></p><p><code>.\\k9.exe dashboard</code>"), "{html}");
    }

    #[test]
    fn title_page_shows_version_and_date() {
        assert_eq!(date_of("Stand: 16.11.2026 10:05 · Programmstand 9e8c686"), "16.11.2026");
        assert_eq!(date_of("ohne Datum"), "");
        let i = icon();
        assert!(i.starts_with("<svg") && i.contains(r#"aria-label="K9""#) && !i.contains("<title>"));
    }

    #[test]
    fn title_page_table_of_contents_and_anchors() {
        let (title, toc, body) = convert("# K9 – Anleitung\n\nText\n\n# Teil 1 – Kurz\n\n## Wichtige Abläufe\n\n### Unter\n");
        assert_eq!(title, "K9 – Anleitung");
        assert!(toc.contains("<li class=\"teil\"><a href=\"#teil-1-kurz-2\">Teil 1 – Kurz</a></li>"), "{toc}");
        assert!(toc.contains("href=\"#wichtige-ablaeufe-3\""), "{toc}");
        assert!(!toc.contains("Unter"));
        assert!(body.contains("<h2 id=\"wichtige-ablaeufe-3\">Wichtige Abläufe</h2>"), "{body}");
        assert!(!body.contains("K9 – Anleitung"));
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
    }
}
