//! Sigma rules (SigmaHQ) for process starts.
//!
//! Sigma is an open collection of detection rules written for SIEM systems. K9 reads the
//! rules of the category "process creation" for Windows and checks every process start
//! against them. Only what K9 knows about a start can be answered: the program (`Image`),
//! its command line, the starting program (`ParentImage`) and – if available – that one's
//! command line. Conditions on other fields (`OriginalFileName`, `Hashes`, `User` …) are
//! *unknown*; the evaluation is three-valued, so a rule fires only when it is certainly
//! true: "Image or OriginalFileName" still works, a filter K9 cannot check never
//! switches a rule on.
//!
//! Licence of the rules: Detection Rule License 1.1 – every message based on a rule must
//! name the rule's author, so the author travels with every hit.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};
use yaml_rust2::{Yaml, YamlLoader};

/// What K9 knows about a process start. Paths as Windows reports them; if only a file
/// name is known it is given as `\name.exe` (the rules compare the end of the path).
#[derive(Debug, Clone, Copy, Default)]
pub struct Event<'a> {
    pub image: &'a str,
    pub command_line: &'a str,
    pub parent_image: &'a str,
    pub parent_command_line: Option<&'a str>,
}

/// One rule that K9 can evaluate.
#[derive(Debug)]
pub struct Rule {
    pub id: String,
    pub title: String,
    /// Authors as written in the rule (must be shown with every hit – DRL 1.1).
    pub author: String,
    /// "high" or "critical" in the core package.
    pub level: String,
    selections: Vec<(String, Selection)>,
    condition: Cond,
}

/// The rules of one package and what was left out.
#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    /// Rules of the category that K9 cannot evaluate (unsupported modifier, keyword search …).
    pub skipped: usize,
    /// Rules that come from the add-on "Emerging Threats".
    pub addon: usize,
    /// Rules that are loaded but can never fire: every way to fulfil their condition needs a
    /// field K9 has no value for (OriginalFileName, IntegrityLevel, Hashes, User …).
    pub dormant: usize,
}

/// Which results an expression can have at all – as bits, for `Rule::can_fire`.
const CAN_T: u8 = 1;
const CAN_F: u8 = 2;
const CAN_U: u8 = 4;

fn each(set: u8) -> impl Iterator<Item = Tri> {
    [(CAN_T, Tri::True), (CAN_F, Tri::False), (CAN_U, Tri::Unknown)].into_iter().filter(move |(b, _)| set & b != 0).map(|(_, t)| t)
}

fn bit(t: Tri) -> u8 {
    match t {
        Tri::True => CAN_T,
        Tri::False => CAN_F,
        Tri::Unknown => CAN_U,
    }
}

/// All results `op` can give for operands out of `a` and `b`.
fn combine(a: u8, b: u8, op: fn(Tri, Tri) -> Tri) -> u8 {
    each(a).flat_map(|x| each(b).map(move |y| bit(op(x, y)))).fold(0, |acc, v| acc | v)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    fn and(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::False, _) | (_, Tri::False) => Tri::False,
            (Tri::True, Tri::True) => Tri::True,
            _ => Tri::Unknown,
        }
    }
    fn or(self, o: Tri) -> Tri {
        match (self, o) {
            (Tri::True, _) | (_, Tri::True) => Tri::True,
            (Tri::False, Tri::False) => Tri::False,
            _ => Tri::Unknown,
        }
    }
    fn not(self) -> Tri {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        }
    }
    fn of(b: bool) -> Tri {
        if b {
            Tri::True
        } else {
            Tri::False
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Field {
    Image,
    CommandLine,
    ParentImage,
    ParentCommandLine,
    /// A field K9 has no value for.
    Other,
}

#[derive(Debug)]
enum Pattern {
    /// No wildcard inside: plain comparison on the lower-cased text.
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Equals(String),
    /// With `*` / `?`.
    Glob(Vec<Tok>),
    Regex(regex::Regex),
    /// `field: null` or `field: ''` – the field is empty.
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Lit(char),
    Star,
    Any,
}

#[derive(Debug)]
struct Item {
    field: Field,
    patterns: Vec<Pattern>,
    /// `|all`: every value must match (otherwise one is enough).
    all: bool,
}

/// A named part of `detection`: a list of alternatives, each a set of conditions that must all hold.
#[derive(Debug)]
struct Selection(Vec<Vec<Item>>);

#[derive(Debug)]
enum Cond {
    Sel(usize),
    Not(Box<Cond>),
    And(Vec<Cond>),
    Or(Vec<Cond>),
    OneOf(Vec<usize>),
    AllOf(Vec<usize>),
}

/// Windows also writes a path as `\??\C:\…` or `\\?\C:\…` (conhost.exe is started that way,
/// and K9 then takes the program path from the command line). The rules expect the plain
/// form – without this every console window raised "System File Execution Location Anomaly"
/// (seen on 21.11.2026).
fn plain(text: &str) -> String {
    for prefix in ["\\??\\", "\\\\?\\"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            return rest.to_string();
        }
        // The same inside quotes at the start of a command line.
        if let Some(rest) = text.strip_prefix('"').and_then(|t| t.strip_prefix(prefix)) {
            return format!("\"{rest}");
        }
    }
    text.to_string()
}

/// Does the path name a folder (`C:\…` or `\\server\…`)? K9 often knows only the file name of
/// a program – of every starter, and of a program that ended before its path could be read.
fn has_folder(path: &str) -> bool {
    let b = path.as_bytes();
    (b.len() > 2 && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || path.starts_with("\\\\")
}

/// The event in plain form, as written and lower-cased (the rules compare without regard to case).
struct Prepared {
    image: (String, String),
    command_line: (String, String),
    parent_image: (String, String),
    parent_command_line: Option<(String, String)>,
    /// The folder of the program / of its starter is known (not only the file name).
    image_folder: bool,
    parent_folder: bool,
}

impl Prepared {
    fn new(ev: &Event) -> Self {
        let both = |s: &str| {
            let p = plain(s);
            (p.to_lowercase(), p)
        };
        // A bare file name is written as `\name.exe`: the rules compare the end of the path.
        // Windows also accepts `/` in a program path (OBS starts `C:/OBS/bin/64bit/…`, #558,
        // 24.11.2026); the rules compare with `\`, so the path is written the Windows way.
        let program = |s: &str| {
            let p = plain(s).replace('/', "\\");
            let p = if p.is_empty() || has_folder(&p) || p.starts_with('\\') { p } else { format!("\\{p}") };
            (has_folder(&p), (p.to_lowercase(), p))
        };
        let (image_folder, image) = program(ev.image);
        let (parent_folder, parent_image) = program(ev.parent_image);
        Prepared { image, command_line: both(ev.command_line), parent_image, parent_command_line: ev.parent_command_line.map(both), image_folder, parent_folder }
    }

    /// False if only the file name of this program field is known: conditions about its
    /// folder then stay undecided (seen on 21.11.2026: "git.exe" without a path made the
    /// rule "Execution Of Non-Existing File" fire for every short-lived program).
    fn folder_known(&self, f: Field) -> bool {
        match f {
            Field::Image => self.image_folder,
            Field::ParentImage => self.parent_folder,
            _ => true,
        }
    }

    /// (lower-cased, original) or `None` if K9 does not know the field.
    fn value(&self, f: Field) -> Option<(&str, &str)> {
        fn pair(p: &(String, String)) -> (&str, &str) {
            (p.0.as_str(), p.1.as_str())
        }
        match f {
            Field::Image => Some(pair(&self.image)),
            Field::CommandLine => Some(pair(&self.command_line)),
            Field::ParentImage => Some(pair(&self.parent_image)),
            Field::ParentCommandLine => self.parent_command_line.as_ref().map(pair),
            Field::Other => None,
        }
    }
}

impl Pattern {
    fn matches(&self, lower: &str, original: &str) -> bool {
        match self {
            Pattern::Contains(v) => lower.contains(v.as_str()),
            Pattern::StartsWith(v) => lower.starts_with(v.as_str()),
            Pattern::EndsWith(v) => lower.ends_with(v.as_str()),
            Pattern::Equals(v) => lower == v,
            Pattern::Glob(toks) => glob(toks, &lower.chars().collect::<Vec<_>>()),
            Pattern::Regex(re) => re.is_match(original),
            Pattern::Empty => lower.is_empty(),
        }
    }
}

/// `*` = any run of characters, `?` = exactly one.
fn glob(pat: &[Tok], text: &[char]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut back: Option<(usize, usize)> = None;
    while t < text.len() {
        match pat.get(p) {
            Some(Tok::Star) => {
                back = Some((p, t));
                p += 1;
            }
            Some(Tok::Any) => {
                p += 1;
                t += 1;
            }
            Some(Tok::Lit(c)) if *c == text[t] => {
                p += 1;
                t += 1;
            }
            _ => match back {
                Some((bp, bt)) => {
                    p = bp + 1;
                    t = bt + 1;
                    back = Some((bp, bt + 1));
                }
                None => return false,
            },
        }
    }
    pat[p..].iter().all(|x| *x == Tok::Star)
}

/// Sigma value -> tokens. A backslash is a plain character unless it stands before a
/// wildcard (`\*` = a real star) – and `\\*` is a real backslash followed by a wildcard.
fn tokens(value: &str) -> Vec<Tok> {
    let c: Vec<char> = value.chars().collect();
    let mut out = Vec::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '\\' if matches!(c.get(i + 1), Some('*') | Some('?')) => {
                out.push(Tok::Lit(c[i + 1]));
                i += 2;
            }
            '\\' if c.get(i + 1) == Some(&'\\') && matches!(c.get(i + 2), Some('*') | Some('?')) => {
                out.push(Tok::Lit('\\'));
                i += 2;
            }
            '*' => {
                out.push(Tok::Star);
                i += 1;
            }
            '?' => {
                out.push(Tok::Any);
                i += 1;
            }
            x => {
                out.extend(x.to_lowercase().map(Tok::Lit));
                i += 1;
            }
        }
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

fn pattern(value: &str, shape: Shape) -> Pattern {
    let toks = tokens(value);
    if toks.iter().all(|t| matches!(t, Tok::Lit(_))) {
        let s: String = toks.iter().map(|t| if let Tok::Lit(c) = t { *c } else { ' ' }).collect();
        return match shape {
            Shape::Equals if s.is_empty() => Pattern::Empty,
            Shape::Equals => Pattern::Equals(s),
            Shape::Contains => Pattern::Contains(s),
            Shape::StartsWith => Pattern::StartsWith(s),
            Shape::EndsWith => Pattern::EndsWith(s),
        };
    }
    let mut g = Vec::with_capacity(toks.len() + 2);
    if matches!(shape, Shape::Contains | Shape::EndsWith) {
        g.push(Tok::Star);
    }
    g.extend(toks);
    if matches!(shape, Shape::Contains | Shape::StartsWith) {
        g.push(Tok::Star);
    }
    Pattern::Glob(g)
}

/// `windash`: a parameter written with `-` is also accepted with `/` and the typographic dashes.
fn windash(value: &str) -> Vec<String> {
    let c: Vec<char> = value.chars().collect();
    // A dash at the start of a word: nothing or a non-word character before it, a word character after it.
    let word = |x: Option<&char>| x.is_some_and(|c| c.is_alphanumeric() || *c == '_');
    let spots: Vec<usize> = (0..c.len()).filter(|&i| (c[i] == '-' || c[i] == '/') && !word(i.checked_sub(1).and_then(|j| c.get(j))) && word(c.get(i + 1))).collect();
    if spots.is_empty() {
        return vec![value.to_string()];
    }
    ['-', '/', '\u{2013}', '\u{2014}', '\u{2015}']
        .iter()
        .map(|dash| {
            let mut v = c.clone();
            for &i in &spots {
                v[i] = *dash;
            }
            v.into_iter().collect::<String>()
        })
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn field_of(name: &str) -> Field {
    match name {
        "Image" => Field::Image,
        "CommandLine" => Field::CommandLine,
        "ParentImage" => Field::ParentImage,
        "ParentCommandLine" => Field::ParentCommandLine,
        _ => Field::Other,
    }
}

fn scalar(y: &Yaml) -> Result<Option<String>> {
    Ok(match y {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Integer(i) => Some(i.to_string()),
        Yaml::Real(r) => Some(r.clone()),
        Yaml::Boolean(b) => Some(b.to_string()),
        Yaml::Null => None,
        other => bail!("Wert nicht unterstützt: {other:?}"),
    })
}

/// `Field|mod1|mod2: value(s)`.
fn item(key: &str, value: &Yaml) -> Result<Item> {
    let mut parts = key.split('|');
    let name = parts.next().unwrap_or("");
    let mods: Vec<&str> = parts.collect();
    let field = field_of(name);
    let values: Vec<Option<String>> = match value {
        Yaml::Array(a) => a.iter().map(scalar).collect::<Result<_>>()?,
        other => vec![scalar(other)?],
    };
    let mut shape = Shape::Equals;
    let (mut all, mut dash, mut re) = (false, false, false);
    let mut flags = String::new();
    for m in &mods {
        match *m {
            "contains" => shape = Shape::Contains,
            "startswith" => shape = Shape::StartsWith,
            "endswith" => shape = Shape::EndsWith,
            "all" => all = true,
            "windash" => dash = true,
            "re" => re = true,
            "i" | "m" | "s" if re => flags.push_str(m),
            other => bail!("Modifikator „{other}“ wird nicht unterstützt"),
        }
    }
    let mut patterns = Vec::new();
    for v in values {
        let Some(v) = v else {
            patterns.push(Pattern::Empty);
            continue;
        };
        if re {
            let src = if flags.is_empty() { v } else { format!("(?{flags}){v}") };
            // A field K9 cannot answer needs no working expression: it stays unknown.
            match regex::Regex::new(&src) {
                Ok(r) => patterns.push(Pattern::Regex(r)),
                Err(_) if field == Field::Other => patterns.push(Pattern::Empty),
                Err(e) => bail!("regulärer Ausdruck nicht unterstützt: {e}"),
            }
            continue;
        }
        let variants = if dash { windash(&v) } else { vec![v] };
        if dash && all && variants.len() > 1 {
            bail!("„windash“ zusammen mit „all“ wird nicht unterstützt");
        }
        patterns.extend(variants.iter().map(|x| pattern(x, shape)));
    }
    if patterns.is_empty() {
        bail!("Bedingung ohne Wert");
    }
    Ok(Item { field, patterns, all })
}

fn selection(y: &Yaml) -> Result<Selection> {
    let one = |h: &Yaml| -> Result<Vec<Item>> {
        let Yaml::Hash(h) = h else { bail!("Schlüsselwortsuche wird nicht unterstützt") };
        h.iter().map(|(k, v)| item(k.as_str().context("Feldname fehlt")?, v)).collect()
    };
    Ok(Selection(match y {
        Yaml::Array(a) => a.iter().map(one).collect::<Result<_>>()?,
        other => vec![one(other)?],
    }))
}

impl Item {
    fn eval(&self, p: &Prepared) -> Tri {
        let Some((lower, original)) = p.value(self.field) else { return Tri::Unknown };
        let folder = p.folder_known(self.field);
        let each = self.patterns.iter().map(|x| if folder || x.needs_no_folder() { Tri::of(x.matches(lower, original)) } else { Tri::Unknown });
        if self.all {
            each.fold(Tri::True, Tri::and)
        } else {
            each.fold(Tri::False, Tri::or)
        }
    }
}

impl Pattern {
    /// Can this be decided when only the file name (`\name.exe`) is known? Only a comparison
    /// of the end of the path with a bare file name can; everything that looks at the folder
    /// (start of the path, "contains a backslash", wildcards …) cannot.
    fn needs_no_folder(&self) -> bool {
        match self {
            Pattern::EndsWith(v) | Pattern::Equals(v) => {
                let name = v.strip_prefix('\\').unwrap_or(v);
                !name.is_empty() && !name.contains(['\\', '/'])
            }
            _ => false,
        }
    }
}

impl Selection {
    fn eval(&self, p: &Prepared) -> Tri {
        self.0.iter().fold(Tri::False, |acc, alt| acc.or(alt.iter().fold(Tri::True, |a, i| a.and(i.eval(p)))))
    }
}

impl Cond {
    fn eval(&self, sel: &[Tri]) -> Tri {
        match self {
            Cond::Sel(i) => sel[*i],
            Cond::Not(c) => c.eval(sel).not(),
            Cond::And(v) => v.iter().fold(Tri::True, |a, c| a.and(c.eval(sel))),
            Cond::Or(v) => v.iter().fold(Tri::False, |a, c| a.or(c.eval(sel))),
            Cond::OneOf(v) => v.iter().fold(Tri::False, |a, i| a.or(sel[*i])),
            Cond::AllOf(v) => v.iter().fold(Tri::True, |a, i| a.and(sel[*i])),
        }
    }
}

/// The package inside the sources folder (as published by SigmaHQ).
pub const PACKAGE_FILE: &str = "sigma/sigma_core.zip";
/// The add-on "Emerging Threats" of the same release: rules for current attack waves and
/// exploited vulnerabilities. Used with the levels high and critical, like the package "core".
pub const ADDON_FILE: &str = "sigma/sigma_emerging_threats_addon.zip";

type Cached = (Instant, Option<SystemTime>, Option<Arc<RuleSet>>);

/// The rule set of the sources folder. Looks at the package file at most once a minute and
/// reads it again only when it has changed; `None` while there is no (readable) package.
pub fn live(sources_dir: &Path) -> Option<Arc<RuleSet>> {
    static CACHE: Mutex<Option<Cached>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((checked, _, set)) = cache.as_ref() {
        if checked.elapsed() < Duration::from_secs(60) {
            return set.clone();
        }
    }
    let path = sources_dir.join(PACKAGE_FILE);
    let addon = sources_dir.join(ADDON_FILE);
    let stamp = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    // The newer of both files: a renewed add-on alone is a change as well.
    let changed = stamp(&path).map(|core| stamp(&addon).map_or(core, |a| a.max(core)));
    let set = match cache.take() {
        Some((_, old, set)) if old == changed => set,
        _ => changed.and_then(|_| std::fs::read(&path).ok()).and_then(|data| match RuleSet::from_packages(&data, std::fs::read(&addon).ok().as_deref()) {
            Ok(set) => {
                tracing::info!(
                    "Sigma-Regeln geladen: {} für Programmstarts ({} davon aus dem Zusatzpaket „Emerging Threats“; {} können mit den Angaben von K9 nie auslösen), {} nicht auswertbar",
                    set.rules.len(),
                    set.addon,
                    set.dormant,
                    set.skipped
                );
                Some(Arc::new(set))
            }
            Err(e) => {
                tracing::warn!("Sigma-Regeln nicht lesbar: {e:#}");
                None
            }
        }),
    };
    *cache = Some((Instant::now(), changed, set.clone()));
    set
}

/// The Sigma rules LOLBAS refers to (see `sources::update_lolbas`): a JSON list of rule texts.
pub const LOLBAS_FILE: &str = "lolbas/lolbas_sigma.json";

/// The LOLBAS rule set of the sources folder; like `live`, with a cache of its own.
pub fn live_lolbas(sources_dir: &Path) -> Option<Arc<RuleSet>> {
    static CACHE: Mutex<Option<Cached>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((checked, _, set)) = cache.as_ref() {
        if checked.elapsed() < Duration::from_secs(60) {
            return set.clone();
        }
    }
    let path = sources_dir.join(LOLBAS_FILE);
    let changed = std::fs::metadata(&path).and_then(|m| m.modified()).ok();
    let set = match cache.take() {
        Some((_, old, set)) if old == changed => set,
        _ => changed.and_then(|_| std::fs::read(&path).ok()).and_then(|data| {
            let texts: Vec<String> = serde_json::from_slice(&data).ok()?;
            let set = RuleSet::from_texts(texts.iter().map(|s| s.as_str()));
            tracing::info!("LOLBAS-Regeln geladen: {} für Programmstarts ({} davon können nie auslösen)", set.rules.len(), set.dormant);
            Some(Arc::new(set))
        }),
    };
    *cache = Some((Instant::now(), changed, set.clone()));
    set
}

/// Rule id, text and severity for a hit of a LOLBAS rule. These rules have the Sigma level
/// "medium": they fire more often on harmless things, so the message is Mittel and – for the
/// time being – only shown quietly in the dashboard (`LOLBAS_QUIET`).
pub fn lolbas_finding_parts(rule: &Rule) -> (String, String, crate::model::Severity) {
    (format!("SIGMA:LOLBAS:{}", rule.id), format!("LOLBAS-Regel „{}“ (Sigma, Autor: {})", rule.title, rule.author), crate::model::Severity::Mittel)
}

/// Why a LOLBAS hit is only shown quietly.
pub const LOLBAS_QUIET: &str = "LOLBAS-Regel der Stufe „mittel“ – in der Probephase nur leise im Dashboard";

/// Rule id, text and severity of the K9 message for a hit. The text names the author (DRL 1.1).
/// Sigma rules are general heuristics: "critical" becomes Hoch, "high" Mittel – never
/// Kritisch, which would freeze the program when "Kritische Programme anhalten" is on.
pub fn finding_parts(rule: &Rule) -> (String, String, crate::model::Severity) {
    (
        format!("SIGMA:{}", rule.id),
        format!("Sigma-Regel „{}“ (Autor: {})", rule.title, rule.author),
        if rule.is_critical() { crate::model::Severity::Hoch } else { crate::model::Severity::Mittel },
    )
}

// ---------------------------------------------------------------- condition parser

struct Parser<'a> {
    toks: Vec<&'a str>,
    pos: usize,
    names: &'a [String],
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<&'a str> {
        self.toks.get(self.pos).copied()
    }
    fn next(&mut self) -> Option<&'a str> {
        let t = self.toks.get(self.pos).copied();
        self.pos += 1;
        t
    }
    fn or(&mut self) -> Result<Cond> {
        let mut v = vec![self.and()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("or")) {
            self.pos += 1;
            v.push(self.and()?);
        }
        Ok(if v.len() == 1 { v.pop().unwrap() } else { Cond::Or(v) })
    }
    fn and(&mut self) -> Result<Cond> {
        let mut v = vec![self.unary()?];
        while self.peek().is_some_and(|t| t.eq_ignore_ascii_case("and")) {
            self.pos += 1;
            v.push(self.unary()?);
        }
        Ok(if v.len() == 1 { v.pop().unwrap() } else { Cond::And(v) })
    }
    fn group(&self, pattern: &str) -> Result<Vec<usize>> {
        let toks = tokens(pattern);
        let v: Vec<usize> = self
            .names
            .iter()
            .enumerate()
            .filter(|(_, n)| if pattern == "them" { !n.starts_with('_') } else { glob(&toks, &n.to_lowercase().chars().collect::<Vec<_>>()) })
            .map(|(i, _)| i)
            .collect();
        if v.is_empty() {
            bail!("„{pattern}“ trifft keinen Teil der Regel");
        }
        Ok(v)
    }
    fn unary(&mut self) -> Result<Cond> {
        let Some(t) = self.next() else { bail!("Bedingung endet unerwartet") };
        match t.to_ascii_lowercase().as_str() {
            "not" => Ok(Cond::Not(Box::new(self.unary()?))),
            "(" => {
                let c = self.or()?;
                if self.next() != Some(")") {
                    bail!("schließende Klammer fehlt");
                }
                Ok(c)
            }
            q @ ("1" | "any" | "all") => {
                if !self.next().is_some_and(|t| t.eq_ignore_ascii_case("of")) {
                    bail!("„of“ erwartet");
                }
                let pat = self.next().context("Name nach „of“ fehlt")?.to_string();
                let g = self.group(&pat)?;
                Ok(if q == "all" { Cond::AllOf(g) } else { Cond::OneOf(g) })
            }
            ")" | "and" | "or" | "of" => bail!("unerwartetes „{t}“"),
            _ => {
                if t.contains('|') {
                    bail!("Zählbedingungen werden nicht unterstützt");
                }
                let i = self.names.iter().position(|n| n == t).with_context(|| format!("„{t}“ ist kein Teil der Regel"))?;
                Ok(Cond::Sel(i))
            }
        }
    }
}

fn condition(text: &str, names: &[String]) -> Result<Cond> {
    let spaced = text.replace('(', " ( ").replace(')', " ) ");
    let mut p = Parser { toks: spaced.split_whitespace().collect(), pos: 0, names };
    let c = p.or()?;
    if p.pos != p.toks.len() {
        bail!("Bedingung nicht vollständig lesbar");
    }
    Ok(c)
}

// ---------------------------------------------------------------- rules

/// `Ok(None)`: a valid rule of another category (not a Windows process start).
pub fn parse_rule(text: &str) -> Result<Option<Rule>> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| anyhow::anyhow!("YAML nicht lesbar: {e}"))?;
    let doc = docs.first().context("leere Regel")?;
    let src = &doc["logsource"];
    if src["category"].as_str() != Some("process_creation") || src["product"].as_str() != Some("windows") {
        return Ok(None);
    }
    let det = doc["detection"].as_hash().context("„detection“ fehlt")?;
    let mut selections = Vec::new();
    let mut cond_text = None;
    for (k, v) in det {
        let name = k.as_str().context("Name in „detection“ fehlt")?;
        match name {
            "condition" => {
                cond_text = Some(match v {
                    Yaml::String(s) => s.clone(),
                    // Several conditions: one of them is enough.
                    Yaml::Array(a) => a.iter().filter_map(|x| x.as_str()).map(|s| format!("({s})")).collect::<Vec<_>>().join(" or "),
                    _ => bail!("Bedingung nicht lesbar"),
                })
            }
            "timeframe" => bail!("Zeitfenster werden nicht unterstützt"),
            _ => selections.push((name.to_string(), selection(v).with_context(|| format!("Teil „{name}“"))?)),
        }
    }
    let names: Vec<String> = selections.iter().map(|(n, _)| n.clone()).collect();
    let condition = condition(&cond_text.context("Bedingung fehlt")?, &names)?;
    let author = match &doc["author"] {
        Yaml::String(s) => s.trim().to_string(),
        Yaml::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
        _ => String::new(),
    };
    Ok(Some(Rule {
        id: doc["id"].as_str().context("Kennung fehlt")?.to_string(),
        title: doc["title"].as_str().context("Titel fehlt")?.trim().to_string(),
        author: if author.is_empty() { "unbekannt (SigmaHQ)".into() } else { author },
        level: doc["level"].as_str().unwrap_or("high").to_string(),
        selections,
        condition,
    }))
}

impl Cond {
    /// Like `eval`, but with the set of possible results of every selection.
    fn possible(&self, sel: &[u8]) -> u8 {
        match self {
            Cond::Sel(i) => sel[*i],
            Cond::Not(c) => each(c.possible(sel)).fold(0, |acc, t| acc | bit(t.not())),
            Cond::And(v) => v.iter().fold(CAN_T, |a, c| combine(a, c.possible(sel), Tri::and)),
            Cond::Or(v) => v.iter().fold(CAN_F, |a, c| combine(a, c.possible(sel), Tri::or)),
            Cond::OneOf(v) => v.iter().fold(CAN_F, |a, i| combine(a, sel[*i], Tri::or)),
            Cond::AllOf(v) => v.iter().fold(CAN_T, |a, i| combine(a, sel[*i], Tri::and)),
        }
    }
}

impl Rule {
    /// Can this rule fire at all with what K9 knows about a process start? A condition on a
    /// field without a value is always undecided; a rule that needs such a condition on every
    /// path to "true" stays silent for ever. (Generous: a condition on a known field counts as
    /// possibly true and possibly false, whatever its patterns are.)
    pub fn can_fire(&self) -> bool {
        let sel: Vec<u8> = self
            .selections
            .iter()
            .map(|(_, s)| {
                s.0.iter().fold(CAN_F, |acc, alt| {
                    let all = alt.iter().fold(CAN_T, |a, i| combine(a, if i.field == Field::Other { CAN_U } else { CAN_T | CAN_F | CAN_U }, Tri::and));
                    combine(acc, all, Tri::or)
                })
            })
            .collect();
        self.condition.possible(&sel) & CAN_T != 0
    }

    fn fires(&self, p: &Prepared) -> bool {
        let sel: Vec<Tri> = self.selections.iter().map(|(_, s)| s.eval(p)).collect();
        self.condition.eval(&sel) == Tri::True
    }
    pub fn is_critical(&self) -> bool {
        self.level == "critical"
    }
}

/// The texts of the rule files of a package whose path contains `folder`.
fn rule_texts(data: &[u8], folder: &str) -> Result<Vec<String>> {
    use std::io::Read;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).context("Sigma-Paket: kein gültiges ZIP-Archiv")?;
    let mut texts = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i)?;
        let Ok(name) = f.name().map(|n| n.replace('\\', "/")) else { continue };
        // Small text files only; a rule has a few kilobytes.
        if !name.contains(folder) || !name.ends_with(".yml") || f.size() > 256 * 1024 {
            continue;
        }
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() {
            texts.push(s);
        }
    }
    Ok(texts)
}

impl RuleSet {
    pub fn from_texts<'a>(texts: impl IntoIterator<Item = &'a str>) -> RuleSet {
        let mut set = RuleSet::default();
        for t in texts {
            match parse_rule(t) {
                Ok(Some(r)) => set.rules.push(r),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("Sigma-Regel ausgelassen: {e:#}");
                    set.skipped += 1;
                }
            }
        }
        // Critical rules first: the first hit names the message.
        set.rules.sort_by_key(|r| !r.is_critical());
        set.dormant = set.rules.iter().filter(|r| !r.can_fire()).count();
        set
    }

    /// Reads a rule package as SigmaHQ publishes it (`sigma_core.zip`): only the rules for
    /// Windows process starts are used.
    pub fn from_zip(data: &[u8]) -> Result<RuleSet> {
        Self::from_packages(data, None)
    }

    /// The package "core" and – if there – the add-on "Emerging Threats" of the same release.
    /// From the add-on only the levels high and critical are taken (as in "core"); a rule that
    /// is in both counts once.
    pub fn from_packages(core: &[u8], addon: Option<&[u8]>) -> Result<RuleSet> {
        let texts = rule_texts(core, "rules/windows/process_creation/")?;
        if texts.is_empty() {
            bail!("Sigma-Paket enthält keine Regeln für Programmstarts");
        }
        let extra: Vec<String> = match addon.map(|a| rule_texts(a, "rules-emerging-threats/")) {
            Some(Ok(t)) => t.into_iter().filter(|t| t.lines().any(|l| matches!(l.trim_end(), "level: high" | "level: critical"))).collect(),
            Some(Err(e)) => {
                tracing::warn!("Sigma-Zusatzpaket nicht lesbar: {e:#}");
                Vec::new()
            }
            None => Vec::new(),
        };
        let mut set = RuleSet::from_texts(texts.iter().map(|s| s.as_str()));
        let known: std::collections::HashSet<String> = set.rules.iter().map(|r| r.id.clone()).collect();
        let more = RuleSet::from_texts(extra.iter().map(|s| s.as_str()));
        set.skipped += more.skipped;
        for r in more.rules {
            if !known.contains(&r.id) {
                set.addon += 1;
                set.rules.push(r);
            }
        }
        set.rules.sort_by_key(|r| !r.is_critical());
        set.dormant = set.rules.iter().filter(|r| !r.can_fire()).count();
        Ok(set)
    }

    /// The rules that fire for this process start, critical ones first.
    pub fn matches(&self, ev: &Event) -> Vec<&Rule> {
        let p = Prepared::new(ev);
        self.rules.iter().filter(|r| r.fires(&p)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_text(detection: &str) -> String {
        format!(
            "title: Testregel\nid: 11111111-2222-3333-4444-555555555555\nstatus: test\nauthor: Erika Muster, Max Beispiel\n\
             logsource:\n    category: process_creation\n    product: windows\ndetection:\n{detection}\nlevel: high\n"
        )
    }

    fn rule(detection: &str) -> Rule {
        parse_rule(&rule_text(detection)).expect("lesbar").expect("Regel für Programmstarts")
    }

    fn fires(r: &Rule, image: &str, cmd: &str, parent: &str) -> bool {
        r.fires(&Prepared::new(&Event { image, command_line: cmd, parent_image: parent, parent_command_line: None }))
    }

    const TOOL: &str = "C:\\Windows\\System32\\certutil.exe";

    #[test]
    fn selections_combine_with_and_or_not_and_ignore_case() {
        let r = rule(
            "    selection_img:\n        Image|endswith: '\\certutil.exe'\n    selection_cli:\n        CommandLine|contains|all:\n            - 'urlcache'\n            - 'http'\n    filter_main:\n        CommandLine|contains: 'intern.example'\n    condition: all of selection_* and not 1 of filter_*",
        );
        assert_eq!((r.author.as_str(), r.level.as_str()), ("Erika Muster, Max Beispiel", "high"));
        assert!(fires(&r, TOOL, "CertUtil -URLCACHE -f HTTP://x.example/a.txt a.txt", ""));
        assert!(!fires(&r, TOOL, "certutil -urlcache -f ftp://x.example/a", ""), "beide Wörter nötig");
        assert!(!fires(&r, "C:\\tools\\other.exe", "x -urlcache http://x", ""), "anderes Programm");
        assert!(!fires(&r, TOOL, "certutil -urlcache http://intern.example/a", ""), "Ausnahme greift");
    }

    #[test]
    fn a_condition_on_an_unknown_field_never_switches_a_rule_on_but_alternatives_still_work() {
        // The usual pattern: the program by its path OR by its original file name.
        let alt = rule("    selection:\n        - Image|endswith: '\\certutil.exe'\n        - OriginalFileName: 'CertUtil.exe'\n    condition: selection");
        assert!(fires(&alt, TOOL, "certutil", ""));
        assert!(!fires(&alt, "C:\\x\\renamed.exe", "renamed", ""), "ob es ein umbenanntes certutil ist, weiß K9 nicht");
        // A rule that depends on a field K9 has no value for stays silent ...
        let only = rule("    selection:\n        Image|endswith: '\\certutil.exe'\n        IntegrityLevel: 'System'\n    condition: selection");
        assert!(!fires(&only, TOOL, "certutil", ""));
        // ... and so does one whose exception K9 cannot check (it might apply).
        let filt = rule("    selection:\n        Image|endswith: '\\certutil.exe'\n    filter:\n        User|contains: 'SYSTEM'\n    condition: selection and not filter");
        assert!(!fires(&filt, TOOL, "certutil", ""));
    }

    #[test]
    fn rules_that_need_a_field_without_a_value_are_counted_as_never_firing() {
        // Needs OriginalFileName on its only path: never.
        assert!(!rule("  sel:\n    OriginalFileName: 'a.exe'\n    CommandLine|contains: 'x'\n  condition: sel").can_fire());
        // An alternative without that field: can fire.
        assert!(rule("  img:\n    Image|endswith: '\\a.exe'\n  orig:\n    OriginalFileName: 'a.exe'\n  cli:\n    CommandLine|contains: 'x'\n  condition: (img or orig) and cli").can_fire());
        // The unknown field only filters ("and not"): the result is never a clear "true".
        assert!(!rule("  sel:\n    Image|endswith: '\\a.exe'\n  filter:\n    User|contains: 'SYSTEM'\n  condition: sel and not filter").can_fire());
        // A filter with an alternative on a known field can be clearly false, the rule can fire.
        assert!(rule("  sel:\n    Image|endswith: '\\a.exe'\n  filter:\n    - User|contains: 'SYSTEM'\n      CommandLine|contains: 'y'\n  condition: sel and not filter").can_fire());
        let (a, b) = (rule_text("  sel:\n    Hashes|contains: 'ab'\n  condition: sel"), rule_text("  sel:\n    Image|endswith: '\\b.exe'\n  condition: sel"));
        let set = RuleSet::from_texts([a.as_str(), b.as_str()]);
        assert_eq!((set.rules.len(), set.dormant), (2, 1));
    }

    #[test]
    fn wildcards_dashes_parents_and_regular_expressions() {
        let wild = rule("    selection:\n        CommandLine: '* -decode *.txt'\n    condition: selection");
        assert!(fires(&wild, TOOL, "certutil -decode in.b64 out.txt", ""));
        assert!(!fires(&wild, TOOL, "certutil -decode in.b64 out.bin", ""));
        let dash = rule("    selection:\n        CommandLine|contains|windash: ' -decode '\n    condition: selection");
        assert!(fires(&dash, TOOL, "certutil /decode a b", ""), "Schrägstrich statt Bindestrich");
        assert!(fires(&dash, TOOL, "certutil -decode a b", ""));
        let parent = rule("    selection:\n        ParentImage|endswith: '\\winword.exe'\n        Image|endswith:\n            - '\\cmd.exe'\n            - '\\wscript.exe'\n    condition: selection");
        assert!(fires(&parent, "C:\\Windows\\System32\\cmd.exe", "cmd /c x", "\\WINWORD.EXE"));
        assert!(!fires(&parent, "C:\\Windows\\System32\\cmd.exe", "cmd /c x", "\\explorer.exe"));
        let re = rule("    selection:\n        CommandLine|re: 'a{3,}\\d+'\n    condition: selection");
        assert!(fires(&re, TOOL, "x aaaa42", ""));
        assert!(!fires(&re, TOOL, "x AAAA42", ""), "reguläre Ausdrücke unterscheiden Groß und Klein");
        // A real star in the value.
        let star = rule("    selection:\n        CommandLine|contains: 'del \\*.log'\n    condition: selection");
        assert!(fires(&star, TOOL, "cmd /c del *.log", ""));
        assert!(!fires(&star, TOOL, "cmd /c del a.log", ""));
    }

    #[test]
    fn a_path_in_nt_form_is_read_like_the_plain_path() {
        // Shape of the real rule "System File Execution Location Anomaly": a system file
        // name that is not started from the Windows folders.
        let r = rule("    selection:\n        Image|endswith: '\\conhost.exe'\n    filter:\n        Image|startswith: 'C:\\Windows\\System32\\'\n    condition: selection and not filter");
        // What Windows really reports for every console window (seen on 21.11.2026):
        assert!(!fires(&r, "\\??\\C:\\WINDOWS\\system32\\conhost.exe", "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1", ""));
        assert!(!fires(&r, "\\\\?\\C:\\Windows\\System32\\conhost.exe", "x", ""));
        assert!(!fires(&r, "C:\\Windows\\System32\\conhost.exe", "x", ""));
        // A conhost.exe somewhere else is still reported, also in NT form.
        assert!(fires(&r, "\\??\\C:\\Users\\x\\AppData\\Local\\Temp\\conhost.exe", "x", ""));
        assert_eq!(plain("\"\\??\\C:\\a b\\c.exe\" -x"), "\"C:\\a b\\c.exe\" -x");
        assert_eq!(plain("C:\\a.exe \\??\\x"), "C:\\a.exe \\??\\x", "nur am Anfang");
    }

    #[test]
    fn with_only_a_file_name_nothing_about_the_folder_is_decided() {
        // Shape of the real rule "Execution Of Non-Existing File": a program path without any folder.
        let no_path = rule("    image_absolute_path:\n        Image|contains: '\\'\n    condition: not image_absolute_path");
        // K9 knew only the name of a program that had already ended (seen on 21.11.2026):
        assert!(!fires(&no_path, "git.exe", "\"git.exe\" --exec-path", "\\cargo.exe"), "unbekannter Ordner ist kein fehlender Ordner");
        assert!(!fires(&no_path, "\\git.exe", "x", ""));
        assert!(!fires(&no_path, "C:\\Program Files\\Git\\cmd\\git.exe", "x", ""));
        assert!(!fires(&no_path, "C:/OBS/bin/64bit/obs-nvenc-test.exe", "C:/OBS/bin/64bit/obs-nvenc-test.exe", "C:\\OBS\\bin\\64bit\\obs64.exe"), "Pfad mit / ist ein Pfad (#558)");
        // A system file name outside the Windows folders – undecided without the folder.
        let place = rule("    selection:\n        Image|endswith: '\\whoami.exe'\n    filter:\n        Image|startswith: 'C:\\Windows\\System32\\'\n    condition: selection and not filter");
        assert!(!fires(&place, "whoami.exe", "whoami", ""));
        assert!(fires(&place, "C:\\Users\\x\\Downloads\\whoami.exe", "whoami", ""), "mit bekanntem Ordner gilt die Regel");
        // The same for the starter, of which K9 always knows only the name.
        let starter = rule("    selection:\n        ParentImage|contains: '\\AppData\\Local\\Temp\\'\n    condition: selection");
        assert!(!fires(&starter, "C:\\x\\y.exe", "y", "\\setup.exe"));
        assert!(fires(&starter, "C:\\x\\y.exe", "y", "C:\\Users\\x\\AppData\\Local\\Temp\\setup.exe"));
        // What only needs the file name still works: program by name plus its command line.
        let by_name = rule("    selection:\n        Image|endswith: '\\certutil.exe'\n        CommandLine|contains: 'urlcache'\n    condition: selection");
        assert!(fires(&by_name, "certutil.exe", "certutil -urlcache -f http://x/a a", "\\cmd.exe"));
        assert!(!fires(&by_name, "other.exe", "other -urlcache", ""));
        // One alternative needs the folder, the other does not: a match of the second is enough.
        let either = rule("    selection:\n        Image|endswith:\n            - '\\Temp\\evil.exe'\n            - '\\evil.exe'\n    condition: selection");
        assert!(fires(&either, "evil.exe", "evil", ""));
    }

    #[test]
    fn what_k9_cannot_evaluate_is_left_out_and_other_categories_are_ignored() {
        let head = "title: T\nid: 1\nauthor: A\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n";
        for body in [
            "    selection:\n        CommandLine|base64offset|contains: 'x'\n    condition: selection",
            "    keywords:\n        - 'mimikatz'\n    condition: keywords",
            "    selection:\n        CommandLine|contains: 'x'\n    condition: selection | count() > 3",
            "    selection:\n        CommandLine|contains: 'x'\n    condition: selection and missing",
        ] {
            assert!(parse_rule(&format!("{head}{body}\nlevel: high\n")).is_err(), "{body}");
        }
        let other = "title: T\nid: 1\nlogsource:\n    category: file_event\n    product: windows\ndetection:\n    s:\n        TargetFilename: x\n    condition: s\n";
        assert!(parse_rule(other).unwrap().is_none());
        let set = RuleSet::from_texts([other, &format!("{head}    keywords:\n        - 'x'\n    condition: keywords\n")]);
        assert_eq!((set.rules.len(), set.skipped), (0, 1));
    }

    #[test]
    fn a_rule_set_reports_its_hits_with_critical_rules_first() {
        let mk = |id: &str, level: &str| {
            format!("title: Regel {id}\nid: {id}\nauthor: A\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        CommandLine|contains: 'zzz-test'\n    condition: s\nlevel: {level}\n")
        };
        let (a, b) = (mk("a", "high"), mk("b", "critical"));
        let set = RuleSet::from_texts([a.as_str(), b.as_str()]);
        let ev = Event { image: "C:\\x\\y.exe", command_line: "y ZZZ-TEST", parent_image: "", parent_command_line: None };
        let hits = set.matches(&ev);
        assert_eq!(hits.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), ["b", "a"]);
        assert!(set.matches(&Event { command_line: "y", ..ev }).is_empty());
    }

    #[test]
    fn a_hit_becomes_a_k9_message_that_names_the_author_and_is_never_critical() {
        let mk = |level: &str| {
            parse_rule(&format!("title: Verdächtiger Aufruf\nid: abc-1\nauthor: Erika Muster\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        CommandLine|contains: 'x'\n    condition: s\nlevel: {level}\n"))
                .unwrap()
                .unwrap()
        };
        let (id, text, sev) = finding_parts(&mk("critical"));
        assert_eq!((id.as_str(), text.as_str(), sev), ("SIGMA:abc-1", "Sigma-Regel „Verdächtiger Aufruf“ (Autor: Erika Muster)", crate::model::Severity::Hoch));
        assert_eq!(finding_parts(&mk("high")).2, crate::model::Severity::Mittel);
    }

    /// With the real package (not part of the repository): how many rules load and what a
    /// process start costs. `cargo test -p k9-core sigma -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_package_statistics() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testlabor/sigma/sigma_core.zip");
        let set = RuleSet::from_zip(&std::fs::read(path).expect("testlabor/sigma/sigma_core.zip")).unwrap();
        println!("geladen: {} Regeln, ausgelassen: {}, können nie auslösen: {}", set.rules.len(), set.skipped, set.dormant);
        // With the add-on "Emerging Threats", if it lies next to the package.
        let addon = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testlabor/sigma/sigma_emerging_threats_addon.zip");
        if let Ok(a) = std::fs::read(addon) {
            let core = std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testlabor/sigma/sigma_core.zip")).unwrap();
            let both = RuleSet::from_packages(&core, Some(&a)).unwrap();
            println!("mit Zusatzpaket: {} Regeln, davon {} aus dem Zusatzpaket, nie auslösbar {}", both.rules.len(), both.addon, both.dormant);
        }
        for r in set.rules.iter().filter(|r| !r.can_fire()).take(8) {
            println!("  nie auslösbar: {}", r.title);
        }
        let events = [
            Event { image: "C:\\Program Files\\Git\\usr\\bin\\bash.exe", command_line: "bash -c \"cargo build --release\"", parent_image: "\\claude.exe", parent_command_line: None },
            Event { image: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command_line: "powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\e2e-test.ps1", parent_image: "\\bash.exe", parent_command_line: None },
            Event { image: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", command_line: "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=1234", parent_image: "\\firefox.exe", parent_command_line: None },
            Event { image: "C:\\Windows\\System32\\svchost.exe", command_line: "C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p -s Schedule", parent_image: "\\services.exe", parent_command_line: None },
            // Seen on the test PC on 21.11.2026 right after Sigma was switched on:
            Event { image: "\\??\\C:\\WINDOWS\\system32\\conhost.exe", command_line: "\\??\\C:\\WINDOWS\\system32\\conhost.exe 0xffffffff -ForceV1", parent_image: "\\", parent_command_line: None },
            Event { image: "C:\\Program Files\\Git\\usr\\bin\\sort.exe", command_line: "sort -u", parent_image: "\\bash.exe", parent_command_line: None },
            Event { image: "git.exe", command_line: "\"git.exe\" --exec-path", parent_image: "\\cargo.exe", parent_command_line: None },
            Event { image: "conhost.exe", command_line: "conhost.exe 0x4", parent_image: "\\", parent_command_line: None },
            Event { image: "rustc.exe", command_line: "rustc.exe --crate-name k9_core --edition=2021 crates\\k9-core\\src\\lib.rs", parent_image: "\\cargo.exe", parent_command_line: None },
            Event { image: "C:\\Windows\\System32\\cmd.exe", command_line: "cmd.exe /c dir", parent_image: "\\explorer.exe", parent_command_line: None },
            Event { image: "C:\\Program Files (x86)\\Steam\\steam.exe", command_line: "\"C:\\Program Files (x86)\\Steam\\steam.exe\" -silent", parent_image: "\\explorer.exe", parent_command_line: None },
        ];
        let start = std::time::Instant::now();
        let rounds = 2000;
        let mut hits = 0usize;
        for i in 0..rounds {
            hits += set.matches(&events[i % events.len()]).len();
        }
        let per = start.elapsed().as_secs_f64() * 1e6 / rounds as f64;
        println!("{per:.0} Mikrosekunden je Programmstart ({rounds} Starts, {hits} Treffer)");
        for ev in &events {
            for r in set.matches(ev) {
                println!("TREFFER bei harmlosem Start: {} | {} | {}", r.title, r.author, ev.command_line);
            }
        }
    }
}
