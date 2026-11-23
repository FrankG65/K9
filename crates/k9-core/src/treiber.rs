//! Kernel drivers: inventory, known vulnerable/malicious drivers and a
//! readiness hint for memory integrity (HVCI/VBS).
//!
//! Lists (sources, updated by the Windows service):
//! * Microsoft recommended driver block rules (`DriverPolicy_Enforced.xml`):
//!   Authenticode hashes (SHA-1/SHA-256) and file name + version ranges.
//! * LOLDrivers (loldrivers.io, Apache-2.0): file hashes and Authenticode hashes.
//!
//! Matching uses hashes; a file name + version rule of the Microsoft list is
//! weaker (the signer is not checked) and is marked as such. A file name
//! alone is never a finding.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::winreg::{self, HKLM};

// ================================================================== lists

/// One entry of a list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListEntry {
    /// "Microsoft-Sperrliste" or "LOLDrivers"
    pub quelle: String,
    /// "verwundbar" or "bösartig"
    pub art: String,
    pub name: String,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub link: Option<String>,
}

/// File name + version range (Microsoft list, signer not checked).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameRule {
    pub datei: String,
    pub min: String,
    pub max: String,
    pub aussteller: String,
}

/// Compact index of one list (stored in the sources folder).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DriverIndex {
    pub eintraege: Vec<ListEntry>,
    /// lower-case hex hash (file SHA-1/SHA-256 or Authenticode SHA-1/SHA-256) -> entry index
    pub hashes: BTreeMap<String, usize>,
    #[serde(default)]
    pub namen: Vec<NameRule>,
}

impl DriverIndex {
    pub fn merge(&mut self, other: DriverIndex) {
        let base = self.eintraege.len();
        self.eintraege.extend(other.eintraege);
        for (h, i) in other.hashes {
            self.hashes.entry(h).or_insert(base + i);
        }
        self.namen.extend(other.namen);
    }

    pub fn len(&self) -> usize {
        self.hashes.len() + self.namen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Loads all lists from the sources folder.
    pub fn load(sources_dir: &Path) -> Self {
        let mut idx = DriverIndex::default();
        for f in [LOL_FILE, MS_FILE] {
            if let Some(i) = std::fs::read(sources_dir.join(f)).ok().and_then(|b| serde_json::from_slice::<DriverIndex>(&b).ok()) {
                idx.merge(i);
            }
        }
        idx
    }
}

pub const LOL_FILE: &str = "treiber/loldrivers.json";
pub const MS_FILE: &str = "treiber/microsoft.json";
pub const LOL_URL: &str = "https://www.loldrivers.io/api/drivers.json";
pub const MS_URL: &str = "https://aka.ms/VulnerableDriverBlockList";

fn hexlow(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_lowercase();
    (matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

/// LOLDrivers `drivers.json` -> index.
pub fn parse_loldrivers(data: &[u8]) -> Result<DriverIndex> {
    let list: Vec<serde_json::Value> = serde_json::from_slice(data).context("drivers.json unlesbar")?;
    let mut idx = DriverIndex::default();
    for d in &list {
        let art = match d["Category"].as_str().unwrap_or("") {
            "malicious" => "bösartig",
            _ => "verwundbar",
        };
        let samples = d["KnownVulnerableSamples"].as_array().cloned().unwrap_or_default();
        let name = samples
            .iter()
            .find_map(|s| s["Filename"].as_str().or(s["OriginalFilename"].as_str()))
            .or_else(|| d["Tags"].as_array().and_then(|t| t.first()).and_then(|t| t.as_str()))
            .unwrap_or("unbekannt")
            .to_string();
        let mut cve: Vec<String> = Vec::new();
        for c in d["CVE"].as_array().into_iter().flatten().filter_map(|c| c.as_str()) {
            cve.push(c.to_string());
        }
        let id = d["Id"].as_str().unwrap_or("");
        let entry = idx.eintraege.len();
        idx.eintraege.push(ListEntry {
            quelle: "LOLDrivers".into(),
            art: art.into(),
            name,
            cve,
            link: (!id.is_empty()).then(|| format!("https://www.loldrivers.io/drivers/{id}/")),
        });
        for s in &samples {
            for h in [&s["SHA256"], &s["SHA1"], &s["Authentihash"]["SHA256"], &s["Authentihash"]["SHA1"]] {
                if let Some(h) = h.as_str().and_then(hexlow) {
                    idx.hashes.entry(h).or_insert(entry);
                }
            }
        }
    }
    if idx.hashes.is_empty() {
        bail!("LOLDrivers-Liste enthält keine Hashes");
    }
    Ok(idx)
}

/// Value of an XML attribute in one tag (the Microsoft policy is simple, generated XML).
fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!(" {name}=\"");
    let i = tag.find(&key)? + key.len();
    let j = tag[i..].find('"')?;
    Some(tag[i..i + j].replace("&amp;", "&").replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">"))
}

fn tags<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name} ");
    xml.match_indices(open.as_str()).filter_map(|(i, _)| xml[i..].find('>').map(|j| &xml[i..i + j + 1])).collect()
}

/// Microsoft `DriverPolicy_Enforced.xml` -> index (Authenticode hashes and name/version rules).
pub fn parse_ms_blocklist(xml: &str) -> Result<DriverIndex> {
    let mut idx = DriverIndex::default();
    for t in tags(xml, "Deny") {
        let (Some(hash), Some(friendly)) = (attr(t, "Hash"), attr(t, "FriendlyName")) else { continue };
        if friendly.contains("Hash Page") {
            continue; // page hashes are not file hashes
        }
        let Some(h) = hexlow(&hash) else { continue };
        let name = friendly.split('\\').next().unwrap_or(&friendly).trim().to_string();
        let entry = idx.eintraege.len();
        idx.eintraege.push(ListEntry { quelle: "Microsoft-Sperrliste".into(), art: "verwundbar".into(), name, cve: Vec::new(), link: None });
        idx.hashes.entry(h).or_insert(entry);
    }
    // File name rules belong to signers ("Name" = issuing CA).
    let mut issuer: HashMap<String, String> = HashMap::new();
    let mut pos = 0;
    while let Some(i) = xml[pos..].find("<Signer ") {
        let start = pos + i;
        let end = xml[start..].find("</Signer>").map(|j| start + j).unwrap_or(xml.len());
        let block = &xml[start..end];
        let head = &block[..block.find('>').unwrap_or(block.len())];
        let ca = attr(head, "Name").unwrap_or_default();
        for r in tags(block, "FileAttribRef") {
            if let Some(id) = attr(r, "RuleID") {
                issuer.insert(id, ca.clone());
            }
        }
        pos = end;
    }
    for t in tags(xml, "FileAttrib") {
        let (Some(id), Some(file)) = (attr(t, "ID"), attr(t, "FileName")) else { continue };
        idx.namen.push(NameRule {
            datei: file.to_ascii_lowercase(),
            min: attr(t, "MinimumFileVersion").unwrap_or_else(|| "0.0.0.0".into()),
            max: attr(t, "MaximumFileVersion").unwrap_or_else(|| "65535.65535.65535.65535".into()),
            aussteller: issuer.get(&id).cloned().unwrap_or_default(),
        });
    }
    if idx.hashes.is_empty() {
        bail!("Microsoft-Sperrliste enthält keine Hashes");
    }
    Ok(idx)
}

/// Downloads both lists into memory (for a report before the first update).
pub fn fetch_lists() -> DriverIndex {
    let mut idx = DriverIndex::default();
    if let Ok(i) = crate::sources::download(LOL_URL, &[], 200 * 1024 * 1024).and_then(|d| parse_loldrivers(&d)) {
        idx.merge(i);
    }
    if let Ok(i) = crate::sources::download(MS_URL, &[], 50 * 1024 * 1024).and_then(|d| ms_xml_from_zip(&d)).and_then(|x| parse_ms_blocklist(&x)) {
        idx.merge(i);
    }
    idx
}

/// `DriverPolicy_Enforced.xml` from the Microsoft download (ZIP).
pub fn ms_xml_from_zip(data: &[u8]) -> Result<String> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(data)).context("Microsoft-Sperrliste: ZIP ungültig")?;
    let name = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().and_then(|f| f.name().ok().map(|n| n.to_string())))
        .find(|n| n.ends_with("DriverPolicy_Enforced.xml"))
        .context("DriverPolicy_Enforced.xml fehlt im ZIP")?;
    let mut xml = String::new();
    std::io::Read::read_to_string(&mut zip.by_name(&name)?, &mut xml)?;
    Ok(xml.trim_start_matches('\u{feff}').to_string())
}

/// Compares dotted versions numerically ("10.2.0.5" < "10.10.0.0").
pub fn version_le(a: &str, b: &str) -> bool {
    let p = |s: &str| s.split('.').map(|x| x.trim().parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let (a, b) = (p(a), p(b));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x < y;
        }
    }
    true
}

// ================================================================= PE files

/// Hashes and memory-integrity readiness of a driver file.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PeInfo {
    pub sha256: String,
    pub sha1: String,
    pub authenti_sha256: String,
    pub authenti_sha1: String,
    /// Reasons why the driver is likely not compatible with memory integrity (HVCI).
    pub hvci_probleme: Vec<String>,
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

/// Parses a PE image: file hashes, Authenticode hashes (file without checksum,
/// certificate table entry and certificate data) and HVCI checks.
pub fn analyze_pe(b: &[u8]) -> Result<PeInfo> {
    use ring::digest::{digest, Context as Dig, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
    if b.get(0..2) != Some(b"MZ") {
        bail!("keine Windows-Programmdatei");
    }
    let pe = u32_at(b, 0x3c).context("PE-Kopf fehlt")? as usize;
    if b.get(pe..pe + 4) != Some(b"PE\0\0") {
        bail!("PE-Signatur fehlt");
    }
    let coff = pe + 4;
    let sections = u16_at(b, coff + 2).context("COFF")? as usize;
    let opt_size = u16_at(b, coff + 16).context("COFF")? as usize;
    let opt = coff + 20;
    let magic = u16_at(b, opt).context("Optional Header")?;
    let dd = match magic {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => bail!("unbekanntes PE-Format"),
    };
    let checksum = opt + 64;
    let cert_dir = dd + 4 * 8;
    let (cert_off, cert_size) = (u32_at(b, cert_dir).unwrap_or(0) as usize, u32_at(b, cert_dir + 4).unwrap_or(0) as usize);

    // Authenticode: skip checksum, certificate directory entry and certificate table.
    let mut ranges: Vec<(usize, usize)> = vec![(0, checksum), (checksum + 4, cert_dir), (cert_dir + 8, b.len())];
    if cert_off > 0 && cert_size > 0 && cert_off < b.len() {
        let end = (cert_off + cert_size).min(b.len());
        ranges = ranges
            .into_iter()
            .flat_map(|(s, e)| {
                if e <= cert_off || s >= end {
                    vec![(s, e)]
                } else {
                    let mut v = Vec::new();
                    if s < cert_off {
                        v.push((s, cert_off));
                    }
                    if end < e {
                        v.push((end, e));
                    }
                    v
                }
            })
            .collect();
    }
    let mut a256 = Dig::new(&SHA256);
    let mut a1 = Dig::new(&SHA1_FOR_LEGACY_USE_ONLY);
    for (s, e) in ranges {
        if s < e && e <= b.len() {
            a256.update(&b[s..e]);
            a1.update(&b[s..e]);
        }
    }

    // Memory integrity (HVCI) readiness, like Microsoft's checks.
    let mut hvci = Vec::new();
    let align = u32_at(b, opt + 32).unwrap_or(0);
    if align != 0x1000 {
        hvci.push(format!("Abschnittsausrichtung {align:#x} statt 4 KB"));
    }
    let iat = dd + 12 * 8;
    let (iat_rva, iat_size) = (u32_at(b, iat).unwrap_or(0), u32_at(b, iat + 4).unwrap_or(0));
    let sec0 = opt + opt_size;
    for i in 0..sections.min(96) {
        let s = sec0 + i * 40;
        let Some(raw) = b.get(s..s + 8) else { break };
        let name = String::from_utf8_lossy(raw).trim_end_matches('\0').to_string();
        let vsize = u32_at(b, s + 8).unwrap_or(0);
        let vaddr = u32_at(b, s + 12).unwrap_or(0);
        let ch = u32_at(b, s + 36).unwrap_or(0);
        let exec = ch & 0x2000_0000 != 0;
        let write = ch & 0x8000_0000 != 0;
        if exec && write {
            hvci.push(format!("Abschnitt {name} ist gleichzeitig schreib- und ausführbar"));
        }
        if exec && iat_size > 0 && iat_rva >= vaddr && iat_rva < vaddr.saturating_add(vsize.max(1)) {
            hvci.push(format!("Importtabelle liegt im ausführbaren Abschnitt {name}"));
        }
    }
    Ok(PeInfo {
        sha256: hex::encode(digest(&SHA256, b)),
        sha1: hex::encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, b)),
        authenti_sha256: hex::encode(a256.finish()),
        authenti_sha1: hex::encode(a1.finish()),
        hvci_probleme: hvci,
    })
}

// ============================================================ version info

#[derive(Debug, Clone, Default, Serialize)]
pub struct VersionInfo {
    pub version: String,
    pub firma: String,
    pub produkt: String,
    pub beschreibung: String,
}

pub fn version_info(path: &Path) -> VersionInfo {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO};
    let w: Vec<u16> = path.as_os_str().encode_wide_nul();
    let mut out = VersionInfo::default();
    // SAFETY: buffer sized by GetFileVersionInfoSizeW; pointers from VerQueryValueW point into it.
    unsafe {
        let size = GetFileVersionInfoSizeW(PCWSTR(w.as_ptr()), None);
        if size == 0 {
            return out;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(PCWSTR(w.as_ptr()), None, size, buf.as_mut_ptr() as *mut _).is_err() {
            return out;
        }
        let q = |sub: &str| -> Option<(*mut core::ffi::c_void, u32)> {
            let s: Vec<u16> = sub.encode_utf16().chain(std::iter::once(0)).collect();
            let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut len = 0u32;
            VerQueryValueW(buf.as_ptr() as *const _, PCWSTR(s.as_ptr()), &mut p, &mut len).as_bool().then_some((p, len))
        };
        if let Some((p, len)) = q("\\") {
            if len as usize >= std::mem::size_of::<VS_FIXEDFILEINFO>() {
                let f = &*(p as *const VS_FIXEDFILEINFO);
                out.version = format!(
                    "{}.{}.{}.{}",
                    f.dwFileVersionMS >> 16,
                    f.dwFileVersionMS & 0xffff,
                    f.dwFileVersionLS >> 16,
                    f.dwFileVersionLS & 0xffff
                );
            }
        }
        let lang = q("\\VarFileInfo\\Translation")
            .filter(|(_, len)| *len >= 4)
            .map(|(p, _)| {
                let t = std::slice::from_raw_parts(p as *const u16, 2);
                format!("{:04x}{:04x}", t[0], t[1])
            })
            .unwrap_or_else(|| "040904b0".into());
        let text = |key: &str| -> String {
            q(&format!("\\StringFileInfo\\{lang}\\{key}"))
                .filter(|(_, len)| *len > 0)
                .map(|(p, len)| {
                    let s = std::slice::from_raw_parts(p as *const u16, len as usize);
                    let end = s.iter().position(|c| *c == 0).unwrap_or(s.len());
                    String::from_utf16_lossy(&s[..end]).trim().to_string()
                })
                .unwrap_or_default()
        };
        out.firma = text("CompanyName");
        out.produkt = text("ProductName");
        out.beschreibung = text("FileDescription");
    }
    out
}

trait WideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

impl WideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

// ================================================================ inventory

/// A kernel driver of this PC.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Driver {
    /// Service name (empty: loaded or present without a service entry)
    pub dienst: String,
    pub anzeigename: String,
    pub datei: PathBuf,
    /// 0 Boot, 1 System, 2 Automatisch, 3 Manuell, 4 Deaktiviert (None: no service)
    pub start: Option<u32>,
    pub geladen: bool,
    pub info: VersionInfo,
    pub signiert: bool,
    /// Subject of the signing certificate (embedded signature)
    pub signierer: String,
    pub pe: Option<PeInfo>,
    /// Programs from "Apps & Features" that probably installed the driver
    pub produkt_installiert: Option<String>,
    pub treffer: Vec<Hit>,
    /// The file lies only in Windows' driver store (installed package, driver not in use).
    #[serde(default)]
    pub vorrat: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    pub eintrag: ListEntry,
    /// "Hash", "Authenticode-Hash" or "Name und Version (Herausgeber nicht geprüft)"
    pub abgleich: String,
}

impl Driver {
    pub fn microsoft(&self) -> bool {
        self.info.firma.to_ascii_lowercase().contains("microsoft") || self.signierer.to_ascii_lowercase().starts_with("microsoft")
    }

    /// Manufacturer: from the version info, else from the signature.
    pub fn hersteller(&self) -> &str {
        if !self.info.firma.is_empty() {
            &self.info.firma
        } else if !self.signierer.is_empty() {
            &self.signierer
        } else {
            "?"
        }
    }

    pub fn start_label(&self) -> &'static str {
        match self.start {
            Some(0) => "Boot",
            Some(1) => "System",
            Some(2) => "Automatisch",
            Some(3) => "Manuell",
            Some(4) => "Deaktiviert",
            Some(_) => "?",
            None => "kein Dienst",
        }
    }

    /// Boot/system drivers are never switched off by the scanner (risk of an unbootable PC).
    pub fn may_disable(&self) -> bool {
        !self.dienst.is_empty() && matches!(self.start, Some(2) | Some(3))
    }
}

/// Resolves driver paths like `\SystemRoot\System32\drivers\x.sys`,
/// `System32\DRIVERS\x.sys`, `\??\C:\x.sys`.
pub fn resolve_image(raw: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let s = raw.trim().trim_matches('"');
    let lower = s.to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("\\??\\") {
        return PathBuf::from(rest);
    }
    if lower.starts_with("\\systemroot\\") {
        return PathBuf::from(&root).join(&s[12..]);
    }
    if lower.starts_with("system32\\") || lower.starts_with("syswow64\\") {
        return PathBuf::from(&root).join(s);
    }
    if lower.starts_with("\\windows\\") {
        let drive = root.get(..2).unwrap_or("C:");
        return PathBuf::from(format!("{drive}{s}"));
    }
    PathBuf::from(crate::paths::expand_env(s))
}

/// Paths of the currently loaded kernel images.
pub fn loaded_drivers() -> HashSet<String> {
    use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW};
    let mut out = HashSet::new();
    let mut bases = vec![std::ptr::null_mut::<core::ffi::c_void>(); 2048];
    let mut needed = 0u32;
    // SAFETY: buffer of pointers; size in bytes.
    unsafe {
        if EnumDeviceDrivers(bases.as_mut_ptr(), (bases.len() * std::mem::size_of::<usize>()) as u32, &mut needed).is_err() {
            return out;
        }
        let n = (needed as usize / std::mem::size_of::<usize>()).min(bases.len());
        for base in &bases[..n] {
            let mut buf = [0u16; 1024];
            let len = GetDeviceDriverFileNameW(*base, &mut buf) as usize;
            if len > 0 {
                out.insert(resolve_image(&String::from_utf16_lossy(&buf[..len])).display().to_string().to_ascii_lowercase());
            }
        }
    }
    out
}

/// Names of running driver services (works without administrator rights,
/// unlike the list of loaded images which Windows hides from normal users).
pub fn running_driver_services() -> HashSet<String> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_DRIVER,
    };
    let mut out = HashSet::new();
    // SAFETY: buffer sized by the first call; handle closed below.
    unsafe {
        let Ok(scm) = OpenSCManagerW(windows::core::PCWSTR::null(), windows::core::PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else {
            return out;
        };
        let mut needed = 0u32;
        let mut count = 0u32;
        let mut resume = 0u32;
        let _ = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, None, &mut needed, &mut count, Some(&mut resume), windows::core::PCWSTR::null());
        let mut buf = vec![0u8; needed as usize + 4096];
        resume = 0;
        if EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_ACTIVE, Some(&mut buf), &mut needed, &mut count, Some(&mut resume), windows::core::PCWSTR::null()).is_ok() {
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
            for it in items {
                if let Ok(n) = it.lpServiceName.to_string() {
                    out.insert(n.to_ascii_lowercase());
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    out
}

/// All kernel driver services (Type 1/2) plus loaded images without service
/// and third-party files in System32\drivers without service.
pub fn inventory() -> Vec<Driver> {
    let loaded = loaded_drivers();
    let running = running_driver_services();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    let base = "SYSTEM\\CurrentControlSet\\Services";
    for name in winreg::subkeys(HKLM, base) {
        let key = format!("{base}\\{name}");
        let typ = winreg::read_dword(HKLM, &key, "Type").unwrap_or(0);
        if typ & 0x3 == 0 || typ & 0x30 != 0 {
            continue; // not a kernel/file system driver
        }
        let image = winreg::read_string(HKLM, &key, "ImagePath")
            .map(|p| resolve_image(&p))
            .unwrap_or_else(|| resolve_image(&format!("System32\\drivers\\{name}.sys")));
        let lower = image.display().to_string().to_ascii_lowercase();
        seen.insert(lower.clone());
        out.push(Driver {
            anzeigename: winreg::read_string(HKLM, &key, "DisplayName").filter(|d| !d.starts_with('@')).unwrap_or_default(),

            start: winreg::read_dword(HKLM, &key, "Start"),
            geladen: loaded.contains(&lower) || running.contains(&name.to_ascii_lowercase()),
            dienst: name.clone(),
            datei: image,
            ..Default::default()
        });
    }
    for l in &loaded {
        if seen.insert(l.clone()) && l.ends_with(".sys") {
            out.push(Driver { datei: PathBuf::from(l), geladen: true, ..Default::default() });
        }
    }
    let dir = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\drivers");
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let p = e.path();
        let lower = p.display().to_string().to_ascii_lowercase();
        if lower.ends_with(".sys") && seen.insert(lower) {
            out.push(Driver { datei: p, ..Default::default() });
        }
    }
    out
}

/// Folders of the driver packages of other manufacturers in Windows' driver store
/// (`System32\DriverStore\FileRepository\<name>.inf_amd64_<hash>`), from the driver database.
pub fn store_packages() -> Vec<String> {
    let base = "SYSTEM\\DriverDatabase\\DriverInfFiles";
    let mut out: Vec<String> = winreg::subkeys(HKLM, base)
        .into_iter()
        .filter(|k| k.to_ascii_lowercase().starts_with("oem"))
        .filter_map(|k| winreg::read_string(HKLM, &format!("{base}\\{k}"), "Active"))
        .filter(|f| !f.is_empty() && !f.contains(['\\', '/']) && !f.contains(".."))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Driver files that lie only in the driver store: installed packages whose driver is not in
/// use (no service, no file in System32\drivers). Windows counts them when it decides whether
/// memory integrity can be switched on - seen on 23.11.2026: a driver a
/// headset needs only during a firmware update, blocked memory integrity and `k9 treiber` did
/// not show it. `known`: the drivers found so far (same file name = the installed copy).
pub fn store_inventory(known: &[Driver]) -> Vec<Driver> {
    let root = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join("System32\\DriverStore\\FileRepository");
    let names: HashSet<String> = known.iter().filter_map(|d| d.datei.file_name()).map(|n| n.to_string_lossy().to_ascii_lowercase()).collect();
    store_inventory_in(&root, &store_packages(), &names)
}

/// `store_inventory` for a given store folder (testable).
pub fn store_inventory_in(root: &Path, packages: &[String], known_names: &HashSet<String>) -> Vec<Driver> {
    let mut seen = known_names.clone();
    let mut out = Vec::new();
    for package in packages {
        let mut stack = vec![(root.join(package), 0u8)];
        while let Some((dir, depth)) = stack.pop() {
            for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let p = e.path();
                if p.is_dir() {
                    if depth < 2 {
                        stack.push((p, depth + 1));
                    }
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_ascii_lowercase();
                if name.ends_with(".sys") && seen.insert(name) {
                    out.push(Driver { datei: p, vorrat: true, ..Default::default() });
                }
            }
        }
    }
    out.sort_by(|a, b| a.datei.cmp(&b.datei));
    out
}

/// Reads version info, hashes, signature; matches the lists. Only files
/// that exist are analysed. `with_hashes = false` skips the hashing (cheap view).
pub fn analyze(drivers: &mut [Driver], index: &DriverIndex, with_hashes: bool) {
    let uninstall = crate::software::inventory();
    for d in drivers.iter_mut() {
        if !d.datei.is_file() {
            continue;
        }
        d.info = version_info(&d.datei);
        clean_boilerplate(&mut d.info);
        if d.microsoft() && !with_hashes {
            continue;
        }
        d.signiert = crate::autostart::is_signed(&d.datei);
        d.signierer = signer_name(&d.datei).unwrap_or_default();
        if with_hashes {
            if let Ok(bytes) = std::fs::read(&d.datei) {
                d.pe = analyze_pe(&bytes).ok();
            }
        }
        d.treffer = matches(d, index);
        if !d.microsoft() {
            d.produkt_installiert = owning_program(d, &uninstall);
        }
    }
}

/// List hits of one driver (hashes; name+version only as a weaker hit).
pub fn matches(d: &Driver, index: &DriverIndex) -> Vec<Hit> {
    let mut out = Vec::new();
    if let Some(pe) = &d.pe {
        for (h, how) in [
            (&pe.sha256, "Hash"),
            (&pe.sha1, "Hash"),
            (&pe.authenti_sha256, "Authenticode-Hash"),
            (&pe.authenti_sha1, "Authenticode-Hash"),
        ] {
            if let Some(&i) = index.hashes.get(h.as_str()) {
                let e = index.eintraege[i].clone();
                if !out.iter().any(|x: &Hit| x.eintrag == e) {
                    out.push(Hit { eintrag: e, abgleich: how.into() });
                }
            }
        }
    }
    if out.is_empty() && !d.info.version.is_empty() && !d.microsoft() {
        let file = d.datei.file_name().map(|f| f.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
        if let Some(r) = index.namen.iter().find(|r| r.datei == file && version_le(&r.min, &d.info.version) && version_le(&d.info.version, &r.max)) {
            out.push(Hit {
                eintrag: ListEntry {
                    quelle: "Microsoft-Sperrliste".into(),
                    art: "verwundbar".into(),
                    name: format!("{} bis Version {}", r.datei, r.max),
                    cve: Vec::new(),
                    link: None,
                },
                abgleich: format!("Name und Version (Herausgeber nicht geprüft{})", if r.aussteller.is_empty() { String::new() } else { format!(", gesperrt bei Signatur über {}", r.aussteller) }),
            });
        }
    }
    out
}

/// Driver kit sample texts ("Windows (R) Server 2003 DDK provider") say nothing
/// about the real manufacturer.
pub fn is_boilerplate(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains(" ddk ") || l.ends_with(" ddk") || l.contains("ddk provider") || l.contains("ddk driver") || l.contains(" wdk") || l.contains("driver development kit")
}

/// Drops DDK/WDK sample texts; the manufacturer then comes from the signature,
/// the product from the file description (if meaningful).
pub fn clean_boilerplate(v: &mut VersionInfo) {
    if is_boilerplate(&v.firma) {
        v.firma.clear();
    }
    if is_boilerplate(&v.produkt) {
        v.produkt = if is_boilerplate(&v.beschreibung) { String::new() } else { v.beschreibung.clone() };
    }
}

/// Display name of the certificate that signed the file (embedded signature).
pub fn signer_name(path: &Path) -> Option<String> {
    use windows::core::{GUID, PCWSTR};
    use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA,
        WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    let wide: Vec<u16> = path.as_os_str().encode_wide_nul();
    let mut file = WINTRUST_FILE_INFO { cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32, pcwszFilePath: PCWSTR(wide.as_ptr()), ..Default::default() };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hwnd = windows::Win32::Foundation::HWND(-1isize as _);
    // SAFETY: structures live during both calls; provider data is valid until the close call.
    unsafe {
        let _ = WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut _);
        let mut name = None;
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if !prov.is_null() {
            let signer = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
            if !signer.is_null() && (*signer).csCertChain > 0 && !(*signer).pasCertChain.is_null() {
                let cert = (*(*signer).pasCertChain).pCert;
                if !cert.is_null() {
                    let mut buf = [0u16; 512];
                    let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf)) as usize;
                    if n > 1 {
                        name = Some(String::from_utf16_lossy(&buf[..n - 1]));
                    }
                }
            }
        }
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = WinVerifyTrust(hwnd, &mut action, &mut data as *mut _ as *mut _);
        name
    }
}

/// Installed program that probably brought the driver (same publisher / product name).
fn owning_program(d: &Driver, apps: &[crate::software::Installed]) -> Option<String> {
    let words = |s: &str| -> Vec<String> {
        s.to_ascii_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() >= 4).map(str::to_string).collect()
    };
    let company = words(d.hersteller());
    let product = words(&d.info.produkt);
    // Driver inside a program folder ("…\Program Files (x86)\MSI Afterburner\x.sys"): program of that name.
    let path = d.datei.display().to_string().to_ascii_lowercase();
    if let Some(folder) = path.split('\\').skip_while(|p| !p.starts_with("program files")).nth(1).filter(|f| f.len() >= 4) {
        if let Some(a) = apps.iter().find(|a| a.name.to_ascii_lowercase().contains(folder)) {
            return Some(format!("{} {}", a.name, a.version).trim().to_string());
        }
    }
    // The first two words of the manufacturer must both appear (MICRO-STAR is not Microsoft).
    let key: Vec<&String> = company.iter().take(2).collect();
    if key.is_empty() {
        return None;
    }
    apps.iter()
        .filter(|a| {
            let p: Vec<String> = words(&a.publisher);
            // "Giga-Byte Technology" (signature) and "GIGABYTE" (publisher): letters only.
            let letters = |s: &str| s.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphabetic()).collect::<String>();
            let (pl, cl) = (letters(&a.publisher), letters(d.hersteller()));
            key.iter().all(|k| p.contains(k)) || (pl.len() >= 5 && cl.starts_with(&pl))
        })
        .max_by_key(|a| {
            let n = a.name.to_ascii_lowercase();
            product.iter().filter(|w| n.contains(w.as_str())).count()
        })
        .map(|a| format!("{} {}", a.name, a.version).trim().to_string())
}

/// "Treiber deaktivieren" (service only, after the confirmation window):
/// Start = 4, the previous value is kept for "Wieder einschalten". Boot and
/// system drivers are never switched off. The values come from a fresh look
/// at the system, not from the (user-supplied) finding.
pub fn disable(store: &crate::Store, det: &crate::model::Detection) -> Result<()> {
    if !crate::schutz::in_service() {
        bail!("Treiber deaktiviert nur der Windows-Dienst");
    }
    let path = PathBuf::from(&det.path);
    let mut drivers = inventory();
    drivers.retain(|d| d.datei == path);
    let d = drivers.into_iter().find(|d| !d.dienst.is_empty()).context("Zu dieser Datei gibt es keinen Treiberdienst")?;
    if d.start == Some(4) {
        // Already switched off (e.g. a remembered decision applied again): nothing to do.
        tracing::info!("Treiber {} ist bereits deaktiviert", d.dienst);
        return Ok(());
    }
    if !d.may_disable() {
        bail!(
            "{} startet als {}-Treiber sehr früh – er wird hier nicht abgeschaltet. Bitte das zugehörige Programm aktualisieren oder deinstallieren (vorher Wiederherstellungspunkt anlegen)",
            d.dienst,
            d.start_label()
        );
    }
    let key = format!("SYSTEM\\CurrentControlSet\\Services\\{}", d.dienst);
    let old = winreg::read_dword(HKLM, &key, "Start").context("Startwert nicht lesbar")?;
    crate::schutz::as_system(|| winreg::set_dword(HKLM, &key, "Start", 4))?;
    let backup = serde_json::json!({ "art": "treiber", "dienst": d.dienst, "start": old, "datei": d.datei.display().to_string() });
    store.insert_disabled(det.id, &det.path, &backup)?;
    tracing::info!("Treiber {} deaktiviert (vorher Start {old})", d.dienst);
    Ok(())
}

/// What happens with an open driver finding at a re-check.
#[derive(Debug, PartialEq)]
pub enum Tidy {
    /// Driver file and service are gone (uninstalled): the finding is done.
    Removed,
    /// Still there: refresh the displayed facts.
    Refresh(serde_json::Value),
    Keep,
}

/// Decides for an open driver finding; `present` is the freshly analysed
/// driver with that file (if any), `service_exists` whether its service entry exists.
pub fn tidy_decision(det: &crate::model::Detection, present: Option<&Driver>, service_exists: bool) -> Tidy {
    if present.is_none() && !Path::new(&det.path).exists() && !service_exists {
        return Tidy::Removed;
    }
    let Some(d) = present else { return Tidy::Keep };
    let fresh = if det.rule_id == "TREIBER:NEU" { None } else { finding(d).and_then(|f| f.details) };
    match fresh {
        Some(mut new) => {
            // Keep the service's token so actions keep working.
            if let (Some(token), Some(obj)) = (det.details.as_ref().and_then(|x| x.get("dienst_token")).cloned(), new.as_object_mut()) {
                obj.insert("dienst_token".into(), token);
            }
            if det.details.as_ref() == Some(&new) {
                Tidy::Keep
            } else {
                Tidy::Refresh(new)
            }
        }
        None => Tidy::Keep,
    }
}

/// Short facts of a driver finding for display (empty values left out);
/// plain text – the dashboard escapes each part once.
pub fn summary_parts(details: &serde_json::Value) -> Vec<String> {
    let s = |k: &str| details[k].as_str().unwrap_or("").trim().to_string();
    let mut parts = Vec::new();
    for (label, key) in [("Version ", "version"), ("", "firma"), (t!("Programm: ", "Program: "), "produkt"), ("Start: ", "start_text")] {
        let v = s(key);
        if !v.is_empty() && v != "?" {
            parts.push(format!("{label}{v}"));
        }
    }
    let list = s("liste");
    if !list.is_empty() && list != "-" {
        parts.push(tf!("Liste: {list} ({})", "List: {list} ({})", s("abgleich")));
    }
    parts
}

/// Second line under the threat name, e.g. "Treiber · LOLDrivers (Hash)".
pub fn category_line(details: &serde_json::Value, rule_id: &str) -> String {
    let quelle = details["quelle"].as_str().map(str::to_string).unwrap_or_else(|| {
        match rule_id {
            "TREIBER:NEU" => t!("neu installiert", "newly installed").into(),
            r if r.contains("LOLDRIVERS") => "LOLDrivers".into(),
            r if r.contains("MICROSOFT") => "Microsoft-Sperrliste".into(),
            r => r.to_string(),
        }
    });
    let abgleich = details["abgleich"].as_str().unwrap_or("");
    if abgleich.is_empty() || abgleich == "nicht auf den Listen" {
        tf!("Treiber · {quelle}", "Driver · {quelle}")
    } else {
        tf!("Treiber · {quelle} ({})", "Driver · {quelle} ({})", abgleich.split(" (").next().unwrap_or(abgleich))
    }
}

/// Recommendation for a hit.
pub fn recommendation(d: &Driver) -> String {
    let product = d
        .produkt_installiert
        .clone()
        .or_else(|| (!d.info.produkt.is_empty()).then(|| d.info.produkt.clone()))
        .map(|p| tf!("das zugehörige Programm (vermutlich {p})", "the program it belongs to (probably {p})"))
        .unwrap_or_else(|| t!("das zugehörige Programm", "the program it belongs to").into());
    // The text matches the offered buttons: "deaktivieren" only where may_disable() holds.
    if d.may_disable() {
        tf!(
            "{product} aktualisieren (Hersteller-Website) oder über „Apps & Features“ deinstallieren, wenn du es nicht brauchst. \
             Bis dahin kann der Treiber hier deaktiviert werden (jederzeit wieder einschaltbar; das Programm funktioniert dann evtl. nicht).", "Update {product} (publisher's website) or uninstall it via “Apps & features” if you do not need it. \
             Until then the driver can be disabled here (can be switched on again at any time; the program may then not work)."
        )
    } else if d.start == Some(4) {
        tf!(
            "Der Treiber ist bereits deaktiviert und lädt nach dem nächsten Neustart nicht mehr. Ganz entfernen: {product} über \
             „Apps & Features“ deinstallieren oder – wenn das Programm schon weg ist – die Reste mit dem Aufräum-Skript entfernen (Anleitung, Kapitel „Treiberprüfung“).", "The driver is already disabled and no longer loads after the next restart. To remove it completely: uninstall {product} via \
             “Apps & features” or – if the program is already gone – remove the leftovers with the clean-up script (guide, chapter “Treiberprüfung”)."
        )
    } else if matches!(d.start, Some(0) | Some(1)) {
        tf!(
            "Startet sehr früh beim Windows-Start – nicht einfach abschalten. Zuerst einen Wiederherstellungspunkt anlegen, dann {product} \
             aktualisieren (Hersteller-Website) oder über „Apps & Features“ deinstallieren, wenn du es nicht brauchst.", "Starts very early when Windows starts – do not simply switch it off. First create a restore point, then update {product} \
             (publisher's website) or uninstall it via “Apps & features” if you do not need it."
        )
    } else {
        tf!("{product} aktualisieren (Hersteller-Website) oder über „Apps & Features“ deinstallieren, wenn du es nicht brauchst.", "Update {product} (publisher's website) or uninstall it via “Apps & features” if you do not need it.")
    }
}

/// Finding for a driver on a list.
pub fn finding(d: &Driver) -> Option<crate::model::Finding> {
    let hit = d.treffer.first()?;
    let pe = d.pe.as_ref()?;
    let strong = !hit.abgleich.starts_with("Name");
    let severity = match (hit.eintrag.art.as_str(), strong) {
        ("bösartig", true) => crate::model::Severity::Kritisch,
        (_, true) => crate::model::Severity::Hoch,
        _ => crate::model::Severity::Mittel,
    };
    let cves: Vec<String> = d.treffer.iter().flat_map(|h| h.eintrag.cve.clone()).collect();
    Some(crate::model::Finding {
        path: d.datei.clone(),
        sha256: pe.sha256.clone(),
        size: std::fs::metadata(&d.datei).map(|m| m.len()).unwrap_or(0),
        rule_id: format!("TREIBER:{}", hit.eintrag.quelle.to_uppercase().replace(' ', "-")),
        threat_name: tf!(
            "{} Treiber {} ({})", "{} driver {} ({})",
            if hit.eintrag.art == "bösartig" { t!("Bösartiger", "Malicious") } else { t!("Verwundbarer", "Vulnerable") },
            d.datei.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(),
            hit.eintrag.quelle
        ),
        category: t!("Treiber", "Driver").into(),
        severity,
        engine: "treiber".into(),
        kind: crate::model::Kind::Treiber,
        details: Some(serde_json::json!({
            "dienst": d.dienst,
            "start": d.start,
            "start_text": d.start_label(),
            "geladen": d.geladen,
            "version": d.info.version,
            "firma": d.hersteller(),
            "produkt": d.produkt_installiert.clone().unwrap_or_else(|| d.info.produkt.clone()),
            "signiert": d.signiert,
            "abgleich": hit.abgleich,
            "quelle": hit.eintrag.quelle,
            "liste": hit.eintrag.name,
            "cve": cves,
            "link": hit.eintrag.link,
            "ziel": d.datei.display().to_string(),
            "deaktivierbar": d.may_disable(),
            "hinweis": recommendation(d),
        })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddk_sample_texts_are_not_a_manufacturer() {
        let mut v = VersionInfo {
            version: "5.2.3790.1830".into(),
            firma: "Windows (R) Server 2003 DDK provider".into(),
            produkt: "Windows (R) Server 2003 DDK driver".into(),
            beschreibung: "GIGABYTE Tools".into(),
        };
        clean_boilerplate(&mut v);
        assert!(v.firma.is_empty());
        assert_eq!(v.produkt, "GIGABYTE Tools");
        let mut d = Driver { signierer: "Giga-Byte Technology".into(), info: v, ..Default::default() };
        assert_eq!(d.hersteller(), "Giga-Byte Technology");
        let apps = vec![crate::software::Installed {
            name: "GIGABYTE Control Center".into(),
            version: "26.08.11.01".into(),
            publisher: "GIGABYTE".into(),
            registry: String::new(),
        }];
        assert_eq!(owning_program(&d, &apps).as_deref(), Some("GIGABYTE Control Center 26.08.11.01"));
        // MICRO-STAR is not Microsoft.
        d.signierer = "MICRO-STAR INTERNATIONAL CO., LTD.".into();
        let ms = vec![crate::software::Installed { name: "Xbox".into(), version: "1".into(), publisher: "Microsoft Corporation".into(), registry: String::new() }];
        assert!(owning_program(&d, &ms).is_none());
        assert!(!is_boilerplate("ASUSTeK Computer Inc."));
    }

    #[test]
    fn display_leaves_out_empty_fields_and_is_not_escaped() {
        let d = serde_json::json!({
            "version": "", "firma": "ASUSTeK Computer Inc.", "produkt": "VGA 1.01.42", "start_text": "System",
            "liste": "asio.sys", "abgleich": "Hash", "quelle": "LOLDrivers",
            "hinweis": "„Apps & Features“"
        });
        let parts = summary_parts(&d);
        assert_eq!(parts.join(" · "), "ASUSTeK Computer Inc. · Programm: VGA 1.01.42 · Start: System · Liste: asio.sys (Hash)");
        assert!(!parts.iter().any(|p| p.contains("&amp;")));
        assert_eq!(category_line(&d, "TREIBER:LOLDRIVERS"), "Treiber · LOLDrivers (Hash)");
        // Older findings without "quelle".
        assert_eq!(category_line(&serde_json::json!({}), "TREIBER:LOLDRIVERS"), "Treiber · LOLDrivers");
    }

    #[test]
    fn recommendation_matches_the_buttons() {
        for (start, dienst) in [(Some(0), "a"), (Some(1), "a"), (Some(2), "a"), (Some(3), "a"), (Some(4), "a"), (Some(3), ""), (None, "")] {
            let d = Driver { dienst: dienst.into(), start, ..Default::default() };
            let offers = recommendation(&d).contains("hier deaktiviert werden");
            assert_eq!(offers, d.may_disable(), "Start {start:?}, Dienst {dienst:?}");
        }
        let off = Driver { dienst: "a".into(), start: Some(4), ..Default::default() };
        assert!(recommendation(&off).contains("bereits deaktiviert"));
    }

    #[test]
    fn removed_drivers_close_their_findings() {
        let det = crate::model::Detection {
            id: 1,
            path: r"C:\gibt\es\nicht\weg.sys".into(),
            sha256: "a".repeat(64),
            rule_id: "TREIBER:LOLDRIVERS".into(),
            threat_name: "x".into(),
            category: "Treiber".into(),
            severity: crate::model::Severity::Hoch,
            engine: "treiber".into(),
            first_seen: String::new(),
            last_seen: String::new(),
            status: crate::model::DetectionStatus::Offen,
            action: None,
            kind: crate::model::Kind::Treiber,
            details: Some(serde_json::json!({ "dienst": "weg", "dienst_token": "t" })),
        };
        assert_eq!(tidy_decision(&det, None, false), Tidy::Removed);
        assert_eq!(tidy_decision(&det, None, true), Tidy::Keep, "Dienst noch eingetragen");
    }

    #[test]
    fn version_compare() {
        assert!(version_le("1.2.3.4", "1.2.3.4"));
        assert!(version_le("1.2.3", "1.2.10"));
        assert!(!version_le("10.0.0.1", "9.9.9.9"));
        assert!(version_le("0.0.0.0", "65535.65535.65535.65535"));
    }

    #[test]
    fn microsoft_list_hashes_and_name_rules() {
        let xml = r#"<?xml version="1.0"?><SiPolicy><FileRules>
<Deny ID="ID_DENY_X_SHA256" FriendlyName="Testtreiber\abc Hash Sha256" Hash="AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899" />
<Deny ID="ID_DENY_X_PAGE" FriendlyName="Testtreiber\abc Hash Page Sha256" Hash="1111111111111111111111111111111111111111111111111111111111111111" />
<FileAttrib ID="ID_FILEATTRIB_T" FriendlyName="t" FileName="Test.sys" MinimumFileVersion="0.0.0.0" MaximumFileVersion="2.5.0.0" />
</FileRules><Signers><Signer ID="S1" Name="Test CA"><CertRoot Type="TBS" Value="00" /><FileAttribRef RuleID="ID_FILEATTRIB_T" /></Signer></Signers></SiPolicy>"#;
        let idx = parse_ms_blocklist(xml).unwrap();
        assert_eq!(idx.hashes.len(), 1, "Seiten-Hashes werden nicht übernommen");
        assert!(idx.hashes.contains_key("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"));
        assert_eq!(idx.namen[0].datei, "test.sys");
        assert_eq!(idx.namen[0].aussteller, "Test CA");
        let mut d = Driver { datei: PathBuf::from(r"C:\x\test.sys"), ..Default::default() };
        d.info.version = "2.4.0.0".into();
        let hits = matches(&d, &idx);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].abgleich.starts_with("Name"));
        d.info.version = "2.6.0.0".into();
        assert!(matches(&d, &idx).is_empty(), "neuere Version ist nicht betroffen");
    }

    #[test]
    fn loldrivers_entries_with_fake_hashes() {
        let json = br#"[{"Id":"abc","Category":"vulnerable driver","CVE":["CVE-2099-0001"],"Tags":["fake.sys"],
          "KnownVulnerableSamples":[{"Filename":"fake.sys","SHA256":"1111111111111111111111111111111111111111111111111111111111111111",
          "SHA1":"2222222222222222222222222222222222222222","Authentihash":{"SHA256":"3333333333333333333333333333333333333333333333333333333333333333"}}]},
          {"Id":"def","Category":"malicious","KnownVulnerableSamples":[{"SHA256":"4444444444444444444444444444444444444444444444444444444444444444"}]}]"#;
        let idx = parse_loldrivers(json).unwrap();
        assert_eq!(idx.hashes.len(), 4);
        let mut d = Driver { datei: PathBuf::from(r"C:\x\fake.sys"), ..Default::default() };
        d.pe = Some(PeInfo { authenti_sha256: "3".repeat(64), ..Default::default() });
        let hits = matches(&d, &idx);
        assert_eq!(hits[0].abgleich, "Authenticode-Hash");
        assert_eq!(hits[0].eintrag.cve, vec!["CVE-2099-0001".to_string()]);
        d.pe = Some(PeInfo { sha256: "4".repeat(64), ..Default::default() });
        assert_eq!(matches(&d, &idx)[0].eintrag.art, "bösartig");
        // Only the file name is never a hit.
        d.pe = Some(PeInfo { sha256: "9".repeat(64), ..Default::default() });
        assert!(matches(&d, &idx).is_empty());
    }

    #[test]
    fn real_driver_files_parse_and_authenticode_is_stable() {
        let root = std::env::var("SystemRoot").unwrap();
        let f = PathBuf::from(root).join("System32\\drivers\\null.sys");
        let b = std::fs::read(&f).unwrap();
        let pe = analyze_pe(&b).unwrap();
        assert_eq!(pe.sha256.len(), 64);
        assert_ne!(pe.sha256, pe.authenti_sha256);
        // Changing the checksum field does not change the Authenticode hash.
        let mut b2 = b.clone();
        let pe_off = u32_at(&b, 0x3c).unwrap() as usize;
        let opt = pe_off + 24;
        b2[opt + 64] ^= 0xff;
        assert_eq!(analyze_pe(&b2).unwrap().authenti_sha256, pe.authenti_sha256);
        assert!(pe.hvci_probleme.is_empty(), "Windows-Treiber sind HVCI-tauglich: {:?}", pe.hvci_probleme);
    }

    #[test]
    fn paths_of_driver_services() {
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(resolve_image(r"\SystemRoot\System32\drivers\a.sys"), PathBuf::from(&root).join(r"System32\drivers\a.sys"));
        assert_eq!(resolve_image(r"System32\DRIVERS\b.sys"), PathBuf::from(&root).join(r"System32\DRIVERS\b.sys"));
        assert_eq!(resolve_image(r"\??\C:\Tools\c.sys"), PathBuf::from(r"C:\Tools\c.sys"));
    }

    #[test]
    fn drivers_that_lie_only_in_the_driver_store() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("kopfhoerer.inf_amd64_95954b42c4dd9704");
        std::fs::create_dir_all(pkg.join("x64")).unwrap();
        std::fs::write(pkg.join("Kopfhoerer64.sys"), b"MZ").unwrap();
        std::fs::write(pkg.join("x64").join("Zweiter.SYS"), b"MZ").unwrap();
        std::fs::write(pkg.join("kopfhoerer.inf"), b"x").unwrap();
        let used = dir.path().join("kamera.inf_amd64_1");
        std::fs::create_dir_all(&used).unwrap();
        std::fs::write(used.join("kamera.sys"), b"MZ").unwrap();
        // A package of Windows itself is not in the list of packages: never looked at.
        let inbox = dir.path().join("usbvideo.inf_amd64_2");
        std::fs::create_dir_all(&inbox).unwrap();
        std::fs::write(inbox.join("usbvideo.sys"), b"MZ").unwrap();
        let packages = vec![pkg.file_name().unwrap().to_string_lossy().to_string(), "kamera.inf_amd64_1".to_string(), "fehlt.inf_amd64_3".to_string()];
        // kamera.sys is installed (lies in System32\drivers): only the store copy, not listed again.
        let known: HashSet<String> = ["kamera.sys".to_string()].into_iter().collect();
        let found = store_inventory_in(dir.path(), &packages, &known);
        let names: Vec<String> = found.iter().map(|d| d.datei.file_name().unwrap().to_string_lossy().to_string()).collect();
        assert_eq!(names, vec!["Kopfhoerer64.sys", "Zweiter.SYS"]);
        assert!(found.iter().all(|d| d.vorrat && !d.geladen && d.dienst.is_empty()));
        // The real driver database of this PC can be read (may be empty on a fresh Windows).
        assert!(store_packages().iter().all(|p| !p.contains('\\')));
    }

    #[test]
    fn inventory_finds_loaded_drivers() {
        let inv = inventory();
        assert!(inv.iter().any(|d| d.geladen), "mindestens ein geladener Treiber");
        assert!(inv.len() > 50);
    }
}
