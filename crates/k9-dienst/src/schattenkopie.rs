//! Shadow copies as a way back after ransomware (opt-in, `schutz.schattenkopien`, default off):
//! on a schedule (default every 24 h), only while the user is idle (reported by the agent),
//! never during a game. Windows rotates the copies itself within its existing shadow-storage
//! limit (it drops the oldest – that is no "vssadmin delete"). The service never deletes a copy
//! and never changes the storage size (that would be a Windows setting change).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::Svc;
use k9_core::funktion::drives;

const META_LAST: &str = "schattenkopie_letzte";
/// The agent's idle report counts this long.
const IDLE_VALID: Duration = Duration::from_secs(6 * 60);

fn epoch() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Is a new copy due? (`last`: time of the last own copy)
pub fn due(last: Option<u64>, now: u64, every_hours: u64) -> bool {
    last.is_none_or(|l| now.saturating_sub(l) >= every_hours.max(1) * 3600)
}

/// State of the shadow copies of one volume.
#[derive(Debug, Default, PartialEq)]
pub struct State {
    pub count: usize,
    pub newest: String,
    /// Shadow storage limit and use in bytes; None = no storage set up.
    pub max: Option<u64>,
    pub used: u64,
}

/// Parses "count|newest|max|used" from the PowerShell query.
pub fn parse_state(line: &str) -> Option<State> {
    let mut p = line.trim().split('|');
    let count = p.next()?.trim().parse().ok()?;
    let newest = p.next().unwrap_or("").trim().to_string();
    let max = p.next().and_then(|v| v.trim().parse::<u64>().ok()).filter(|v| *v > 0);
    let used = p.next().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
    Some(State { count, newest, max, used })
}

/// One line for the status / dashboard.
pub fn describe(s: &State, drive: &str) -> String {
    let gb = |b: u64| b as f64 / 1024.0 / 1024.0 / 1024.0;
    match s.max {
        None => format!("{drive} kein Speicher für Schattenkopien eingerichtet (Computerschutz aus?) – es können keine angelegt werden"),
        Some(max) => format!(
            "{drive} {} Schattenkopien, neueste {}, Speicher {:.1} von {:.1} GB belegt (Windows löscht die ältesten selbst)",
            s.count,
            if s.newest.is_empty() { "–" } else { &s.newest },
            gb(s.used),
            gb(max)
        ),
    }
}

fn powershell(cmd: &str) -> Option<String> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = std::path::Path::new(&windir).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    let out = std::process::Command::new(exe).args(["-NoProfile", "-NonInteractive", "-Command", cmd]).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Time of the last own copy of a drive (older versions kept one value, for their one drive).
fn meta_key(drive: &str) -> String {
    format!("{META_LAST}:{drive}")
}

fn query(drive: &str) -> Option<State> {
    let cmd = format!(
        "$v = (Get-CimInstance Win32_Volume -Filter \"DriveLetter='{drive}'\").DeviceID; \
         $c = @(Get-CimInstance Win32_ShadowCopy | Where-Object VolumeName -eq $v); \
         $s = Get-CimInstance Win32_ShadowStorage | Where-Object {{ $_.Volume.DeviceID -eq $v }} | Select-Object -First 1; \
         $n = $c | Sort-Object InstallDate -Descending | Select-Object -First 1; \
         '{{0}}|{{1}}|{{2}}|{{3}}' -f $c.Count, $(if ($n) {{ $n.InstallDate.ToString('yyyy-MM-dd HH:mm') }}), $s.MaxSpace, $s.UsedSpace"
    );
    parse_state(&powershell(&cmd)?)
}

fn create(drive: &str) -> bool {
    let cmd = format!("(Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{{Volume='{drive}\\'; Context='ClientAccessible'}}).ReturnValue");
    powershell(&cmd).as_deref() == Some("0")
}

/// Sleeps `secs` seconds in steps of 10; false if the service is stopping.
fn wait(svc: &Svc, secs: u64) -> bool {
    for _ in 0..secs.div_ceil(10) {
        if svc.is_stopping() {
            return false;
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    true
}

pub fn run(svc: Arc<Svc>) {
    // Switching on/off and the drive list apply without a restart (the settings watcher updates `live`).
    loop {
        let (on, list, hours) = {
            let l = svc.live();
            (l.schutz.schattenkopien, drives(&l.schutz.schattenkopien_laufwerke), l.schutz.schattenkopien_stunden)
        };
        if on && !list.is_empty() {
            match active(&svc, &list, hours) {
                Phase::Stopping => return,
                Phase::Changed => continue,
                Phase::Off => {
                    *svc.vss_status.lock().unwrap() = None;
                    tracing::info!("Schattenkopien im Leerlauf: aus");
                }
            }
        } else if !wait(&svc, 30) {
            return;
        }
    }
}

enum Phase {
    Stopping,
    Off,
    /// Drives or interval changed: start again with the new values.
    Changed,
}

fn notice_no_storage(svc: &Svc, drive: &str) {
    tracing::warn!("Schattenkopien: kein Speicher auf {drive} eingerichtet");
    let mut f = crate::wache::notice(
        "SCHATTENKOPIE:KEIN-SPEICHER",
        "Schattenkopien sind eingeschaltet, aber Windows hat keinen Speicher dafür",
        &format!(
            "Auf Laufwerk {drive} ist der Computerschutz (Speicher für Schattenkopien) nicht eingerichtet, deshalb kann K9 dort keine Kopien anlegen. \
             K9 ändert diese Windows-Einstellung nicht selbst. Einschalten: Systemsteuerung → System → Computerschutz → Laufwerk {drive} → Konfigurieren."
        ),
    );
    f.severity = k9_core::model::Severity::Mittel;
    // One finding per drive while it is open (not a new one at every service start).
    f.sha256 = k9_core::sha256_hex(format!("schattenkopie|kein-speicher|{drive}").as_bytes());
    f.path = std::path::PathBuf::from(format!("Schattenkopien auf {drive}: kein Speicher eingerichtet"));
    svc.report(&f);
}

/// While switched on, for these drives.
fn active(svc: &Arc<Svc>, list: &[String], hours: u64) -> Phase {
    tracing::info!("Schattenkopien im Leerlauf: aktiv ({}, alle {hours} h)", list.join(", "));
    let mut warned: Vec<String> = Vec::new();
    let mut status: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut refresh = |svc: &Svc, drive: &str| -> Option<State> {
        let s = query(drive)?;
        status.insert(drive.to_string(), describe(&s, drive));
        *svc.vss_status.lock().unwrap() = Some(status.values().cloned().collect::<Vec<_>>().join("; "));
        if s.max.is_none() && !warned.iter().any(|w| w == drive) {
            warned.push(drive.to_string());
            notice_no_storage(svc, drive);
        }
        Some(s)
    };
    for d in list {
        refresh(svc, d);
    }
    loop {
        for _ in 0..10 {
            if !wait(svc, 30) {
                return Phase::Stopping;
            }
            let l = svc.live();
            if !l.schutz.schattenkopien {
                return Phase::Off;
            }
            if drives(&l.schutz.schattenkopien_laufwerke) != list || l.schutz.schattenkopien_stunden != hours {
                return Phase::Changed;
            }
        }
        let Ok(store) = svc.app.store() else { continue };
        for drive in list {
            // Before every drive again: only while idle, never during a game.
            let idle = svc.user_idle.lock().unwrap().is_some_and(|t| t.elapsed() < IDLE_VALID);
            if !idle || crate::quellen::gaming(svc) {
                break;
            }
            let key = meta_key(drive);
            let mut last = store.meta_get(&key).ok().flatten();
            if last.is_none() && drive == "C:" {
                last = store.meta_get(META_LAST).ok().flatten();
            }
            if !due(last.and_then(|v| v.parse::<u64>().ok()), epoch(), hours) {
                continue;
            }
            if refresh(svc, drive).is_some_and(|s| s.max.is_none()) {
                let _ = store.meta_set(&key, &epoch().to_string()); // try again next interval
                continue;
            }
            let started = Instant::now();
            let ok = create(drive);
            let _ = store.meta_set(&key, &epoch().to_string());
            if ok {
                let _ = store.log_event("info", &format!("Schattenkopie von {drive} angelegt (Leerlauf)"));
                tracing::info!("Schattenkopie von {drive} angelegt ({:.0} s)", started.elapsed().as_secs_f64());
            } else {
                tracing::warn!("Schattenkopie von {drive} konnte nicht angelegt werden");
            }
            crate::stoerungen::job_result(
                svc,
                &crate::stoerungen::Job {
                    key: &format!("SCHATTENKOPIE:{drive}"),
                    threshold: 2,
                    title: &format!("Schattenkopien von {drive} lassen sich nicht anlegen"),
                    hint: &format!(
                        "Zwei Versuche hintereinander sind gescheitert. Ohne neue Schattenkopien fehlt dir nach einem Ransomware-Befall der letzte Stand deiner Dateien auf {drive}. \
                         Häufige Gründe: der Speicher für Schattenkopien ist voll oder nicht eingerichtet, das Laufwerk ist fast voll, oder der Windows-Dienst „Volumeschattenkopie“ ist deaktiviert. \
                         Ansehen: „k9 dienst status“ zeigt den Stand je Laufwerk. Klappt die nächste Kopie, schließt K9 diese Meldung von selbst."
                    ),
                    done: &format!("Schattenkopie von {drive} wurde wieder angelegt"),
                    severity: k9_core::model::Severity::Mittel,
                },
                ok,
            );
            refresh(svc, drive);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k9_core::funktion::drive_letter;

    #[test]
    fn the_service_never_deletes_or_resizes_shadow_copies() {
        // Only "Create" and reading queries – no delete, no storage change (Windows rotates itself).
        let code: String = include_str!("schattenkopie.rs").lines().take_while(|l| !l.starts_with("#[cfg(test)]")).filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n").to_lowercase();
        for forbidden in ["delete", "remove-", "vssadmin", "resize", "maxspace ="] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
        assert!(code.contains("-methodname create"));
    }

    #[test]
    fn only_clean_drive_letters_reach_powershell() {
        assert_eq!(drive_letter("c"), Some("C:".into()));
        assert_eq!(drive_letter(" F:\\ "), Some("F:".into()));
        for bad in ["", "CD:", "C:\\x", "1:", "C;", "C:'; Remove-Item x", "Ü:"] {
            assert_eq!(drive_letter(bad), None, "{bad}");
        }
        let list: Vec<String> = ["C:", "f", "c:\\", "x;y", "F:"].iter().map(|s| s.to_string()).collect();
        assert_eq!(drives(&list), vec!["C:".to_string(), "F:".to_string()]);
    }

    #[test]
    fn copies_on_schedule_and_status_is_readable() {
        let h = 3600;
        assert!(due(None, 100 * h, 24));
        assert!(!due(Some(90 * h), 100 * h, 24), "noch nicht 24 h");
        assert!(due(Some(76 * h), 100 * h, 24));
        let s = parse_state("3|2026-11-15 04:00|10737418240|2147483648").unwrap();
        assert_eq!(s.count, 3);
        assert!(describe(&s, "C:").contains("2.0 von 10.0 GB"));
        let none = parse_state("0||||").unwrap();
        assert_eq!(none.max, None);
        assert!(describe(&none, "C:").contains("kein Speicher"));
        assert_eq!(drive_letter("d:\\"), Some("D:".into()));
        assert_eq!(drive_letter("???"), None);
    }
}
