//! Hidden autostarts through WMI ("permanent event subscriptions"): a filter (for example
//! "every few minutes" or "when the user logs on") bound to a consumer that runs a command
//! line or a script. Malware likes this trick because it leaves no Run entry, no file in
//! the Startup folder and no scheduled task. Windows itself and normal programs hardly ever
//! use command line or script consumers, so every bound one is reported.
//! Read only (the Windows service reads the namespace root\subscription); nothing is removed –
//! the finding says how to remove an entry.

use std::path::PathBuf;

use crate::model::{Finding, Kind, Severity};

/// A consumer that runs something.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Consumer {
    /// "CommandLineEventConsumer" or "ActiveScriptEventConsumer".
    pub class: String,
    pub name: String,
    /// Command line, or script engine + file/text.
    pub action: String,
}

/// Binding of a filter to a consumer (WMI object paths as stored).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Binding {
    pub filter: String,
    pub consumer: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Filter {
    pub name: String,
    pub query: String,
}

/// The name from a WMI object path like `CommandLineEventConsumer.Name="x"` (or `\\.\root\…:…Name="x"`).
fn name_in_path(path: &str) -> Option<String> {
    let i = path.find("Name=\"")? + 6;
    let rest = &path[i..];
    let end = rest.find('"')?;
    Some(rest[..end].replace("\\\\", "\\"))
}

fn class_in_path(path: &str) -> String {
    let p = path.rsplit(':').next().unwrap_or(path);
    p.split('.').next().unwrap_or("").to_string()
}

/// Findings for every consumer that runs something and is bound to a filter.
pub fn findings(consumers: &[Consumer], bindings: &[Binding], filters: &[Filter]) -> Vec<Finding> {
    let mut out = Vec::new();
    for c in consumers {
        let bound: Vec<&Binding> = bindings
            .iter()
            .filter(|b| class_in_path(&b.consumer).eq_ignore_ascii_case(&c.class) && name_in_path(&b.consumer).as_deref() == Some(c.name.as_str()))
            .collect();
        if bound.is_empty() {
            continue; // never triggered – nothing runs
        }
        let triggers: Vec<String> = bound
            .iter()
            .filter_map(|b| name_in_path(&b.filter))
            .map(|n| match filters.iter().find(|f| f.name == n) {
                Some(f) => format!("{n}: {}", f.query),
                None => n,
            })
            .collect();
        let script = c.class.eq_ignore_ascii_case("ActiveScriptEventConsumer");
        let remove = format!(
            "Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object {{ $_.Consumer.Name -eq '{}' }} | Remove-CimInstance",
            c.name.replace('\'', "''")
        );
        let hint = tf!(
            "Startet {}: {}\nAuslöser: {}\nKennst du das nicht (z. B. Werkzeug deines PC-Herstellers), ist das ein typisches Versteck von Schadsoftware. Entfernen in einer Administrator-PowerShell:\n{remove}\nDanach einen vollständigen Scan starten. Kennst du es: „Gesehen“ – dieser Eintrag wird dann nicht mehr gemeldet.", "Starts {}: {}\nTrigger: {}\nIf you do not know this (e.g. a tool of your PC manufacturer), it is a typical hiding place for malware. Remove it in an administrator PowerShell:\n{remove}\nThen start a full scan. If you know it: “Seen” – this entry is then no longer reported.",
            if script { t!("ein Skript", "a script") } else { t!("eine Befehlszeile", "a command line") },
            c.action,
            if triggers.is_empty() { t!("unbekannt", "unknown").to_string() } else { triggers.join("; ") },
        );
        out.push(Finding {
            path: PathBuf::from(tf!("WMI-Autostart „{}“", "WMI autostart “{}”", c.name)),
            // Stable: the same entry is one finding, "Gesehen" is remembered for exactly it.
            sha256: crate::sha256_hex(format!("wmi|{}|{}|{}", c.class, c.name, c.action).as_bytes()),
            size: 0,
            rule_id: "AUTOSTART:WMI".into(),
            threat_name: tf!("Versteckter Autostart über WMI: „{}“ startet {}", "Hidden autostart via WMI: “{}” starts {}", c.name, if script { t!("ein Skript", "a script") } else { t!("ein Programm", "a program") }),
            category: "Autostart (WMI)".into(),
            severity: Severity::Hoch,
            engine: "dienst".into(),
            kind: Kind::Hinweis,
            details: Some(serde_json::json!({
                "hinweis": hint,
                "klasse": c.class,
                "name": c.name,
                "befehl": c.action,
                "ausloeser": triggers,
            })),
        });
    }
    out
}

/// Reads consumers, bindings and filters from root\subscription (needs administrator rights;
/// the Windows service). None if WMI can't be read.
pub fn read() -> Option<(Vec<Consumer>, Vec<Binding>, Vec<Filter>)> {
    let wmi = Wmi::connect("ROOT\\subscription")?;
    let mut consumers = Vec::new();
    for o in wmi.query("SELECT Name, CommandLineTemplate, ExecutablePath FROM CommandLineEventConsumer")? {
        let cmd = o.get("CommandLineTemplate");
        let exe = o.get("ExecutablePath");
        let action = match (exe.is_empty(), cmd.is_empty()) {
            (false, false) => format!("{exe} | {cmd}"),
            (false, true) => exe,
            _ => cmd,
        };
        consumers.push(Consumer { class: "CommandLineEventConsumer".into(), name: o.get("Name"), action });
    }
    for o in wmi.query("SELECT Name, ScriptingEngine, ScriptFileName, ScriptText FROM ActiveScriptEventConsumer")? {
        let file = o.get("ScriptFileName");
        let text: String = o.get("ScriptText").chars().take(300).collect();
        let action = format!("{} {}", o.get("ScriptingEngine"), if file.is_empty() { text } else { file });
        consumers.push(Consumer { class: "ActiveScriptEventConsumer".into(), name: o.get("Name"), action });
    }
    let bindings = wmi
        .query("SELECT Filter, Consumer FROM __FilterToConsumerBinding")?
        .into_iter()
        .map(|o| Binding { filter: o.get("Filter"), consumer: o.get("Consumer") })
        .collect();
    let filters = wmi.query("SELECT Name, Query FROM __EventFilter")?.into_iter().map(|o| Filter { name: o.get("Name"), query: o.get("Query") }).collect();
    Some((consumers, bindings, filters))
}

pub(crate) struct Wmi(windows::Win32::System::Wmi::IWbemServices);

pub(crate) struct Obj(windows::Win32::System::Wmi::IWbemClassObject);

impl Obj {
    pub(crate) fn get(&self, name: &str) -> String {
        use windows::core::HSTRING;
        use windows::Win32::System::Variant::{VariantClear, VariantToString, VARIANT};
        let mut v = VARIANT::default();
        let mut buf = vec![0u16; 8192];
        // SAFETY: the VARIANT is filled by WMI and cleared afterwards; the buffer is sized.
        unsafe {
            if self.0.Get(&HSTRING::from(name), 0, &mut v, None, None).is_err() {
                return String::new();
            }
            let ok = VariantToString(&v, &mut buf).is_ok();
            let _ = VariantClear(&mut v);
            if !ok {
                return String::new();
            }
        }
        let len = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }
}

impl Wmi {
    pub(crate) fn connect(namespace: &str) -> Option<Self> {
        use windows::core::BSTR;
        use windows::Win32::System::Com::{
            CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        };
        use windows::Win32::System::Wmi::{IWbemLocator, WbemLocator};
        // SAFETY: COM calls with owned interfaces; RPC_C_AUTHN_WINNT = 10, RPC_C_AUTHZ_NONE = 0.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER).ok()?;
            let svc = loc.ConnectServer(&BSTR::from(namespace), &BSTR::new(), &BSTR::new(), &BSTR::new(), 0, &BSTR::new(), None).ok()?;
            CoSetProxyBlanket(&svc, 10, 0, None, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, None, EOAC_NONE).ok()?;
            Some(Self(svc))
        }
    }

    pub(crate) fn query(&self, wql: &str) -> Option<Vec<Obj>> {
        use windows::core::BSTR;
        use windows::Win32::System::Wmi::{IWbemClassObject, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_INFINITE};
        let mut out = Vec::new();
        // SAFETY: COM enumeration with owned interfaces.
        unsafe {
            let e = self.0.ExecQuery(&BSTR::from("WQL"), &BSTR::from(wql), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, None).ok()?;
            loop {
                let mut objs: [Option<IWbemClassObject>; 1] = [None];
                let mut got = 0u32;
                let hr = e.Next(WBEM_INFINITE, &mut objs, &mut got);
                if hr.is_err() || got == 0 {
                    break;
                }
                if let Some(o) = objs[0].take() {
                    out.push(Obj(o));
                }
                if out.len() > 1000 {
                    break;
                }
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bound_consumers_that_run_something_are_reported() {
        let consumers = vec![
            Consumer { class: "CommandLineEventConsumer".into(), name: "Updater".into(), action: "powershell -enc AAAA".into() },
            Consumer { class: "CommandLineEventConsumer".into(), name: "Lose".into(), action: "calc.exe".into() },
        ];
        let bindings = vec![Binding {
            filter: "\\\\.\\root\\subscription:__EventFilter.Name=\"Alle5Minuten\"".into(),
            consumer: "\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"Updater\"".into(),
        }];
        let filters = vec![Filter { name: "Alle5Minuten".into(), query: "SELECT * FROM __InstanceModificationEvent WITHIN 300".into() }];
        let f = findings(&consumers, &bindings, &filters);
        assert_eq!(f.len(), 1, "nicht gebundene Eintraege starten nichts");
        assert_eq!((f[0].rule_id.as_str(), f[0].severity, f[0].kind), ("AUTOSTART:WMI", Severity::Hoch, Kind::Hinweis));
        let hint = f[0].details.as_ref().unwrap()["hinweis"].as_str().unwrap().to_string();
        assert!(hint.contains("powershell -enc AAAA") && hint.contains("WITHIN 300") && hint.contains("Remove-CimInstance"));
        assert_eq!(f[0].sha256, findings(&consumers, &bindings, &filters)[0].sha256, "stabiler Fingerabdruck");
    }

    #[test]
    fn names_in_object_paths() {
        assert_eq!(name_in_path("CommandLineEventConsumer.Name=\"a b\"").as_deref(), Some("a b"));
        assert_eq!(class_in_path("\\\\.\\root\\subscription:ActiveScriptEventConsumer.Name=\"x\""), "ActiveScriptEventConsumer");
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "liest das echte WMI dieses PCs"]
    fn read_real_wmi() {
        let r = super::read();
        println!("{r:?}");
        assert!(r.is_some());
    }
}
