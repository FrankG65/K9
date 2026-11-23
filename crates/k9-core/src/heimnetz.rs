//! New devices in the home network: the agent asks every address of its own /24 network
//! (the one with the default route, no virtual Hyper-V/WSL networks) for its hardware address
//! (ARP) – once an hour, never while a game runs. The very first run only remembers the
//! devices present; afterwards an unknown device is reported once (Niedrig, only "Gesehen").
//! Nothing is sent to the devices except the normal ARP question every PC asks.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::model::{Finding, Kind, Severity};

pub const META_KEY: &str = "heimnetz_geraete";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Geraet {
    pub ip: String,
    pub erstmals: String,
    pub zuletzt: String,
}

/// MAC address ("aa-bb-cc-dd-ee-ff") -> device.
pub type Bekannt = BTreeMap<String, Geraet>;

/// Locally administered address: phones and tablets use a random one per network.
pub fn is_random_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(0..2).unwrap_or("00"), 16).is_ok_and(|b| b & 0x02 != 0)
}

fn mac_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join("-")
}

/// Merges a sweep into the known devices. Returns the new devices (none on the very first
/// run, `first`: everything present is the starting point).
pub fn merge(known: &mut Bekannt, seen: &[(Ipv4Addr, String)], now: &str, first: bool) -> Vec<(Ipv4Addr, String)> {
    let mut new = Vec::new();
    for (ip, mac) in seen {
        match known.get_mut(mac) {
            Some(g) => {
                g.ip = ip.to_string();
                g.zuletzt = now.to_string();
            }
            None => {
                known.insert(mac.clone(), Geraet { ip: ip.to_string(), erstmals: now.to_string(), zuletzt: now.to_string() });
                if !first {
                    new.push((*ip, mac.clone()));
                }
            }
        }
    }
    new
}

pub fn finding(ip: Ipv4Addr, mac: &str) -> Finding {
    let random = is_random_mac(mac);
    let hint = if random {
        t!("Das Gerät nutzt eine zufällige Hardware-Adresse – das machen Handys, Tablets und Laptops. Kennst du es (z. B. ein Handy der Familie oder von Gästen): „Gesehen“. Sonst in der Geräteliste deines Routers nachsehen und dort sperren bzw. das WLAN-Passwort ändern.", "The device uses a random hardware address – phones, tablets and laptops do that. If you know it (e.g. a phone of the family or of guests): “Seen”. Otherwise look it up in the device list of your router and block it there or change the Wi-Fi password.")
    } else {
        t!("Kennst du das Gerät (neuer Fernseher, Drucker, Konsole, Handy von Gästen …): „Gesehen“. Sonst in der Geräteliste deines Routers nachsehen, was es ist, und es dort sperren bzw. das WLAN-Passwort ändern.", "If you know the device (new TV, printer, console, phone of guests …): “Seen”. Otherwise look up in the device list of your router what it is and block it there or change the Wi-Fi password.")
    };
    Finding {
        path: PathBuf::from(tf!("Gerät {ip} ({mac})", "Device {ip} ({mac})")),
        // One finding per hardware address: "Gesehen" is remembered for exactly this device.
        sha256: crate::sha256_hex(format!("heimnetz|{mac}").as_bytes()),
        size: 0,
        rule_id: "HEIMNETZ:NEUES-GERAET".into(),
        threat_name: tf!("Neues Gerät im Heimnetz: {ip}{}", "New device in the home network: {ip}{}", if random { t!(" (zufällige Adresse, vermutlich Handy/Tablet)", " (random address, probably phone/tablet)") } else { "" }),
        category: t!("Heimnetz", "Home network").into(),
        severity: Severity::Niedrig,
        engine: "echtzeit".into(),
        kind: Kind::Hinweis,
        details: Some(serde_json::json!({ "hinweis": hint, "ip": ip.to_string(), "mac": mac })),
    }
}

/// Own address and mask of the interface with the default route (None: no network).
fn home_network() -> Option<(Ipv4Addr, Ipv4Addr)> {
    use windows::Win32::NetworkManagement::IpHelper::{GetBestInterface, GetIpAddrTable, MIB_IPADDRTABLE};
    // SAFETY: buffers sized by the API; reads only within dwNumEntries.
    unsafe {
        let mut index = 0u32;
        // 1.1.1.1 – only to find the interface with the default route, nothing is sent.
        if GetBestInterface(u32::from_le_bytes([1, 1, 1, 1]), &mut index) != 0 {
            return None;
        }
        let mut size = 0u32;
        let _ = GetIpAddrTable(None, &mut size, false);
        let mut buf = vec![0u8; size as usize + 64];
        if GetIpAddrTable(Some(buf.as_mut_ptr().cast::<MIB_IPADDRTABLE>()), &mut size, false) != 0 {
            return None;
        }
        let t = &*(buf.as_ptr().cast::<MIB_IPADDRTABLE>());
        let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
        let row = rows.iter().find(|r| r.dwIndex == index && r.dwAddr != 0)?;
        Some((Ipv4Addr::from(row.dwAddr.to_le_bytes()), Ipv4Addr::from(row.dwMask.to_le_bytes())))
    }
}

/// Devices Windows already knows in the home network (its neighbour table) – read only, no
/// packet is sent. A device that talks to this PC or asks for it shows up here at once.
pub fn neighbours() -> Option<Vec<(Ipv4Addr, String)>> {
    use windows::Win32::NetworkManagement::IpHelper::{GetIpNetTable, MIB_IPNETTABLE};
    let (own, mask) = home_network()?;
    let allowed = targets(own, mask);
    let mut size = 0u32;
    let mut out = Vec::new();
    // SAFETY: buffer sized by the API; reads only within dwNumEntries.
    unsafe {
        let _ = GetIpNetTable(None, &mut size, false);
        if size == 0 {
            return Some(out);
        }
        let mut buf = vec![0u64; (size as usize).div_ceil(8) + 64];
        size = (buf.len() * 8) as u32;
        if GetIpNetTable(Some(buf.as_mut_ptr().cast::<MIB_IPNETTABLE>()), &mut size, false) != 0 {
            return None;
        }
        let t = &*(buf.as_ptr().cast::<MIB_IPNETTABLE>());
        let rows = std::slice::from_raw_parts(t.table.as_ptr(), t.dwNumEntries as usize);
        for r in rows {
            let ip = Ipv4Addr::from(r.dwAddr.to_le_bytes());
            let mac = &r.bPhysAddr[..6];
            // dynamic (3) or static (4) entries with a real hardware address of the own network
            if r.dwPhysAddrLen == 6 && matches!(r.Anonymous.dwType, 3 | 4) && mac != [0; 6] && mac != [0xff; 6] && mac[0] & 1 == 0 && allowed.contains(&ip) {
                out.push((ip, mac_string(mac)));
            }
        }
    }
    Some(out)
}

/// The addresses to ask: the own /24 (or the smaller network), only private networks.
pub fn targets(own: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    if !own.is_private() {
        return Vec::new();
    }
    let m = u32::from(mask).max(0xFFFF_FF00);
    let net = u32::from(own) & m;
    let bcast = net | !m;
    (net + 1..bcast).map(Ipv4Addr::from).filter(|a| *a != own).collect()
}

/// Asks every address of the home network for its hardware address (32 at a time).
pub fn sweep() -> Option<Vec<(Ipv4Addr, String)>> {
    let (own, mask) = home_network()?;
    let list = targets(own, mask);
    let mut found = Vec::new();
    for chunk in list.chunks(32) {
        let handles: Vec<_> = chunk
            .iter()
            .map(|ip| {
                let ip = *ip;
                std::thread::spawn(move || {
                    let mut mac = [0u8; 8];
                    let mut len = 6u32;
                    // SAFETY: buffer of 8 bytes, length passed.
                    let r = unsafe { windows::Win32::NetworkManagement::IpHelper::SendARP(u32::from_le_bytes(ip.octets()), 0, mac.as_mut_ptr().cast(), &mut len) };
                    (r == 0 && len == 6 && mac[..6] != [0; 6] && mac[..6] != [0xff; 6]).then(|| (ip, mac_string(&mac[..6])))
                })
            })
            .collect();
        found.extend(handles.into_iter().filter_map(|h| h.join().ok().flatten()));
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_run_is_the_baseline_then_new_devices_are_reported_once() {
        let mut known = Bekannt::new();
        let a = (Ipv4Addr::new(192, 168, 178, 1), "aa-aa-aa-aa-aa-01".to_string());
        let b = (Ipv4Addr::new(192, 168, 178, 20), "3e-11-22-33-44-55".to_string());
        assert!(merge(&mut known, std::slice::from_ref(&a), "t1", true).is_empty());
        assert_eq!(merge(&mut known, &[a.clone(), b.clone()], "t2", false), vec![b.clone()]);
        assert!(merge(&mut known, &[a, b.clone()], "t3", false).is_empty(), "nur einmal");
        assert!(is_random_mac(&b.1) && !is_random_mac("00-11-22-33-44-55"));
        let f = finding(b.0, &b.1);
        assert!(f.threat_name.contains("Handy"));
        assert_eq!(f.sha256, finding(Ipv4Addr::new(192, 168, 178, 99), &b.1).sha256, "gleiches Geraet, neue Adresse: gleicher Fund");
    }

    #[test]
    fn sweeps_only_the_own_small_private_network() {
        let t = targets(Ipv4Addr::new(192, 168, 178, 20), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(t.len(), 253, "hoechstens das eigene /24, ohne die eigene Adresse");
        assert!(targets(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(255, 255, 255, 0)).is_empty());
    }
}

#[cfg(test)]
mod live {
    #[test]
    #[ignore = "fragt das echte Heimnetz ab"]
    fn real_sweep() {
        let t = std::time::Instant::now();
        let r = super::sweep();
        println!("{:?} in {:?}", r.as_ref().map(|l| l.len()), t.elapsed());
        for (ip, mac) in r.unwrap_or_default() {
            println!("  {ip} {mac} zufaellig={}", super::is_random_mac(&mac));
        }
    }
}

#[cfg(test)]
mod live_neighbours {
    #[test]
    #[ignore = "liest die Nachbartabelle dieses PCs"]
    fn real_neighbours() {
        println!("{:?}", super::neighbours());
    }
}
