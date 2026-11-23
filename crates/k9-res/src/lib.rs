//! Build helper: turns `pictures/k9.ico` into a Windows resource file (`.res`) with the program
//! icon (RT_GROUP_ICON id 1) and hands it to the linker. No resource compiler is needed: the
//! format is written here, link.exe converts it itself.

use std::path::{Path, PathBuf};

const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;
/// Id of the icon group (the first group is the program icon in Explorer and shortcuts).
pub const ICON_ID: u16 = 1;

/// One image of an .ico file.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub width: u8,
    pub height: u8,
    pub colors: u8,
    pub planes: u16,
    pub bits: u16,
    pub data: Vec<u8>,
}

/// Reads the images of an .ico file.
pub fn parse_ico(ico: &[u8]) -> Result<Vec<Image>, String> {
    let u16le = |o: usize| -> Result<u16, String> { ico.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or("ICO zu kurz".to_string()) };
    let u32le = |o: usize| -> Result<u32, String> { ico.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or("ICO zu kurz".to_string()) };
    if u16le(0)? != 0 || u16le(2)? != 1 {
        return Err("keine ICO-Datei".into());
    }
    let n = u16le(4)? as usize;
    let mut out = Vec::new();
    for i in 0..n {
        let e = 6 + 16 * i;
        let size = u32le(e + 8)? as usize;
        let offset = u32le(e + 12)? as usize;
        let data = ico.get(offset..offset + size).ok_or("ICO-Eintrag ausserhalb der Datei")?.to_vec();
        out.push(Image { width: ico[e], height: ico[e + 1], colors: ico[e + 2], planes: u16le(e + 4)?, bits: u16le(e + 6)?, data });
    }
    Ok(out)
}

fn resource(out: &mut Vec<u8>, kind: u16, name: u16, data: &[u8]) {
    let header_size: u32 = 32;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&name.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    let flags: u16 = if kind == RT_ICON { 0x1010 } else { 0x1030 }; // MOVEABLE|DISCARDABLE (|PURE)
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0x0409u16.to_le_bytes()); // language (neutral enough; icons are language-free)
    out.extend_from_slice(&0u32.to_le_bytes()); // Version
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// The .res file for these images (one icon group, id 1).
pub fn res_file(images: &[Image]) -> Vec<u8> {
    res_file_groups(&[(ICON_ID, images.to_vec())])
}

/// The .res file for several icon groups (group id, images). Image ids: 100 * group + n.
pub fn res_file_groups(groups: &[(u16, Vec<Image>)]) -> Vec<u8> {
    let mut out = Vec::new();
    // Empty first entry marks a 32-bit resource file.
    out.extend_from_slice(&[0, 0, 0, 0, 0x20, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0]);
    out.extend_from_slice(&[0u8; 16]);
    for (group_id, images) in groups {
        let mut group = Vec::new();
        group.extend_from_slice(&0u16.to_le_bytes());
        group.extend_from_slice(&1u16.to_le_bytes());
        group.extend_from_slice(&(images.len() as u16).to_le_bytes());
        for (i, img) in images.iter().enumerate() {
            let id = 100 * group_id + i as u16;
            resource(&mut out, RT_ICON, id, &img.data);
            group.extend_from_slice(&[img.width, img.height, img.colors, 0]);
            group.extend_from_slice(&img.planes.to_le_bytes());
            group.extend_from_slice(&img.bits.to_le_bytes());
            group.extend_from_slice(&(img.data.len() as u32).to_le_bytes());
            group.extend_from_slice(&id.to_le_bytes());
        }
        resource(&mut out, RT_GROUP_ICON, *group_id, &group);
    }
    out
}

/// For build.rs: the program icon (pictures/k9.ico) as icon 1.
pub fn embed_icon() {
    embed_icons(&[(ICON_ID, "k9.ico")]);
}

/// For build.rs: icons from pictures/ as icon groups (id, file name); the first group is the
/// program icon. Writes the .res file into OUT_DIR and links it.
pub fn embed_icons(icons: &[(u16, &str)]) {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let dir = manifest.ancestors().map(|d| d.join("pictures")).find(|p| p.join("k9.ico").is_file()).expect("pictures/k9.ico fehlt");
    let groups: Vec<(u16, Vec<Image>)> = icons
        .iter()
        .map(|(id, name)| {
            let ico = dir.join(name);
            println!("cargo:rerun-if-changed={}", ico.display());
            (*id, parse_ico(&std::fs::read(&ico).unwrap_or_else(|e| panic!("{name}: {e}"))).unwrap_or_else(|e| panic!("{name}: {e}")))
        })
        .collect();
    let out = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("k9-symbol.res");
    std::fs::write(&out, res_file_groups(&groups)).expect("k9-symbol.res schreiben");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_project_icon_becomes_a_valid_resource_file() {
        let ico = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../pictures/k9.ico")).unwrap();
        let images = parse_ico(&ico).unwrap();
        assert_eq!(images.len(), 10, "16 bis 256 Pixel");
        assert!(images.iter().any(|i| i.width == 16) && images.iter().any(|i| i.width == 0), "16 und 256 (Breite 0)");
        let res = res_file(&images);
        assert_eq!(&res[..8], &[0, 0, 0, 0, 0x20, 0, 0, 0]);
        assert!(res.len().is_multiple_of(4));
        // 1 empty + 10 icons + 1 group
        let mut n = 0;
        let mut o = 0;
        while o < res.len() {
            let size = u32::from_le_bytes(res[o..o + 4].try_into().unwrap()) as usize;
            let head = u32::from_le_bytes(res[o + 4..o + 8].try_into().unwrap()) as usize;
            o += (head + size).div_ceil(4) * 4;
            n += 1;
        }
        assert_eq!(n, 12);
        assert!(parse_ico(b"not an icon").is_err());
    }
}
