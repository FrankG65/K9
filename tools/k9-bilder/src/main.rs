//! Erzeugt aus den SVG-Quellen in `pictures/` alle PNG- und ICO-Dateien von K9.
//! Aufruf (im Projektordner): `cargo run --release --manifest-path tools/k9-bilder/Cargo.toml`
//! Die Ausgabe ist reproduzierbar: gleiche SVG-Dateien ergeben gleiche Bilder.

use std::path::{Path, PathBuf};

use resvg::{tiny_skia, usvg};

/// Ab dieser Groesse die Pfote mit Schriftzug, darunter die vereinfachte Pfote.
const KLEIN_BIS: u32 = 32;

fn tree(path: &Path) -> usvg::Tree {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    usvg::Tree::from_data(&data, &usvg::Options::default()).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Rendert eine SVG-Datei auf `width` Pixel Breite (Hoehe im Seitenverhaeltnis) als PNG.
fn png(svg: &Path, width: u32) -> Vec<u8> {
    let t = tree(svg);
    let size = t.size();
    let scale = width as f32 / size.width();
    let height = (size.height() * scale).round() as u32;
    let mut pixmap = tiny_skia::Pixmap::new(width, height).expect("Bildgroesse");
    resvg::render(&t, tiny_skia::Transform::from_scale(scale, scale), &mut pixmap.as_mut());
    pixmap.encode_png().expect("PNG")
}

/// ICO-Datei mit PNG-Eintraegen (Windows Vista und neuer).
fn ico(images: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (size, data) in images {
        let b = if *size >= 256 { 0 } else { *size as u8 };
        out.extend_from_slice(&[b, b, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for (_, data) in images {
        out.extend_from_slice(data);
    }
    out
}

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "pictures".into()));
    let gross = dir.join("k9-pfote.svg");
    let klein = dir.join("k9-pfote-klein.svg");
    let quelle = |s: u32| if s <= KLEIN_BIS { &klein } else { &gross };
    let write = |name: &str, data: &[u8]| {
        std::fs::write(dir.join(name), data).unwrap_or_else(|e| panic!("{name}: {e}"));
        println!("{name} ({} Bytes)", data.len());
    };

    for s in [16, 20, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024] {
        write(&format!("k9-{s}.png"), &png(quelle(s), s));
    }
    let haupt: Vec<(u32, Vec<u8>)> = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256].iter().map(|&s| (s, png(quelle(s), s))).collect();
    write("k9.ico", &ico(&haupt));
    for zustand in ["normal", "warnung", "kritisch", "gestoppt"] {
        let svg = dir.join(format!("k9-tray-{zustand}.svg"));
        let bilder: Vec<(u32, Vec<u8>)> = [16, 20, 24, 32, 40, 48].iter().map(|&s| (s, png(&svg, s))).collect();
        write(&format!("k9-tray-{zustand}.ico"), &ico(&bilder));
    }
    let fav = dir.join("favicon.svg");
    write("favicon.ico", &ico(&[16, 32, 48].map(|s| (s, png(&fav, s)))));
    write("k9-logo.png", &png(&dir.join("k9-logo.svg"), 1200));
    write("k9-logo-hell.png", &png(&dir.join("k9-logo-hell.svg"), 1200));
}
