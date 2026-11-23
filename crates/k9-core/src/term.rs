//! Console output: German umlauts are written as ae/oe/ue/ss, because some
//! Windows consoles (and prompts of helper libraries) show them as "?".
//! File paths are left unchanged, so the displayed path always matches the
//! real one; the console is switched to UTF-8 so such paths display correctly.

use std::io::Write;

/// Switches the console to UTF-8 (input and output). Harmless without console.
pub fn init_console() {
    use windows::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    // SAFETY: simple calls without pointers.
    unsafe {
        let _ = SetConsoleOutputCP(65001);
        let _ = SetConsoleCP(65001);
    }
}

fn translit_char(c: char, out: &mut String) {
    match c {
        'ä' => out.push_str("ae"),
        'ö' => out.push_str("oe"),
        'ü' => out.push_str("ue"),
        'Ä' => out.push_str("Ae"),
        'Ö' => out.push_str("Oe"),
        'Ü' => out.push_str("Ue"),
        'ß' => out.push_str("ss"),
        '–' | '—' => out.push('-'),
        '„' | '“' | '”' => out.push('"'),
        '‚' | '‘' | '’' => out.push('\''),
        '…' => out.push_str("..."),
        '→' => out.push_str("->"),
        '•' | '·' => out.push('*'),
        '×' => out.push('x'),
        _ => out.push(c),
    }
}

/// True for words that are (part of) a file path or URL – kept unchanged.
fn is_path_like(word: &str) -> bool {
    word.contains('\\') || word.contains(":/") || word.contains("%")
}

/// Transliterates umlauts and typographic characters for console output.
/// Words containing a backslash (paths) or URLs stay unchanged.
pub fn ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if is_path_like(word) {
            out.push_str(word);
        } else {
            for c in word.chars() {
                translit_char(c, out);
            }
        }
        word.clear();
    };
    for c in text.chars() {
        if c.is_whitespace() {
            flush(&mut word, &mut out);
            out.push(c);
        } else {
            word.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Writer for console log output (tracing) that transliterates each write.
pub struct AsciiWriter<W: Write>(pub W);

impl<W: Write> Write for AsciiWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(ascii(&text).as_bytes())?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// `println!` for the console with transliteration.
#[macro_export]
macro_rules! say {
    ($($arg:tt)*) => { println!("{}", $crate::term::ascii(&format!($($arg)*))) };
}

/// `eprintln!` for the console with transliteration.
#[macro_export]
macro_rules! say_err {
    ($($arg:tt)*) => { eprintln!("{}", $crate::term::ascii(&format!($($arg)*))) };
}

/// `writeln!` for the console with transliteration.
#[macro_export]
macro_rules! sayw {
    ($out:expr, $($arg:tt)*) => { writeln!($out, "{}", $crate::term::ascii(&format!($($arg)*))) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umlauts_become_ascii_but_paths_stay() {
        assert_eq!(ascii("Wert für Schlüssel: Größe – „OK“ …"), "Wert fuer Schluessel: Groesse - \"OK\" ...");
        assert_eq!(ascii("Prüfe C:\\Users\\Jürgen\\Downloads jetzt"), "Pruefe C:\\Users\\Jürgen\\Downloads jetzt");
        assert_eq!(ascii("Äpfel Öl Übung Straße"), "Aepfel Oel Uebung Strasse");
        assert!(ascii("Dienst läuft → bereit · gut").is_ascii());
    }

    #[test]
    fn writer_transliterates() {
        let mut w = AsciiWriter(Vec::new());
        w.write_all("Prüfung beendet".as_bytes()).unwrap();
        assert_eq!(String::from_utf8(w.0).unwrap(), "Pruefung beendet");
    }
}
