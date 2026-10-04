//! Registry locale preferences, resolved once for an authenticated principal.
use std::collections::BTreeMap;
use std::path::Path;

use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};
use peios::security::SidRef;
use peios::token::{Token, TokenAccess};

pub const MACHINE_KEY: &str = "Machine\\System\\Locale";
pub const DEFAULT: &str = "C.UTF-8";
pub const CATEGORIES: &[&str] = &[
    "LC_CTYPE",
    "LC_NUMERIC",
    "LC_TIME",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_MESSAGES",
    "LC_PAPER",
    "LC_NAME",
    "LC_ADDRESS",
    "LC_TELEPHONE",
    "LC_MEASUREMENT",
    "LC_IDENTIFICATION",
];
pub type Environment = BTreeMap<String, String>;

/// Resolve for the caller's installed primary token. A failed identity lookup
/// cannot select another principal's preferences.
pub fn current() -> Environment {
    match Token::open_self(true, TokenAccess::QUERY).and_then(|t| t.user()) {
        Ok(user) => for_principal(user.as_ref()),
        Err(e) => {
            eprintln!("session locale: cannot read principal: {e}; using machine defaults");
            resolve(read(MACHINE_KEY), Environment::new(), installed)
        }
    }
}

/// The caller supplies a SID obtained from the granted token, never a username
/// or other unauthenticated request field. GXWI uses this before job submission.
pub fn for_principal(user: &SidRef) -> Environment {
    resolve(
        read(MACHINE_KEY),
        read(&format!("Users\\{user}\\Locale")),
        installed,
    )
}

fn read(path: &str) -> Environment {
    let mut values = Environment::new();
    let key = match Key::open(None, path, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(e) => {
            if e.raw_os_error() != Some(2) {
                eprintln!("session locale: cannot read {path}: {e}");
            }
            return values;
        }
    };
    // An allowlist deliberately excludes LC_ALL, LOCPATH and arbitrary env.
    for name in std::iter::once("LANG").chain(CATEGORIES.iter().copied()) {
        match key.query_value(name.as_bytes(), None) {
            Ok(value) => match text(&value) {
                Some(value) => {
                    values.insert(name.into(), value.into());
                }
                None => eprintln!("session locale: ignoring invalid {path}\\{name}"),
            },
            Err(e) if e.raw_os_error() == Some(2) => {}
            Err(e) => eprintln!("session locale: cannot read {path}\\{name}: {e}"),
        }
    }
    values
}

fn text(value: &RegValue) -> Option<&str> {
    if value.ty != ValueType::SZ {
        return None;
    }
    let bytes = value.data.strip_suffix(&[0]).unwrap_or(&value.data);
    let text = std::str::from_utf8(bytes).ok()?;
    valid_name(text).then_some(text)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.@-".contains(&b))
}

// glibc's installed directory names normalize codesets (UTF-8 -> utf8).
// Inspect only its fixed system path: privileged launchers must not consult
// an inherited LOCPATH or change their own process-wide locale to probe one.
fn directory(value: &str) -> String {
    let Some((language, codeset)) = value.split_once('.') else {
        return value.into();
    };
    let (codeset, modifier) = codeset
        .split_once('@')
        .map_or((codeset, ""), |(c, m)| (c, m));
    let codeset: String = codeset
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    format!(
        "{language}.{codeset}{}",
        if modifier.is_empty() {
            String::new()
        } else {
            format!("@{modifier}")
        }
    )
}

/// Where glibc's compiled locales are, one directory each.
pub const LOCALE_ROOT: &str = "/usr/lib/x86_64-linux-peios/locale";

/// Would `value` be honoured for `name` (`LANG` or one of [`CATEGORIES`])?
/// The check a session makes, for a program choosing what to write: a value
/// that fails it is ignored when a session starts.
pub fn usable(name: &str, value: &str) -> bool {
    (name == "LANG" || CATEGORIES.contains(&name)) && valid_name(value) && installed(name, value)
}

/// A locale installed in full, which can be a `LANG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Available {
    /// The value to write: `en_GB.UTF-8`, with the codeset as people write
    /// it rather than as glibc names the directory.
    pub name: String,
    /// The language, in English, as the locale names itself (`English`).
    pub language: Option<String>,
    /// Where, likewise (`United Kingdom`).
    pub territory: Option<String>,
}

/// Every locale installed in full, sorted by name, `C.UTF-8` included. A
/// language pack adds to it (`org.gnu.glibc-langpack-<language>`).
pub fn available() -> Vec<Available> {
    let mut found = vec![Available {
        name: DEFAULT.into(),
        language: None,
        territory: None,
    }];
    let Ok(entries) = std::fs::read_dir(LOCALE_ROOT) else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(directory) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let name = written(&directory);
        if name == DEFAULT || !valid_name(&name) || !installed("LANG", &name) {
            continue;
        }
        let (language, territory) =
            identification(&entry.path().join("LC_IDENTIFICATION")).unwrap_or_default();
        found.push(Available {
            name,
            language,
            territory,
        });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found.dedup_by(|a, b| a.name == b.name);
    found
}

/// A directory name as people write the value: `en_GB.utf8` is
/// `en_GB.UTF-8`. Other codesets are left as glibc names them, which
/// `directory` maps back to the same place.
fn written(directory: &str) -> String {
    match directory.split_once('.') {
        Some((language, rest)) if rest == "utf8" || rest.starts_with("utf8@") => {
            format!("{language}.UTF-8{}", &rest[4..])
        }
        _ => directory.to_string(),
    }
}

/// The language and territory a compiled `LC_IDENTIFICATION` names. The
/// file is a magic number, a count, that many offsets, then the strings
/// they point at; glibc lists the category's items in a fixed order, and
/// language and territory are the eighth and ninth.
fn identification(path: &Path) -> Option<(Option<String>, Option<String>)> {
    let bytes = std::fs::read(path).ok()?;
    let word = |at: usize| -> Option<usize> {
        Some(u32::from_ne_bytes(bytes.get(at..at + 4)?.try_into().ok()?) as usize)
    };
    let count = word(4)?;
    let string = |index: usize| -> Option<String> {
        if index >= count {
            return None;
        }
        let start = word(8 + index * 4)?;
        let tail = bytes.get(start..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        let text = std::str::from_utf8(&tail[..end]).ok()?.trim();
        (!text.is_empty()).then(|| text.to_string())
    };
    Some((string(7), string(8)))
}

fn installed(name: &str, value: &str) -> bool {
    if matches!(value, "C" | "POSIX") {
        return true;
    }
    let root = Path::new(LOCALE_ROOT).join(directory(value));
    let exists = |category: &str| {
        root.join(if category == "LC_MESSAGES" {
            "LC_MESSAGES/SYS_LC_MESSAGES"
        } else {
            category
        })
        .is_file()
    };
    if name == "LANG" {
        CATEGORIES.iter().all(|c| exists(c))
    } else {
        exists(name)
    }
}

fn resolve(
    machine: Environment,
    user: Environment,
    available: impl Fn(&str, &str) -> bool,
) -> Environment {
    let mut result = Environment::from([("LANG".into(), DEFAULT.into())]);
    for layer in [machine, user] {
        for (name, value) in layer {
            if name != "LANG" && !CATEGORIES.contains(&name.as_str()) {
                continue;
            }
            if valid_name(&value) && available(&name, &value) {
                result.insert(name, value);
            } else {
                eprintln!("session locale: ignoring unavailable or invalid {name}={value:?}");
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn env(entries: &[(&str, &str)]) -> Environment {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    #[test]
    fn precedence_categories_and_missing_packages() {
        let machine = env(&[("LANG", "en_GB.UTF-8"), ("LC_TIME", "de_DE.UTF-8")]);
        let user = env(&[
            ("LANG", "fr_FR.UTF-8"),
            ("LC_TIME", "missing"),
            ("LC_NUMERIC", "C"),
            ("LC_ALL", "C"),
            ("LOCPATH", "/tmp"),
        ]);
        assert_eq!(
            resolve(machine, user, |_, v| v != "missing"),
            env(&[
                ("LANG", "fr_FR.UTF-8"),
                ("LC_TIME", "de_DE.UTF-8"),
                ("LC_NUMERIC", "C")
            ])
        );
        assert_eq!(
            resolve(env(&[("LANG", "missing")]), Environment::new(), |_, _| {
                false
            }),
            env(&[("LANG", DEFAULT)])
        );
    }
    #[test]
    fn malformed_values_and_paths_are_rejected() {
        for v in ["", "../C", "/tmp/locale", "en\0US", "en\nUS", " C", "C=C"] {
            assert!(!valid_name(v));
        }
        let value = |ty, data: &[u8]| RegValue {
            sequence: 0,
            ty,
            data: data.to_vec(),
            layer: vec![],
        };
        assert_eq!(text(&value(ValueType::SZ, b"C.UTF-8\0")), Some("C.UTF-8"));
        assert_eq!(text(&value(ValueType::SZ, b"C\0junk")), None);
        assert_eq!(text(&value(ValueType::DWORD, b"C")), None);
        assert_eq!(directory("en_GB.UTF-8"), "en_GB.utf8");
        assert_eq!(directory("de_DE.ISO-8859-15@euro"), "de_DE.iso885915@euro");
    }
    #[test]
    fn a_directory_is_listed_as_the_value_people_write() {
        assert_eq!(written("en_GB.utf8"), "en_GB.UTF-8");
        assert_eq!(written("sr_RS.utf8@latin"), "sr_RS.UTF-8@latin");
        assert_eq!(written("de_DE.iso885915@euro"), "de_DE.iso885915@euro");
        // And each maps back to the same directory.
        for d in ["en_GB.utf8", "sr_RS.utf8@latin", "de_DE.iso885915@euro"] {
            assert_eq!(directory(&written(d)), d);
        }
    }
    #[test]
    fn identification_reads_language_and_territory() {
        // Built the way localedef lays the category out: magic, count,
        // offsets, strings. Fifteen items; the eighth and ninth matter.
        let items = [
            "English locale for Britain", "", "", "", "", "", "",
            "English", "United Kingdom", "", "", "", "1.0", "2000-06-24", "",
        ];
        let header = 8 + items.len() * 4;
        let mut strings = Vec::new();
        let mut offsets = Vec::new();
        for item in items {
            offsets.push((header + strings.len()) as u32);
            strings.extend_from_slice(item.as_bytes());
            strings.push(0);
        }
        let mut file = 0x2005_1017u32.to_ne_bytes().to_vec();
        file.extend_from_slice(&(items.len() as u32).to_ne_bytes());
        for o in offsets {
            file.extend_from_slice(&o.to_ne_bytes());
        }
        file.extend_from_slice(&strings);
        let path = std::env::temp_dir().join(format!("libsession-id-{}", std::process::id()));
        std::fs::write(&path, &file).unwrap();
        assert_eq!(
            identification(&path),
            Some((Some("English".into()), Some("United Kingdom".into())))
        );
        std::fs::write(&path, b"short").unwrap();
        assert_eq!(identification(&path), None);
        let _ = std::fs::remove_file(&path);
    }
}
