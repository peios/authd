//! Registry locale preferences for an authenticated principal.
//!
//! Resolve preferences when starting a session. Valid user values override the
//! matching machine values; category overrides remain independent of `LANG`.
//! Missing or unusable values retain the lower-precedence setting. These helpers
//! return data without changing the caller's environment or process-wide locale.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;

use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};
use peios::security::SidRef;
use peios::token::{Token, TokenAccess};

/// Registry key containing machine-wide locale defaults.
pub const MACHINE_KEY: &str = "Machine\\System\\Locale";
/// Baseline `LANG` when neither registry layer supplies a usable value.
pub const DEFAULT: &str = "C.UTF-8";
/// Supported category overrides; excludes `LC_ALL` and arbitrary environment keys.
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
/// Owned locale variable names and values for a session launcher to apply.
pub type Environment = BTreeMap<String, String>;

// Locale names are registry text, not paths. Bound both parsing and probing work.
const MAX_LOCALE_NAME_BYTES: usize = 128;

// glibc category files use native-endian 32-bit words on the target system.
// See glibc locale/localeinfo.h and locale/categories.def for this layout.
const LOCALE_WORD_BYTES: usize = size_of::<u32>();
const LOCALE_COUNT_OFFSET: usize = LOCALE_WORD_BYTES;
const LOCALE_OFFSETS_OFFSET: usize = 2 * LOCALE_WORD_BYTES;
const IDENTIFICATION_LANGUAGE_INDEX: usize = 7;
const IDENTIFICATION_TERRITORY_INDEX: usize = 8;

/// Resolve preferences for the caller's installed primary token.
///
/// If identity lookup fails, report the error and use machine defaults without
/// reading another principal's preferences. Registry and locale failures use the
/// fallback rules in [`for_principal`]. The result does not change the process.
pub fn current() -> Environment {
    const USE_PRIMARY_TOKEN: bool = true;
    match Token::open_self(USE_PRIMARY_TOKEN, TokenAccess::QUERY).and_then(|token| token.user()) {
        Ok(user) => for_principal(user.as_ref()),
        Err(error) => {
            eprintln!("session locale: cannot read principal: {error}; using machine defaults");
            resolve(read(MACHINE_KEY), Environment::new(), installed)
        }
    }
}

/// Resolve machine defaults and user overrides for an authenticated principal.
///
/// Obtain `user` from the granted token, never from an unauthenticated request.
/// Valid, installed user values replace matching machine values. An absent,
/// unreadable, invalid, or unavailable setting retains the lower-precedence value;
/// `LANG` starts at [`DEFAULT`]. Registry failures other than missing keys or
/// values are reported to standard error. Invalid or unavailable values are also
/// reported. Unsupported variable names are ignored.
///
/// Apply the returned variables only to the new session. The result is a snapshot,
/// not a subscription to registry or installed-locale changes.
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
        Err(error) => {
            if error.kind() != ErrorKind::NotFound {
                eprintln!("session locale: cannot read {path}: {error}");
            }
            return values;
        }
    };
    // Missing settings are optional. Exclude LC_ALL, LOCPATH, and arbitrary variables.
    for name in std::iter::once("LANG").chain(CATEGORIES.iter().copied()) {
        let value = match key.query_value(name.as_bytes(), None) {
            Ok(value) => value,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                eprintln!("session locale: cannot read {path}\\{name}: {error}");
                continue;
            }
        };
        let Some(value) = text(&value) else {
            eprintln!("session locale: ignoring invalid {path}\\{name}");
            continue;
        };
        values.insert(name.into(), value.into());
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
        && value.len() <= MAX_LOCALE_NAME_BYTES
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
    let (codeset, modifier) = codeset.split_once('@').unwrap_or((codeset, ""));
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

/// Fixed system directory containing glibc compiled locale directories.
pub const LOCALE_ROOT: &str = "/usr/lib/x86_64-linux-peios/locale";

/// Check whether a session can use `value` for `LANG` or one of [`CATEGORIES`].
///
/// Invalid names and missing or inaccessible category files return `false`.
/// `C` and `POSIX` are built in and need no files. `LANG` requires all supported
/// categories; a category override requires only that category's file. This is a
/// point-in-time check, so it does not guarantee availability at session startup.
pub fn usable(name: &str, value: &str) -> bool {
    (name == "LANG" || CATEGORIES.contains(&name)) && valid_name(value) && installed(name, value)
}

/// A locale choice for `LANG`, with optional display metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Available {
    /// Registry value, such as `en_GB.UTF-8`, with normalized UTF-8 spelling.
    pub name: String,
    /// Language label from the locale, such as `English`, when readable.
    pub language: Option<String>,
    /// Territory label from the locale, such as `United Kingdom`, when readable.
    pub territory: Option<String>,
}

/// List complete installed locales in name order, without duplicate names.
///
/// Always include [`DEFAULT`], even when its files are unavailable. An unreadable
/// locale directory returns only that baseline. Skip unreadable directory entries,
/// invalid names, and incomplete locales. Missing or malformed identification
/// metadata leaves its display fields absent; discovery is best effort and does
/// not report these optional-data failures. Use [`usable`] to recheck a selection.
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

// Identification supplies optional display labels, so an unreadable file does
// not exclude an otherwise usable locale from discovery.
fn identification(path: &Path) -> Option<(Option<String>, Option<String>)> {
    decode_identification(&std::fs::read(path).ok()?)
}

// Read labels from an installed glibc category file in the target's native byte
// order. The header contains a magic word, a count, then absolute string offsets.
// This reader extracts optional labels; it does not validate the whole category.
fn decode_identification(bytes: &[u8]) -> Option<(Option<String>, Option<String>)> {
    let word = |offset: usize| -> Option<usize> {
        let word_bytes = bytes.get(offset..offset + LOCALE_WORD_BYTES)?;
        Some(u32::from_ne_bytes(word_bytes.try_into().ok()?) as usize)
    };
    let count = word(LOCALE_COUNT_OFFSET)?;
    let string = |index: usize| -> Option<String> {
        if index >= count {
            return None;
        }
        let start = word(LOCALE_OFFSETS_OFFSET + index * LOCALE_WORD_BYTES)?;
        let tail = bytes.get(start..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        let text = std::str::from_utf8(&tail[..end]).ok()?.trim();
        (!text.is_empty()).then(|| text.to_string())
    };
    Some((
        string(IDENTIFICATION_LANGUAGE_INDEX),
        string(IDENTIFICATION_TERRITORY_INDEX),
    ))
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
    use peios::registry::{RegValue, ValueType};

    use super::{
        DEFAULT, Environment, decode_identification, directory, resolve, text, valid_name, written,
    };

    fn env(entries: &[(&str, &str)]) -> Environment {
        entries
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
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
            resolve(machine, user, |_, value| value != "missing"),
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
        for value in ["", "../C", "/tmp/locale", "en\0US", "en\nUS", " C", "C=C"] {
            assert!(!valid_name(value), "accepted invalid locale: {value:?}");
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
        for directory_name in ["en_GB.utf8", "sr_RS.utf8@latin", "de_DE.iso885915@euro"] {
            assert_eq!(directory(&written(directory_name)), directory_name);
        }
    }

    #[test]
    fn identification_reads_language_and_territory() {
        // Built the way localedef lays the category out: magic, count,
        // offsets, strings. Fifteen items; the eighth and ninth matter.
        let items = [
            "English locale for Britain",
            "",
            "",
            "",
            "",
            "",
            "",
            "English",
            "United Kingdom",
            "",
            "",
            "",
            "1.0",
            "2000-06-24",
            "",
        ];
        let header_bytes = 8 + items.len() * 4;
        let mut strings = Vec::new();
        let mut offsets = Vec::new();
        for item in items {
            offsets.push((header_bytes + strings.len()) as u32);
            strings.extend_from_slice(item.as_bytes());
            strings.push(0);
        }
        const FIXTURE_MAGIC: u32 = 0x2005_1017;
        let mut file = FIXTURE_MAGIC.to_ne_bytes().to_vec();
        file.extend_from_slice(&(items.len() as u32).to_ne_bytes());
        for offset in offsets {
            file.extend_from_slice(&offset.to_ne_bytes());
        }
        file.extend_from_slice(&strings);
        assert_eq!(
            decode_identification(&file),
            Some((Some("English".into()), Some("United Kingdom".into())))
        );
        assert_eq!(decode_identification(b"short"), None);
    }
}
