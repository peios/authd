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

fn installed(name: &str, value: &str) -> bool {
    if matches!(value, "C" | "POSIX") {
        return true;
    }
    let root = Path::new("/usr/lib/x86_64-linux-peios/locale").join(directory(value));
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
}
