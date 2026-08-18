//! Creating a principal, with the tool asking for what was not given.
//!
//! A principal has grown from "a name and a password" to a name, a password,
//! memberships, a primary group, a home directory, a shell and a display name.
//! A flag for each is fine in a script and miserable to type, so `lps add` asks
//! for what it was not told.
//!
//! # Three rules, and each of them exists because of a way this could go wrong
//!
//! 1. **A flag suppresses its prompt.** Every existing invocation keeps working
//!    unchanged, and an operator who knows what they want can say so.
//!
//! 2. **A non-terminal never prompts.** Down a pipe there is nobody to answer,
//!    and a prompt would consume the *next* line of whatever is driving the
//!    tool — reading a password as a shell, or worse. The first-account script
//!    on a fresh image depends on this exactly: it pipes one line and expects it
//!    to be the password.
//!
//! 3. **Nothing is sent until the whole thing is confirmed.** Half a principal
//!    is worse than none, and an operator who realises at the shell prompt that
//!    they meant something else can still say no.
//!
//! Defaults come from the daemon, not from here — [`lps`](crate) resolves
//! nothing itself. An empty answer means "whatever you would have chosen", which
//! travels as an absent field rather than as a guess this side made.

use libauthd::lps;

use crate::session::Session;
use crate::{encode, Failed};

/// Options `lps add` understands, before anything has been asked for.
#[derive(Default)]
struct Requested {
    name: Option<String>,
    groups: Vec<String>,
    primary_group: Option<String>,
    home: Option<String>,
    shell: Option<String>,
    display_name: Option<String>,
    enabled: bool,
    /// Fail rather than ask. For a script that wants a missing field to be an
    /// error rather than a hang — which on a terminal it otherwise would be.
    no_prompt: bool,
    /// Create a principal that authenticates without a credential.
    no_password: bool,
}

/// `lps add`.
pub fn add(options: &[&str]) -> Result<(), Failed> {
    let mut requested = parse(options)?;

    let interactive = libtty::stdin_is_a_terminal() && !requested.no_prompt;

    let name = match requested.name.take() {
        Some(name) => name,
        None if interactive => {
            let name = prompt("Name", "")?;
            if name.is_empty() {
                return Err(Failed::Usage("a principal needs a name".into()));
            }
            name
        }
        None => return Err(Failed::Usage("a principal needs a name".into())),
    };

    if interactive {
        // Only asked for when unset. A flag is an answer already given, and
        // asking again would invite an operator to contradict themselves.
        if requested.display_name.is_none() {
            requested.display_name = non_empty(prompt("Full name", "optional")?);
        }
        if requested.groups.is_empty() {
            let answer = prompt("Additional groups", "comma-separated, optional")?;
            requested.groups = answer
                .split(',')
                .map(str::trim)
                .filter(|group| !group.is_empty())
                .map(str::to_string)
                .collect();
        }
        if requested.primary_group.is_none() {
            requested.primary_group = non_empty(prompt("Primary group", "the daemon's default")?);
        }
        if requested.home.is_none() {
            requested.home = non_empty(prompt("Home directory", "the daemon's default")?);
        }
        if requested.shell.is_none() {
            requested.shell = non_empty(prompt("Shell", "the daemon's default")?);
        }
    }

    // Read before connecting: a prompt that appears and then fails because the
    // daemon is unreachable wastes the operator's typing, and there is no reason
    // to hold a connection open while a human thinks.
    //
    // `--no-password` asks for nothing, including in the interactive flow. An
    // operator who has said the account needs no credential should not then be
    // asked to invent one.
    let secret = if requested.no_password {
        None
    } else {
        Some(confirmed_password(&format!("Password for {name}: "))?)
    };

    if interactive {
        describe(&name, &requested);
        if !confirm("Create this principal?")? {
            // Not an error. An operator who changes their mind has used the
            // tool correctly, and exiting 1 would make a script think something
            // broke.
            println!("nothing was created");
            return Ok(());
        }
    }

    let mut session = Session::open()?;
    let message = lps::encode_add(&lps::Add {
        name: name.clone(),
        credential: match &secret {
            Some(secret) => lps::Credential::Password(secret.expose()),
            None => lps::Credential::None,
        },
        enabled: requested.enabled,
        groups: requested.groups.clone(),
    })
    .map_err(|error| Failed::Refused(format!("could not encode the request: {error:?}")))?;

    let reply = session.request(message.expose())?;
    let rid = session.expect(lps::decode_created(reply.expose()))?;
    println!("created {name} with RID {rid}");

    // The profile and the primary group are separate requests, because `Add`
    // carries a password and every extra field on it is another field beside a
    // secret in the same buffer. They run after the principal exists, so a
    // rejected home directory leaves an account that can be corrected rather
    // than no account at all — and each prints its own line, so an operator can
    // see exactly how far it got.
    if requested.home.is_some() || requested.shell.is_some() || requested.display_name.is_some() {
        apply(
            lps::encode_set_profile(&lps::SetProfile {
                name: name.clone(),
                home: requested.home,
                shell: requested.shell,
                display_name: requested.display_name,
            }),
            "set the profile",
        )?;
    }
    if let Some(group) = requested.primary_group {
        apply(
            lps::encode_set_primary_group(&lps::Membership {
                name: name.clone(),
                group: group.clone(),
            }),
            &format!("set the primary group to {group}"),
        )?;
    }
    Ok(())
}

fn parse(options: &[&str]) -> Result<Requested, Failed> {
    let mut requested = Requested {
        enabled: true,
        ..Requested::default()
    };

    let mut rest = options;
    while let Some((option, tail)) = rest.split_first() {
        // The first bare word is the name; anything after that is a mistake
        // worth naming rather than silently ignoring.
        if !option.starts_with("--") {
            if requested.name.is_some() {
                return Err(Failed::Usage(format!("unexpected argument {option:?}")));
            }
            requested.name = Some(option.to_string());
            rest = tail;
            continue;
        }

        match *option {
            "--disabled" => {
                requested.enabled = false;
                rest = tail;
                continue;
            }
            "--no-prompt" => {
                requested.no_prompt = true;
                rest = tail;
                continue;
            }
            "--no-password" => {
                requested.no_password = true;
                rest = tail;
                continue;
            }
            _ => {}
        }

        let (value, tail) = crate::value_for(option, tail)?;
        match *option {
            "--group" => requested.groups.push(value.to_string()),
            "--primary-group" => requested.primary_group = Some(value.to_string()),
            "--home" => requested.home = Some(value.to_string()),
            "--shell" => requested.shell = Some(value.to_string()),
            "--display-name" => requested.display_name = Some(value.to_string()),
            other => return Err(Failed::Usage(format!("unknown option {other:?}"))),
        }
        rest = tail;
    }
    Ok(requested)
}

/// Show what is about to be created, so the confirmation means something.
fn describe(name: &str, requested: &Requested) {
    let or_default = |value: &Option<String>| {
        value
            .clone()
            .unwrap_or_else(|| "(the daemon's default)".to_string())
    };

    println!();
    println!("  name           {name}");
    if let Some(display_name) = &requested.display_name {
        println!("  full name      {display_name}");
    }
    println!("  primary group  {}", or_default(&requested.primary_group));
    println!("  home           {}", or_default(&requested.home));
    println!("  shell          {}", or_default(&requested.shell));
    println!(
        "  groups         {}",
        if requested.groups.is_empty() {
            "none".to_string()
        } else {
            requested.groups.join(", ")
        }
    );
    if !requested.enabled {
        println!("  state          disabled");
    }
    println!();
}

/// Send a follow-up request, reporting what it did.
fn apply(message: Result<Vec<u8>, libauthd::WireError>, done: &str) -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(message)?)?;
    session.expect(lps::decode_done(reply.expose()))?;
    println!("{done}");
    Ok(())
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Ask a question, showing what an empty answer will mean.
fn prompt(question: &str, default: &str) -> Result<String, Failed> {
    let label = if default.is_empty() {
        format!("{question}: ")
    } else {
        format!("{question} [{default}]: ")
    };
    libtty::prompt_line(&label)
        .map(|answer| answer.trim().to_string())
        .map_err(|error| Failed::Refused(format!("could not read an answer: {error}")))
}

/// Ask a yes/no question. Anything but an explicit refusal is a yes, since the
/// operator has just been shown exactly what will happen.
fn confirm(question: &str) -> Result<bool, Failed> {
    let answer = prompt(question, "Y/n")?;
    Ok(!matches!(answer.to_ascii_lowercase().as_str(), "n" | "no"))
}

/// Obtain a password: from a terminal, asked twice; from a pipe, read once.
///
/// The confirmation exists because a password nobody can reproduce is worse
/// than no change at all — especially here, where the operator may be setting
/// one for somebody who is not in the room and will not find out until they
/// cannot log on.
///
/// Down a pipe there is nobody to confirm with, and asking twice would be
/// actively wrong: it would consume the *next* line of whatever is driving the
/// tool and compare two unrelated things. So a non-terminal reads exactly one
/// line and takes it at face value, which is what the boot-time script that
/// creates the first account on a fresh image relies on.
/// Read a password, refusing an empty one.
///
/// The daemon refuses it too, and that is where the rule lives — but a round
/// trip to be told the obvious is a poor way to learn it, and an operator who
/// pressed Enter by accident should find out before anything is sent.
///
/// Empty is not a way to spell "no password": `--no-password` is, and the
/// message says so, because the two produce accounts that behave differently
/// and an operator who wanted the second should not get the first.
pub fn confirmed_password(label: &str) -> Result<libauthd::Secret, Failed> {
    let read =
        |error: std::io::Error| Failed::Refused(format!("could not read a password: {error}"));
    let refuse_empty = |secret: libauthd::Secret| {
        if secret.expose().is_empty() {
            return Err(Failed::Refused(
                "an empty password is not a password: pass --no-password to create a principal \
                 that authenticates without one"
                    .into(),
            ));
        }
        Ok(secret)
    };

    if !libtty::stdin_is_a_terminal() {
        return refuse_empty(libtty::read_line_secret().map_err(read)?);
    }

    let first = libtty::prompt_secret(label).map_err(read)?;
    let again = libtty::prompt_secret("Again: ").map_err(read)?;

    if first.expose() != again.expose() {
        return Err(Failed::Refused("the passwords did not match".into()));
    }
    refuse_empty(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(options: &[&str]) -> Requested {
        parse(options).expect("must parse")
    }

    #[test]
    fn a_bare_word_is_the_name() {
        assert_eq!(parsed(&["jack"]).name.as_deref(), Some("jack"));
        assert_eq!(parsed(&[]).name, None);
    }

    #[test]
    fn a_second_bare_word_is_a_usage_error() {
        // Silently ignoring it would let `lps add jack developers` look like it
        // worked while adding no membership at all.
        assert!(matches!(
            parse(&["jack", "developers"]),
            Err(Failed::Usage(_))
        ));
    }

    #[test]
    fn every_option_parses() {
        let requested = parsed(&[
            "jack",
            "--group",
            "Administrators",
            "--group",
            "developers",
            "--primary-group",
            "Users",
            "--home",
            "/srv/jack",
            "--shell",
            "/bin/bash",
            "--display-name",
            "Jack Palfrey",
            "--disabled",
        ]);
        assert_eq!(requested.name.as_deref(), Some("jack"));
        assert_eq!(requested.groups, vec!["Administrators", "developers"]);
        assert_eq!(requested.primary_group.as_deref(), Some("Users"));
        assert_eq!(requested.home.as_deref(), Some("/srv/jack"));
        assert_eq!(requested.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(requested.display_name.as_deref(), Some("Jack Palfrey"));
        assert!(!requested.enabled);
    }

    #[test]
    fn a_principal_is_enabled_unless_asked_otherwise() {
        assert!(parsed(&["jack"]).enabled);
        assert!(!parsed(&["jack", "--disabled"]).enabled);
    }

    #[test]
    fn options_may_come_before_the_name() {
        let requested = parsed(&["--home", "/srv/jack", "jack"]);
        assert_eq!(requested.name.as_deref(), Some("jack"));
        assert_eq!(requested.home.as_deref(), Some("/srv/jack"));
    }

    #[test]
    fn an_unknown_option_is_refused() {
        assert!(matches!(parse(&["jack", "--nonesuch"]), Err(Failed::Usage(_))));
        assert!(matches!(
            parse(&["jack", "--nonesuch", "x"]),
            Err(Failed::Usage(_))
        ));
    }

    #[test]
    fn an_option_missing_its_value_is_refused() {
        assert!(matches!(parse(&["jack", "--home"]), Err(Failed::Usage(_))));
    }

    #[test]
    fn no_password_is_recorded_without_consuming_a_value() {
        let requested = parsed(&["kiosk", "--no-password", "--home", "/srv/kiosk"]);
        assert!(requested.no_password);
        assert_eq!(requested.home.as_deref(), Some("/srv/kiosk"));
    }

    #[test]
    fn a_principal_needs_no_password_flag_by_default() {
        assert!(!parsed(&["jack"]).no_password);
    }

    #[test]
    fn no_prompt_is_recorded_without_consuming_a_value() {
        let requested = parsed(&["jack", "--no-prompt", "--home", "/srv/jack"]);
        assert!(requested.no_prompt);
        assert_eq!(requested.home.as_deref(), Some("/srv/jack"));
    }

    #[test]
    fn an_empty_answer_means_no_answer() {
        assert_eq!(non_empty(String::new()), None);
        assert_eq!(non_empty("x".into()), Some("x".into()));
    }
}
