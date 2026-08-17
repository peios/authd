//! **lps** — administer this machine's local principal store.
//!
//! A client of lpsd and nothing else. It holds no state, opens no store, and
//! has no privilege of its own: every command here is a request over
//! `/run/lpsd/admin.sock` that lpsd decides whether to honour.
//!
//! That is the whole design, and it is worth saying why rather than editing the
//! store file directly. The store's descriptor grants `LocalSystem` alone, so
//! that the machine's credential verifiers are readable by as few principals as
//! possible. A tool that wrote the file would need that descriptor widened to
//! whatever the tool runs as — undoing the one thing it exists to do. Going
//! through the daemon also leaves the store with exactly one writer, which is
//! what atomic replacement quietly assumes, and makes "an administrator may add
//! a principal, but a principal may change their own password" something that
//! can be expressed at all.
//!
//! # It resolves nothing itself
//!
//! Group names are sent as the operator typed them and resolved by the daemon.
//! `lps` could parse a SID, but it could not resolve `Administrators` or a local
//! group's name without carrying its own copy of the machine's identity scheme —
//! a second implementation, free to disagree with the first. So it carries none:
//! not the well-known table, not the domain, not the Unix ID base.
//!
//! # What this is not
//!
//! Not `passwd`. Changing your *own* password will go over PGSS Logon, so that
//! it is a property of being a principal source rather than something each
//! source's administration tool reinvents — a domain principal will change
//! their password exactly as a local one does. `lps password` here is an
//! administrator resetting somebody else's, which is a different operation and
//! genuinely local.

mod format;
mod interactive;
mod session;

use std::process::ExitCode;

use libauthd::claim::{self, Claim, Values};
use libauthd::lps::{self, Failure};

use crate::session::Session;

const USAGE: &str = "\
usage: lps <command> [arguments]

  list                        every principal
  show <name>                 one principal in full
  domain                      this machine's domain SID

  add [name] [options]        create a principal; prompts for what it needs
      --group <group>           a membership; repeatable
      --primary-group <group>   the group that becomes the POSIX gid
      --home <path>             home directory
      --shell <path>            login shell
      --display-name <text>     a human's name for a human to read
      --disabled                create it disabled
      --no-prompt               fail rather than ask for anything missing
  remove <name>               delete a principal
  enable <name>               allow it to log on
  disable <name>              refuse it, keeping the account
  password <name>             set a principal's password

  set <name> [options]        change a principal's profile
      --home <path>
      --shell <path>
      --display-name <text>     empty clears it
      --primary-group <group>

  group list                  every local group
  group create <name>         create a local group
  group delete <name>         delete one, if nobody is in it
  group add <name> <group>    grant a membership
  group remove <name> <group> revoke one

  claim set <name> <claim> <type> [value]...
  claim remove <name> <claim>
                              types: int64 uint64 boolean string sid octet

A group is named however you like: `Administrators`, a local group's name, or a
literal SID. The daemon resolves it.

A principal's RID is never reissued, so `disable` is usually what is wanted
rather than `remove`: a deleted principal's SID keeps appearing in the security
descriptors of everything they owned, and nothing will ever hold it again.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();

    match run(&borrowed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failed::Usage(message)) => {
            eprintln!("lps: {message}");
            eprint!("\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Failed::Refused(reason)) => {
            eprintln!("lps: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// Why a command did not succeed.
#[derive(Debug)]
pub enum Failed {
    /// The command line was wrong. Exits 2, as a usage error conventionally
    /// does, so a script can tell "I called this wrongly" from "it refused".
    Usage(String),
    /// The daemon refused, or could not be reached.
    Refused(String),
}

impl From<String> for Failed {
    fn from(reason: String) -> Self {
        Self::Refused(reason)
    }
}

fn run(arguments: &[&str]) -> Result<(), Failed> {
    match arguments {
        [] | ["-h"] | ["--help"] | ["help"] => {
            print!("{USAGE}");
            Ok(())
        }

        ["list"] => list(),
        ["show", name] => show(name),
        ["domain"] => domain(),

        ["add", options @ ..] => interactive::add(options),
        ["remove", name] => simple(lps::encode_remove(&named(name)), &format!("removed {name}")),
        ["enable", name] => set_enabled(name, true),
        ["disable", name] => set_enabled(name, false),
        ["password", name] => password(name),
        ["set", name, options @ ..] => set(name, options),

        ["group", "list"] => group_list(),
        ["group", "create", name] => group_create(name),
        ["group", "delete", name] => simple(
            lps::encode_group_delete(&named(name)),
            &format!("deleted the group {name}"),
        ),
        ["group", "add", name, group] => membership(name, group, true),
        ["group", "remove", name, group] => membership(name, group, false),

        ["claim", "set", name, claim, kind, values @ ..] => set_claim(name, claim, kind, values),
        ["claim", "remove", name, claim] => simple(
            lps::encode_remove_claim(&lps::NamedClaim {
                name: name.to_string(),
                claim_name: claim.to_string(),
            }),
            &format!("removed the claim {claim} from {name}"),
        ),

        [command, ..] => Err(Failed::Usage(format!("unknown command {command:?}"))),
    }
}

fn named(name: &str) -> lps::Named {
    lps::Named {
        name: name.to_string(),
    }
}

fn list() -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(lps::encode_list())?)?;
    let principals = session.expect(lps::decode_principals(reply.expose()))?;
    print!("{}", format::listing(&principals));
    Ok(())
}

fn group_list() -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(lps::encode_group_list())?)?;
    let groups = session.expect(lps::decode_groups(reply.expose()))?;
    print!("{}", format::groups(&groups));
    Ok(())
}

/// Creating a group allocates a RID, so the daemon answers `MSG_CREATED` with
/// it rather than a bare `MSG_DONE` — the same shape as creating a principal.
fn group_create(name: &str) -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(lps::encode_group_create(&named(name)))?)?;
    let rid = session.expect(lps::decode_created(reply.expose()))?;
    println!("created the group {name} with RID {rid}");
    Ok(())
}

fn show(name: &str) -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(lps::encode_show(&named(name)))?)?;
    let detail = session.expect(lps::decode_principal(reply.expose()))?;
    print!("{}", format::detail(&detail));
    Ok(())
}

fn domain() -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(lps::encode_domain())?)?;
    let sid = session.expect(lps::decode_domain_is(reply.expose()))?;
    println!("{}", format::sid(&sid));
    Ok(())
}

fn password(name: &str) -> Result<(), Failed> {
    let secret = interactive::confirmed_password(&format!("New password for {name}: "))?;

    let mut session = Session::open()?;
    let message = lps::encode_set_password(&lps::SetPassword {
        name: name.to_string(),
        secret: secret.expose(),
    })
    .map_err(|error| Failed::Refused(format!("could not encode the request: {error:?}")))?;

    let reply = session.request(message.expose())?;
    session.expect(lps::decode_done(reply.expose()))?;
    println!("set the password for {name}");
    Ok(())
}

/// `lps set` — change parts of a profile, leaving the rest alone.
fn set(name: &str, options: &[&str]) -> Result<(), Failed> {
    let mut profile = lps::SetProfile {
        name: name.to_string(),
        ..lps::SetProfile::default()
    };
    let mut primary_group = None;

    let mut rest = options;
    while let Some((option, tail)) = rest.split_first() {
        let (value, tail) = value_for(option, tail)?;
        match *option {
            "--home" => profile.home = Some(value.to_string()),
            "--shell" => profile.shell = Some(value.to_string()),
            // Deliberately accepts the empty string: clearing a display name is
            // a real operation, and the protocol keeps "cleared" and
            // "unchanged" distinct precisely so this works.
            "--display-name" => profile.display_name = Some(value.to_string()),
            "--primary-group" => primary_group = Some(value.to_string()),
            other => return Err(Failed::Usage(format!("unknown option {other:?}"))),
        }
        rest = tail;
    }

    if profile.home.is_none()
        && profile.shell.is_none()
        && profile.display_name.is_none()
        && primary_group.is_none()
    {
        return Err(Failed::Usage("nothing to set".into()));
    }

    if profile.home.is_some() || profile.shell.is_some() || profile.display_name.is_some() {
        simple(lps::encode_set_profile(&profile), &format!("updated {name}"))?;
    }
    if let Some(group) = primary_group {
        simple(
            lps::encode_set_primary_group(&lps::Membership {
                name: name.to_string(),
                group: group.clone(),
            }),
            &format!("set {name}'s primary group to {group}"),
        )?;
    }
    Ok(())
}

fn set_claim(name: &str, claim_name: &str, kind: &str, values: &[&str]) -> Result<(), Failed> {
    let type_code = Values::type_from_name(kind)
        .ok_or_else(|| Failed::Usage(format!("unknown claim type {kind:?}")))?;

    let values = parse_values(type_code, values)?;
    let claim = Claim {
        name: claim_name.to_string(),
        // No flag surface yet. Every flag in §3.9 narrows what a claim can do —
        // deny-only, disabled, non-inheritable — and offering them before
        // anything on this machine writes a conditional ACE would be offering
        // controls over a mechanism with nothing to control.
        flags: 0,
        values,
    };
    claim
        .validate()
        .map_err(|error| Failed::Usage(error.to_string()))?;

    simple(
        lps::encode_set_claim(&lps::SetClaim {
            name: name.to_string(),
            claim,
        }),
        &format!("set the claim {claim_name} on {name}"),
    )
}

/// Parse command-line values into a claim's typed values.
///
/// No values is legal and means an empty claim, which §3.9 distinguishes from an
/// absent one — so `lps claim set jack Department string` empties it rather than
/// being a usage error.
fn parse_values(type_code: u32, values: &[&str]) -> Result<Values, Failed> {
    let bad = |what: &str, value: &str| Failed::Usage(format!("{value:?} is not {what}"));

    Ok(match type_code {
        claim::TYPE_INT64 => Values::Int64(
            values
                .iter()
                .map(|v| v.parse::<i64>().map_err(|_| bad("an integer", v)))
                .collect::<Result<_, _>>()?,
        ),
        claim::TYPE_UINT64 => Values::Uint64(
            values
                .iter()
                .map(|v| v.parse::<u64>().map_err(|_| bad("an unsigned integer", v)))
                .collect::<Result<_, _>>()?,
        ),
        claim::TYPE_BOOLEAN => Values::Boolean(
            values
                .iter()
                .map(|v| match *v {
                    "true" | "yes" | "1" => Ok(true),
                    "false" | "no" | "0" => Ok(false),
                    other => Err(bad("a boolean (true/false)", other)),
                })
                .collect::<Result<_, _>>()?,
        ),
        claim::TYPE_STRING => Values::String(values.iter().map(|v| v.to_string()).collect()),
        claim::TYPE_SID => Values::Sid(
            values
                .iter()
                .map(|v| {
                    v.parse::<peios::security::Sid>()
                        .map(|sid| sid.as_ref().as_bytes().to_vec())
                        .map_err(|_| bad("a SID", v))
                })
                .collect::<Result<_, _>>()?,
        ),
        claim::TYPE_OCTET => Values::Octet(
            values
                .iter()
                .map(|v| hex(v).ok_or_else(|| bad("hexadecimal", v)))
                .collect::<Result<_, _>>()?,
        ),
        _ => return Err(Failed::Usage("unknown claim type".into())),
    })
}

/// Parse an even-length hexadecimal string.
fn hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

fn set_enabled(name: &str, enabled: bool) -> Result<(), Failed> {
    let message = lps::encode_set_enabled(&lps::SetEnabled {
        name: name.to_string(),
        enabled,
    });
    let done = if enabled { "enabled" } else { "disabled" };
    simple(message, &format!("{done} {name}"))
}

fn membership(name: &str, group: &str, add: bool) -> Result<(), Failed> {
    let membership = lps::Membership {
        name: name.to_string(),
        group: group.to_string(),
    };
    let (message, done) = if add {
        (
            lps::encode_group_add(&membership),
            format!("added {name} to {group}"),
        )
    } else {
        (
            lps::encode_group_remove(&membership),
            format!("removed {name} from {group}"),
        )
    };
    simple(message, &done)
}

/// Take an option's value, or say which option is missing one.
fn value_for<'a>(option: &str, tail: &'a [&'a str]) -> Result<(&'a str, &'a [&'a str]), Failed> {
    tail.split_first()
        .map(|(value, rest)| (*value, rest))
        .ok_or_else(|| Failed::Usage(format!("{option} needs a value")))
}

/// Send a request whose only successful answer is "done".
fn simple(message: Result<Vec<u8>, libauthd::WireError>, done: &str) -> Result<(), Failed> {
    let mut session = Session::open()?;
    let reply = session.request(&encode(message)?)?;
    session.expect(lps::decode_done(reply.expose()))?;
    println!("{done}");
    Ok(())
}

pub fn encode(message: Result<Vec<u8>, libauthd::WireError>) -> Result<Vec<u8>, Failed> {
    message.map_err(|error| Failed::Refused(format!("could not encode the request: {error:?}")))
}

/// Render a refusal the way an operator should read it.
///
/// The daemon's `reason` is printed rather than interpreted; the [`Failure`]
/// code exists for a caller that wants to branch, and here it only chooses
/// whether a hint is worth adding.
pub fn describe(failure: Failure, reason: &str) -> String {
    match failure {
        Failure::Denied => format!(
            "{reason}\nAdministering the local principal store requires membership of \
             BUILTIN\\Administrators."
        ),
        _ => reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parses_even_length_input_only() {
        assert_eq!(hex("dead"), Some(vec![0xde, 0xad]));
        assert_eq!(hex(""), Some(Vec::new()));
        assert_eq!(hex("abc"), None, "an odd length is ambiguous");
        assert_eq!(hex("zz"), None);
    }

    #[test]
    fn every_claim_type_parses_from_the_command_line() {
        assert_eq!(
            parse_values(claim::TYPE_INT64, &["-3", "7"]).ok(),
            Some(Values::Int64(vec![-3, 7]))
        );
        assert_eq!(
            parse_values(claim::TYPE_UINT64, &["7"]).ok(),
            Some(Values::Uint64(vec![7]))
        );
        assert_eq!(
            parse_values(claim::TYPE_BOOLEAN, &["true", "no", "1"]).ok(),
            Some(Values::Boolean(vec![true, false, true]))
        );
        assert_eq!(
            parse_values(claim::TYPE_STRING, &["Engineering"]).ok(),
            Some(Values::String(vec!["Engineering".into()]))
        );
        assert!(matches!(
            parse_values(claim::TYPE_SID, &["S-1-5-32-544"]).ok(),
            Some(Values::Sid(_))
        ));
        assert_eq!(
            parse_values(claim::TYPE_OCTET, &["dead"]).ok(),
            Some(Values::Octet(vec![vec![0xde, 0xad]]))
        );
    }

    /// An empty claim is legal and distinct from an absent one, so no values
    /// must not be a usage error.
    #[test]
    fn no_values_is_an_empty_claim_rather_than_an_error() {
        assert_eq!(
            parse_values(claim::TYPE_STRING, &[]).ok(),
            Some(Values::String(Vec::new()))
        );
    }

    #[test]
    fn a_value_of_the_wrong_type_is_a_usage_error() {
        for (code, value) in [
            (claim::TYPE_INT64, "banana"),
            (claim::TYPE_UINT64, "-1"),
            (claim::TYPE_BOOLEAN, "maybe"),
            (claim::TYPE_SID, "not-a-sid"),
            (claim::TYPE_OCTET, "nothex"),
        ] {
            assert!(
                matches!(parse_values(code, &[value]), Err(Failed::Usage(_))),
                "{value:?} must be refused for type {code:#06x}"
            );
        }
    }

    #[test]
    fn an_option_without_a_value_says_which_one() {
        let error = value_for("--home", &[]).err().expect("must fail");
        match error {
            Failed::Usage(message) => assert!(message.contains("--home"), "{message}"),
            Failed::Refused(_) => panic!("a missing value is a usage error"),
        }
    }
}
