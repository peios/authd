//! The administrative side: lpsd listening, `lps` asking.
//!
//! # lpsd is now a listener
//!
//! Until this existed, lpsd only ever *dialled out* — one outbound connection
//! to authd, and nothing accepted. That was a deliberate property and this ends
//! it, so it is worth being explicit about what replaces it: a socket only an
//! administrator may usefully reach, carrying a protocol that cannot mint or
//! assert anything, serving one request at a time.
//!
//! # One request per connection
//!
//! An accepted connection is read once, answered once, and closed. That is less
//! a limitation of the protocol than the shape of the tool — `lps` does a single
//! operation and exits.
//!
//! It also bounds a real hazard. Admin requests are served on the same thread as
//! logons, because lpsd stays single-threaded, so a client that connected and
//! then said nothing would stall every logon behind it. One request under a read
//! deadline bounds that to [`REQUEST_TIMEOUT`] rather than forever.
//!
//! # Nothing is acknowledged before it is durable
//!
//! A mutation is applied in memory, **written to disk, and only then reported as
//! done**. If the write fails the in-memory change is rolled back from a
//! snapshot taken beforehand, so the daemon's idea of the store never runs ahead
//! of the file.
//!
//! Both halves matter. Replying first would tell an administrator their change
//! landed when it may not have. Skipping the rollback would leave lpsd
//! authenticating against principals that exist nowhere but in its own memory,
//! and would disappear at the next restart with no trace of why.
//!
//! # Authorization is the peer's token
//!
//! Not the socket's Unix mode, which decides nothing at all here — KACS raises
//! `CAP_DAC_OVERRIDE` on every managed process. See [`DIRECTORY_MODE`].
//!
//! Two things do decide. [`protect`] stamps a KACS descriptor admitting SYSTEM
//! and administrators, without which nothing lpsd creates under `/run` is
//! reachable by an administrator at all. Then [`may_administer`] reads the
//! connected peer's token, which is the check that actually authorises the
//! request — the same discipline authd applies on `psi.sock`.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use libauthd::lps::{self, Failed, Failure};
use libauthd::transport::{recv_message, send_message};
use libauthd::{LPSD_ADMIN_SOCKET_PATH, LPSD_RUN_DIR};
use peios::security::{GroupAttributes, Sid, WellKnown};
use peios::token::Token;

use crate::log;
use libauthd::psi;

use crate::store::{self, NewPrincipal, Store, StoreError};

/// How long a connected client has to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// And how long lpsd will spend trying to hand back the answer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether an operation changed the store, and so must be persisted before it
/// is acknowledged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changed {
    Yes,
    No,
}

/// Why a request could not be served.
enum Refused {
    Store(StoreError),
    /// The daemon built a reply it could not encode. A bug here, not a bad
    /// request, but the client still needs an answer rather than a hang.
    Encode,
}

impl From<StoreError> for Refused {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl Refused {
    fn failure(&self) -> Failure {
        match self {
            Self::Store(StoreError::NotFound(_)) => Failure::NotFound,
            // `add` is the only operation that reports a name collision, and
            // reporting it distinctly lets a script tell "already so" from "you
            // asked for something impossible".
            Self::Store(StoreError::Invalid(what)) if what.contains("already exists") => {
                Failure::Exists
            }
            Self::Store(StoreError::Invalid(_)) => Failure::Invalid,
            Self::Store(_) | Self::Encode => Failure::Internal,
        }
    }

    fn reason(&self) -> String {
        match self {
            Self::Store(error) => error.to_string(),
            Self::Encode => "the daemon could not encode a reply".into(),
        }
    }
}

/// Create `/run/lpsd` and bind the administrative socket.
///
/// `/run` is tmpfs, so this happens every boot. A stale socket cannot survive a
/// reboot but can survive a crash, so an existing one is removed rather than
/// treated as a fatal bind failure — otherwise a crashed daemon would refuse to
/// restart until someone deleted a file by hand.
///
/// The **directory** is peinit's: `RuntimeDirectories=["lpsd"]` provisions it
/// before launch with a descriptor that is a strict superset of anything lpsd
/// would write — SYSTEM, Administrators, *and lpsd's own service SID*.
/// Stamping over it on every start made that declaration cosmetic (PEI-476),
/// so lpsd no longer touches the directory's descriptor or its mode:
/// `create_dir_all` remains only as the fallback for running without peinit,
/// where the directory takes `/run`'s inherited descriptor as it always did.
/// The **socket** stays lpsd's to protect — it creates it, and nothing else
/// knows it exists. No POSIX mode is set on it: KACS raises
/// `CAP_DAC_OVERRIDE` on every managed process, so the bits decide nothing,
/// and a mode beside the descriptor would read as a control that has no say.
pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(LPSD_RUN_DIR);
    std::fs::create_dir_all(directory)?;

    let path = Path::new(LPSD_ADMIN_SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {LPSD_ADMIN_SOCKET_PATH}")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let listener = UnixListener::bind(path)?;
    protect(path);
    Ok(listener)
}

/// Stamp a SYSTEM-and-Administrators descriptor on the administrative socket.
///
/// **This is load-bearing, not defence in depth.** peinit seeds every Phase-1
/// virtual mount with `O:SYG:SYD:(A;OICI;GA;;;SY)` — SYSTEM alone, inheritable —
/// so everything lpsd creates under `/run` inherits a descriptor admitting only
/// SYSTEM. Without this call an administrator running `lps` is denied by KACS
/// before a byte is exchanged, which is exactly what happened.
///
/// Widening peinit's seed was the alternative and is the wrong lever: it would
/// make the whole of `/run`, `/dev/shm` and the cgroup tree administrator-
/// writable by inheritance in order to fix one daemon's socket. A daemon owning
/// the descriptor on its own runtime directory is both narrower and where the
/// knowledge lives — only lpsd knows that administering lpsd is an
/// administrator's business.
///
/// Unlike the *store's* descriptor, this one admits `BUILTIN\Administrators`:
/// administering the store is precisely what administrators are for, where
/// reading the verifiers is not.
///
/// Non-fatal, because a daemon that cannot authenticate is worse than one that
/// cannot be administered — but loud, because the administrative interface is
/// unreachable until someone fixes it.
fn protect(path: &Path) {
    use peios::file::SecInfo;
    use peios::security::{AccessMask, AceFlags, AclBuilder, SdBuilder};

    let system = Sid::well_known(WellKnown::System);
    let administrators = Sid::well_known(WellKnown::Administrators);

    let descriptor = AclBuilder::new()
        .allow(
            system.as_ref(),
            AccessMask::GENERIC_ALL.bits(),
            AceFlags::empty(),
        )
        .allow(
            administrators.as_ref(),
            AccessMask::GENERIC_ALL.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| {
            SdBuilder::new()
                .owner(system.as_ref())
                .group(system.as_ref())
                .dacl(&dacl)
                .build()
        });

    let descriptor = match descriptor {
        Ok(descriptor) => descriptor,
        Err(error) => {
            log::warn(format_args!("admin: could not build a descriptor: {error}"));
            return;
        }
    };

    if let Err(error) = peios::file::set_sd(
        None,
        path,
        SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
        &descriptor,
        0,
    ) {
        log::error(format_args!(
            "admin: could not set a descriptor on {} ({error}); administrators will not \
             be able to reach {LPSD_ADMIN_SOCKET_PATH}",
            path.display()
        ));
    }
}

/// Whether the peer on this connection may administer the store.
///
/// Two ways to satisfy it:
///
/// - **`BUILTIN\Administrators`, enabled.** The attribute matters: a group that
///   is present but marked deny-only contributes to denials and grants nothing,
///   so treating it as membership would let a deliberately-restricted token
///   administer the machine.
/// - **`LocalSystem`.** Required rather than a convenience: the first account on
///   a machine is created by a boot-time service before any human principal
///   exists to be an administrator. Without this there would be no way to
///   bootstrap an account at all.
fn may_administer(stream: &UnixStream) -> bool {
    let token = match Token::open_peer(stream.as_fd()) {
        Ok(token) => token,
        Err(error) => {
            log::warn(format_args!(
                "admin: could not read a peer's token: {error}"
            ));
            return false;
        }
    };

    if token
        .user()
        .is_ok_and(|user| user == Sid::well_known(WellKnown::System))
    {
        return true;
    }

    let administrators = Sid::well_known(WellKnown::Administrators);
    token.groups().is_ok_and(|groups| {
        groups.iter().any(|(sid, attributes)| {
            *sid == administrators
                && GroupAttributes::from_bits_retain(*attributes).contains(GroupAttributes::ENABLED)
        })
    })
}

/// Serve one administrative request, persisting through `save` before
/// acknowledging anything.
pub fn serve(
    stream: UnixStream,
    store: &mut Store,
    registered: psi::Registered,
    save: impl FnOnce(&Store) -> Result<(), StoreError>,
) {
    if let Err(error) = stream.set_read_timeout(Some(REQUEST_TIMEOUT)) {
        log::warn(format_args!("admin: could not set a read timeout: {error}"));
        return;
    }
    if let Err(error) = stream.set_write_timeout(Some(REPLY_TIMEOUT)) {
        log::warn(format_args!(
            "admin: could not set a write timeout: {error}"
        ));
        return;
    }

    if !may_administer(&stream) {
        log::warn(format_args!(
            "admin: refused a caller that is not an administrator"
        ));
        refuse(
            &stream,
            Failure::Denied,
            "Not authorised to administer the local principal store.",
        );
        return;
    }

    let received = match recv_message(&lps::FRAMING, &stream) {
        Ok(received) => received,
        Err(error) => {
            log::warn(format_args!("admin: could not read a request: {error}"));
            return;
        }
    };

    let Ok((msg_type, _)) = lps::decode_type(received.expose()) else {
        log::warn(format_args!("admin: malformed request header"));
        refuse(&stream, Failure::Invalid, "Malformed request.");
        return;
    };

    // Taken before anything is applied, so a failed write can be undone. The
    // store is a few hundred records; copying it is cheaper than any of the
    // alternatives for keeping memory and disk in step.
    let snapshot = store.clone();

    let answer = dispatch(store, registered, msg_type, received.expose());

    // Check the daemon's own answer against the protocol's declared pairing.
    // A reply of the wrong type is a bug here, and its symptom is the worst
    // kind: the operation *succeeds*, the tool reports a failure, and an
    // operator retries something that has already happened. Caught at the one
    // point every reply passes through, rather than trusted to sixteen match
    // arms staying right.
    if let Ok((_, reply)) = &answer {
        let sent = lps::decode_type(reply).map(|(ty, _)| ty).ok();
        let expected = lps::reply_to(msg_type);
        if sent != expected {
            log::error(format_args!(
                "admin: {} was answered with {sent:?}, not the declared {expected:?}; \
                 this is a bug in lpsd",
                describe(msg_type)
            ));
        }
    }

    match answer {
        Ok((Changed::Yes, reply)) => match save(store) {
            Ok(()) => {
                log::info(format_args!("admin: {}", describe(msg_type)));
                send(&stream, &reply);
            }
            Err(error) => {
                *store = snapshot;
                log::error(format_args!(
                    "admin: could not persist {}: {error}; the change was rolled back",
                    describe(msg_type)
                ));
                refuse(
                    &stream,
                    Failure::Internal,
                    &format!("The change could not be saved and was not applied: {error}"),
                );
            }
        },
        Ok((Changed::No, reply)) => send(&stream, &reply),
        Err(refused) => {
            // Every mutating method validates before it writes, so a refusal
            // leaves the store untouched — the snapshot is belt and braces.
            *store = snapshot;
            log::warn(format_args!(
                "admin: {} refused: {}",
                describe(msg_type),
                refused.reason()
            ));
            refuse(&stream, refused.failure(), &refused.reason());
        }
    }
}

/// What a message type is called, for logs.
fn describe(msg_type: u16) -> &'static str {
    match msg_type {
        lps::MSG_LIST => "list",
        lps::MSG_SHOW => "show",
        lps::MSG_DOMAIN => "domain",
        lps::MSG_ADD => "add",
        lps::MSG_REMOVE => "remove",
        lps::MSG_SET_ENABLED => "set-enabled",
        lps::MSG_SET_PASSWORD => "set-password",
        lps::MSG_GROUP_ADD => "group-add",
        lps::MSG_GROUP_REMOVE => "group-remove",
        lps::MSG_GROUP_LIST => "group-list",
        lps::MSG_GROUP_CREATE => "group-create",
        lps::MSG_GROUP_DELETE => "group-delete",
        lps::MSG_SET_PROFILE => "set-profile",
        lps::MSG_SET_PRIMARY_GROUP => "set-primary-group",
        lps::MSG_SET_CLAIM => "set-claim",
        lps::MSG_REMOVE_CLAIM => "remove-claim",
        _ => "an unknown request",
    }
}

fn dispatch(
    store: &mut Store,
    registered: psi::Registered,
    msg_type: u16,
    buf: &[u8],
) -> Result<(Changed, Vec<u8>), Refused> {
    // What a relative Unix ID projects to once authd has rebased it. Shown to
    // an operator rather than used for anything: lpsd stores and asserts the
    // relative number, and only authd may add the base.
    let effective = |relative: u32| -> u32 {
        // Out of range projects to nothing, not to an absolute number.
        // Checking only `relative == 0` displayed a uid for an identifier authd
        // refuses and projects to `nobody` — the opposite of the reason §2.8
        // discloses the range in the first place, which is so an operator can
        // see what a principal will actually appear as.
        if registered.unix_id_base == 0 || relative == 0 || relative > registered.unix_id_count {
            0
        } else {
            registered.unix_id_base.saturating_add(relative)
        }
    };

    match msg_type {
        lps::MSG_LIST => {
            let summaries = store
                .summaries()
                .into_iter()
                .map(|summary| lps::Summary {
                    name: summary.name,
                    rid: summary.rid,
                    enabled: summary.enabled,
                    groups: summary.groups as u32,
                    unix_id: effective(summary.unix_id),
                })
                .collect::<Vec<_>>();
            Ok((Changed::No, encoded(lps::encode_principals(&summaries))?))
        }

        lps::MSG_DOMAIN => {
            let domain = store.domain_sid()?;
            Ok((
                Changed::No,
                encoded(lps::encode_domain_is(domain.as_ref().as_bytes()))?,
            ))
        }

        lps::MSG_SHOW => {
            let named = request(lps::decode_show(buf))?;
            let record = store.record(&named.name)?;
            let group_ref = |group: &store::GroupRef| lps::GroupRef {
                sid: group.sid.as_ref().as_bytes().to_vec(),
                name: group.name.clone().unwrap_or_default(),
                // A group lpsd does not own has no relative id to rebase, and
                // authd's number for it is not something lpsd can know. Zero
                // reads as "this machine cannot tell you", which is honest.
                unix_id: group.unix_id.map(&effective).unwrap_or(0),
            };
            let detail = lps::Detail {
                name: record.name,
                rid: record.rid,
                enabled: record.enabled,
                sid: record.sid.as_ref().as_bytes().to_vec(),
                groups: record.groups.iter().map(group_ref).collect(),
                unix_id: effective(record.unix_id),
                primary_group: group_ref(&record.primary_group),
                home: record.home,
                shell: record.shell,
                display_name: record.display_name,
                claims: record.claims,
            };
            Ok((Changed::No, encoded(lps::encode_principal(&detail))?))
        }

        lps::MSG_ADD => {
            let add = request(lps::decode_add(buf))?;
            // Resolved here rather than by the tool, so `lps` needs no copy of
            // the well-known table or the domain — see `Store::resolve_group`.
            let groups = add
                .groups
                .iter()
                .map(|group| store.resolve_group(group))
                .collect::<Result<Vec<_>, _>>()?;
            // Created disabled rather than created and then disabled. The two
            // differ on an empty store: the second step would trip the
            // last-administrator guard and leave a half-made account behind.
            let rid = store.add(
                NewPrincipal {
                    permitted_logon_types: add.permitted_logon_types,
                    enabled: add.enabled,
                    groups,
                    ..NewPrincipal::named(&add.name)
                },
                match add.credential {
                    lps::Credential::Password(secret) => Some(secret),
                    lps::Credential::None => None,
                },
            )?;
            Ok((Changed::Yes, encoded(lps::encode_created(rid))?))
        }

        lps::MSG_REMOVE => {
            let named = request(lps::decode_remove(buf))?;
            store.remove(&named.name)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_SET_ENABLED => {
            let set = request(lps::decode_set_enabled(buf))?;
            let changed = store.set_enabled(&set.name, set.enabled)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_PASSWORD => {
            let set = request(lps::decode_set_password(buf))?;
            store.set_password(&set.name, set.secret)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_ADD => {
            let membership = request(lps::decode_group_add(buf))?;
            let group = store.resolve_group(&membership.group)?;
            let changed = store.add_membership(&membership.name, group)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_REMOVE => {
            let membership = request(lps::decode_group_remove(buf))?;
            let group = store.resolve_group(&membership.group)?;
            let changed = store.remove_membership(&membership.name, group.as_ref())?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_LIST => {
            request(lps::decode_group_list(buf))?;
            let groups = store
                .group_summaries()?
                .into_iter()
                .map(|group| lps::GroupSummary {
                    name: group.name,
                    rid: group.rid,
                    unix_id: effective(group.unix_id),
                    sid: group.sid.as_ref().as_bytes().to_vec(),
                    members: group.members as u32,
                })
                .collect::<Vec<_>>();
            Ok((Changed::No, encoded(lps::encode_groups(&groups))?))
        }

        lps::MSG_GROUP_CREATE => {
            let named = request(lps::decode_group_create(buf))?;
            let rid = store.create_group(&named.name)?;
            Ok((Changed::Yes, encoded(lps::encode_created(rid))?))
        }

        lps::MSG_GROUP_DELETE => {
            let named = request(lps::decode_group_delete(buf))?;
            store.delete_group(&named.name)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_SET_PROFILE => {
            let set = request(lps::decode_set_profile(buf))?;
            // Every field is applied before anything is reported, and a refusal
            // from any one of them aborts the request — `serve` restores the
            // snapshot, so a half-applied profile is not reachable.
            let mut changed = false;
            if let Some(home) = &set.home {
                changed |= store.set_home(&set.name, home)?;
            }
            if let Some(shell) = &set.shell {
                changed |= store.set_shell(&set.name, shell)?;
            }
            if let Some(display_name) = &set.display_name {
                changed |= store.set_display_name(&set.name, display_name)?;
            }
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_PRIMARY_GROUP => {
            let membership = request(lps::decode_set_primary_group(buf))?;
            let group = store.resolve_group(&membership.group)?;
            let changed = store.set_primary_group(&membership.name, group)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_CLAIM => {
            let set = request(lps::decode_set_claim(buf))?;
            let changed = store.set_claim(&set.name, set.claim)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_REMOVE_CLAIM => {
            let named = request(lps::decode_remove_claim(buf))?;
            let changed = store.remove_claim(&named.name, &named.claim_name)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        _ => Err(Refused::Store(StoreError::Invalid(
            "this daemon does not understand that request".into(),
        ))),
    }
}

fn changed_flag(changed: bool) -> Changed {
    if changed { Changed::Yes } else { Changed::No }
}

/// A malformed request is the client's fault, so it reads as `Invalid`.
fn request<T>(result: Result<T, libauthd::WireError>) -> Result<T, Refused> {
    result.map_err(|_| Refused::Store(StoreError::Invalid("malformed request".into())))
}

/// A reply that will not encode is the daemon's fault, so it reads as internal.
fn encoded(result: Result<Vec<u8>, libauthd::WireError>) -> Result<Vec<u8>, Refused> {
    result.map_err(|_| Refused::Encode)
}

fn send(stream: &UnixStream, message: &[u8]) {
    if let Err(error) = send_message(stream, message) {
        log::warn(format_args!("admin: could not send a reply: {error}"));
    }
}

fn refuse(stream: &UnixStream, failure: Failure, reason: &str) {
    let Ok(message) = lps::encode_failed(&Failed {
        failure,
        reason: reason.to_string(),
    }) else {
        return;
    };
    send(stream, &message);
}
