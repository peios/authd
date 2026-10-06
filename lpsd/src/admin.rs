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
use peios::security::{GroupAttributes, Sid, SidRef, WellKnown};
use peios::token::Token;

use crate::audit;
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
            Self::Store(StoreError::NotFound(_) | StoreError::NoSuchGroup(_)) => Failure::NotFound,
            // Distinct, so a script can tell "already so" from "you asked for
            // something impossible".
            Self::Store(StoreError::Exists(_)) => Failure::Exists,
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

    if let Err(error) = peios::file::set_sd(None, path, SecInfo::DACL, &descriptor, 0) {
        log::error(format_args!(
            "admin: could not set a descriptor on {} ({error}); administrators will not \
             be able to reach {LPSD_ADMIN_SOCKET_PATH}",
            path.display()
        ));
    }
}

/// The administrator on this connection — the user SID of the peer's token —
/// or `None` if the peer may not administer the store.
///
/// The SID is returned rather than a yes, because it is who every record of
/// the request names as having acted (`subject.token.sid`).
///
/// This is a test of the token, not a KACS access check against a
/// descriptor, so a refusal here reaches no audit record: KACS records only
/// the decisions it makes.
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
fn may_administer(stream: &UnixStream) -> Option<Sid> {
    let token = match Token::open_peer(stream.as_fd()) {
        Ok(token) => token,
        Err(error) => {
            log::warn(format_args!(
                "admin: could not read a peer's token: {error}"
            ));
            return None;
        }
    };

    // A token whose user cannot be read is nobody this can record, and so
    // nobody it admits.
    let user = match token.user() {
        Ok(user) => user,
        Err(error) => {
            log::warn(format_args!("admin: could not read a peer's user: {error}"));
            return None;
        }
    };
    if user == Sid::well_known(WellKnown::System) {
        return Some(user);
    }

    let administrators = Sid::well_known(WellKnown::Administrators);
    let administrator = token.groups().is_ok_and(|groups| {
        groups.iter().any(|(sid, attributes)| {
            *sid == administrators
                && GroupAttributes::from_bits_retain(*attributes).contains(GroupAttributes::ENABLED)
        })
    });
    administrator.then_some(user)
}

/// What a mutating request is recorded as: which event, what it changed, and
/// whom. Filled in by [`dispatch`] as it learns them — the account and group
/// before anything is applied, so that a refusal and a deletion still name
/// them, and a new account or group once it has a SID.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Act {
    event: &'static str,
    operation: Option<&'static str>,
    account: Option<Sid>,
    group: Option<Sid>,
    /// The request creates the account or group named, which therefore does
    /// not exist unless it succeeded.
    creates: bool,
}

impl Act {
    fn new(event: &'static str) -> Self {
        Self {
            event,
            operation: None,
            account: None,
            group: None,
            creates: false,
        }
    }

    /// `lpsd.account.modified`, doing `operation` to the account `name`.
    fn modified(store: &Store, operation: &'static str, name: &str) -> Self {
        Self {
            operation: Some(operation),
            account: account_sid(store, name),
            ..Self::new("lpsd.account.modified")
        }
    }

    /// The record, given who asked and how it ended.
    fn record(&self, administrator: &SidRef, failed: Option<&str>) -> audit::Record {
        let mut record = audit::Record::new();
        record.sid("subject.token.sid", administrator);
        // A creation that did not happen created nothing to name.
        if !(self.creates && failed.is_some()) {
            if let Some(account) = &self.account {
                record.sid("object.account.sid", account.as_ref());
            }
            if let Some(group) = &self.group {
                record.sid("object.group.sid", group.as_ref());
            }
        }
        if let Some(operation) = self.operation {
            record.str("operation.name", operation);
        }
        record.outcome(failed);
        record
    }
}

/// The SID of the account `name`, if the store holds one.
fn account_sid(store: &Store, name: &str) -> Option<Sid> {
    store.record(name).ok().map(|record| record.sid)
}

/// The SID of the group `name` — the store's own, or a well-known one — if
/// there is one.
fn group_sid(store: &Store, name: &str) -> Option<Sid> {
    store.resolve_group(name).ok()
}

/// The SID of the object a new RID was given.
fn created_sid(store: &Store, rid: u32) -> Option<Sid> {
    match store.lookup_relative_id(rid)? {
        store::Object::Principal(record) => Some(record.sid),
        store::Object::Group(group) => Some(group.sid),
    }
}

/// What a failed request is recorded as: the failure `lps` was told.
fn failure_reason(failure: Failure) -> &'static str {
    match failure {
        Failure::NotFound => "not-found",
        Failure::Exists => "exists",
        Failure::Invalid => "invalid",
        Failure::Denied => "denied",
        Failure::Internal => "internal",
    }
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

    let Some(administrator) = may_administer(&stream) else {
        log::warn(format_args!(
            "admin: refused a caller that is not an administrator"
        ));
        refuse(
            &stream,
            Failure::Denied,
            "Not authorised to administer the local principal store.",
        );
        return;
    };

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

    let mut act = None;
    let answer = dispatch(store, registered, msg_type, received.expose(), &mut act);

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

    // Recorded once the outcome is settled — after the save, so a success is
    // only ever recorded for a change that is durable — and before the reply,
    // so the record exists by the time `lps` reports it.
    let record = |failed: Option<&str>| {
        if let Some(act) = &act {
            audit::essential(act.event, &act.record(administrator.as_ref(), failed));
        }
    };

    match answer {
        Ok((Changed::Yes, reply)) => match save(store) {
            Ok(()) => {
                log::info(format_args!("admin: {}", describe(msg_type)));
                record(None);
                send(&stream, &reply);
            }
            Err(error) => {
                *store = snapshot;
                log::error(format_args!(
                    "admin: could not persist {}: {error}; the change was rolled back",
                    describe(msg_type)
                ));
                record(Some("not-saved"));
                refuse(
                    &stream,
                    Failure::Internal,
                    &format!("The change could not be saved and was not applied: {error}"),
                );
            }
        },
        // Nothing changed — a read, or a change to what already was — so
        // nothing happened to record.
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
            record(Some(failure_reason(refused.failure())));
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
        lps::MSG_KEY_LIST => "key-list",
        lps::MSG_KEY_ADD => "key-add",
        lps::MSG_KEY_REMOVE => "key-remove",
        lps::MSG_CREDENTIAL_POLICY => "credential-policy",
        lps::MSG_RENAME => "rename",
        lps::MSG_SET_LOGON_TYPES => "set-logon-types",
        lps::MSG_GROUP_RENAME => "group-rename",
        lps::MSG_GROUP_DESCRIBE => "group-describe",
        _ => "an unknown request",
    }
}

/// Serve one decoded request. A request that can change the store sets `act`
/// to what it will be recorded as, as soon as it has decoded whom it is about
/// — so a refusal is recorded too. A read leaves it `None`, and so do the two
/// group changes no event type covers yet (`group-rename`, `group-describe`).
fn dispatch(
    store: &mut Store,
    registered: psi::Registered,
    msg_type: u16,
    buf: &[u8],
    act: &mut Option<Act>,
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
        lps::MSG_KEY_LIST | lps::MSG_KEY_ADD | lps::MSG_KEY_REMOVE | lps::MSG_CREDENTIAL_POLICY => {
            match request(lps::decode_key_request(buf))? {
                lps::KeyRequest::List { name } => {
                    let keys: Vec<_> = store
                        .keys(&name)?
                        .iter()
                        .map(|k| lps::KeyInfo {
                            id: k.id,
                            fingerprint: crate::ssh::fingerprint(&k.blob).unwrap_or_default(),
                            label: k.label.clone(),
                            created: k.created,
                        })
                        .collect();
                    Ok((
                        Changed::No,
                        encoded(lps::encode_keys(store.credential_policy(&name)?, &keys))?,
                    ))
                }
                lps::KeyRequest::Add {
                    name,
                    public_key,
                    label,
                } => {
                    *act = Some(Act::modified(store, "key-add", &name));
                    store.add_key(&name, &public_key, &label)?;
                    Ok((Changed::Yes, encoded(lps::encode_done())?))
                }
                lps::KeyRequest::Remove { name, id } => {
                    *act = Some(Act::modified(store, "key-remove", &name));
                    store.remove_key(&name, id)?;
                    Ok((Changed::Yes, encoded(lps::encode_done())?))
                }
                lps::KeyRequest::Policy { name, policy } => {
                    *act = Some(Act::modified(store, "set-credential-policy", &name));
                    store.set_credential_policy(&name, policy)?;
                    Ok((Changed::Yes, encoded(lps::encode_done())?))
                }
            }
        }

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
                permitted_logon_types: record.permitted_logon_types,
                credential_policy: Some(store.credential_policy(&named.name)?),
            };
            Ok((Changed::No, encoded(lps::encode_principal(&detail))?))
        }

        lps::MSG_ADD => {
            let add = request(lps::decode_add(buf))?;
            *act = Some(Act {
                creates: true,
                ..Act::new("lpsd.account.created")
            });
            // Resolved here rather than by the tool, so `lps` needs no copy of
            // the well-known table or the domain — see `Store::resolve_group`.
            let groups = add
                .groups
                .iter()
                .map(|group| store.resolve_group(group))
                .collect::<Result<Vec<_>, _>>()?;
            let primary_group = add
                .primary_group
                .as_deref()
                .map(|group| store.resolve_group(group))
                .transpose()?;
            // Created whole, disabled and profiled, rather than created and
            // then changed. The two differ on an empty store, where disabling
            // afterwards would trip the last-administrator guard, and wherever
            // a later step is refused: half an account would be left behind.
            let rid = store.add(
                NewPrincipal {
                    permitted_logon_types: add.permitted_logon_types,
                    enabled: add.enabled,
                    groups,
                    primary_group,
                    home: add.home,
                    shell: add.shell,
                    display_name: add.display_name,
                    ..NewPrincipal::named(&add.name)
                },
                match add.credential {
                    lps::Credential::Password(secret) => Some(secret),
                    lps::Credential::None => None,
                },
            )?;
            if let Some(act) = act.as_mut() {
                act.account = created_sid(store, rid);
            }
            Ok((Changed::Yes, encoded(lps::encode_created(rid))?))
        }

        lps::MSG_REMOVE => {
            let named = request(lps::decode_remove(buf))?;
            // Before it goes: afterwards there is nothing to ask.
            *act = Some(Act {
                account: account_sid(store, &named.name),
                ..Act::new("lpsd.account.deleted")
            });
            store.remove(&named.name)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_SET_ENABLED => {
            let set = request(lps::decode_set_enabled(buf))?;
            *act = Some(Act::modified(store, "set-enabled", &set.name));
            let changed = store.set_enabled(&set.name, set.enabled)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_PASSWORD => {
            let set = request(lps::decode_set_password(buf))?;
            *act = Some(Act::modified(store, "set-password", &set.name));
            store.set_password(&set.name, set.secret)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_ADD => {
            let membership = request(lps::decode_group_add(buf))?;
            *act = Some(Act {
                account: account_sid(store, &membership.name),
                group: group_sid(store, &membership.group),
                ..Act::new("lpsd.group.member.added")
            });
            let group = store.resolve_group(&membership.group)?;
            let changed = store.add_membership(&membership.name, group)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_REMOVE => {
            let membership = request(lps::decode_group_remove(buf))?;
            *act = Some(Act {
                account: account_sid(store, &membership.name),
                group: group_sid(store, &membership.group),
                ..Act::new("lpsd.group.member.removed")
            });
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
                    description: group.description,
                })
                .collect::<Vec<_>>();
            Ok((Changed::No, encoded(lps::encode_groups(&groups))?))
        }

        lps::MSG_GROUP_CREATE => {
            let group = request(lps::decode_group_create(buf))?;
            *act = Some(Act {
                creates: true,
                ..Act::new("lpsd.group.created")
            });
            let rid = store.create_group(&group.name, &group.description)?;
            if let Some(act) = act.as_mut() {
                act.group = created_sid(store, rid);
            }
            Ok((Changed::Yes, encoded(lps::encode_created(rid))?))
        }

        lps::MSG_GROUP_RENAME => {
            let rename = request(lps::decode_group_rename(buf))?;
            let changed = store.rename_group(&rename.name, &rename.new_name)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_DESCRIBE => {
            let describe = request(lps::decode_group_describe(buf))?;
            let changed = store.describe_group(&describe.name, &describe.description)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_GROUP_DELETE => {
            let named = request(lps::decode_group_delete(buf))?;
            // Before it goes: afterwards there is nothing to ask.
            *act = Some(Act {
                group: group_sid(store, &named.name),
                ..Act::new("lpsd.group.deleted")
            });
            store.delete_group(&named.name)?;
            Ok((Changed::Yes, encoded(lps::encode_done())?))
        }

        lps::MSG_SET_PROFILE => {
            let set = request(lps::decode_set_profile(buf))?;
            *act = Some(Act::modified(store, "set-profile", &set.name));
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
            *act = Some(Act {
                group: group_sid(store, &membership.group),
                ..Act::modified(store, "set-primary-group", &membership.name)
            });
            let group = store.resolve_group(&membership.group)?;
            let changed = store.set_primary_group(&membership.name, group)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_CLAIM => {
            let set = request(lps::decode_set_claim(buf))?;
            *act = Some(Act::modified(store, "set-claim", &set.name));
            let changed = store.set_claim(&set.name, set.claim)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_REMOVE_CLAIM => {
            let named = request(lps::decode_remove_claim(buf))?;
            *act = Some(Act::modified(store, "remove-claim", &named.name));
            let changed = store.remove_claim(&named.name, &named.claim_name)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_RENAME => {
            let rename = request(lps::decode_rename(buf))?;
            *act = Some(Act::modified(store, "rename", &rename.name));
            let changed = store.rename(&rename.name, &rename.new_name)?;
            Ok((changed_flag(changed), encoded(lps::encode_done())?))
        }

        lps::MSG_SET_LOGON_TYPES => {
            let set = request(lps::decode_set_logon_types(buf))?;
            *act = Some(Act::modified(store, "set-logon-types", &set.name));
            let changed = store.set_logon_types(&set.name, set.permitted_logon_types)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(store: &mut Store, msg_type: u16, message: &[u8]) -> Result<Vec<u8>, Failure> {
        dispatch(store, psi::Registered::default(), msg_type, message, &mut None)
            .map(|(_, reply)| reply)
            .map_err(|refused| refused.failure())
    }

    /// What a request would be recorded as, and whether it was refused.
    fn act_of(store: &mut Store, msg_type: u16, message: &[u8]) -> (Option<Act>, bool) {
        let mut act = None;
        let refused = dispatch(store, psi::Registered::default(), msg_type, message, &mut act)
            .is_err();
        (act, refused)
    }

    fn bin(sid: &Sid) -> audit::Value {
        audit::Value::Bin(sid.as_ref().as_bytes().to_vec())
    }

    /// An account created names its new SID; a group membership names both
    /// the account and the group, a well-known group included; and a deletion
    /// names what it deleted, found before it went.
    #[test]
    fn changes_are_recorded_by_sid() {
        let mut store = Store::provision().unwrap();
        let admin: Sid = "S-1-5-21-9-9-9-500".parse().unwrap();

        let message = lps::encode_add(&dana()).unwrap();
        let (act, refused) = act_of(&mut store, lps::MSG_ADD, message.expose());
        assert!(!refused);
        let act = act.unwrap();
        assert_eq!(act.event, "lpsd.account.created");
        let dana_sid = store.record("dana").unwrap().sid;
        assert_eq!(act.account.as_ref(), Some(&dana_sid));
        let record = act.record(admin.as_ref(), None);
        assert_eq!(record.get("subject.token.sid"), Some(&bin(&admin)));
        assert_eq!(record.get("object.account.sid"), Some(&bin(&dana_sid)));
        assert_eq!(record.get("outcome.success"), Some(&audit::Value::Bool(true)));
        // A creation that failed names nothing it did not create.
        let failed = act.record(admin.as_ref(), Some("not-saved"));
        assert_eq!(failed.get("object.account.sid"), None);
        assert_eq!(
            failed.get("outcome.reason"),
            Some(&audit::Value::Str("not-saved".into()))
        );

        add(
            &mut store,
            &lps::Add {
                name: "erin".into(),
                groups: vec![],
                ..dana()
            },
        )
        .unwrap();
        let erin_sid = store.record("erin").unwrap().sid;
        let message = lps::encode_group_add(&lps::Membership {
            name: "erin".into(),
            group: "Administrators".into(),
        })
        .unwrap();
        let (act, refused) = act_of(&mut store, lps::MSG_GROUP_ADD, &message);
        assert!(!refused);
        let act = act.unwrap();
        assert_eq!(act.event, "lpsd.group.member.added");
        assert_eq!(act.account.as_ref(), Some(&erin_sid));
        assert_eq!(
            act.group.as_ref(),
            Some(&Sid::well_known(WellKnown::Administrators))
        );

        let message = lps::encode_remove(&lps::Named {
            name: "erin".into(),
        })
        .unwrap();
        let (act, refused) = act_of(&mut store, lps::MSG_REMOVE, &message);
        assert!(!refused);
        let act = act.unwrap();
        assert_eq!(act.event, "lpsd.account.deleted");
        assert_eq!(act.account.as_ref(), Some(&erin_sid));
    }

    /// A refused change is recorded with what it was about, and a read is not
    /// recorded at all.
    #[test]
    fn a_refusal_is_an_act_and_a_read_is_not() {
        let mut store = Store::provision().unwrap();
        add(&mut store, &dana()).unwrap();

        // dana is the only administrator, so she may not be disabled.
        let message = lps::encode_set_enabled(&lps::SetEnabled {
            name: "dana".into(),
            enabled: false,
        })
        .unwrap();
        let (act, refused) = act_of(&mut store, lps::MSG_SET_ENABLED, &message);
        assert!(refused);
        let act = act.unwrap();
        assert_eq!(act.event, "lpsd.account.modified");
        assert_eq!(act.operation, Some("set-enabled"));
        assert_eq!(act.account, Some(store.record("dana").unwrap().sid));

        let message = lps::encode_show(&lps::Named {
            name: "dana".into(),
        })
        .unwrap();
        assert_eq!(act_of(&mut store, lps::MSG_SHOW, &message), (None, false));
    }

    #[test]
    fn every_failure_has_a_reason() {
        for failure in [
            Failure::Denied,
            Failure::NotFound,
            Failure::Exists,
            Failure::Invalid,
            Failure::Internal,
        ] {
            assert!(!failure_reason(failure).is_empty());
        }
    }

    fn add(store: &mut Store, add: &lps::Add<'_>) -> Result<Vec<u8>, Failure> {
        let message = lps::encode_add(add).unwrap();
        ask(store, lps::MSG_ADD, message.expose())
    }

    fn dana<'a>() -> lps::Add<'a> {
        lps::Add {
            name: "dana".into(),
            credential: lps::Credential::None,
            enabled: true,
            groups: vec!["Administrators".into()],
            permitted_logon_types: lps::LogonTypes::UNSTATED,
            primary_group: None,
            home: None,
            shell: None,
            display_name: None,
        }
    }

    fn show(store: &mut Store, name: &str) -> lps::Detail {
        let message = lps::encode_show(&lps::Named { name: name.into() }).unwrap();
        lps::decode_principal(&ask(store, lps::MSG_SHOW, &message).unwrap()).unwrap()
    }

    #[test]
    fn an_add_carries_the_whole_profile() {
        let mut store = Store::provision().unwrap();
        store.create_group("developers", "").unwrap();
        add(
            &mut store,
            &lps::Add {
                primary_group: Some("developers".into()),
                home: Some("/srv/dana".into()),
                shell: Some("/bin/bash".into()),
                display_name: Some("Dana Scully".into()),
                permitted_logon_types: lps::LogonTypes::DEFAULT,
                ..dana()
            },
        )
        .unwrap();

        let detail = show(&mut store, "dana");
        assert_eq!(detail.primary_group.name, "developers");
        assert_eq!(detail.home, "/srv/dana");
        assert_eq!(detail.shell, "/bin/bash");
        assert_eq!(detail.display_name, "Dana Scully");
        assert_eq!(detail.permitted_logon_types, lps::LogonTypes::DEFAULT);
        assert_eq!(
            detail.credential_policy,
            Some(libauthd::credential::Policy::NoCredential)
        );
    }

    /// Half an account is not left behind: a refused shell refuses the add.
    #[test]
    fn an_add_with_a_refused_field_creates_nothing() {
        let mut store = Store::provision().unwrap();
        let refused = add(
            &mut store,
            &lps::Add {
                shell: Some("bash".into()),
                ..dana()
            },
        );
        assert_eq!(refused.unwrap_err(), Failure::Invalid);
        assert!(store.is_empty());
    }

    #[test]
    fn failures_are_coded_by_kind_not_by_words() {
        let mut store = Store::provision().unwrap();
        add(&mut store, &dana()).unwrap();

        assert_eq!(add(&mut store, &dana()).unwrap_err(), Failure::Exists);
        assert_eq!(
            add(
                &mut store,
                &lps::Add {
                    name: "erin".into(),
                    primary_group: Some("nonesuch".into()),
                    ..dana()
                }
            )
            .unwrap_err(),
            Failure::NotFound
        );
        let delete = lps::encode_group_delete(&lps::Named {
            name: "nonesuch".into(),
        })
        .unwrap();
        assert_eq!(
            ask(&mut store, lps::MSG_GROUP_DELETE, &delete).unwrap_err(),
            Failure::NotFound
        );
        let rename = lps::encode_rename(&lps::Rename {
            name: "nobody".into(),
            new_name: "x".into(),
        })
        .unwrap();
        assert_eq!(
            ask(&mut store, lps::MSG_RENAME, &rename).unwrap_err(),
            Failure::NotFound
        );
    }

    #[test]
    fn rename_and_logon_types_reach_the_store() {
        let mut store = Store::provision().unwrap();
        add(&mut store, &dana()).unwrap();
        add(
            &mut store,
            &lps::Add {
                name: "erin".into(),
                groups: vec![],
                ..dana()
            },
        )
        .unwrap();

        let rename = lps::encode_rename(&lps::Rename {
            name: "erin".into(),
            new_name: "erin.k".into(),
        })
        .unwrap();
        lps::decode_done(&ask(&mut store, lps::MSG_RENAME, &rename).unwrap()).unwrap();

        let set = lps::encode_set_logon_types(&lps::SetLogonTypes {
            name: "erin.k".into(),
            permitted_logon_types: lps::LogonTypes::SERVICE_ONLY,
        })
        .unwrap();
        lps::decode_done(&ask(&mut store, lps::MSG_SET_LOGON_TYPES, &set).unwrap()).unwrap();
        assert_eq!(
            show(&mut store, "erin.k").permitted_logon_types,
            lps::LogonTypes::SERVICE_ONLY
        );

        // dana is the only administrator.
        let set = lps::encode_set_logon_types(&lps::SetLogonTypes {
            name: "dana".into(),
            permitted_logon_types: lps::LogonTypes::SERVICE_ONLY,
        })
        .unwrap();
        assert_eq!(
            ask(&mut store, lps::MSG_SET_LOGON_TYPES, &set).unwrap_err(),
            Failure::Invalid
        );
    }
}
