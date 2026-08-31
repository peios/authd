//! Durable replacement of a single file, and a filesystem thin enough to lie
//! to in tests.
//!
//! # The whole durability strategy
//!
//! lpsd's store is a few hundred principals — kilobytes — rewritten when an
//! administrator changes an account. There is no write-rate problem to solve, so
//! there is no write-ahead log, no snapshot chain, and no replay: the store is
//! serialised whole and put in place with [`replace`].
//!
//! That is not a smaller version of a database. It is a different property.
//! Because the swap is a `rename`, a reader sees the old file or the new file
//! and there is no third outcome to recover from — which means **there is no
//! recovery code**, and code that does not exist cannot be wrong. In the daemon
//! holding every local credential verifier, that is worth more than a
//! well-tested implementation of the alternative. Recorded in PEI-166.
//!
//! # The order is the algorithm
//!
//! ```text
//! create temp -> write -> set SD -> fsync(temp) -> rename -> fsync(dir)
//! ```
//!
//! Every step is load-bearing:
//!
//! - **The SD is stamped on the temp file**, before the rename. Stamping after
//!   would leave the store readable at its real name, however briefly, under
//!   whatever descriptor it inherited from its directory.
//! - **`fsync` precedes the rename.** Reversed, a crash can leave the store's
//!   name pointing at a block that was never written — the file is present,
//!   correctly named, and empty. This is the single most common way an
//!   atomic-replace is got wrong.
//! - **`fsync` on the directory** after the rename, because the rename is a
//!   directory modification and is not durable until the directory is.
//!
//! [`FaultyFs`] exists to hold that order still. It models content durability
//! and name durability separately, so a test can cut power between any two
//! steps and assert what a reader would find.

use std::io;
use std::path::{Path, PathBuf};

use libauthd::Secret;
use peios::security::SecurityDescriptor;

/// Suffix for the file a replacement is staged in. Same directory as the target
/// — `rename` cannot cross a filesystem, and a temp directory elsewhere would
/// make the swap non-atomic on exactly the systems where it matters.
const STAGING_SUFFIX: &str = ".new";

/// Mode for the store file.
///
/// The security descriptor is the real control on Peios; this is what the file
/// looks like to anything reading the inode without KACS in the path — a
/// recovery shell, a backup tool, an image mounted elsewhere. Belt and braces,
/// and free.
pub const STORE_MODE: u32 = 0o600;

/// The filesystem operations a durable replacement needs, and nothing else.
///
/// Narrow on purpose: every method here is a step [`FaultyFs`] can fail or
/// crash between, and a wider trait would mean untested paths.
pub trait Fs {
    type File: File;

    /// Read a file whole. `Ok(None)` means it does not exist, which is a
    /// supported state (an unprovisioned machine), not an error.
    fn read(&self, path: &Path) -> io::Result<Option<Secret>>;

    /// Create or truncate `path`. Truncating rather than failing on an existing
    /// file is deliberate: a crash can leave a stale staging file behind, and
    /// refusing to overwrite it would wedge every future write until someone
    /// deleted it by hand.
    fn create(&self, path: &Path) -> io::Result<Self::File>;

    /// Stamp a security descriptor on a file.
    fn set_sd(&self, path: &Path, sd: &SecurityDescriptor) -> io::Result<()>;

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;

    /// Make a directory's *contents list* durable — i.e. commit a rename.
    fn sync_dir(&self, dir: &Path) -> io::Result<()>;

    fn remove(&self, path: &Path) -> io::Result<()>;
}

pub trait File {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()>;
    /// Make this file's *contents* durable.
    fn sync(&mut self) -> io::Result<()>;
}

/// Where a replacement is staged.
fn staging_path(path: &Path) -> io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the store path has no file name",
        )
    })?;
    let mut staged = name.to_os_string();
    staged.push(STAGING_SUFFIX);
    Ok(path.with_file_name(staged))
}

/// Replace `path`'s contents durably, or leave the previous contents entirely
/// intact.
///
/// On any failure before the rename the target is untouched — that is the
/// property this function exists to provide, and it is why the caller can treat
/// a failed save as "nothing happened" rather than as an unknown state.
///
/// A failure at the final directory sync is different and is reported as such:
/// the new contents *are* in place, they are merely not yet known to have
/// survived a power loss. Callers should treat that as fatal rather than
/// retrying, since a filesystem that cannot sync will not sync on the retry
/// either.
pub fn replace<F: Fs>(
    fs: &F,
    path: &Path,
    contents: &[u8],
    sd: &SecurityDescriptor,
) -> io::Result<()> {
    let staged = staging_path(path)?;
    let directory = path.parent().unwrap_or_else(|| Path::new("."));

    let outcome = (|| -> io::Result<()> {
        let mut file = fs.create(&staged)?;
        file.write_all(contents)?;
        fs.set_sd(&staged, sd)?;
        file.sync()?;
        fs.rename(&staged, path)?;
        fs.sync_dir(directory)
    })();

    if outcome.is_err() {
        // Best effort. If this fails too, the next write truncates it anyway —
        // which is why `create` truncates rather than refusing.
        let _ = fs.remove(&staged);
    }
    outcome
}

// ---------------------------------------------------------------------------
// The real filesystem
// ---------------------------------------------------------------------------

pub struct RealFs;

impl RealFs {
    /// Create `dir` and any missing ancestors, making each one durable.
    ///
    /// `std::fs::create_dir_all` is not enough on its own, and the gap is the
    /// same one [`replace`] closes for the store file: a new directory is an
    /// entry in its *parent*, and that entry is not durable until the parent
    /// is synced. Without this, a crash shortly after first provisioning can
    /// take `/var/state/lpsd` with it — store and all.
    ///
    /// That failure is worse than losing an ordinary file. lpsd would find no
    /// store, provision, and mint a **new domain**, so every principal on the
    /// machine would come back with a different SID and every descriptor naming
    /// them would be orphaned. It is exactly the outcome the absent-versus-
    /// corrupt rule in [`crate::store`] exists to prevent, arriving by a
    /// different route.
    pub fn create_directory(&self, dir: &Path) -> io::Result<()> {
        if dir.is_dir() {
            return Ok(());
        }
        // Ancestors first, so each `create_dir` below has a parent to land in.
        if let Some(parent) = dir.parent() {
            self.create_directory(parent)?;
        }
        match std::fs::create_dir(dir) {
            Ok(()) => {}
            // Raced, or created between the check and here. Either way it
            // exists, and whoever made it is responsible for its durability.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(error) => return Err(error),
        }
        match dir.parent() {
            Some(parent) => self.sync_dir(parent),
            None => Ok(()),
        }
    }
}

pub struct RealFile(std::fs::File);

impl File for RealFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(&mut self.0, buf)
    }

    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
}

impl Fs for RealFs {
    type File = RealFile;

    fn read(&self, path: &Path) -> io::Result<Option<Secret>> {
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let len = file.metadata()?.len();
        let len = usize::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "the store is absurdly large")
        })?;

        // Read straight into a self-wiping buffer. Staging in an ordinary `Vec`
        // first would leave a copy of every verifier in freed memory.
        let mut secret = Secret::zeroed(len);
        io::Read::read_exact(&mut &file, secret.expose_mut())?;
        Ok(Some(secret))
    }

    fn create(&self, path: &Path) -> io::Result<Self::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(STORE_MODE)
            .open(path)?;
        Ok(RealFile(file))
    }

    fn set_sd(&self, path: &Path, sd: &SecurityDescriptor) -> io::Result<()> {
        use peios::file::SecInfo;
        peios::file::set_sd(
            None,
            path,
            SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
            sd,
            0,
        )
        .map_err(|error| io::Error::other(format!("could not set the store's descriptor: {error}")))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        // Opening a directory read-only and fsyncing it is how POSIX commits a
        // rename. There is no std wrapper for it; `File::open` on a directory
        // succeeds on Linux and `sync_all` does the right thing.
        std::fs::File::open(dir)?.sync_all()
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }
}

// ---------------------------------------------------------------------------
// A filesystem that can be made to fail, and to lose power
// ---------------------------------------------------------------------------

#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::rc::Rc;

/// The operations a test can fail or crash between.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Read,
    Create,
    Write,
    SetSd,
    Sync,
    Rename,
    SyncDir,
    Remove,
}

#[cfg(test)]
#[derive(Default)]
struct State {
    /// What a reader would see right now.
    live: BTreeMap<PathBuf, Vec<u8>>,
    /// Contents known to have reached the platter, per path.
    synced: BTreeMap<PathBuf, Vec<u8>>,
    /// Names known to have reached the platter.
    durable_names: BTreeSet<PathBuf>,
    descriptors: BTreeMap<PathBuf, Vec<u8>>,
    /// Operations to fail, consumed in order.
    failures: Vec<Op>,
    /// Every operation performed, for asserting on ordering.
    journal: Vec<Op>,
}

#[cfg(test)]
impl State {
    fn perform(&mut self, op: Op) -> io::Result<()> {
        self.journal.push(op);
        if let Some(position) = self.failures.iter().position(|&f| f == op) {
            self.failures.remove(position);
            return Err(io::Error::other(format!("injected failure in {op:?}")));
        }
        Ok(())
    }
}

/// An in-memory filesystem that models content durability and name durability
/// separately, so a test can cut power at any point in [`replace`] and ask what
/// a reader would find.
///
/// Not thread-safe, and deliberately so: it is a test double for a
/// single-threaded daemon, and `RefCell` panicking on re-entrancy is a better
/// outcome than a mutex quietly permitting it.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct FaultyFs {
    state: Rc<RefCell<State>>,
}

#[cfg(test)]
impl FaultyFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a file that is already fully durable — an existing store.
    pub fn preload(&self, path: &Path, contents: &[u8]) {
        let mut state = self.state.borrow_mut();
        state.live.insert(path.to_path_buf(), contents.to_vec());
        state.synced.insert(path.to_path_buf(), contents.to_vec());
        state.durable_names.insert(path.to_path_buf());
    }

    /// Fail the next occurrence of `op`.
    pub fn fail_next(&self, op: Op) {
        self.state.borrow_mut().failures.push(op);
    }

    /// The operations performed so far, in order.
    pub fn journal(&self) -> Vec<Op> {
        self.state.borrow().journal.clone()
    }

    pub fn read_now(&self, path: &Path) -> Option<Vec<u8>> {
        self.state.borrow().live.get(path).cloned()
    }

    pub fn exists(&self, path: &Path) -> bool {
        self.state.borrow().live.contains_key(path)
    }

    pub fn descriptor_of(&self, path: &Path) -> Option<Vec<u8>> {
        self.state.borrow().descriptors.get(path).cloned()
    }

    /// Cut the power.
    ///
    /// `directories_flushed` picks between the two outcomes a filesystem is
    /// permitted to produce for a rename that was never followed by a directory
    /// sync: the rename survives, or it does not. Both are legal, so both are
    /// worth testing, and modelling the choice explicitly is more honest than
    /// picking one and calling it *the* behaviour.
    pub fn crash(&self, directories_flushed: bool) {
        let mut state = self.state.borrow_mut();
        if directories_flushed {
            state.durable_names = state.live.keys().cloned().collect();
        }
        let names = state.durable_names.clone();
        let mut recovered = BTreeMap::new();
        for name in names {
            // A name that reached the platter while its contents did not is a
            // real outcome — it is precisely what an fsync-less rename gives
            // you — and it presents as an empty file.
            let contents = state.synced.get(&name).cloned().unwrap_or_default();
            recovered.insert(name, contents);
        }
        state.live = recovered;
        state.journal.clear();
    }
}

#[cfg(test)]
pub struct FaultyFile {
    state: Rc<RefCell<State>>,
    path: PathBuf,
}

#[cfg(test)]
impl File for FaultyFile {
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Write)?;
        state
            .live
            .entry(self.path.clone())
            .or_default()
            .extend_from_slice(buf);
        Ok(())
    }

    fn sync(&mut self) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Sync)?;
        let contents = state.live.get(&self.path).cloned().unwrap_or_default();
        state.synced.insert(self.path.clone(), contents);
        Ok(())
    }
}

#[cfg(test)]
impl Fs for FaultyFs {
    type File = FaultyFile;

    fn read(&self, path: &Path) -> io::Result<Option<Secret>> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Read)?;
        Ok(state.live.get(path).map(|bytes| Secret::from_slice(bytes)))
    }

    fn create(&self, path: &Path) -> io::Result<Self::File> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Create)?;
        state.live.insert(path.to_path_buf(), Vec::new());
        drop(state);
        Ok(FaultyFile {
            state: Rc::clone(&self.state),
            path: path.to_path_buf(),
        })
    }

    fn set_sd(&self, path: &Path, sd: &SecurityDescriptor) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::SetSd)?;
        state
            .descriptors
            .insert(path.to_path_buf(), sd.as_bytes().to_vec());
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Rename)?;
        let Some(contents) = state.live.remove(from) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such file"));
        };
        state.live.insert(to.to_path_buf(), contents);

        // The staged file's synced contents become the target's synced
        // contents: same blocks, new name. The *name* is not durable until a
        // directory sync, which is what `crash` then arbitrates.
        if let Some(synced) = state.synced.get(from).cloned() {
            state.synced.insert(to.to_path_buf(), synced);
        }
        if let Some(sd) = state.descriptors.remove(from) {
            state.descriptors.insert(to.to_path_buf(), sd);
        }
        Ok(())
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::SyncDir)?;
        let in_dir: BTreeSet<PathBuf> = state
            .live
            .keys()
            .filter(|path| path.parent() == Some(dir))
            .cloned()
            .collect();
        state
            .durable_names
            .retain(|path| path.parent() != Some(dir));
        state.durable_names.extend(in_dir);
        Ok(())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.perform(Op::Remove)?;
        state.live.remove(path);
        state.synced.remove(path);
        state.descriptors.remove(path);
        Ok(())
    }
}

/// A real directory that removes itself.
///
/// Rolled here rather than taken as a dev-dependency: lpsd already draws
/// randomness from the kernel, so a unique name costs three lines, and this
/// crate's dependency list is short on purpose.
#[cfg(test)]
struct TempDir {
    path: PathBuf,
}

#[cfg(test)]
impl TempDir {
    fn new() -> Self {
        let bytes = crate::random::array::<8>().expect("randomness");
        let mut name = String::from("lpsd-test-");
        for byte in bytes {
            name.push_str(&format!("{byte:02x}"));
        }
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).expect("must create a temp directory");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

#[cfg(test)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// `RealFs` with the descriptor step stubbed out.
///
/// `set_sd` is a KACS syscall and fails anywhere that is not Peios, so an
/// end-to-end test of [`replace`] against a real filesystem cannot include it.
/// Everything else here is the genuine article: real `open`, real `write`, real
/// `fsync`, real `rename`, real directory sync.
///
/// So `set_sd` is the one primitive whose real implementation is exercised only
/// on Peios itself. Stated plainly rather than papered over — the alternative
/// was to weaken production behaviour to make it testable, which trades a real
/// property for a green tick.
#[cfg(test)]
struct RealFsWithoutSd;

#[cfg(test)]
impl Fs for RealFsWithoutSd {
    type File = RealFile;

    fn read(&self, path: &Path) -> io::Result<Option<Secret>> {
        RealFs.read(path)
    }
    fn create(&self, path: &Path) -> io::Result<Self::File> {
        RealFs.create(path)
    }
    fn set_sd(&self, _path: &Path, _sd: &SecurityDescriptor) -> io::Result<()> {
        Ok(())
    }
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        RealFs.rename(from, to)
    }
    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        RealFs.sync_dir(dir)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        RealFs.remove(path)
    }
}

#[cfg(test)]
mod real_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_replacement_lands_on_a_real_filesystem() {
        let dir = TempDir::new();
        let store = dir.join("principals");
        let sd = crate::store::store_descriptor().expect("must build a descriptor");

        replace(&RealFsWithoutSd, &store, b"first", &sd).expect("must replace");
        assert_eq!(std::fs::read(&store).unwrap(), b"first");

        replace(&RealFsWithoutSd, &store, b"second", &sd).expect("must replace over");
        assert_eq!(std::fs::read(&store).unwrap(), b"second");

        assert!(
            !dir.join("principals.new").exists(),
            "the staging file must not survive a successful replacement"
        );
    }

    #[test]
    fn the_store_is_created_unreadable_to_anyone_else() {
        // Defence in depth behind the descriptor: this is what the inode looks
        // like to anything reading it without KACS in the path.
        let dir = TempDir::new();
        let store = dir.join("principals");
        let sd = crate::store::store_descriptor().expect("must build a descriptor");
        replace(&RealFsWithoutSd, &store, b"secret", &sd).expect("must replace");

        let mode = std::fs::metadata(&store).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, STORE_MODE, "expected {STORE_MODE:o}, found {mode:o}");
    }

    #[test]
    fn reading_back_gives_exactly_what_was_written() {
        let dir = TempDir::new();
        let store = dir.join("principals");
        let sd = crate::store::store_descriptor().expect("must build a descriptor");

        // Bytes that would break a text-mode or NUL-terminated reader.
        let contents: Vec<u8> = (0..=255u8).chain([0, 0, 0]).collect();
        replace(&RealFsWithoutSd, &store, &contents, &sd).expect("must replace");

        let read = RealFs.read(&store).expect("must read").expect("must exist");
        assert_eq!(read.expose(), contents.as_slice());
    }

    #[test]
    fn an_empty_file_reads_back_as_empty_rather_than_absent() {
        // The distinction the whole absent-versus-corrupt rule rests on, at the
        // filesystem layer: `Some(empty)` and `None` must not be confused.
        let dir = TempDir::new();
        let store = dir.join("principals");
        std::fs::write(&store, b"").unwrap();

        let read = RealFs.read(&store).expect("must read");
        assert!(
            read.is_some(),
            "an empty file exists and must read as present"
        );
        assert_eq!(read.unwrap().expose(), b"");
    }

    #[test]
    fn reading_an_absent_file_is_not_an_error() {
        let dir = TempDir::new();
        assert!(
            RealFs
                .read(&dir.join("nothing"))
                .expect("absence is not failure")
                .is_none()
        );
    }

    #[test]
    fn syncing_a_real_directory_succeeds() {
        // `File::open` on a directory plus `sync_all` is how POSIX commits a
        // rename, and std has no wrapper saying so. If this ever stops working
        // the durability argument quietly evaporates, so it is asserted rather
        // than assumed.
        let dir = TempDir::new();
        RealFs
            .sync_dir(&dir.path)
            .expect("a directory must be syncable");
    }

    #[test]
    fn a_stale_staging_file_is_overwritten_rather_than_blocking() {
        let dir = TempDir::new();
        let store = dir.join("principals");
        let sd = crate::store::store_descriptor().expect("must build a descriptor");
        std::fs::write(dir.join("principals.new"), b"debris from a crash").unwrap();

        replace(&RealFsWithoutSd, &store, b"new", &sd).expect("must replace over the debris");
        assert_eq!(std::fs::read(&store).unwrap(), b"new");
    }

    #[test]
    fn create_directory_makes_every_missing_ancestor() {
        let dir = TempDir::new();
        let nested = dir.join("var").join("lib").join("lpsd");
        RealFs.create_directory(&nested).expect("must create");
        assert!(nested.is_dir());
    }

    #[test]
    fn create_directory_is_idempotent() {
        let dir = TempDir::new();
        let nested = dir.join("lpsd");
        RealFs.create_directory(&nested).expect("must create");
        RealFs
            .create_directory(&nested)
            .expect("an existing directory must not be an error");
        assert!(nested.is_dir());
    }

    #[test]
    fn create_directory_refuses_where_a_file_is_in_the_way() {
        let dir = TempDir::new();
        let blocked = dir.join("lpsd");
        std::fs::write(&blocked, b"not a directory").unwrap();
        RealFs
            .create_directory(&blocked.join("deeper"))
            .expect_err("a file where a directory belongs must surface");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> PathBuf {
        PathBuf::from("/var/state/lpsd/principals")
    }

    fn staged() -> PathBuf {
        PathBuf::from("/var/state/lpsd/principals.new")
    }

    /// Any descriptor will do; these tests care that one was applied and when,
    /// not what it says.
    fn descriptor() -> SecurityDescriptor {
        crate::store::store_descriptor().expect("must build a descriptor")
    }

    #[test]
    fn a_replacement_lands() {
        let fs = FaultyFs::new();
        replace(&fs, &store(), b"new", &descriptor()).expect("must replace");
        assert_eq!(fs.read_now(&store()).as_deref(), Some(&b"new"[..]));
        assert!(!fs.exists(&staged()), "the staging file must not survive");
    }

    #[test]
    fn the_order_is_write_protect_sync_rename_syncdir() {
        let fs = FaultyFs::new();
        replace(&fs, &store(), b"new", &descriptor()).expect("must replace");
        assert_eq!(
            fs.journal(),
            vec![
                Op::Create,
                Op::Write,
                Op::SetSd,
                Op::Sync,
                Op::Rename,
                Op::SyncDir
            ]
        );
    }

    #[test]
    fn the_descriptor_is_stamped_before_the_rename() {
        let fs = FaultyFs::new();
        replace(&fs, &store(), b"new", &descriptor()).expect("must replace");
        let journal = fs.journal();
        let set_sd = journal.iter().position(|&op| op == Op::SetSd).unwrap();
        let rename = journal.iter().position(|&op| op == Op::Rename).unwrap();
        assert!(
            set_sd < rename,
            "the store must never exist at its real name under an inherited descriptor"
        );
        assert!(fs.descriptor_of(&store()).is_some());
    }

    #[test]
    fn contents_are_synced_before_the_rename() {
        let fs = FaultyFs::new();
        replace(&fs, &store(), b"new", &descriptor()).expect("must replace");
        let journal = fs.journal();
        let sync = journal.iter().position(|&op| op == Op::Sync).unwrap();
        let rename = journal.iter().position(|&op| op == Op::Rename).unwrap();
        assert!(
            sync < rename,
            "renaming before fsync can leave the store present and empty"
        );
    }

    #[test]
    fn a_failure_before_the_rename_leaves_the_old_store_untouched() {
        for op in [Op::Create, Op::Write, Op::SetSd, Op::Sync] {
            let fs = FaultyFs::new();
            fs.preload(&store(), b"old");
            fs.fail_next(op);

            replace(&fs, &store(), b"new", &descriptor())
                .expect_err("the injected failure must surface");

            assert_eq!(
                fs.read_now(&store()).as_deref(),
                Some(&b"old"[..]),
                "failing at {op:?} must not disturb the store"
            );
            assert!(
                !fs.exists(&staged()),
                "failing at {op:?} must not leave a staging file behind"
            );
        }
    }

    #[test]
    fn a_crash_before_the_rename_leaves_the_old_store() {
        for flushed in [false, true] {
            let fs = FaultyFs::new();
            fs.preload(&store(), b"old");

            // Everything up to but not including the rename.
            let mut file = fs.create(&staged()).unwrap();
            file.write_all(b"new").unwrap();
            fs.set_sd(&staged(), &descriptor()).unwrap();
            file.sync().unwrap();

            fs.crash(flushed);
            assert_eq!(
                fs.read_now(&store()).as_deref(),
                Some(&b"old"[..]),
                "a crash before the rename must leave the previous store (flushed={flushed})"
            );
        }
    }

    #[test]
    fn a_crash_after_the_rename_gives_one_whole_store_or_the_other() {
        for flushed in [false, true] {
            let fs = FaultyFs::new();
            fs.preload(&store(), b"old");

            let mut file = fs.create(&staged()).unwrap();
            file.write_all(b"new").unwrap();
            fs.set_sd(&staged(), &descriptor()).unwrap();
            file.sync().unwrap();
            fs.rename(&staged(), &store()).unwrap();
            // No directory sync: both outcomes are legal from here.

            fs.crash(flushed);
            let found = fs.read_now(&store());
            assert!(
                found.as_deref() == Some(&b"old"[..]) || found.as_deref() == Some(&b"new"[..]),
                "a crash must leave one whole store or the other, found {found:?} (flushed={flushed})"
            );
        }
    }

    #[test]
    fn a_completed_replacement_survives_a_crash() {
        let fs = FaultyFs::new();
        fs.preload(&store(), b"old");
        replace(&fs, &store(), b"new", &descriptor()).expect("must replace");

        fs.crash(false);
        assert_eq!(
            fs.read_now(&store()).as_deref(),
            Some(&b"new"[..]),
            "once replace() returns, the new store must be durable"
        );
    }

    #[test]
    fn syncing_the_directory_without_syncing_the_file_loses_the_contents() {
        // Not a property lpsd relies on — a demonstration that the model has
        // teeth, and that the fsync-before-rename ordering is load-bearing
        // rather than decorative.
        let fs = FaultyFs::new();
        let mut file = fs.create(&staged()).unwrap();
        file.write_all(b"new").unwrap();
        fs.rename(&staged(), &store()).unwrap();
        fs.sync_dir(Path::new("/var/state/lpsd")).unwrap();

        fs.crash(false);
        assert_eq!(
            fs.read_now(&store()).as_deref(),
            Some(&b""[..]),
            "renaming before fsync leaves the name pointing at unwritten blocks"
        );
    }

    #[test]
    fn a_stale_staging_file_does_not_wedge_the_next_write() {
        let fs = FaultyFs::new();
        fs.preload(&store(), b"old");
        fs.preload(&staged(), b"debris from a crash");

        replace(&fs, &store(), b"new", &descriptor()).expect("must replace over the debris");
        assert_eq!(fs.read_now(&store()).as_deref(), Some(&b"new"[..]));
    }

    #[test]
    fn reading_an_absent_file_is_not_an_error() {
        let fs = FaultyFs::new();
        assert!(fs.read(&store()).expect("absence is not failure").is_none());
    }

    #[test]
    fn staging_path_sits_beside_the_target() {
        assert_eq!(
            staging_path(Path::new("/var/state/lpsd/principals")).unwrap(),
            PathBuf::from("/var/state/lpsd/principals.new"),
        );
    }

    #[test]
    fn a_path_with_no_file_name_is_rejected() {
        assert!(staging_path(Path::new("/")).is_err());
    }
}
