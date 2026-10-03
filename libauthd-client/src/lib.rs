//! Clients of the two sockets a program asks about principals on.
//!
//! - [`admin`]: lpsd's admin socket, PLPS (PSPU §10), on which an
//!   administrator lists and changes the local principal store.
//! - [`ident`]: authd's identity socket (PGSS Logon, identity lookup), on
//!   which anyone may find out who a name or a SID is, and list principals
//!   and a group's members.
//!
//! Both connect for what they ask and close: lpsd answers one request a
//! connection, and authd closes a lookup connection left idle, so a client
//! held for the life of a window would only fail later. Neither retries. A
//! refusal is an answer, and a daemon that isn't there won't be there a
//! moment later either.

pub mod admin;
pub mod ident;
