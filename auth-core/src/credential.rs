//! Explicit local credential policy. Absence of material never grants access.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Policy {
    Denied = 0,
    Password = 1,
    SshPublicKey = 2,
    PasswordOrKey = 3,
    NoCredential = 4,
}

impl Policy {
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::Denied,
            1 => Self::Password,
            2 => Self::SshPublicKey,
            3 => Self::PasswordOrKey,
            4 => Self::NoCredential,
            _ => return None,
        })
    }
    pub fn password(self) -> bool {
        matches!(self, Self::Password | Self::PasswordOrKey)
    }
    pub fn ssh(self) -> bool {
        matches!(self, Self::SshPublicKey | Self::PasswordOrKey)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub id: [u8; 16],
    pub blob: Vec<u8>,
    pub label: String,
    pub created: u64,
}

pub const MAX_KEYS: usize = 32;
pub const MAX_LABEL: usize = 128;
