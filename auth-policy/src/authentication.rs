//! Machine policy for invoking authentication and disclosing identity.
//! The registry key's own SD protects edits; its stored AuthenticationSecurity
//! descriptor protects the authority's operations, not registry operations.

use peios::registry::{Key, KeyAccess, OpenFlags};
use peios::security::{SecurityDescriptor, Sid, SidRef, sddl};
use sha1::{Digest, Sha1};
use sha2::Sha256;

pub const SECURITY_VALUE: &str = "AuthenticationSecurity";
pub const CAPABILITIES_VALUE: &str = "Capabilities";
pub const AUTHENTICATE: u32 = 0x1;
pub const LOGON: u32 = 0x2;
pub const READ_GROUPS: u32 = 0x4;
pub const READ_CLAIM: u32 = 0x8;
pub const ALL: u32 = AUTHENTICATE | LOGON | READ_GROUPS | READ_CLAIM;
pub const AUTHENTICATE_CAPABILITY: &str = "peios.auth.authenticate";
pub const LOGON_CAPABILITY: &str = "peios.auth.logon";

// Fixed UUID namespace in RFC network byte order. Never change after use:
// changing it would silently invalidate every previously issued claim ACE.
pub const CLAIM_NAMESPACE: [u8; 16] = [
    0x75, 0x03, 0xa8, 0xf1, 0xbb, 0x10, 0x4b, 0x57, 0xa1, 0xd2, 0xd4, 0x94, 0x62, 0x56, 0xf4, 0x04,
];

/// UUID v5, returned in the little-endian GUID layout used by object ACEs.
pub fn claim_guid(name: &str) -> Result<[u8; 16], String> {
    let name = auth_core::authentication::canonical_claim_name(name)
        .map_err(|_| "Invalid claim name.".to_owned())?;
    let mut hash = Sha1::new();
    hash.update(CLAIM_NAMESPACE);
    hash.update(name.as_bytes());
    let mut guid: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    guid[6] = (guid[6] & 0x0f) | 0x50;
    guid[8] = (guid[8] & 0x3f) | 0x80;
    guid[..4].reverse();
    guid[4..6].reverse();
    guid[6..8].reverse();
    Ok(guid)
}

/// Custom capability SID: S-1-15-3 followed by SHA-256's eight LE words.
pub fn capability_sid(name: &str) -> Result<Sid, String> {
    if name.is_empty() || name.len() > 256 || name.contains('\0') {
        return Err("Invalid capability name.".into());
    }
    let digest = Sha256::digest(name.as_bytes());
    let mut parts = vec![3];
    for word in digest.as_chunks::<4>().0 {
        parts.push(u32::from_le_bytes(*word));
    }
    Sid::build(15, &parts).map_err(|e| e.to_string())
}

pub fn default_sddl() -> String {
    let authenticate = capability_sid(AUTHENTICATE_CAPABILITY).expect("constant capability name");
    let logon = capability_sid(LOGON_CAPABILITY).expect("constant capability name");
    let radius = crate::service_sid::of("radiusd").expect("constant service name");
    format!("O:SYG:SYD:(A;;0xf;;;SY)(A;;0x1;;;{authenticate})(A;;0x2;;;{logon})(A;;0xc;;;{radius})")
}

pub fn descriptor() -> Result<SecurityDescriptor, String> {
    let configured = match Key::open(None, crate::KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => match key.query_value(SECURITY_VALUE.as_bytes(), None) {
            Ok(value) => Some(
                crate::sz(&value.ty, &value.data)
                    .filter(|s| !s.is_empty())
                    .ok_or("AuthenticationSecurity is not nonempty SDDL.")?
                    .to_owned(),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    sddl::parse(&configured.unwrap_or_else(default_sddl)).map_err(|e| e.to_string())
}

/// Read only the attested service SID's direct record. A source's claimed
/// memberships or an AuthenticateStart body cannot assign these capabilities.
pub fn service_capabilities(service: &SidRef) -> Result<Vec<Sid>, String> {
    let path = format!("{}\\{}", crate::KEY, service);
    let key = match Key::open(None, &path, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let value = match key.query_value(CAPABILITIES_VALUE.as_bytes(), None) {
        Ok(value) => value,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let names =
        crate::multi_sz(&value.ty, &value.data).ok_or("Capabilities is not REG_MULTI_SZ.")?;
    if names.len() > 32 {
        return Err("Too many service capabilities.".into());
    }
    let mut result = Vec::new();
    for name in names {
        let sid = capability_sid(name)?;
        if !result.contains(&sid) {
            result.push(sid);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_aliases_cannot_select_different_permissions() {
        assert_eq!(
            claim_guid("Department").unwrap(),
            claim_guid("department").unwrap()
        );
        assert_ne!(
            claim_guid("department").unwrap(),
            claim_guid("account_type").unwrap()
        );
        assert!(claim_guid("").is_err());
        assert!(claim_guid("department\0private").is_err());
        for (left, right) in [("Équipe", "équipe"), ("İ", "i\u{307}"), ("K", "k")] {
            assert_eq!(claim_guid(left).unwrap(), claim_guid(right).unwrap());
        }
        assert_ne!(claim_guid("é").unwrap(), claim_guid("e\u{301}").unwrap());
        assert_eq!(
            claim_guid("Équipe").unwrap(),
            [
                0xc6, 0x73, 0x25, 0x7c, 0x3a, 0x9c, 0x76, 0x5f, 0xa1, 0x02, 0xd6, 0xd5, 0xac, 0xec,
                0x12, 0x16
            ]
        );
        // Independently generated with Python uuid.uuid5; the bytes here are
        // GUID little-endian, not RFC UUID network order.
        assert_eq!(
            claim_guid("department").unwrap(),
            [
                0x79, 0xd3, 0xab, 0xc4, 0xd6, 0xa4, 0x10, 0x59, 0xbc, 0xcf, 0x9f, 0x01, 0xf9, 0xa4,
                0x73, 0x8f,
            ]
        );
    }

    #[test]
    fn default_capabilities_have_distinct_operation_grants() {
        let auth = capability_sid(AUTHENTICATE_CAPABILITY).unwrap();
        let logon = capability_sid(LOGON_CAPABILITY).unwrap();
        assert_ne!(auth, logon);
        assert_eq!(
            auth.to_string(),
            "S-1-15-3-815189116-3587081081-2225730562-134748649-517842195-1560836879-2444240241-858498395"
        );
        assert!(default_sddl().contains(&format!("(A;;0x1;;;{auth})")));
        assert!(default_sddl().contains(&format!("(A;;0x2;;;{logon})")));
        let radius = crate::service_sid::of("radiusd").expect("constant service name");
        assert!(default_sddl().contains(&format!("(A;;0xc;;;{radius})")));
        sddl::parse(&default_sddl()).expect("default descriptor must parse");
    }
}
