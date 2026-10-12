//! GXWI information shown by the managed local console before authentication.

use std::io::Read;
use std::net::{IpAddr, SocketAddr};

use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};

const FINGERPRINT: &str = "/var/state/gxwi/certificate.sha256";

pub(super) fn announce() {
    if !std::path::Path::new("/usr/bin/gxwid").exists() {
        return;
    }
    let mut text = String::new();
    let fingerprint = std::fs::File::open(FINGERPRINT)
        .and_then(|file| file.take(256).read_to_string(&mut text))
        .ok()
        .and_then(|_| fingerprint(&text));
    let listen = listen();
    let addresses = browser_addresses(listen, addresses());
    print!("{}", banner(listen.port(), &addresses, fingerprint));
}

fn fingerprint(text: &str) -> Option<&str> {
    let text = text.trim();
    (text.len() == 95
        && text.bytes().enumerate().all(|(i, byte)| {
            if i % 3 == 2 {
                byte == b':'
            } else {
                byte.is_ascii_hexdigit()
            }
        }))
    .then_some(text)
}

fn listen() -> SocketAddr {
    let configured = (|| {
        let key = Key::open(
            None,
            "Machine\\Software\\GXWI",
            KeyAccess::QUERY_VALUE,
            OpenFlags::empty(),
        )
        .ok()?;
        let value = key.query_value(b"Listen", None).ok()?;
        if value.ty != ValueType::SZ {
            return None;
        }
        let bytes = value.data.split(|&byte| byte == 0).next()?;
        std::str::from_utf8(bytes).ok()?.trim().parse().ok()
    })();
    configured.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 7780)))
}

fn browser_addresses(listen: SocketAddr, mut addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    if !listen.ip().is_unspecified() {
        addresses = vec![listen.ip()];
    }
    addresses.retain(|address| {
        !address.is_unspecified()
            && !address.is_multicast()
            && (!listen.ip().is_unspecified() || !address.is_loopback())
            && address.is_ipv4() == listen.is_ipv4()
            && !matches!(address, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
    });
    addresses.sort();
    addresses.dedup();
    addresses
}

fn banner(port: u16, addresses: &[IpAddr], fingerprint: Option<&str>) -> String {
    let mut out = String::new();
    if port != 0 {
        for address in addresses {
            out.push_str(&format!(
                "login: GXWI: https://{}/\n",
                SocketAddr::new(*address, port)
            ));
        }
    }
    if out.is_empty() {
        out.push_str("login: GXWI: no browser address available yet.\n");
    }
    match fingerprint {
        Some(value) => out.push_str(&format!("login: GXWI certificate SHA-256: {value}\n")),
        None => out.push_str("login: GXWI certificate fingerprint unavailable.\n"),
    }
    out
}

fn addresses() -> Vec<IpAddr> {
    let mut found = Vec::new();
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the list, which is freed once below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return found;
    }
    let mut at = list;
    while !at.is_null() {
        // SAFETY: every node and address belongs to the still-live list.
        let entry = unsafe { &*at };
        at = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        // SAFETY: the address family identifies the concrete sockaddr layout.
        let address = unsafe {
            match (*entry.ifa_addr).sa_family as i32 {
                libc::AF_INET => {
                    let v4 = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::from(v4.sin_addr.s_addr.to_ne_bytes())
                }
                libc::AF_INET6 => {
                    let v6 = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::from(v6.sin6_addr.s6_addr)
                }
                _ => continue,
            }
        };
        found.push(address);
    }
    // SAFETY: free precisely the list returned by the successful getifaddrs.
    unsafe { libc::freeifaddrs(list) };
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_requires_the_complete_digest_and_no_control_bytes() {
        let valid = ["aB"; 32].join(":");
        assert_eq!(fingerprint(&format!("{valid}\n")), Some(valid.as_str()));
        for wrong in [
            String::new(),
            "AB:CD".into(),
            valid.replace(':', "-"),
            format!("{valid}\x1b[2J"),
            valid.replace("aB", "ZZ"),
        ] {
            assert_eq!(fingerprint(&wrong), None);
        }
    }

    #[test]
    fn wildcard_addresses_follow_the_listener_family_and_skip_unusable_addresses() {
        let given = [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.0.2",
            "10.0.0.2",
            "224.0.0.1",
            "::1",
            "fe80::2",
            "2001:db8::2",
        ]
        .map(|s| s.parse().unwrap())
        .to_vec();
        assert_eq!(
            browser_addresses("0.0.0.0:7780".parse().unwrap(), given.clone()),
            vec!["10.0.0.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            browser_addresses("[::]:443".parse().unwrap(), given.clone()),
            vec!["2001:db8::2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            browser_addresses("192.0.2.8:443".parse().unwrap(), given),
            vec!["192.0.2.8".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn banner_formats_ipv6_and_does_not_invent_a_missing_address_or_fingerprint() {
        let value = ["AB"; 32].join(":");
        let text = banner(8443, &["2001:db8::2".parse().unwrap()], Some(&value));
        assert!(text.contains("https://[2001:db8::2]:8443/"));
        assert!(text.contains(&format!("certificate SHA-256: {value}")));
        let absent = banner(7780, &[], None);
        assert!(!absent.contains("https://"));
        assert!(absent.contains("fingerprint unavailable"));
        assert!(!banner(0, &["10.0.0.2".parse().unwrap()], None).contains("https://"));
    }
}
