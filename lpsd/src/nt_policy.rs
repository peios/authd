//! Live local-source credential-storage policy. No network knowledge here.
use peios::registry::{Key, KeyAccess, NotifyFilter, OpenFlags, ValueType};
use std::io;

const KEY: &str = "Machine\\Software\\Lpsd";

pub fn read() -> io::Result<(bool, bool)> {
    let key = match Key::open(None, KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(e) => {
            let e = io::Error::from(e);
            if e.kind() == io::ErrorKind::NotFound {
                return Ok((true, true));
            }
            return Err(e);
        }
    };
    let read = |name: &[u8]| -> io::Result<bool> {
        match key.query_value(name, None) {
            Ok(value) if value.ty == ValueType::DWORD && value.data.len() == 4 => {
                match u32::from_le_bytes(value.data.as_slice().try_into().expect("DWORD length")) {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "NT policy must be 0 or 1",
                    )),
                }
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NT policy must be REG_DWORD",
            )),
            Err(e) => {
                let e = io::Error::from(e);
                if e.kind() == io::ErrorKind::NotFound {
                    Ok(true)
                } else {
                    Err(e)
                }
            }
        }
    };
    Ok((read(b"StoreNtHashes")?, read(b"BackfillNtHashes")?))
}

pub fn watch() -> io::Result<Key> {
    // Watch the existing ancestor so creating/deleting/replacing Lpsd is seen.
    let key = Key::open(
        None,
        "Machine\\Software",
        KeyAccess::NOTIFY,
        OpenFlags::empty(),
    )
    .map_err(io::Error::from)?;
    key.set_nonblocking(true).map_err(io::Error::from)?;
    key.notify(NotifyFilter::ALL, true)
        .map_err(io::Error::from)?;
    Ok(key)
}
