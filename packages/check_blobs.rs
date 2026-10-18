//! Verify the uncompressed SHA-256 identity of every blob in a store.
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf};

fn main() -> Result<()> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("expected blob directory")?,
    );
    let mut count = 0;
    for item in fs::read_dir(directory)? {
        let item = item?;
        let name = item
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 blob name"))?;
        let expected = name
            .strip_suffix(".zst")
            .context("unexpected blob filename")?;
        if expected.len() != 64
            || !expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("invalid blob filename: {name}");
        }
        let mut decoder = zstd::stream::read::Decoder::new(fs::File::open(item.path())?)?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        loop {
            let length = decoder
                .read(&mut buffer)
                .with_context(|| format!("decoding {name}"))?;
            if length == 0 {
                break;
            }
            hash.update(&buffer[..length]);
        }
        if format!("{:x}", hash.finalize()) != expected {
            bail!("blob hash mismatch: {name}");
        }
        count += 1;
    }
    println!("verified {count} content-addressed blobs");
    Ok(())
}
