use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom},
    num::NonZeroUsize,
    path::Path,
    usize,
};

use libsodium_rs::{SodiumError, crypto_generichash::blake2b};
use secrets::SecretVec;
use serde::Serialize;
use zeroize::Zeroize;

use crate::crypto::{
    buffer,
    consts::{FILE_RNG_PADDING_1, FILE_RNG_PADDING_2},
};

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("Buffer Operation Error: {0}")]
    BufferOperationError(#[from] buffer::OperationError),
    #[error("I/O Error: {0}")]
    IoError(#[from] io::Error),
    #[error("Overflow.")]
    OverflowError,
    #[error("Buffer too large.")]
    BufferTooLargeError,
    #[error("Bincode Library Error: {0}")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
    #[error("Sodium Library Error: {0}")]
    SodiumError(#[from] SodiumError),
    #[error("No enough bytes.")]
    NoEnoughBytesError,
}

#[derive(Serialize, Default)]
struct FileRngHeaderTemplate {
    output_buffer_size: u64, // 8
    repeat_times: u64,       // 8
    index: u64,              // 8
    index_used: bool,        // 1
    padding_1: [u8; 32],
    padding_2: [u8; 7],
}

pub fn from_system(buf: &mut buffer::CryptoBuffer) -> Result<(), OperationError> {
    buf.private_write(|v| {
        libsodium_rs::random::fill_bytes(v);
    })?;
    Ok(())
}

/// buf: 1~64 bytes
pub fn from_file<P: AsRef<Path>>(
    buf: &mut buffer::CryptoBuffer,
    path: P,
    repeats: NonZeroUsize,
    index: Option<u64>,
) -> Result<(), OperationError> {
    if buf.len() > 64 {
        return Err(OperationError::BufferTooLargeError);
    }
    let bincode_cfg = bincode::config::legacy().with_limit::<64>();
    let template = FileRngHeaderTemplate {
        output_buffer_size: buf.len() as u64,
        repeat_times: repeats.get() as u64,
        index: index.unwrap_or_default(),
        index_used: index.is_some(),
        padding_1: *FILE_RNG_PADDING_1,
        padding_2: *FILE_RNG_PADDING_2,
    };
    let mut small_buf = SecretVec::zero(64);
    let size =
        bincode::serde::encode_into_slice(template, &mut small_buf.borrow_mut(), bincode_cfg)?;
    assert_eq!(size, 64);
    let mut s = blake2b::State::new(Some(&small_buf.borrow()), 64)?;
    small_buf.borrow_mut().zeroize();
    let mut read_off = 0usize;
    let mut rounds_left = repeats.get();
    let mut f = File::open(path)?;
    loop {
        let mut sb = small_buf.borrow_mut();
        match f.read(&mut sb[read_off..]) {
            Ok(0) => {
                if f.seek(SeekFrom::Start(0)).is_ok() {
                    continue;
                } else {
                    sb.zeroize();
                    return Err(OperationError::NoEnoughBytesError);
                }
            }
            Ok(n) => {
                read_off += n;
                if read_off == 64 {
                    s.update(&sb);
                    sb.zeroize();
                    rounds_left -= 1;
                    read_off = 0;
                    if rounds_left == 0 {
                        break;
                    }
                }
            }
            Err(e) => {
                sb.zeroize();
                return Err(e.into());
            }
        }
    }
    buf.copy_from_slice(&s.finalize())?;
    Ok(())
}

mod test {
    #[test]
    fn test_bincode() {
        use crate::crypto::rng::FileRngHeaderTemplate;
        let template = FileRngHeaderTemplate::default();
        let mut template_dst = vec![0u8; 64];
        let bincode_cfg = bincode::config::legacy().with_limit::<64>();
        let b =
            bincode::serde::encode_into_slice(template, &mut template_dst, bincode_cfg).unwrap();
        assert_eq!(b, 64);
        assert_eq!(template_dst, [0u8; 64]);
    }

    #[test]
    fn test_system_rng() {
        use crate::crypto::buffer::CryptoBuffer;
        use crate::crypto::rng::from_system;
        let mut buf = CryptoBuffer::new(64);
        from_system(&mut buf).unwrap();
        buf.read(|x| println!("rng: {}", hex::encode(x))).unwrap();
    }

    #[test]
    fn test_file_rng() {
        use crate::crypto::buffer::CryptoBuffer;
        use crate::crypto::rng::from_file;
        use std::num::NonZero;
        let mut buf = CryptoBuffer::new(64);
        from_file(&mut buf, "/dev/random", NonZero::new(8).unwrap(), None).unwrap();
        buf.read(|x| println!("rng: {}", hex::encode(x))).unwrap();
        from_file(&mut buf, "/dev/random", NonZero::new(8).unwrap(), Some(1)).unwrap();
        buf.read(|x| println!("rng(1): {}", hex::encode(x)))
            .unwrap();
    }
}
