use libsodium_rs::{SodiumError, crypto_generichash::blake2b};
use secrets::SecretVec;
use serde::Serialize;
use zeroize::Zeroize;

use crate::crypto::{
    buffers,
    consts::{KDF_SALT_FOOTER_1, KDF_SALT_FOOTER_2},
};

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("Buffer Operation Error: {0}")]
    BufferOperationError(#[from] buffers::OperationError),
    #[error("Invaild Input size.")]
    InvaildInputSize,
    #[error("Invaild Output size.")]
    InvaildOutputSize,
    #[error("Sodium Library Error: {0}")]
    SodiumError(#[from] SodiumError),
    #[error("Bincode Library Error: {0}")]
    BincodeEncodeError(#[from] bincode::error::EncodeError),
}

#[derive(Serialize, Default)]
#[repr(C)]
struct KdfSaltHeaderTemplate {
    salt_size: u64,    // 8
    subkey_index: u64, // 8
    salt_used: bool,   // 1
    subkey_used: bool, // 1
    footer: [u8; 32],
    footer2: [u8; 14],
}

/// input: 64 bytes
/// output: 64 bytes
pub fn kdf_extract(
    input: &buffers::CryptoBuffer,
    salt: Option<&buffers::CryptoBuffer>,
    subkey_index: Option<u64>,
) -> Result<buffers::CryptoBuffer, OperationError> {
    if input.len() != 64 {
        return Err(OperationError::InvaildInputSize);
    }
    let bincode_cfg = bincode::config::legacy().with_limit::<64>();
    let mut t = match salt {
        Some(b) => {
            let template = KdfSaltHeaderTemplate {
                salt_size: b.len() as u64,
                subkey_index: subkey_index.unwrap_or_default(),
                salt_used: true,
                subkey_used: subkey_index.is_some(),
                footer: *KDF_SALT_FOOTER_1,
                footer2: *KDF_SALT_FOOTER_2,
            };
            let mut template_dst = SecretVec::zero(64);
            let _ = bincode::serde::encode_into_slice(
                template,
                &mut template_dst.borrow_mut(),
                bincode_cfg,
            )?;
            let mut s = blake2b::State::new(Some(&template_dst.borrow()), 64)?;
            b.private_read(|x| s.update(x))?;
            s.finalize()
        }
        None => {
            let template = KdfSaltHeaderTemplate {
                salt_size: 0,
                subkey_index: subkey_index.unwrap_or_default(),
                salt_used: false,
                subkey_used: subkey_index.is_some(),
                footer: *KDF_SALT_FOOTER_1,
                footer2: *KDF_SALT_FOOTER_2,
            };
            let mut template_dst = SecretVec::zero(64);
            let _ = bincode::serde::encode_into_slice(
                template,
                &mut template_dst.borrow_mut(),
                bincode_cfg,
            )?;
            let mut s = blake2b::State::new(Some(&template_dst.borrow()), 64)?;
            s.finalize()
        }
    };
    let mut template = SecretVec::zero(64);
    template.borrow_mut().copy_from_slice(&t);
    t.zeroize();
    let mut s = input.private_read(|x| blake2b::State::new(Some(x), 64))??;
    s.update(&template.borrow());
    let mut o = SecretVec::zero(64);
    o.borrow_mut().copy_from_slice(&s.finalize());
    Ok(o.into())
}

pub fn kdf_expand() {}

mod test {
    #[test]
    fn test_bincode() {
        use crate::crypto::kdf::KdfSaltHeaderTemplate;
        let template = KdfSaltHeaderTemplate::default();
        let mut template_dst = vec![0u8; 64];
        let bincode_cfg = bincode::config::legacy().with_limit::<64>();
        let b =
            bincode::serde::encode_into_slice(template, &mut template_dst, bincode_cfg).unwrap();
        assert_eq!(b, 64);
        assert_eq!(template_dst, [0u8; 64]);
    }
}
