use libsodium_rs::{SodiumError, crypto_generichash::blake2b};
use secrets::SecretVec;
use serde::Serialize;
use zeroize::Zeroize;

use crate::crypto::{
    buffers,
    consts::{KDF_PADDING_1, KDF_PADDING_2},
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
struct KdfHeaderTemplate {
    salt_size: u64,    // 8
    subkey_index: u64, // 8
    salt_used: bool,   // 1
    subkey_used: bool, // 1
    padding_1: [u8; 32],
    padding_2: [u8; 14],
}

/// input: 64 bytes
/// output: 64 bytes
pub fn extract(
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
            let template = KdfHeaderTemplate {
                salt_size: b.len() as u64,
                subkey_index: subkey_index.unwrap_or_default(),
                salt_used: true,
                subkey_used: subkey_index.is_some(),
                padding_1: *KDF_PADDING_1,
                padding_2: *KDF_PADDING_2,
            };
            let mut template_dst = SecretVec::zero(64);
            let size = bincode::serde::encode_into_slice(
                template,
                &mut template_dst.borrow_mut(),
                bincode_cfg,
            )?;
            assert_eq!(size, 64);
            let mut s = blake2b::State::new(Some(&template_dst.borrow()), 64)?;
            b.private_read(|x| s.update(x))?;
            s.finalize()
        }
        None => {
            let template = KdfHeaderTemplate {
                salt_size: 0,
                subkey_index: subkey_index.unwrap_or_default(),
                salt_used: false,
                subkey_used: subkey_index.is_some(),
                padding_1: *KDF_PADDING_1,
                padding_2: *KDF_PADDING_2,
            };
            let mut template_dst = SecretVec::zero(64);
            let size = bincode::serde::encode_into_slice(
                template,
                &mut template_dst.borrow_mut(),
                bincode_cfg,
            )?;
            assert_eq!(size, 64);
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

// pub fn expand() {}

mod test {
    #[test]
    fn test_bincode() {
        use crate::crypto::kdf::KdfHeaderTemplate;
        let template = KdfHeaderTemplate::default();
        let mut template_dst = vec![0u8; 64];
        let bincode_cfg = bincode::config::legacy().with_limit::<64>();
        let b =
            bincode::serde::encode_into_slice(template, &mut template_dst, bincode_cfg).unwrap();
        assert_eq!(b, 64);
        assert_eq!(template_dst, [0u8; 64]);
    }

    #[test]
    fn test_kdf_extract() {
        use crate::crypto::buffers::CryptoBuffer;
        use crate::crypto::kdf::extract;
        // use crate::crypto::rng::local_random;

        let test_input = "a58496cce3191895885498b6b67ca41c0c2bf963c9751e2ef6d52b3d9a5dd8756e1f0f0455cb4525a9b00f5fbdb5c1a66b58fe34133e27778bc117a55b123dee";
        let test_salt = "acb086a1a1c4e25c9d175458c604991fbb49033e507d9c1a15784e93303ea2ea";

        let test_out = "12f7c397536785e3a94a437a6475b813e4c29acc396b8485e8c5087d12665a68843ee35efde39d36c2ed8d78ae1f6d9f4a375a2cd8ce7c96d03d27e67153decd";
        let test_out_0 = "e74b3d52c008b7afe3a6ffa1b3bce788c23bb8b70f09b3b8e029866ddd9a7e0f624d3a71c43a604160760d1fcb3b6d9f8e8e76a113108c82dffa2dbb7123ef6c";
        let test_out_1 = "8e22676173b1ba821f157395ec798cc691f97350ce59db2fdc840f312cb6c56ae0412ce09baad8a01a8e11c84b7be83c9ec5afdf19b4a958cb985f3646e30064";
        let test_out_2 = "e6c5a7aef9dea6cc5a82f038460b4cd7e93840163a49d2f0b8538fba18a569061b6e2dd8be8ae573877481ce6a073041cc96c4e08084d79fa83bbf85c0e27da8";
        let test_outws = "52b8951922d9d372f5a4ed53b66a4d77c99b98b961addb1c71b3eb979cf24c8d08ebaa5fe49d080a56bde2a19736391f8ee559c5e1db58e4fd798e3434a13e59";
        let test_outws_0 = "5c0026fc36cdb45ca074fc2f20cc0234e56edf9db40d6adaa767305317fada245b309dfb3e3342a81881f42843f17492a13e781559bb35816407f4cdd26f48bd";
        let test_outws_1 = "fb289a23f3542f31c48f3f6afc0a65e6376b1efd4a093d76f18f99c093ca571f1c93802655905acc9c0bb434b3ad94a50bc34f3895cbda9cc36e0c819b8c36ed";
        let test_outws_2 = "b225651ef7f41e0e0a5e7d631910cbde49b6cb8433d4f60b1a88ef6c7d74e73d8e0b0d67af59df670055aa1d8c357ccdae752b1ddd70805ce7297bf94f5943e2";

        let mut input_buf = CryptoBuffer::new(64);
        let mut salt_buf = CryptoBuffer::new(32);
        input_buf
            .write(|x| hex::decode_to_slice(test_input, x).unwrap())
            .unwrap();
        salt_buf
            .write(|x| hex::decode_to_slice(test_salt, x).unwrap())
            .unwrap();
        // local_random(&mut input_buf).unwrap();
        // local_random(&mut salt_buf).unwrap();
        // input_buf
        //     .read(|x| println!("input: {}", hex::encode(x)))
        //     .unwrap();
        // salt_buf
        //     .read(|x| println!("salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, Some(&salt_buf), None).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, Some(&salt_buf), Some(0)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_0))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(0): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, Some(&salt_buf), Some(1)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_1))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(1): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, Some(&salt_buf), Some(2)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_2))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(2): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, None, None).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out, without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, None, Some(0)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_0))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(0), without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, None, Some(1)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_1))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(1), without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = extract(&input_buf, None, Some(2)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_2))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(2), without salt: {}", hex::encode(x)))
        //     .unwrap();
    }
}
