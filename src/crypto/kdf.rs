use libsodium_rs::{SodiumError, crypto_generichash::blake2b};
use secrets::SecretVec;
use serde::Serialize;
use zeroize::Zeroize;

use crate::crypto::{
    buffer,
    consts::{KDF_PADDING_1, KDF_PADDING_2},
};

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("Buffer Operation Error: {0}")]
    BufferOperationError(#[from] buffer::OperationError),
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
struct KdfHeaderTemplate {
    salt_size: u64,   // 8
    index: u64,       // 8
    salt_used: bool,  // 1
    index_used: bool, // 1
    padding_1: [u8; 32],
    padding_2: [u8; 14],
}

/// input: 64 bytes
/// output: 64 bytes
pub fn derive(
    input: &buffer::CryptoBuffer,
    salt: Option<&buffer::CryptoBuffer>,
    index: Option<u64>,
) -> Result<buffer::CryptoBuffer, OperationError> {
    if input.len() != 64 {
        return Err(OperationError::InvaildInputSize);
    }
    let bincode_cfg = bincode::config::legacy().with_limit::<64>();
    let mut t = match salt {
        Some(b) => {
            let template = KdfHeaderTemplate {
                salt_size: b.len() as u64,
                index: index.unwrap_or_default(),
                salt_used: true,
                index_used: index.is_some(),
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
                index: index.unwrap_or_default(),
                salt_used: false,
                index_used: index.is_some(),
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
        use crate::crypto::buffer::CryptoBuffer;
        use crate::crypto::kdf::derive;

        let test_input = "a58496cce3191895885498b6b67ca41c0c2bf963c9751e2ef6d52b3d9a5dd8756e1f0f0455cb4525a9b00f5fbdb5c1a66b58fe34133e27778bc117a55b123dee";
        let test_salt = "acb086a1a1c4e25c9d175458c604991fbb49033e507d9c1a15784e93303ea2ea";

        let test_out = "6407ee6fcbfadabf5ed2b9db1b58c4c1e0bda7f9231dedab1d873ade20fb3cf74924fce123f5374246e66c2c88122dcc51e7436c0a9ede83c3ae3c81356da0fb";
        let test_out_0 = "7f5ef8ea00ef3cb9efc86fe1e4ba6a29392df8831c994d33333f15900292251a41b9454027c103d10537b6ad17ac3651da9dc6204aad991e12ef6d23ca20d796";
        let test_out_1 = "0b5aa4ffbbdd8e3e6e354b25e8f83389e392849829a9b42a3a6c0a32e2795bb1819ed7cc1101b4d0e6c009f77c1c86feafe28ce35052a0abc2977b770a37776d";
        let test_out_2 = "62057763fb37e213b18d40ce7a479facbbfb16eadea0f67cb431aa36fc7a063a9f0da9b3898d2060ecb021723445c83f8778bde04dc5139cdd245ce8a786a8e3";
        let test_outws = "a0aa1b278807dd8cbed45a0a44a223578817d0c9c0482afd4a5df6809871db60d919d3cec5dc8491ed019ce6e30b81d9c6354a2a9f33a9520eefd7e7fef6a70b";
        let test_outws_0 = "a35ede4703a50ba6bdf3656e79a36ff1488ddcacfacfa0f0d10ac8f9248e0126fc9b81f66cd2e1f48caf12b0677cbcd22f1af0b4d976c4efd6ed4896a32ce466";
        let test_outws_1 = "a3226f567923ae123b0feed8e18297f08a755e8f5765144de541a8839dfaa03ca12563a5f6b1945114ac7bf5aea5f255619a3236207cc6db4a85e75ba16f3a2c";
        let test_outws_2 = "00a77e3aaf03e6630886ae55f0d6887733ef2f6b074dc99328eb349663b45e7cc02e9bbee12aef194aa8a5a1c0ac8ad128b629d3794f1cba8d674dd9c91669bc";

        let mut input_buf = CryptoBuffer::new(64);
        let mut salt_buf = CryptoBuffer::new(32);
        input_buf
            .write(|x| hex::decode_to_slice(test_input, x).unwrap())
            .unwrap();
        salt_buf
            .write(|x| hex::decode_to_slice(test_salt, x).unwrap())
            .unwrap();
        // input_buf
        //     .read(|x| println!("input: {}", hex::encode(x)))
        //     .unwrap();
        // salt_buf
        //     .read(|x| println!("salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, Some(&salt_buf), None).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, Some(&salt_buf), Some(0)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_0))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(0): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, Some(&salt_buf), Some(1)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_1))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(1): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, Some(&salt_buf), Some(2)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_out_2))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(2): {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, None, None).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out, without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, None, Some(0)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_0))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(0), without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, None, Some(1)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_1))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(1), without salt: {}", hex::encode(x)))
        //     .unwrap();

        let out_buf = derive(&input_buf, None, Some(2)).unwrap();
        out_buf
            .read(|x| assert_eq!(hex::encode(x), test_outws_2))
            .unwrap();
        // out_buf
        //     .read(|x| println!("out(2), without salt: {}", hex::encode(x)))
        //     .unwrap();
    }
}
