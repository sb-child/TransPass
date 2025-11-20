use crate::crypto::buffers;

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("Buffer Operation Error: {0}")]
    BufferOperationError(#[from] buffers::OperationError),
}

pub fn local_random(buf: &mut buffers::CryptoBuffer) -> Result<(), OperationError> {
    buf.private_modify(|v| {
        libsodium_rs::random::fill_bytes(v);
    })?;
    Ok(())
}
