pub mod buffers;
pub mod consts;
pub mod kdf;
pub mod rng;

#[derive(thiserror::Error, Debug)]
pub enum InitError {
    #[error("Sodium Library Initialization Error.")]
    SodiumInitError,
}

pub fn ensure_init() -> Result<(), InitError> {
    libsodium_rs::ensure_init().map_err(|_e| InitError::SodiumInitError)?;
    Ok(())
}
