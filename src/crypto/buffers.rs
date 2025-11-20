use secrets::SecretVec;
use zeroize::ZeroizeOnDrop;

#[derive(Default, Clone, ZeroizeOnDrop, PartialEq)]
pub enum Permission {
    #[default]
    /// Public: RW, Private: RW
    ReadWrite,
    /// Public: R-, Private: RW
    ReadOnly,
    /// Public: -W, Private: RW
    WriteOnly,
    /// Public: --, Private: RW
    Refused,
    /// Public: --, Private: R-
    PrivateReadOnly,
    /// Public: --, Private: -W
    PrivateWriteOnly,
    /// Public: --, Private: --
    PrivateRefused,
}

impl Permission {
    pub fn readable(&self, private: bool) -> bool {
        match self {
            Permission::ReadWrite => true,
            Permission::ReadOnly => !private,
            Permission::WriteOnly => private,
            Permission::Refused => false,
            Permission::PrivateReadOnly => private,
            Permission::PrivateWriteOnly => false,
            Permission::PrivateRefused => false,
        }
    }

    pub fn writeable(&self, private: bool) -> bool {
        match self {
            Permission::ReadWrite => true,
            Permission::ReadOnly => private,
            Permission::WriteOnly => !private,
            Permission::Refused => private,
            Permission::PrivateReadOnly => false,
            Permission::PrivateWriteOnly => private,
            Permission::PrivateRefused => false,
        }
    }

    pub fn readwriteable(&self, private: bool) -> bool {
        self.readable(private) && self.writeable(private)
    }

    pub fn set(&mut self, perm: Permission) {
        *self = perm;
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub enum PermLock {
    Unlocked(Permission),
    Locked(Permission),
}

impl Default for PermLock {
    fn default() -> Self {
        PermLock::Unlocked(Permission::default())
    }
}

impl PermLock {
    pub fn lock(&mut self) -> Option<()> {
        match self {
            PermLock::Unlocked(permission) => {
                *self = PermLock::Locked(permission.clone());
                Some(())
            }
            PermLock::Locked(_) => None,
        }
    }

    pub fn get_permission(&self) -> Permission {
        match self {
            PermLock::Unlocked(permission) => permission,
            PermLock::Locked(permission) => permission,
        }
        .clone()
    }

    pub fn set_permission(&mut self, perm: Permission) -> Option<()> {
        match self {
            PermLock::Unlocked(_) => {
                *self = PermLock::Locked(perm);
                Some(())
            }
            PermLock::Locked(_) => None,
        }
    }

    pub fn locked(&self) -> bool {
        match self {
            PermLock::Unlocked(_) => false,
            PermLock::Locked(_) => true,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum OperationError {
    #[error("Buffer size is not equal.")]
    UnevenBufferSize,

    #[error("This buffer is empty.")]
    EmptyBuffer,

    #[error("Permission denied.")]
    PermissionDenied,
}

pub struct CryptoBuffer {
    inner: SecretVec<u8>,
    permlock: PermLock,
}

impl From<SecretVec<u8>> for CryptoBuffer {
    fn from(value: SecretVec<u8>) -> Self {
        Self {
            inner: value,
            permlock: PermLock::default(),
        }
    }
}

impl From<Vec<u8>> for CryptoBuffer {
    fn from(value: Vec<u8>) -> Self {
        let mut sv = SecretVec::zero(value.len());
        sv.borrow_mut().copy_from_slice(&value);
        Self {
            inner: sv,
            permlock: PermLock::default(),
        }
    }
}

impl CryptoBuffer {
    pub fn new(size: usize) -> Self {
        let v = SecretVec::zero(size);
        Self {
            inner: v,
            permlock: PermLock::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn _readable(&self, private: bool) -> bool {
        self.permlock.get_permission().readable(private)
    }

    fn _writeable(&self, private: bool) -> bool {
        self.permlock.get_permission().writeable(private)
    }

    fn _readwriteable(&self, private: bool) -> bool {
        self.permlock.get_permission().readwriteable(private)
    }

    fn _copy_from_slice(&mut self, buf: &[u8], private: bool) -> Result<(), OperationError> {
        if !self.permlock.get_permission().writeable(private) {
            return Err(OperationError::PermissionDenied);
        };
        if buf.len() == 0 || self.len() == 0 {
            return Err(OperationError::EmptyBuffer);
        }
        if self.len() != buf.len() {
            return Err(OperationError::UnevenBufferSize);
        }
        let mut v = self.inner.borrow_mut();
        v.copy_from_slice(buf);
        Ok(())
    }

    fn _copy_to_slice(&mut self, buf: &mut [u8], private: bool) -> Result<(), OperationError> {
        if !self.permlock.get_permission().readable(private) {
            return Err(OperationError::PermissionDenied);
        };
        if buf.len() == 0 || self.len() == 0 {
            return Err(OperationError::EmptyBuffer);
        }
        if self.len() != buf.len() {
            return Err(OperationError::UnevenBufferSize);
        }
        let v = self.inner.borrow();
        buf.copy_from_slice(&v);
        drop(v);
        Ok(())
    }

    fn _modify<R>(
        &mut self,
        mut f: impl FnMut(&mut [u8]) -> R,
        private: bool,
    ) -> Result<R, OperationError> {
        if !self.permlock.get_permission().readwriteable(private) {
            return Err(OperationError::PermissionDenied);
        };
        if self.len() == 0 {
            return Err(OperationError::EmptyBuffer);
        }
        let mut v = self.inner.borrow_mut();
        Ok(f(&mut v))
    }

    fn _read<R>(&self, mut f: impl FnMut(&[u8]) -> R, private: bool) -> Result<R, OperationError> {
        if !self.permlock.get_permission().readable(private) {
            return Err(OperationError::PermissionDenied);
        };
        if self.len() == 0 {
            return Err(OperationError::EmptyBuffer);
        }
        let v = self.inner.borrow();
        Ok(f(&v))
    }

    fn _write<R>(
        &mut self,
        mut f: impl FnMut(&mut [u8]) -> R,
        private: bool,
    ) -> Result<R, OperationError> {
        if !self.permlock.get_permission().writeable(private) {
            return Err(OperationError::PermissionDenied);
        };
        if self.len() == 0 {
            return Err(OperationError::EmptyBuffer);
        }
        let mut v = SecretVec::zero(self.len());
        let mut vp = v.borrow_mut();
        let r = f(&mut vp);
        drop(vp);
        let vr = v.borrow();
        let mut vp = self.inner.borrow_mut();
        vp.copy_from_slice(&vr);
        Ok(r)
    }

    pub fn copy_from_slice(&mut self, buf: &[u8]) -> Result<(), OperationError> {
        self._copy_from_slice(buf, false)
    }

    pub fn copy_to_slice(&mut self, buf: &mut [u8]) -> Result<(), OperationError> {
        self._copy_to_slice(buf, false)
    }

    pub fn modify<R>(&mut self, f: impl FnMut(&mut [u8]) -> R) -> Result<R, OperationError> {
        self._modify(f, false)
    }

    pub fn read<R>(&self, f: impl FnMut(&[u8]) -> R) -> Result<R, OperationError> {
        self._read(f, false)
    }

    pub fn write<R>(&mut self, f: impl FnMut(&mut [u8]) -> R) -> Result<R, OperationError> {
        self._write(f, false)
    }

    pub fn readable(&self) -> bool {
        self._readable(false)
    }

    pub fn writeable(&self) -> bool {
        self._writeable(false)
    }

    pub fn readwriteable(&self) -> bool {
        self._readwriteable(false)
    }

    pub(crate) fn private_copy_from_slice(&mut self, buf: &[u8]) -> Result<(), OperationError> {
        self._copy_from_slice(buf, true)
    }

    pub(crate) fn private_copy_to_slice(&mut self, buf: &mut [u8]) -> Result<(), OperationError> {
        self._copy_to_slice(buf, true)
    }

    pub(crate) fn private_modify<R>(
        &mut self,
        f: impl FnMut(&mut [u8]) -> R,
    ) -> Result<R, OperationError> {
        self._modify(f, true)
    }

    pub(crate) fn private_read<R>(&self, f: impl FnMut(&[u8]) -> R) -> Result<R, OperationError> {
        self._read(f, true)
    }

    pub(crate) fn private_write<R>(
        &mut self,
        f: impl FnMut(&mut [u8]) -> R,
    ) -> Result<R, OperationError> {
        self._write(f, true)
    }

    pub(crate) fn private_readable(&self) -> bool {
        self._readable(true)
    }

    pub(crate) fn private_writeable(&self) -> bool {
        self._writeable(true)
    }

    pub(crate) fn private_readwriteable(&self) -> bool {
        self._readwriteable(true)
    }
}
