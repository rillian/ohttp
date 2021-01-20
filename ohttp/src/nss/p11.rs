// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::err::{secstatus_to_res, Error, Res};

use std::boxed::Box;
use std::convert::TryFrom;
use std::marker::PhantomData;
use std::mem;
use std::os::raw::{c_int, c_uint, c_void};
use std::pin::Pin;
use std::ptr::null_mut;

#[allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::pedantic
)]
pub mod sys {
    include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));
}

use sys::{
    PK11SlotInfo, PK11SymKey, PK11_ExtractKeyValue, PK11_FreeSlot, PK11_FreeSymKey,
    PK11_GenerateKeyPair, PK11_GenerateRandom, PK11_GetInternalSlot, PK11_GetKeyData,
    PK11_ReferenceSymKey, PRBool, SECITEM_FreeItem, SECItem, SECItemType, SECKEYPrivateKey,
    SECKEYPublicKey, SECKEY_DestroyPrivateKey, SECKEY_DestroyPublicKey, SECOID_FindOIDByTag,
    SECOidTag, CKM_EC_KEY_PAIR_GEN, CK_MECHANISM_TYPE, SEC_ASN1_OBJECT_ID,
};

macro_rules! scoped_ptr {
    ($scoped:ident, $target:ty, $dtor:path) => {
        pub struct $scoped {
            ptr: *mut $target,
        }

        impl $scoped {
            pub fn from_ptr(ptr: *mut $target) -> Result<Self, crate::nss::err::Error> {
                if ptr.is_null() {
                    Err(crate::nss::err::Error::last())
                } else {
                    Ok(Self { ptr })
                }
            }
        }

        impl std::ops::Deref for $scoped {
            type Target = *mut $target;
            #[must_use]
            fn deref(&self) -> &*mut $target {
                &self.ptr
            }
        }

        impl std::ops::DerefMut for $scoped {
            fn deref_mut(&mut self) -> &mut *mut $target {
                &mut self.ptr
            }
        }

        impl Drop for $scoped {
            fn drop(&mut self) {
                let _ = unsafe { $dtor(self.ptr) };
            }
        }
    };
}

scoped_ptr!(PrivateKey, SECKEYPrivateKey, SECKEY_DestroyPrivateKey);
scoped_ptr!(PublicKey, SECKEYPublicKey, SECKEY_DestroyPublicKey);
scoped_ptr!(Slot, PK11SlotInfo, PK11_FreeSlot);

impl Slot {
    pub(crate) fn internal() -> Res<Self> {
        let p = unsafe { PK11_GetInternalSlot() };
        Slot::from_ptr(p)
    }
}

scoped_ptr!(SymKey, PK11SymKey, PK11_FreeSymKey);

impl SymKey {
    /// You really don't want to use this.
    ///
    /// # Errors
    /// Some keys cannot be inspected in this way.
    /// Also, internal errors in case of failures in NSS.
    pub fn key_data<'a>(&'a self) -> Res<&'a [u8]> {
        secstatus_to_res(unsafe { PK11_ExtractKeyValue(self.ptr) })?;

        let key_item = unsafe { PK11_GetKeyData(self.ptr) };
        // This is accessing a value attached to the key, so we can treat this as a borrow.
        match unsafe { key_item.as_mut() } {
            None => Err(Error::last()),
            Some(key) => Ok(unsafe { std::slice::from_raw_parts(key.data, key.len as usize) }),
        }
    }
}

impl Clone for SymKey {
    #[must_use]
    fn clone(&self) -> Self {
        let ptr = unsafe { PK11_ReferenceSymKey(self.ptr) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "SymKey {}", crate::hex::hex(b))
        } else {
            write!(f, "Opaque SymKey")
        }
    }
}

/// Generate a randomized buffer.
#[must_use]
pub fn random(size: usize) -> Vec<u8> {
    let mut buf = vec![0; size];
    secstatus_to_res(unsafe {
        PK11_GenerateRandom(buf.as_mut_ptr(), c_int::try_from(buf.len()).unwrap())
    })
    .unwrap();
    buf
}

pub(crate) struct ParamItem<T> {
    reference: Pin<Box<SECItem>>,
    params: Vec<u8>,
    marker: PhantomData<T>,
}

impl<T: Sized> ParamItem<T> {
    pub fn new(v: &T) -> Self {
        let slc =
            unsafe { std::slice::from_raw_parts(v as *const T as *const u8, mem::size_of::<T>()) };
        let mut params = Vec::from(slc);
        let reference = Box::pin(SECItem {
            type_: SECItemType::siBuffer,
            data: params.as_mut_ptr() as *mut T as *mut u8,
            len: c_uint::try_from(params.len()).unwrap(),
        });
        Self {
            reference,
            params,
            marker: PhantomData::default(),
        }
    }

    pub fn ptr(&mut self) -> *mut SECItem {
        Pin::into_inner(self.reference.as_mut()) as *mut SECItem
    }
}

unsafe fn destroy_secitem(item: *mut SECItem) {
    SECITEM_FreeItem(item, PRBool::from(true));
}
scoped_ptr!(Item, SECItem, destroy_secitem);

impl Item {
    /// Create a wrapper for a slice of this object.
    /// Creating this object is technically safe, but using it is extremely dangerous.
    /// Minimally, it can only be passed as a `const SECItem*` argument to functions.
    pub(crate) fn wrap(buf: &[u8]) -> SECItem {
        SECItem {
            type_: SECItemType::siBuffer,
            data: buf.as_ptr() as *mut u8,
            len: c_uint::try_from(buf.len()).unwrap(),
        }
    }

    /// This dereferences the pointer held by the item and makes a copy of the
    /// content that is referenced there.
    ///
    /// # Safety
    /// This dereferences two pointers.  It doesn't get much less safe.
    pub(crate) unsafe fn into_vec(self) -> Vec<u8> {
        let b = self.ptr.as_ref().unwrap();
        // Sanity check the type, as some types don't count bytes in `Item::len`.
        assert_eq!(b.type_, SECItemType::siBuffer);
        let slc = std::slice::from_raw_parts(b.data, usize::try_from(b.len).unwrap());
        Vec::from(slc)
    }
}

/// Generates an X25519 key pair.
/// This might need to be more flexible in future, but this will do for now.
pub fn generate_key_pair() -> Res<(PrivateKey, PublicKey)> {
    let slot = Slot::internal()?;

    let oid_data = unsafe { SECOID_FindOIDByTag(SECOidTag::SEC_OID_CURVE25519) };
    let oid = unsafe { oid_data.as_ref() }.ok_or_else(Error::internal)?;
    let oid_slc =
        unsafe { std::slice::from_raw_parts(oid.oid.data, usize::try_from(oid.oid.len).unwrap()) };
    let mut params: Vec<u8> = Vec::with_capacity(oid_slc.len() + 2);
    params.push(u8::try_from(SEC_ASN1_OBJECT_ID).unwrap());
    params.push(u8::try_from(oid.oid.len).unwrap());
    params.extend_from_slice(oid_slc);

    let mut pk: *mut SECKEYPublicKey = null_mut();
    let sk = unsafe {
        PK11_GenerateKeyPair(
            *slot,
            CK_MECHANISM_TYPE::from(CKM_EC_KEY_PAIR_GEN),
            &mut Item::wrap(&params) as *mut _ as *mut c_void,
            &mut pk,
            PRBool::from(false),
            PRBool::from(true),
            null_mut(),
        )
    };
    Ok((PrivateKey::from_ptr(sk)?, PublicKey::from_ptr(pk)?))
}

#[cfg(test)]
mod test {
    use super::super::init;
    use super::{generate_key_pair, random};

    #[test]
    fn randomness() {
        init();
        // If this ever fails, there is either a bug, or it's time to buy a lottery ticket.
        assert_ne!(random(16), random(16));
    }

    #[test]
    fn keypair() {
        init();
        generate_key_pair().unwrap();
    }
}
