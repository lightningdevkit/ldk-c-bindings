// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Tagged hashes for use in signature calculation and verification.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::merkle::TaggedHash as nativeTaggedHashImport;
pub(crate) type nativeTaggedHash = nativeTaggedHashImport;

/// A hash for use in a specific context by tweaking with a context-dependent tag as per [BIP 340]
/// and computed over the merkle root of a TLV stream to sign as defined in [BOLT 12].
///
/// [BIP 340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
/// [BOLT 12]: https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md#signature-calculation
#[must_use]
#[repr(C)]
pub struct TaggedHash {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTaggedHash,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for TaggedHash {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTaggedHash>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TaggedHash, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TaggedHash_free(this_obj: TaggedHash) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TaggedHash_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTaggedHash) };
}
#[allow(unused)]
impl TaggedHash {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTaggedHash {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTaggedHash {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTaggedHash {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for TaggedHash {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeTaggedHash>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TaggedHash_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeTaggedHash)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the TaggedHash
pub extern "C" fn TaggedHash_clone(orig: &TaggedHash) -> TaggedHash {
	orig.clone()
}
/// Get a string which allows debug introspection of a TaggedHash object
pub extern "C" fn TaggedHash_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::merkle::TaggedHash }).into()}
/// Returns the digest to sign.
#[must_use]
#[no_mangle]
pub extern "C" fn TaggedHash_as_digest(this_arg: &crate::lightning::offers::merkle::TaggedHash) -> *const [u8; 32] {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_digest();
	ret.as_ref()
}

/// Returns the tag used in the tagged hash.
#[must_use]
#[no_mangle]
pub extern "C" fn TaggedHash_tag(this_arg: &crate::lightning::offers::merkle::TaggedHash) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tag();
	ret.into()
}

/// Returns the merkle root used in the tagged hash.
#[must_use]
#[no_mangle]
pub extern "C" fn TaggedHash_merkle_root(this_arg: &crate::lightning::offers::merkle::TaggedHash) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.merkle_root();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

