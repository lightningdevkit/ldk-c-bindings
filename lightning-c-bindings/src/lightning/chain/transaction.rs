// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Types describing on-chain transactions.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::chain::transaction::OutPoint as nativeOutPointImport;
pub(crate) type nativeOutPoint = nativeOutPointImport;

/// A reference to a transaction output.
///
/// Differs from bitcoin::blockdata::transaction::OutPoint as the index is a u16 instead of u32
/// due to LN's restrictions on index values. Should reduce (possibly) unsafe conversions this way.
#[must_use]
#[repr(C)]
pub struct OutPoint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOutPoint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OutPoint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOutPoint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OutPoint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OutPoint_free(this_obj: OutPoint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutPoint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOutPoint) };
}
#[allow(unused)]
impl OutPoint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOutPoint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOutPoint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOutPoint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The referenced transaction's txid.
#[no_mangle]
pub extern "C" fn OutPoint_get_txid(this_ptr: &OutPoint) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().txid;
	inner_val.as_ref()
}
/// The referenced transaction's txid.
#[no_mangle]
pub extern "C" fn OutPoint_set_txid(this_ptr: &mut OutPoint, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.txid = ::bitcoin::hash_types::Txid::from_slice(&val.data[..]).unwrap();
}
/// The index of the referenced output in its transaction's vout.
#[no_mangle]
pub extern "C" fn OutPoint_get_index(this_ptr: &OutPoint) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().index;
	*inner_val
}
/// The index of the referenced output in its transaction's vout.
#[no_mangle]
pub extern "C" fn OutPoint_set_index(this_ptr: &mut OutPoint, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.index = val;
}
/// Constructs a new OutPoint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OutPoint_new(mut txid_arg: crate::c_types::ThirtyTwoBytes, mut index_arg: u16) -> OutPoint {
	OutPoint { inner: ObjOps::heap_alloc(nativeOutPoint {
		txid: ::bitcoin::hash_types::Txid::from_slice(&txid_arg.data[..]).unwrap(),
		index: index_arg,
	}), is_owned: true }
}
impl Clone for OutPoint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOutPoint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OutPoint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOutPoint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OutPoint
pub extern "C" fn OutPoint_clone(orig: &OutPoint) -> OutPoint {
	orig.clone()
}
/// Checks if two OutPoints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn OutPoint_eq(a: &OutPoint, b: &OutPoint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Get a string which allows debug introspection of a OutPoint object
pub extern "C" fn OutPoint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::chain::transaction::OutPoint }).into()}
/// Generates a non-cryptographic 64-bit hash of the OutPoint.
#[no_mangle]
pub extern "C" fn OutPoint_hash(o: &OutPoint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Convert an `OutPoint` to a lightning channel id.
#[must_use]
#[no_mangle]
pub extern "C" fn OutPoint_to_channel_id(this_arg: &crate::lightning::chain::transaction::OutPoint) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_channel_id();
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}

#[no_mangle]
/// Serialize the OutPoint object into a byte array which can be read by OutPoint_read
pub extern "C" fn OutPoint_write(obj: &crate::lightning::chain::transaction::OutPoint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn OutPoint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOutPoint) })
}
#[no_mangle]
/// Read a OutPoint from a byte array, created by OutPoint_write
pub extern "C" fn OutPoint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_OutPointDecodeErrorZ {
	let res: Result<lightning::chain::transaction::OutPoint, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
