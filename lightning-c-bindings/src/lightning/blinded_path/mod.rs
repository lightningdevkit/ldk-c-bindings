// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Creating blinded paths and related utilities live here.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod payment;
mod message {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod utils {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning::blinded_path::BlindedPath as nativeBlindedPathImport;
pub(crate) type nativeBlindedPath = nativeBlindedPathImport;

/// Onion messages and payments can be sent and received to blinded paths, which serve to hide the
/// identity of the recipient.
#[must_use]
#[repr(C)]
pub struct BlindedPath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedPath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPath_free(this_obj: BlindedPath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPath) };
}
#[allow(unused)]
impl BlindedPath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// To send to a blinded path, the sender first finds a route to the unblinded
/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
/// message or payment's next hop and forward it along.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_get_introduction_node_id(this_ptr: &BlindedPath) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().introduction_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// To send to a blinded path, the sender first finds a route to the unblinded
/// `introduction_node_id`, which can unblind its [`encrypted_payload`] to find out the onion
/// message or payment's next hop and forward it along.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_set_introduction_node_id(this_ptr: &mut BlindedPath, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.introduction_node_id = val.into_rust();
}
/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
/// message or payment.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_get_blinding_point(this_ptr: &BlindedPath) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinding_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Used by the introduction node to decrypt its [`encrypted_payload`] to forward the onion
/// message or payment.
///
/// [`encrypted_payload`]: BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn BlindedPath_set_blinding_point(this_ptr: &mut BlindedPath, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinding_point = val.into_rust();
}
/// The hops composing the blinded path.
#[no_mangle]
pub extern "C" fn BlindedPath_get_blinded_hops(this_ptr: &BlindedPath) -> crate::c_types::derived::CVec_BlindedHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinded_hops;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::blinded_path::BlindedHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::blinded_path::BlindedHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The hops composing the blinded path.
#[no_mangle]
pub extern "C" fn BlindedPath_set_blinded_hops(this_ptr: &mut BlindedPath, mut val: crate::c_types::derived::CVec_BlindedHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinded_hops = local_val;
}
/// Constructs a new BlindedPath given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_new(mut introduction_node_id_arg: crate::c_types::PublicKey, mut blinding_point_arg: crate::c_types::PublicKey, mut blinded_hops_arg: crate::c_types::derived::CVec_BlindedHopZ) -> BlindedPath {
	let mut local_blinded_hops_arg = Vec::new(); for mut item in blinded_hops_arg.into_rust().drain(..) { local_blinded_hops_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	BlindedPath { inner: ObjOps::heap_alloc(nativeBlindedPath {
		introduction_node_id: introduction_node_id_arg.into_rust(),
		blinding_point: blinding_point_arg.into_rust(),
		blinded_hops: local_blinded_hops_arg,
	}), is_owned: true }
}
impl Clone for BlindedPath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBlindedPath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPath
pub extern "C" fn BlindedPath_clone(orig: &BlindedPath) -> BlindedPath {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the BlindedPath.
#[no_mangle]
pub extern "C" fn BlindedPath_hash(o: &BlindedPath) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedPaths contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedPath_eq(a: &BlindedPath, b: &BlindedPath) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::blinded_path::BlindedHop as nativeBlindedHopImport;
pub(crate) type nativeBlindedHop = nativeBlindedHopImport;

/// An encrypted payload and node id corresponding to a hop in a payment or onion message path, to
/// be encoded in the sender's onion packet. These hops cannot be identified by outside observers
/// and thus can be used to hide the identity of the recipient.
#[must_use]
#[repr(C)]
pub struct BlindedHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedHop_free(this_obj: BlindedHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedHop) };
}
#[allow(unused)]
impl BlindedHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The blinded node id of this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_get_blinded_node_id(this_ptr: &BlindedHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinded_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The blinded node id of this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_set_blinded_node_id(this_ptr: &mut BlindedHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinded_node_id = val.into_rust();
}
/// The encrypted payload intended for this hop in a [`BlindedPath`].
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn BlindedHop_get_encrypted_payload(this_ptr: &BlindedHop) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = this_ptr.get_native_mut_ref().encrypted_payload.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// The encrypted payload intended for this hop in a [`BlindedPath`].
#[no_mangle]
pub extern "C" fn BlindedHop_set_encrypted_payload(this_ptr: &mut BlindedHop, mut val: crate::c_types::derived::CVec_u8Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.encrypted_payload = local_val;
}
/// Constructs a new BlindedHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHop_new(mut blinded_node_id_arg: crate::c_types::PublicKey, mut encrypted_payload_arg: crate::c_types::derived::CVec_u8Z) -> BlindedHop {
	let mut local_encrypted_payload_arg = Vec::new(); for mut item in encrypted_payload_arg.into_rust().drain(..) { local_encrypted_payload_arg.push( { item }); };
	BlindedHop { inner: ObjOps::heap_alloc(nativeBlindedHop {
		blinded_node_id: blinded_node_id_arg.into_rust(),
		encrypted_payload: local_encrypted_payload_arg,
	}), is_owned: true }
}
impl Clone for BlindedHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedHop>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBlindedHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedHop
pub extern "C" fn BlindedHop_clone(orig: &BlindedHop) -> BlindedHop {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the BlindedHop.
#[no_mangle]
pub extern "C" fn BlindedHop_hash(o: &BlindedHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedHop_eq(a: &BlindedHop, b: &BlindedHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Create a blinded path for an onion message, to be forwarded along `node_pks`. The last node
/// pubkey in `node_pks` will be the destination node.
///
/// Errors if less than two hops are provided or if `node_pk`(s) are invalid.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_new_for_message(mut node_pks: crate::c_types::derived::CVec_PublicKeyZ, entropy_source: &crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_BlindedPathNoneZ {
	let mut local_node_pks = Vec::new(); for mut item in node_pks.into_rust().drain(..) { local_node_pks.push( { item.into_rust() }); };
	let mut ret = lightning::blinded_path::BlindedPath::new_for_message(&local_node_pks[..], entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a one-hop blinded path for a payment.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPath_one_hop_for_payment(mut payee_node_id: crate::c_types::PublicKey, mut payee_tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, entropy_source: &crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_C2Tuple_BlindedPayInfoBlindedPathZNoneZ {
	let mut ret = lightning::blinded_path::BlindedPath::one_hop_for_payment(payee_node_id.into_rust(), *unsafe { Box::from_raw(payee_tlvs.take_inner()) }, entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

#[no_mangle]
/// Serialize the BlindedPath object into a byte array which can be read by BlindedPath_read
pub extern "C" fn BlindedPath_write(obj: &crate::lightning::blinded_path::BlindedPath) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn BlindedPath_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedPath) })
}
#[no_mangle]
/// Read a BlindedPath from a byte array, created by BlindedPath_write
pub extern "C" fn BlindedPath_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedPathDecodeErrorZ {
	let res: Result<lightning::blinded_path::BlindedPath, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the BlindedHop object into a byte array which can be read by BlindedHop_read
pub extern "C" fn BlindedHop_write(obj: &crate::lightning::blinded_path::BlindedHop) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn BlindedHop_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedHop) })
}
#[no_mangle]
/// Read a BlindedHop from a byte array, created by BlindedHop_write
pub extern "C" fn BlindedHop_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedHopDecodeErrorZ {
	let res: Result<lightning::blinded_path::BlindedHop, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::BlindedHop { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
