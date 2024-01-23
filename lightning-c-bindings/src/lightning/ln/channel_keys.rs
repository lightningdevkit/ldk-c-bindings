// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Keys used to generate commitment transactions.
//! See: <https://github.com/lightning/bolts/blob/master/03-transactions.md#keys>

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::channel_keys::DelayedPaymentBasepoint as nativeDelayedPaymentBasepointImport;
pub(crate) type nativeDelayedPaymentBasepoint = nativeDelayedPaymentBasepointImport;

/// Base key used in conjunction with a `per_commitment_point` to generate a [`DelayedPaymentKey`].
///
/// The delayed payment key is used to pay the commitment state broadcaster their
/// non-HTLC-encumbered funds after a delay to give their counterparty a chance to punish if the
/// state broadcasted was previously revoked.
#[must_use]
#[repr(C)]
pub struct DelayedPaymentBasepoint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDelayedPaymentBasepoint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DelayedPaymentBasepoint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDelayedPaymentBasepoint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DelayedPaymentBasepoint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_free(this_obj: DelayedPaymentBasepoint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentBasepoint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDelayedPaymentBasepoint) };
}
#[allow(unused)]
impl DelayedPaymentBasepoint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDelayedPaymentBasepoint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDelayedPaymentBasepoint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDelayedPaymentBasepoint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_get_a(this_ptr: &DelayedPaymentBasepoint) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_set_a(this_ptr: &mut DelayedPaymentBasepoint, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new DelayedPaymentBasepoint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_new(mut a_arg: crate::c_types::PublicKey) -> DelayedPaymentBasepoint {
	DelayedPaymentBasepoint { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::DelayedPaymentBasepoint (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two DelayedPaymentBasepoints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_eq(a: &DelayedPaymentBasepoint, b: &DelayedPaymentBasepoint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for DelayedPaymentBasepoint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDelayedPaymentBasepoint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentBasepoint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeDelayedPaymentBasepoint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DelayedPaymentBasepoint
pub extern "C" fn DelayedPaymentBasepoint_clone(orig: &DelayedPaymentBasepoint) -> DelayedPaymentBasepoint {
	orig.clone()
}
/// Get a string which allows debug introspection of a DelayedPaymentBasepoint object
pub extern "C" fn DelayedPaymentBasepoint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::DelayedPaymentBasepoint }).into()}
/// Generates a non-cryptographic 64-bit hash of the DelayedPaymentBasepoint.
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_hash(o: &DelayedPaymentBasepoint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentBasepoint_to_public_key(this_arg: &crate::lightning::ln::channel_keys::DelayedPaymentBasepoint) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the DelayedPaymentBasepoint object into a byte array which can be read by DelayedPaymentBasepoint_read
pub extern "C" fn DelayedPaymentBasepoint_write(obj: &crate::lightning::ln::channel_keys::DelayedPaymentBasepoint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn DelayedPaymentBasepoint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeDelayedPaymentBasepoint) })
}
#[no_mangle]
/// Read a DelayedPaymentBasepoint from a byte array, created by DelayedPaymentBasepoint_write
pub extern "C" fn DelayedPaymentBasepoint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_DelayedPaymentBasepointDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::DelayedPaymentBasepoint, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::DelayedPaymentBasepoint { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_keys::DelayedPaymentKey as nativeDelayedPaymentKeyImport;
pub(crate) type nativeDelayedPaymentKey = nativeDelayedPaymentKeyImport;

/// A derived key built from a [`DelayedPaymentBasepoint`] and `per_commitment_point`.
///
/// The delayed payment key is used to pay the commitment state broadcaster their
/// non-HTLC-encumbered funds after a delay. This delay gives their counterparty a chance to
/// punish and claim all the channel funds if the state broadcasted was previously revoked.
///
/// [See the BOLT specs]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation)
/// for more information on key derivation details.
#[must_use]
#[repr(C)]
pub struct DelayedPaymentKey {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDelayedPaymentKey,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DelayedPaymentKey {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDelayedPaymentKey>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DelayedPaymentKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_free(this_obj: DelayedPaymentKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentKey_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDelayedPaymentKey) };
}
#[allow(unused)]
impl DelayedPaymentKey {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDelayedPaymentKey {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDelayedPaymentKey {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDelayedPaymentKey {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_get_a(this_ptr: &DelayedPaymentKey) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_set_a(this_ptr: &mut DelayedPaymentKey, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new DelayedPaymentKey given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_new(mut a_arg: crate::c_types::PublicKey) -> DelayedPaymentKey {
	DelayedPaymentKey { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::DelayedPaymentKey (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two DelayedPaymentKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_eq(a: &DelayedPaymentKey, b: &DelayedPaymentKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for DelayedPaymentKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDelayedPaymentKey>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentKey_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeDelayedPaymentKey)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DelayedPaymentKey
pub extern "C" fn DelayedPaymentKey_clone(orig: &DelayedPaymentKey) -> DelayedPaymentKey {
	orig.clone()
}
/// Get a string which allows debug introspection of a DelayedPaymentKey object
pub extern "C" fn DelayedPaymentKey_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::DelayedPaymentKey }).into()}
///Derive a public delayedpubkey using one node\'s `per_commitment_point` and its countersignatory\'s `basepoint`
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_from_basepoint(countersignatory_basepoint: &crate::lightning::ln::channel_keys::DelayedPaymentBasepoint, mut per_commitment_point: crate::c_types::PublicKey) -> crate::lightning::ln::channel_keys::DelayedPaymentKey {
	let mut ret = lightning::ln::channel_keys::DelayedPaymentKey::from_basepoint(secp256k1::global::SECP256K1, countersignatory_basepoint.get_native_ref(), &per_commitment_point.into_rust());
	crate::lightning::ln::channel_keys::DelayedPaymentKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

///Build a delayedpubkey directly from an already-derived private key
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_from_secret_key(sk: *const [u8; 32]) -> crate::lightning::ln::channel_keys::DelayedPaymentKey {
	let mut ret = lightning::ln::channel_keys::DelayedPaymentKey::from_secret_key(secp256k1::global::SECP256K1, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *sk}[..]).unwrap());
	crate::lightning::ln::channel_keys::DelayedPaymentKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentKey_to_public_key(this_arg: &crate::lightning::ln::channel_keys::DelayedPaymentKey) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the DelayedPaymentKey object into a byte array which can be read by DelayedPaymentKey_read
pub extern "C" fn DelayedPaymentKey_write(obj: &crate::lightning::ln::channel_keys::DelayedPaymentKey) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn DelayedPaymentKey_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeDelayedPaymentKey) })
}
#[no_mangle]
/// Read a DelayedPaymentKey from a byte array, created by DelayedPaymentKey_write
pub extern "C" fn DelayedPaymentKey_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_DelayedPaymentKeyDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::DelayedPaymentKey, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::DelayedPaymentKey { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_keys::HtlcBasepoint as nativeHtlcBasepointImport;
pub(crate) type nativeHtlcBasepoint = nativeHtlcBasepointImport;

/// Base key used in conjunction with a `per_commitment_point` to generate an [`HtlcKey`].
///
/// HTLC keys are used to ensure only the recipient of an HTLC can claim it on-chain with the HTLC
/// preimage and that only the sender of an HTLC can claim it on-chain after it has timed out.
/// Thus, both channel counterparties' HTLC keys will appears in each HTLC output's script.
#[must_use]
#[repr(C)]
pub struct HtlcBasepoint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHtlcBasepoint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for HtlcBasepoint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHtlcBasepoint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HtlcBasepoint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HtlcBasepoint_free(this_obj: HtlcBasepoint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HtlcBasepoint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHtlcBasepoint) };
}
#[allow(unused)]
impl HtlcBasepoint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHtlcBasepoint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHtlcBasepoint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHtlcBasepoint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn HtlcBasepoint_get_a(this_ptr: &HtlcBasepoint) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn HtlcBasepoint_set_a(this_ptr: &mut HtlcBasepoint, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new HtlcBasepoint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcBasepoint_new(mut a_arg: crate::c_types::PublicKey) -> HtlcBasepoint {
	HtlcBasepoint { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::HtlcBasepoint (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two HtlcBasepoints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn HtlcBasepoint_eq(a: &HtlcBasepoint, b: &HtlcBasepoint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for HtlcBasepoint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHtlcBasepoint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HtlcBasepoint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeHtlcBasepoint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HtlcBasepoint
pub extern "C" fn HtlcBasepoint_clone(orig: &HtlcBasepoint) -> HtlcBasepoint {
	orig.clone()
}
/// Get a string which allows debug introspection of a HtlcBasepoint object
pub extern "C" fn HtlcBasepoint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::HtlcBasepoint }).into()}
/// Generates a non-cryptographic 64-bit hash of the HtlcBasepoint.
#[no_mangle]
pub extern "C" fn HtlcBasepoint_hash(o: &HtlcBasepoint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcBasepoint_to_public_key(this_arg: &crate::lightning::ln::channel_keys::HtlcBasepoint) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the HtlcBasepoint object into a byte array which can be read by HtlcBasepoint_read
pub extern "C" fn HtlcBasepoint_write(obj: &crate::lightning::ln::channel_keys::HtlcBasepoint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn HtlcBasepoint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHtlcBasepoint) })
}
#[no_mangle]
/// Read a HtlcBasepoint from a byte array, created by HtlcBasepoint_write
pub extern "C" fn HtlcBasepoint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HtlcBasepointDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::HtlcBasepoint, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::HtlcBasepoint { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_keys::HtlcKey as nativeHtlcKeyImport;
pub(crate) type nativeHtlcKey = nativeHtlcKeyImport;

/// A derived key built from a [`HtlcBasepoint`] and `per_commitment_point`.
///
/// HTLC keys are used to ensure only the recipient of an HTLC can claim it on-chain with the HTLC
/// preimage and that only the sender of an HTLC can claim it on-chain after it has timed out.
/// Thus, both channel counterparties' HTLC keys will appears in each HTLC output's script.
///
/// [See the BOLT specs]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#localpubkey-local_htlcpubkey-remote_htlcpubkey-local_delayedpubkey-and-remote_delayedpubkey-derivation)
/// for more information on key derivation details.
#[must_use]
#[repr(C)]
pub struct HtlcKey {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHtlcKey,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for HtlcKey {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHtlcKey>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HtlcKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HtlcKey_free(this_obj: HtlcKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HtlcKey_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHtlcKey) };
}
#[allow(unused)]
impl HtlcKey {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHtlcKey {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHtlcKey {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHtlcKey {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn HtlcKey_get_a(this_ptr: &HtlcKey) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn HtlcKey_set_a(this_ptr: &mut HtlcKey, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new HtlcKey given each field
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcKey_new(mut a_arg: crate::c_types::PublicKey) -> HtlcKey {
	HtlcKey { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::HtlcKey (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two HtlcKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn HtlcKey_eq(a: &HtlcKey, b: &HtlcKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for HtlcKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHtlcKey>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HtlcKey_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeHtlcKey)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HtlcKey
pub extern "C" fn HtlcKey_clone(orig: &HtlcKey) -> HtlcKey {
	orig.clone()
}
/// Get a string which allows debug introspection of a HtlcKey object
pub extern "C" fn HtlcKey_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::HtlcKey }).into()}
///Derive a public htlcpubkey using one node\'s `per_commitment_point` and its countersignatory\'s `basepoint`
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcKey_from_basepoint(countersignatory_basepoint: &crate::lightning::ln::channel_keys::HtlcBasepoint, mut per_commitment_point: crate::c_types::PublicKey) -> crate::lightning::ln::channel_keys::HtlcKey {
	let mut ret = lightning::ln::channel_keys::HtlcKey::from_basepoint(secp256k1::global::SECP256K1, countersignatory_basepoint.get_native_ref(), &per_commitment_point.into_rust());
	crate::lightning::ln::channel_keys::HtlcKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

///Build a htlcpubkey directly from an already-derived private key
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcKey_from_secret_key(sk: *const [u8; 32]) -> crate::lightning::ln::channel_keys::HtlcKey {
	let mut ret = lightning::ln::channel_keys::HtlcKey::from_secret_key(secp256k1::global::SECP256K1, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *sk}[..]).unwrap());
	crate::lightning::ln::channel_keys::HtlcKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn HtlcKey_to_public_key(this_arg: &crate::lightning::ln::channel_keys::HtlcKey) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the HtlcKey object into a byte array which can be read by HtlcKey_read
pub extern "C" fn HtlcKey_write(obj: &crate::lightning::ln::channel_keys::HtlcKey) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn HtlcKey_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHtlcKey) })
}
#[no_mangle]
/// Read a HtlcKey from a byte array, created by HtlcKey_write
pub extern "C" fn HtlcKey_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HtlcKeyDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::HtlcKey, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::HtlcKey { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_keys::RevocationBasepoint as nativeRevocationBasepointImport;
pub(crate) type nativeRevocationBasepoint = nativeRevocationBasepointImport;

/// Master key used in conjunction with per_commitment_point to generate [htlcpubkey](https://github.com/lightning/bolts/blob/master/03-transactions.md#key-derivation) for the latest state of a channel.
/// A watcher can be given a [RevocationBasepoint] to generate per commitment [RevocationKey] to create justice transactions.
#[must_use]
#[repr(C)]
pub struct RevocationBasepoint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRevocationBasepoint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RevocationBasepoint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRevocationBasepoint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RevocationBasepoint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RevocationBasepoint_free(this_obj: RevocationBasepoint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RevocationBasepoint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRevocationBasepoint) };
}
#[allow(unused)]
impl RevocationBasepoint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRevocationBasepoint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRevocationBasepoint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRevocationBasepoint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn RevocationBasepoint_get_a(this_ptr: &RevocationBasepoint) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn RevocationBasepoint_set_a(this_ptr: &mut RevocationBasepoint, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new RevocationBasepoint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RevocationBasepoint_new(mut a_arg: crate::c_types::PublicKey) -> RevocationBasepoint {
	RevocationBasepoint { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::RevocationBasepoint (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two RevocationBasepoints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RevocationBasepoint_eq(a: &RevocationBasepoint, b: &RevocationBasepoint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RevocationBasepoint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRevocationBasepoint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RevocationBasepoint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRevocationBasepoint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RevocationBasepoint
pub extern "C" fn RevocationBasepoint_clone(orig: &RevocationBasepoint) -> RevocationBasepoint {
	orig.clone()
}
/// Get a string which allows debug introspection of a RevocationBasepoint object
pub extern "C" fn RevocationBasepoint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::RevocationBasepoint }).into()}
/// Generates a non-cryptographic 64-bit hash of the RevocationBasepoint.
#[no_mangle]
pub extern "C" fn RevocationBasepoint_hash(o: &RevocationBasepoint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn RevocationBasepoint_to_public_key(this_arg: &crate::lightning::ln::channel_keys::RevocationBasepoint) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the RevocationBasepoint object into a byte array which can be read by RevocationBasepoint_read
pub extern "C" fn RevocationBasepoint_write(obj: &crate::lightning::ln::channel_keys::RevocationBasepoint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RevocationBasepoint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRevocationBasepoint) })
}
#[no_mangle]
/// Read a RevocationBasepoint from a byte array, created by RevocationBasepoint_write
pub extern "C" fn RevocationBasepoint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RevocationBasepointDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::RevocationBasepoint, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::RevocationBasepoint { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::channel_keys::RevocationKey as nativeRevocationKeyImport;
pub(crate) type nativeRevocationKey = nativeRevocationKeyImport;

/// The revocation key is used to allow a channel party to revoke their state - giving their
/// counterparty the required material to claim all of their funds if they broadcast that state.
///
/// Each commitment transaction has a revocation key based on the basepoint and
/// per_commitment_point which is used in both commitment and HTLC transactions.
///
/// See [the BOLT spec for derivation details]
/// (https://github.com/lightning/bolts/blob/master/03-transactions.md#revocationpubkey-derivation)
#[must_use]
#[repr(C)]
pub struct RevocationKey {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRevocationKey,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RevocationKey {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRevocationKey>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RevocationKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RevocationKey_free(this_obj: RevocationKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RevocationKey_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRevocationKey) };
}
#[allow(unused)]
impl RevocationKey {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRevocationKey {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRevocationKey {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRevocationKey {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn RevocationKey_get_a(this_ptr: &RevocationKey) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn RevocationKey_set_a(this_ptr: &mut RevocationKey, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new RevocationKey given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RevocationKey_new(mut a_arg: crate::c_types::PublicKey) -> RevocationKey {
	RevocationKey { inner: ObjOps::heap_alloc(lightning::ln::channel_keys::RevocationKey (
		a_arg.into_rust(),
	)), is_owned: true }
}
/// Checks if two RevocationKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RevocationKey_eq(a: &RevocationKey, b: &RevocationKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RevocationKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRevocationKey>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RevocationKey_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRevocationKey)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RevocationKey
pub extern "C" fn RevocationKey_clone(orig: &RevocationKey) -> RevocationKey {
	orig.clone()
}
/// Get a string which allows debug introspection of a RevocationKey object
pub extern "C" fn RevocationKey_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::channel_keys::RevocationKey }).into()}
/// Generates a non-cryptographic 64-bit hash of the RevocationKey.
#[no_mangle]
pub extern "C" fn RevocationKey_hash(o: &RevocationKey) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Derives a per-commitment-transaction revocation public key from one party's per-commitment
/// point and the other party's [`RevocationBasepoint`]. This is the public equivalent of
/// [`chan_utils::derive_private_revocation_key`] - using only public keys to derive a public
/// key instead of private keys.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
///
/// [`chan_utils::derive_private_revocation_key`]: crate::ln::chan_utils::derive_private_revocation_key
#[must_use]
#[no_mangle]
pub extern "C" fn RevocationKey_from_basepoint(countersignatory_basepoint: &crate::lightning::ln::channel_keys::RevocationBasepoint, mut per_commitment_point: crate::c_types::PublicKey) -> crate::lightning::ln::channel_keys::RevocationKey {
	let mut ret = lightning::ln::channel_keys::RevocationKey::from_basepoint(secp256k1::global::SECP256K1, countersignatory_basepoint.get_native_ref(), &per_commitment_point.into_rust());
	crate::lightning::ln::channel_keys::RevocationKey { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get inner Public Key
#[must_use]
#[no_mangle]
pub extern "C" fn RevocationKey_to_public_key(this_arg: &crate::lightning::ln::channel_keys::RevocationKey) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_public_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the RevocationKey object into a byte array which can be read by RevocationKey_read
pub extern "C" fn RevocationKey_write(obj: &crate::lightning::ln::channel_keys::RevocationKey) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RevocationKey_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRevocationKey) })
}
#[no_mangle]
/// Read a RevocationKey from a byte array, created by RevocationKey_write
pub extern "C" fn RevocationKey_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RevocationKeyDecodeErrorZ {
	let res: Result<lightning::ln::channel_keys::RevocationKey, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channel_keys::RevocationKey { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
