// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and methods for constructing [`BlindedPath`]s to send a payment over.
//!
//! [`BlindedPath`]: crate::blinded_path::BlindedPath

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::blinded_path::payment::ForwardNode as nativeForwardNodeImport;
pub(crate) type nativeForwardNode = nativeForwardNodeImport;

/// An intermediate node, its outbound channel, and relay parameters.
#[must_use]
#[repr(C)]
pub struct ForwardNode {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeForwardNode,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ForwardNode {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeForwardNode>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ForwardNode, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ForwardNode_free(this_obj: ForwardNode) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardNode_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeForwardNode) };
}
#[allow(unused)]
impl ForwardNode {
	pub(crate) fn get_native_ref(&self) -> &'static nativeForwardNode {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeForwardNode {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeForwardNode {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The TLVs for this node's [`BlindedHop`], where the fee parameters contained within are also
/// used for [`BlindedPayInfo`] construction.
#[no_mangle]
pub extern "C" fn ForwardNode_get_tlvs(this_ptr: &ForwardNode) -> crate::lightning::blinded_path::payment::ForwardTlvs {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().tlvs;
	crate::lightning::blinded_path::payment::ForwardTlvs { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::ForwardTlvs<>) as *mut _) }, is_owned: false }
}
/// The TLVs for this node's [`BlindedHop`], where the fee parameters contained within are also
/// used for [`BlindedPayInfo`] construction.
#[no_mangle]
pub extern "C" fn ForwardNode_set_tlvs(this_ptr: &mut ForwardNode, mut val: crate::lightning::blinded_path::payment::ForwardTlvs) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.tlvs = *unsafe { Box::from_raw(val.take_inner()) };
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn ForwardNode_get_node_id(this_ptr: &ForwardNode) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// This node's pubkey.
#[no_mangle]
pub extern "C" fn ForwardNode_set_node_id(this_ptr: &mut ForwardNode, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_id = val.into_rust();
}
/// The maximum value, in msat, that may be accepted by this node.
#[no_mangle]
pub extern "C" fn ForwardNode_get_htlc_maximum_msat(this_ptr: &ForwardNode) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	*inner_val
}
/// The maximum value, in msat, that may be accepted by this node.
#[no_mangle]
pub extern "C" fn ForwardNode_set_htlc_maximum_msat(this_ptr: &mut ForwardNode, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = val;
}
/// Constructs a new ForwardNode given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ForwardNode_new(mut tlvs_arg: crate::lightning::blinded_path::payment::ForwardTlvs, mut node_id_arg: crate::c_types::PublicKey, mut htlc_maximum_msat_arg: u64) -> ForwardNode {
	ForwardNode { inner: ObjOps::heap_alloc(nativeForwardNode {
		tlvs: *unsafe { Box::from_raw(tlvs_arg.take_inner()) },
		node_id: node_id_arg.into_rust(),
		htlc_maximum_msat: htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for ForwardNode {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeForwardNode>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardNode_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeForwardNode)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ForwardNode
pub extern "C" fn ForwardNode_clone(orig: &ForwardNode) -> ForwardNode {
	orig.clone()
}
/// Get a string which allows debug introspection of a ForwardNode object
pub extern "C" fn ForwardNode_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::ForwardNode }).into()}

use lightning::blinded_path::payment::ForwardTlvs as nativeForwardTlvsImport;
pub(crate) type nativeForwardTlvs = nativeForwardTlvsImport;

/// Data to construct a [`BlindedHop`] for forwarding a payment.
#[must_use]
#[repr(C)]
pub struct ForwardTlvs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeForwardTlvs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ForwardTlvs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeForwardTlvs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ForwardTlvs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ForwardTlvs_free(this_obj: ForwardTlvs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardTlvs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeForwardTlvs) };
}
#[allow(unused)]
impl ForwardTlvs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeForwardTlvs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeForwardTlvs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeForwardTlvs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The short channel id this payment should be forwarded out over.
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_short_channel_id(this_ptr: &ForwardTlvs) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short channel id this payment should be forwarded out over.
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_short_channel_id(this_ptr: &mut ForwardTlvs, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// Payment parameters for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_payment_relay(this_ptr: &ForwardTlvs) -> crate::lightning::blinded_path::payment::PaymentRelay {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_relay;
	crate::lightning::blinded_path::payment::PaymentRelay { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentRelay<>) as *mut _) }, is_owned: false }
}
/// Payment parameters for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_payment_relay(this_ptr: &mut ForwardTlvs, mut val: crate::lightning::blinded_path::payment::PaymentRelay) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_relay = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Payment constraints for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_payment_constraints(this_ptr: &ForwardTlvs) -> crate::lightning::blinded_path::payment::PaymentConstraints {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_constraints;
	crate::lightning::blinded_path::payment::PaymentConstraints { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentConstraints<>) as *mut _) }, is_owned: false }
}
/// Payment constraints for relaying over [`Self::short_channel_id`].
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_payment_constraints(this_ptr: &mut ForwardTlvs, mut val: crate::lightning::blinded_path::payment::PaymentConstraints) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_constraints = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Supported and required features when relaying a payment onion containing this object's
/// corresponding [`BlindedHop::encrypted_payload`].
///
/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn ForwardTlvs_get_features(this_ptr: &ForwardTlvs) -> crate::lightning::ln::features::BlindedHopFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning::ln::features::BlindedHopFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::BlindedHopFeatures<>) as *mut _) }, is_owned: false }
}
/// Supported and required features when relaying a payment onion containing this object's
/// corresponding [`BlindedHop::encrypted_payload`].
///
/// [`BlindedHop::encrypted_payload`]: crate::blinded_path::BlindedHop::encrypted_payload
#[no_mangle]
pub extern "C" fn ForwardTlvs_set_features(this_ptr: &mut ForwardTlvs, mut val: crate::lightning::ln::features::BlindedHopFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ForwardTlvs given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ForwardTlvs_new(mut short_channel_id_arg: u64, mut payment_relay_arg: crate::lightning::blinded_path::payment::PaymentRelay, mut payment_constraints_arg: crate::lightning::blinded_path::payment::PaymentConstraints, mut features_arg: crate::lightning::ln::features::BlindedHopFeatures) -> ForwardTlvs {
	ForwardTlvs { inner: ObjOps::heap_alloc(nativeForwardTlvs {
		short_channel_id: short_channel_id_arg,
		payment_relay: *unsafe { Box::from_raw(payment_relay_arg.take_inner()) },
		payment_constraints: *unsafe { Box::from_raw(payment_constraints_arg.take_inner()) },
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for ForwardTlvs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeForwardTlvs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ForwardTlvs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeForwardTlvs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ForwardTlvs
pub extern "C" fn ForwardTlvs_clone(orig: &ForwardTlvs) -> ForwardTlvs {
	orig.clone()
}
/// Get a string which allows debug introspection of a ForwardTlvs object
pub extern "C" fn ForwardTlvs_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::ForwardTlvs }).into()}

use lightning::blinded_path::payment::ReceiveTlvs as nativeReceiveTlvsImport;
pub(crate) type nativeReceiveTlvs = nativeReceiveTlvsImport;

/// Data to construct a [`BlindedHop`] for receiving a payment. This payload is custom to LDK and
/// may not be valid if received by another lightning implementation.
#[must_use]
#[repr(C)]
pub struct ReceiveTlvs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReceiveTlvs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ReceiveTlvs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeReceiveTlvs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ReceiveTlvs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_free(this_obj: ReceiveTlvs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReceiveTlvs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeReceiveTlvs) };
}
#[allow(unused)]
impl ReceiveTlvs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeReceiveTlvs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeReceiveTlvs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeReceiveTlvs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_get_payment_secret(this_ptr: &ReceiveTlvs) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_secret;
	&inner_val.0
}
/// Used to authenticate the sender of a payment to the receiver and tie MPP HTLCs together.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_set_payment_secret(this_ptr: &mut ReceiveTlvs, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_secret = ::lightning::ln::PaymentSecret(val.data);
}
/// Constraints for the receiver of this payment.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_get_payment_constraints(this_ptr: &ReceiveTlvs) -> crate::lightning::blinded_path::payment::PaymentConstraints {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_constraints;
	crate::lightning::blinded_path::payment::PaymentConstraints { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::blinded_path::payment::PaymentConstraints<>) as *mut _) }, is_owned: false }
}
/// Constraints for the receiver of this payment.
#[no_mangle]
pub extern "C" fn ReceiveTlvs_set_payment_constraints(this_ptr: &mut ReceiveTlvs, mut val: crate::lightning::blinded_path::payment::PaymentConstraints) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_constraints = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ReceiveTlvs given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ReceiveTlvs_new(mut payment_secret_arg: crate::c_types::ThirtyTwoBytes, mut payment_constraints_arg: crate::lightning::blinded_path::payment::PaymentConstraints) -> ReceiveTlvs {
	ReceiveTlvs { inner: ObjOps::heap_alloc(nativeReceiveTlvs {
		payment_secret: ::lightning::ln::PaymentSecret(payment_secret_arg.data),
		payment_constraints: *unsafe { Box::from_raw(payment_constraints_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for ReceiveTlvs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeReceiveTlvs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReceiveTlvs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeReceiveTlvs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ReceiveTlvs
pub extern "C" fn ReceiveTlvs_clone(orig: &ReceiveTlvs) -> ReceiveTlvs {
	orig.clone()
}
/// Get a string which allows debug introspection of a ReceiveTlvs object
pub extern "C" fn ReceiveTlvs_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::ReceiveTlvs }).into()}

use lightning::blinded_path::payment::PaymentRelay as nativePaymentRelayImport;
pub(crate) type nativePaymentRelay = nativePaymentRelayImport;

/// Parameters for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[must_use]
#[repr(C)]
pub struct PaymentRelay {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentRelay,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PaymentRelay {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentRelay>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentRelay, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentRelay_free(this_obj: PaymentRelay) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentRelay_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentRelay) };
}
#[allow(unused)]
impl PaymentRelay {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentRelay {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentRelay {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentRelay {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_get_cltv_expiry_delta(this_ptr: &PaymentRelay) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_set_cltv_expiry_delta(this_ptr: &mut PaymentRelay, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
/// this [`BlindedHop`], (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn PaymentRelay_get_fee_proportional_millionths(this_ptr: &PaymentRelay) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Liquidity fee charged (in millionths of the amount transferred) for relaying a payment over
/// this [`BlindedHop`], (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn PaymentRelay_set_fee_proportional_millionths(this_ptr: &mut PaymentRelay, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_get_fee_base_msat(this_ptr: &PaymentRelay) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base fee charged (in millisatoshi) for relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentRelay_set_fee_base_msat(this_ptr: &mut PaymentRelay, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Constructs a new PaymentRelay given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentRelay_new(mut cltv_expiry_delta_arg: u16, mut fee_proportional_millionths_arg: u32, mut fee_base_msat_arg: u32) -> PaymentRelay {
	PaymentRelay { inner: ObjOps::heap_alloc(nativePaymentRelay {
		cltv_expiry_delta: cltv_expiry_delta_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		fee_base_msat: fee_base_msat_arg,
	}), is_owned: true }
}
impl Clone for PaymentRelay {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentRelay>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentRelay_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentRelay)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentRelay
pub extern "C" fn PaymentRelay_clone(orig: &PaymentRelay) -> PaymentRelay {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentRelay object
pub extern "C" fn PaymentRelay_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentRelay }).into()}

use lightning::blinded_path::payment::PaymentConstraints as nativePaymentConstraintsImport;
pub(crate) type nativePaymentConstraints = nativePaymentConstraintsImport;

/// Constraints for relaying over a given [`BlindedHop`].
///
/// [`BlindedHop`]: crate::blinded_path::BlindedHop
#[must_use]
#[repr(C)]
pub struct PaymentConstraints {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentConstraints,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PaymentConstraints {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentConstraints>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentConstraints, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentConstraints_free(this_obj: PaymentConstraints) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentConstraints_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentConstraints) };
}
#[allow(unused)]
impl PaymentConstraints {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentConstraints {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentConstraints {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentConstraints {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The maximum total CLTV that is acceptable when relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_get_max_cltv_expiry(this_ptr: &PaymentConstraints) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_cltv_expiry;
	*inner_val
}
/// The maximum total CLTV that is acceptable when relaying a payment over this [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_set_max_cltv_expiry(this_ptr: &mut PaymentConstraints, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_cltv_expiry = val;
}
/// The minimum value, in msat, that may be accepted by the node corresponding to this
/// [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_get_htlc_minimum_msat(this_ptr: &PaymentConstraints) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum value, in msat, that may be accepted by the node corresponding to this
/// [`BlindedHop`].
#[no_mangle]
pub extern "C" fn PaymentConstraints_set_htlc_minimum_msat(this_ptr: &mut PaymentConstraints, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// Constructs a new PaymentConstraints given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentConstraints_new(mut max_cltv_expiry_arg: u32, mut htlc_minimum_msat_arg: u64) -> PaymentConstraints {
	PaymentConstraints { inner: ObjOps::heap_alloc(nativePaymentConstraints {
		max_cltv_expiry: max_cltv_expiry_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
	}), is_owned: true }
}
impl Clone for PaymentConstraints {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentConstraints>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentConstraints_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentConstraints)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentConstraints
pub extern "C" fn PaymentConstraints_clone(orig: &PaymentConstraints) -> PaymentConstraints {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentConstraints object
pub extern "C" fn PaymentConstraints_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::blinded_path::payment::PaymentConstraints }).into()}
#[no_mangle]
/// Serialize the ForwardTlvs object into a byte array which can be read by ForwardTlvs_read
pub extern "C" fn ForwardTlvs_write(obj: &crate::lightning::blinded_path::payment::ForwardTlvs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ForwardTlvs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeForwardTlvs) })
}
#[no_mangle]
/// Serialize the ReceiveTlvs object into a byte array which can be read by ReceiveTlvs_read
pub extern "C" fn ReceiveTlvs_write(obj: &crate::lightning::blinded_path::payment::ReceiveTlvs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ReceiveTlvs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeReceiveTlvs) })
}
#[no_mangle]
/// Serialize the PaymentRelay object into a byte array which can be read by PaymentRelay_read
pub extern "C" fn PaymentRelay_write(obj: &crate::lightning::blinded_path::payment::PaymentRelay) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentRelay_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePaymentRelay) })
}
#[no_mangle]
/// Read a PaymentRelay from a byte array, created by PaymentRelay_write
pub extern "C" fn PaymentRelay_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentRelayDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::PaymentRelay, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::PaymentRelay { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the PaymentConstraints object into a byte array which can be read by PaymentConstraints_read
pub extern "C" fn PaymentConstraints_write(obj: &crate::lightning::blinded_path::payment::PaymentConstraints) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentConstraints_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePaymentConstraints) })
}
#[no_mangle]
/// Read a PaymentConstraints from a byte array, created by PaymentConstraints_write
pub extern "C" fn PaymentConstraints_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentConstraintsDecodeErrorZ {
	let res: Result<lightning::blinded_path::payment::PaymentConstraints, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::blinded_path::payment::PaymentConstraints { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
