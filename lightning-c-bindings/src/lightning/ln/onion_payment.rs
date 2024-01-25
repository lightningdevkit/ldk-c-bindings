// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities to decode payment onions and do contextless validation of incoming payments.
//!
//! Primarily features [`peel_payment_onion`], which allows the decoding of an onion statelessly
//! and can be used to predict whether we'd accept a payment.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::ln::onion_payment::InboundHTLCErr as nativeInboundHTLCErrImport;
pub(crate) type nativeInboundHTLCErr = nativeInboundHTLCErrImport;

/// Invalid inbound onion payment.
#[must_use]
#[repr(C)]
pub struct InboundHTLCErr {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInboundHTLCErr,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InboundHTLCErr {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInboundHTLCErr>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InboundHTLCErr, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_free(this_obj: InboundHTLCErr) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InboundHTLCErr_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInboundHTLCErr) };
}
#[allow(unused)]
impl InboundHTLCErr {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInboundHTLCErr {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInboundHTLCErr {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInboundHTLCErr {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// BOLT 4 error code.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_get_err_code(this_ptr: &InboundHTLCErr) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().err_code;
	*inner_val
}
/// BOLT 4 error code.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_set_err_code(this_ptr: &mut InboundHTLCErr, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.err_code = val;
}
/// Data attached to this error.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_get_err_data(this_ptr: &InboundHTLCErr) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = this_ptr.get_native_mut_ref().err_data.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// Data attached to this error.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_set_err_data(this_ptr: &mut InboundHTLCErr, mut val: crate::c_types::derived::CVec_u8Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.err_data = local_val;
}
/// Error message text.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_get_msg(this_ptr: &InboundHTLCErr) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().msg;
	inner_val.into()
}
/// Error message text.
#[no_mangle]
pub extern "C" fn InboundHTLCErr_set_msg(this_ptr: &mut InboundHTLCErr, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.msg = val.into_str();
}
/// Constructs a new InboundHTLCErr given each field
#[must_use]
#[no_mangle]
pub extern "C" fn InboundHTLCErr_new(mut err_code_arg: u16, mut err_data_arg: crate::c_types::derived::CVec_u8Z, mut msg_arg: crate::c_types::Str) -> InboundHTLCErr {
	let mut local_err_data_arg = Vec::new(); for mut item in err_data_arg.into_rust().drain(..) { local_err_data_arg.push( { item }); };
	InboundHTLCErr { inner: ObjOps::heap_alloc(nativeInboundHTLCErr {
		err_code: err_code_arg,
		err_data: local_err_data_arg,
		msg: msg_arg.into_str(),
	}), is_owned: true }
}
/// Get a string which allows debug introspection of a InboundHTLCErr object
pub extern "C" fn InboundHTLCErr_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::onion_payment::InboundHTLCErr }).into()}
/// Peel one layer off an incoming onion, returning a [`PendingHTLCInfo`] that contains information
/// about the intended next-hop for the HTLC.
///
/// This does all the relevant context-free checks that LDK requires for payment relay or
/// acceptance. If the payment is to be received, and the amount matches the expected amount for
/// a given invoice, this indicates the [`msgs::UpdateAddHTLC`], once fully committed in the
/// channel, will generate an [`Event::PaymentClaimable`].
///
/// [`Event::PaymentClaimable`]: crate::events::Event::PaymentClaimable
#[no_mangle]
pub extern "C" fn peel_payment_onion(msg: &crate::lightning::ln::msgs::UpdateAddHTLC, node_signer: &crate::lightning::sign::NodeSigner, logger: &crate::lightning::util::logger::Logger, mut cur_height: u32, mut accept_mpp_keysend: bool, mut allow_skimmed_fees: bool) -> crate::c_types::derived::CResult_PendingHTLCInfoInboundHTLCErrZ {
	let mut ret = lightning::ln::onion_payment::peel_payment_onion(msg.get_native_ref(), node_signer, logger, secp256k1::global::SECP256K1, cur_height, accept_mpp_keysend, allow_skimmed_fees);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channelmanager::PendingHTLCInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::onion_payment::InboundHTLCErr { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

