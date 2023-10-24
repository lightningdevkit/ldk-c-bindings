// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities for paying Lightning invoices.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Pays the given [`Bolt11Invoice`], retrying if needed based on [`Retry`].
///
/// [`Bolt11Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. If the payment succeeds, you must ensure that a second payment
/// with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see [`pay_invoice_with_id`].
#[no_mangle]
pub extern "C" fn pay_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice, mut retry_strategy: crate::lightning::ln::outbound_payment::Retry, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_ThirtyTwoBytesPaymentErrorZ {
	let mut ret = lightning_invoice::payment::pay_invoice::<_>(invoice.get_native_ref(), retry_strategy.into_native(), channelmanager.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given [`Bolt11Invoice`] with a custom idempotency key, retrying if needed based on
/// [`Retry`].
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Bolt11Invoice::payment_hash`] is unique and the same
/// [`PaymentHash`] has never been paid before.
///
/// See [`pay_invoice`] for a variant which uses the [`PaymentHash`] for the idempotency token.
#[no_mangle]
pub extern "C" fn pay_invoice_with_id(invoice: &crate::lightning_invoice::Bolt11Invoice, mut payment_id: crate::c_types::ThirtyTwoBytes, mut retry_strategy: crate::lightning::ln::outbound_payment::Retry, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NonePaymentErrorZ {
	let mut ret = lightning_invoice::payment::pay_invoice_with_id::<_>(invoice.get_native_ref(), ::lightning::ln::channelmanager::PaymentId(payment_id.data), retry_strategy.into_native(), channelmanager.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given zero-value [`Bolt11Invoice`] using the given amount, retrying if needed based on
/// [`Retry`].
///
/// [`Bolt11Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. If the payment succeeds, you must ensure that a second payment
/// with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see
/// [`pay_zero_value_invoice_with_id`].
#[no_mangle]
pub extern "C" fn pay_zero_value_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice, mut amount_msats: u64, mut retry_strategy: crate::lightning::ln::outbound_payment::Retry, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_ThirtyTwoBytesPaymentErrorZ {
	let mut ret = lightning_invoice::payment::pay_zero_value_invoice::<_>(invoice.get_native_ref(), amount_msats, retry_strategy.into_native(), channelmanager.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given zero-value [`Bolt11Invoice`] using the given amount and custom idempotency key,
/// retrying if needed based on [`Retry`].
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Bolt11Invoice::payment_hash`] is unique and the same
/// [`PaymentHash`] has never been paid before.
///
/// See [`pay_zero_value_invoice`] for a variant which uses the [`PaymentHash`] for the
/// idempotency token.
#[no_mangle]
pub extern "C" fn pay_zero_value_invoice_with_id(invoice: &crate::lightning_invoice::Bolt11Invoice, mut amount_msats: u64, mut payment_id: crate::c_types::ThirtyTwoBytes, mut retry_strategy: crate::lightning::ln::outbound_payment::Retry, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NonePaymentErrorZ {
	let mut ret = lightning_invoice::payment::pay_zero_value_invoice_with_id::<_>(invoice.get_native_ref(), amount_msats, ::lightning::ln::channelmanager::PaymentId(payment_id.data), retry_strategy.into_native(), channelmanager.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Sends payment probes over all paths of a route that would be used to pay the given invoice.
///
/// See [`ChannelManager::send_preflight_probes`] for more information.
#[no_mangle]
pub extern "C" fn preflight_probe_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut liquidity_limit_multiplier: crate::c_types::derived::COption_u64Z) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesThirtyTwoBytesZZProbingErrorZ {
	let mut local_liquidity_limit_multiplier = if liquidity_limit_multiplier.is_some() { Some( { liquidity_limit_multiplier.take() }) } else { None };
	let mut ret = lightning_invoice::payment::preflight_probe_invoice::<_>(invoice.get_native_ref(), channelmanager.get_native_ref(), local_liquidity_limit_multiplier);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_1.0 }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::ProbingError::native_into(e) }).into() };
	local_ret
}

/// Sends payment probes over all paths of a route that would be used to pay the given zero-value
/// invoice using the given amount.
///
/// See [`ChannelManager::send_preflight_probes`] for more information.
#[no_mangle]
pub extern "C" fn preflight_probe_zero_value_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice, mut amount_msat: u64, channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut liquidity_limit_multiplier: crate::c_types::derived::COption_u64Z) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesThirtyTwoBytesZZProbingErrorZ {
	let mut local_liquidity_limit_multiplier = if liquidity_limit_multiplier.is_some() { Some( { liquidity_limit_multiplier.take() }) } else { None };
	let mut ret = lightning_invoice::payment::preflight_probe_zero_value_invoice::<_>(invoice.get_native_ref(), amount_msat, channelmanager.get_native_ref(), local_liquidity_limit_multiplier);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_1.0 }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::ProbingError::native_into(e) }).into() };
	local_ret
}

/// An error that may occur when making a payment.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentError {
	/// An error resulting from the provided [`Bolt11Invoice`] or payment hash.
	Invoice(
		crate::c_types::Str),
	/// An error occurring when sending a payment.
	Sending(
		crate::lightning::ln::outbound_payment::RetryableSendFailure),
}
use lightning_invoice::payment::PaymentError as PaymentErrorImport;
pub(crate) type nativePaymentError = PaymentErrorImport;

impl PaymentError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentError {
		match self {
			PaymentError::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentError::Invoice (
					a_nonref.into_str(),
				)
			},
			PaymentError::Sending (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentError::Sending (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentError {
		match self {
			PaymentError::Invoice (mut a, ) => {
				nativePaymentError::Invoice (
					a.into_str(),
				)
			},
			PaymentError::Sending (mut a, ) => {
				nativePaymentError::Sending (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePaymentError) -> Self {
		match native {
			nativePaymentError::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentError::Invoice (
					a_nonref.into(),
				)
			},
			nativePaymentError::Sending (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentError::Sending (
					crate::lightning::ln::outbound_payment::RetryableSendFailure::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentError) -> Self {
		match native {
			nativePaymentError::Invoice (mut a, ) => {
				PaymentError::Invoice (
					a.into(),
				)
			},
			nativePaymentError::Sending (mut a, ) => {
				PaymentError::Sending (
					crate::lightning::ln::outbound_payment::RetryableSendFailure::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the PaymentError
#[no_mangle]
pub extern "C" fn PaymentError_free(this_ptr: PaymentError) { }
/// Creates a copy of the PaymentError
#[no_mangle]
pub extern "C" fn PaymentError_clone(orig: &PaymentError) -> PaymentError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PaymentError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PaymentError) };
}
#[no_mangle]
/// Utility method to constructs a new Invoice-variant PaymentError
pub extern "C" fn PaymentError_invoice(a: crate::c_types::Str) -> PaymentError {
	PaymentError::Invoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new Sending-variant PaymentError
pub extern "C" fn PaymentError_sending(a: crate::lightning::ln::outbound_payment::RetryableSendFailure) -> PaymentError {
	PaymentError::Sending(a, )
}
/// Checks if two PaymentErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PaymentError_eq(a: &PaymentError, b: &PaymentError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// An error that may occur when sending a payment probe.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ProbingError {
	/// An error resulting from the provided [`Bolt11Invoice`].
	Invoice(
		crate::c_types::Str),
	/// An error occurring when sending a payment probe.
	Sending(
		crate::lightning::ln::outbound_payment::ProbeSendFailure),
}
use lightning_invoice::payment::ProbingError as ProbingErrorImport;
pub(crate) type nativeProbingError = ProbingErrorImport;

impl ProbingError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeProbingError {
		match self {
			ProbingError::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeProbingError::Invoice (
					a_nonref.into_str(),
				)
			},
			ProbingError::Sending (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeProbingError::Sending (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeProbingError {
		match self {
			ProbingError::Invoice (mut a, ) => {
				nativeProbingError::Invoice (
					a.into_str(),
				)
			},
			ProbingError::Sending (mut a, ) => {
				nativeProbingError::Sending (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeProbingError) -> Self {
		match native {
			nativeProbingError::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				ProbingError::Invoice (
					a_nonref.into(),
				)
			},
			nativeProbingError::Sending (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				ProbingError::Sending (
					crate::lightning::ln::outbound_payment::ProbeSendFailure::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeProbingError) -> Self {
		match native {
			nativeProbingError::Invoice (mut a, ) => {
				ProbingError::Invoice (
					a.into(),
				)
			},
			nativeProbingError::Sending (mut a, ) => {
				ProbingError::Sending (
					crate::lightning::ln::outbound_payment::ProbeSendFailure::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the ProbingError
#[no_mangle]
pub extern "C" fn ProbingError_free(this_ptr: ProbingError) { }
/// Creates a copy of the ProbingError
#[no_mangle]
pub extern "C" fn ProbingError_clone(orig: &ProbingError) -> ProbingError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbingError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ProbingError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbingError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ProbingError) };
}
#[no_mangle]
/// Utility method to constructs a new Invoice-variant ProbingError
pub extern "C" fn ProbingError_invoice(a: crate::c_types::Str) -> ProbingError {
	ProbingError::Invoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new Sending-variant ProbingError
pub extern "C" fn ProbingError_sending(a: crate::lightning::ln::outbound_payment::ProbeSendFailure) -> ProbingError {
	ProbingError::Sending(a, )
}
/// Checks if two ProbingErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ProbingError_eq(a: &ProbingError, b: &ProbingError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
