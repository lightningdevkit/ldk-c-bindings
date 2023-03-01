// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities to send payments and manage outbound payment information.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Strategies available to retry payment path failures.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Retry {
	/// Max number of attempts to retry payment.
	///
	/// Each attempt may be multiple HTLCs along multiple paths if the router decides to split up a
	/// retry, and may retry multiple failed HTLCs at once if they failed around the same time and
	/// were retried along a route from a single call to [`Router::find_route`].
	Attempts(
		usize),
	/// Time elapsed before abandoning retries for a payment. At least one attempt at payment is made;
	/// see [`PaymentParameters::expiry_time`] to avoid any attempt at payment after a specific time.
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	Timeout(
		u64),
}
use lightning::ln::outbound_payment::Retry as RetryImport;
pub(crate) type nativeRetry = RetryImport;

impl Retry {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeRetry {
		match self {
			Retry::Attempts (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeRetry::Attempts (
					a_nonref,
				)
			},
			Retry::Timeout (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeRetry::Timeout (
					core::time::Duration::from_secs(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeRetry {
		match self {
			Retry::Attempts (mut a, ) => {
				nativeRetry::Attempts (
					a,
				)
			},
			Retry::Timeout (mut a, ) => {
				nativeRetry::Timeout (
					core::time::Duration::from_secs(a),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeRetry) -> Self {
		match native {
			nativeRetry::Attempts (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Retry::Attempts (
					a_nonref,
				)
			},
			nativeRetry::Timeout (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Retry::Timeout (
					a_nonref.as_secs(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeRetry) -> Self {
		match native {
			nativeRetry::Attempts (mut a, ) => {
				Retry::Attempts (
					a,
				)
			},
			nativeRetry::Timeout (mut a, ) => {
				Retry::Timeout (
					a.as_secs(),
				)
			},
		}
	}
}
/// Frees any resources used by the Retry
#[no_mangle]
pub extern "C" fn Retry_free(this_ptr: Retry) { }
/// Creates a copy of the Retry
#[no_mangle]
pub extern "C" fn Retry_clone(orig: &Retry) -> Retry {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Attempts-variant Retry
pub extern "C" fn Retry_attempts(a: usize) -> Retry {
	Retry::Attempts(a, )
}
#[no_mangle]
/// Utility method to constructs a new Timeout-variant Retry
pub extern "C" fn Retry_timeout(a: u64) -> Retry {
	Retry::Timeout(a, )
}
/// Checks if two Retrys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Retry_eq(a: &Retry, b: &Retry) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Checks if two Retrys contain equal inner contents.
#[no_mangle]
pub extern "C" fn Retry_hash(o: &Retry) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Indicates an immediate error on [`ChannelManager::send_payment_with_retry`]. Further errors
/// may be surfaced later via [`Event::PaymentPathFailed`] and [`Event::PaymentFailed`].
///
/// [`ChannelManager::send_payment_with_retry`]: crate::ln::channelmanager::ChannelManager::send_payment_with_retry
/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum RetryableSendFailure {
	/// The provided [`PaymentParameters::expiry_time`] indicated that the payment has expired. Note
	/// that this error is *not* caused by [`Retry::Timeout`].
	///
	/// [`PaymentParameters::expiry_time`]: crate::routing::router::PaymentParameters::expiry_time
	PaymentExpired,
	/// We were unable to find a route to the destination.
	RouteNotFound,
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::PaymentSent`] or [`Event::PaymentFailed`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::PaymentSent`]: crate::util::events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
	DuplicatePayment,
}
use lightning::ln::outbound_payment::RetryableSendFailure as RetryableSendFailureImport;
pub(crate) type nativeRetryableSendFailure = RetryableSendFailureImport;

impl RetryableSendFailure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeRetryableSendFailure {
		match self {
			RetryableSendFailure::PaymentExpired => nativeRetryableSendFailure::PaymentExpired,
			RetryableSendFailure::RouteNotFound => nativeRetryableSendFailure::RouteNotFound,
			RetryableSendFailure::DuplicatePayment => nativeRetryableSendFailure::DuplicatePayment,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeRetryableSendFailure {
		match self {
			RetryableSendFailure::PaymentExpired => nativeRetryableSendFailure::PaymentExpired,
			RetryableSendFailure::RouteNotFound => nativeRetryableSendFailure::RouteNotFound,
			RetryableSendFailure::DuplicatePayment => nativeRetryableSendFailure::DuplicatePayment,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeRetryableSendFailure) -> Self {
		match native {
			nativeRetryableSendFailure::PaymentExpired => RetryableSendFailure::PaymentExpired,
			nativeRetryableSendFailure::RouteNotFound => RetryableSendFailure::RouteNotFound,
			nativeRetryableSendFailure::DuplicatePayment => RetryableSendFailure::DuplicatePayment,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeRetryableSendFailure) -> Self {
		match native {
			nativeRetryableSendFailure::PaymentExpired => RetryableSendFailure::PaymentExpired,
			nativeRetryableSendFailure::RouteNotFound => RetryableSendFailure::RouteNotFound,
			nativeRetryableSendFailure::DuplicatePayment => RetryableSendFailure::DuplicatePayment,
		}
	}
}
/// Creates a copy of the RetryableSendFailure
#[no_mangle]
pub extern "C" fn RetryableSendFailure_clone(orig: &RetryableSendFailure) -> RetryableSendFailure {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new PaymentExpired-variant RetryableSendFailure
pub extern "C" fn RetryableSendFailure_payment_expired() -> RetryableSendFailure {
	RetryableSendFailure::PaymentExpired}
#[no_mangle]
/// Utility method to constructs a new RouteNotFound-variant RetryableSendFailure
pub extern "C" fn RetryableSendFailure_route_not_found() -> RetryableSendFailure {
	RetryableSendFailure::RouteNotFound}
#[no_mangle]
/// Utility method to constructs a new DuplicatePayment-variant RetryableSendFailure
pub extern "C" fn RetryableSendFailure_duplicate_payment() -> RetryableSendFailure {
	RetryableSendFailure::DuplicatePayment}
/// If a payment fails to send with [`ChannelManager::send_payment`], it can be in one of several
/// states. This enum is returned as the Err() type describing which state the payment is in, see
/// the description of individual enum states for more.
///
/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentSendFailure {
	/// A parameter which was passed to send_payment was invalid, preventing us from attempting to
	/// send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
	ParameterError(
		crate::lightning::util::errors::APIError),
	/// A parameter in a single path which was passed to send_payment was invalid, preventing us
	/// from attempting to send the payment at all.
	///
	/// You can freely resend the payment in full (with the parameter error fixed).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment.
	///
	/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
	PathParameterError(
		crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ),
	/// All paths which were attempted failed to send, with no channel state change taking place.
	/// You can freely resend the payment in full (though you probably want to do so over different
	/// paths than the ones selected).
	///
	/// Because the payment failed outright, no payment tracking is done and no
	/// [`Event::PaymentPathFailed`] or [`Event::PaymentFailed`] events will be generated.
	///
	/// [`Event::PaymentPathFailed`]: crate::util::events::Event::PaymentPathFailed
	/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
	AllFailedResendSafe(
		crate::c_types::derived::CVec_APIErrorZ),
	/// Indicates that a payment for the provided [`PaymentId`] is already in-flight and has not
	/// yet completed (i.e. generated an [`Event::PaymentSent`] or [`Event::PaymentFailed`]).
	///
	/// [`PaymentId`]: crate::ln::channelmanager::PaymentId
	/// [`Event::PaymentSent`]: crate::util::events::Event::PaymentSent
	/// [`Event::PaymentFailed`]: crate::util::events::Event::PaymentFailed
	DuplicatePayment,
	/// Some paths that were attempted failed to send, though some paths may have succeeded. At least
	/// some paths have irrevocably committed to the HTLC.
	///
	/// The results here are ordered the same as the paths in the route object that was passed to
	/// send_payment.
	///
	/// Any entries that contain `Err(APIError::MonitorUpdateInprogress)` will send once a
	/// [`MonitorEvent::Completed`] is provided for the next-hop channel with the latest update_id.
	///
	/// [`MonitorEvent::Completed`]: crate::chain::channelmonitor::MonitorEvent::Completed
	PartialFailure {
		/// The errors themselves, in the same order as the paths from the route.
		results: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ,
		/// If some paths failed without irrevocably committing to the new HTLC(s), this will
		/// contain a [`RouteParameters`] object for the failing paths.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		failed_paths_retry: crate::lightning::routing::router::RouteParameters,
		/// The payment id for the payment, which is now at least partially pending.
		payment_id: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::ln::outbound_payment::PaymentSendFailure as PaymentSendFailureImport;
pub(crate) type nativePaymentSendFailure = PaymentSendFailureImport;

impl PaymentSendFailure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentSendFailure {
		match self {
			PaymentSendFailure::ParameterError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentSendFailure::ParameterError (
					a_nonref.into_native(),
				)
			},
			PaymentSendFailure::PathParameterError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_nonref_0 }); };
				nativePaymentSendFailure::PathParameterError (
					local_a_nonref,
				)
			},
			PaymentSendFailure::AllFailedResendSafe (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { item.into_native() }); };
				nativePaymentSendFailure::AllFailedResendSafe (
					local_a_nonref,
				)
			},
			PaymentSendFailure::DuplicatePayment => nativePaymentSendFailure::DuplicatePayment,
			PaymentSendFailure::PartialFailure {ref results, ref failed_paths_retry, ref payment_id, } => {
				let mut results_nonref = Clone::clone(results);
				let mut local_results_nonref = Vec::new(); for mut item in results_nonref.into_rust().drain(..) { local_results_nonref.push( { let mut local_results_nonref_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_results_nonref_0 }); };
				let mut failed_paths_retry_nonref = Clone::clone(failed_paths_retry);
				let mut local_failed_paths_retry_nonref = if failed_paths_retry_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(failed_paths_retry_nonref.take_inner()) } }) };
				let mut payment_id_nonref = Clone::clone(payment_id);
				nativePaymentSendFailure::PartialFailure {
					results: local_results_nonref,
					failed_paths_retry: local_failed_paths_retry_nonref,
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentSendFailure {
		match self {
			PaymentSendFailure::ParameterError (mut a, ) => {
				nativePaymentSendFailure::ParameterError (
					a.into_native(),
				)
			},
			PaymentSendFailure::PathParameterError (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { let mut local_a_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_0 }); };
				nativePaymentSendFailure::PathParameterError (
					local_a,
				)
			},
			PaymentSendFailure::AllFailedResendSafe (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { item.into_native() }); };
				nativePaymentSendFailure::AllFailedResendSafe (
					local_a,
				)
			},
			PaymentSendFailure::DuplicatePayment => nativePaymentSendFailure::DuplicatePayment,
			PaymentSendFailure::PartialFailure {mut results, mut failed_paths_retry, mut payment_id, } => {
				let mut local_results = Vec::new(); for mut item in results.into_rust().drain(..) { local_results.push( { let mut local_results_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_results_0 }); };
				let mut local_failed_paths_retry = if failed_paths_retry.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(failed_paths_retry.take_inner()) } }) };
				nativePaymentSendFailure::PartialFailure {
					results: local_results,
					failed_paths_retry: local_failed_paths_retry,
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePaymentSendFailure) -> Self {
		match native {
			nativePaymentSendFailure::ParameterError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentSendFailure::ParameterError (
					crate::lightning::util::errors::APIError::native_into(a_nonref),
				)
			},
			nativePaymentSendFailure::PathParameterError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_nonref_0 }); };
				PaymentSendFailure::PathParameterError (
					local_a_nonref.into(),
				)
			},
			nativePaymentSendFailure::AllFailedResendSafe (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { crate::lightning::util::errors::APIError::native_into(item) }); };
				PaymentSendFailure::AllFailedResendSafe (
					local_a_nonref.into(),
				)
			},
			nativePaymentSendFailure::DuplicatePayment => PaymentSendFailure::DuplicatePayment,
			nativePaymentSendFailure::PartialFailure {ref results, ref failed_paths_retry, ref payment_id, } => {
				let mut results_nonref = Clone::clone(results);
				let mut local_results_nonref = Vec::new(); for mut item in results_nonref.drain(..) { local_results_nonref.push( { let mut local_results_nonref_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_results_nonref_0 }); };
				let mut failed_paths_retry_nonref = Clone::clone(failed_paths_retry);
				let mut local_failed_paths_retry_nonref = crate::lightning::routing::router::RouteParameters { inner: if failed_paths_retry_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((failed_paths_retry_nonref.unwrap())) } }, is_owned: true };
				let mut payment_id_nonref = Clone::clone(payment_id);
				PaymentSendFailure::PartialFailure {
					results: local_results_nonref.into(),
					failed_paths_retry: local_failed_paths_retry_nonref,
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentSendFailure) -> Self {
		match native {
			nativePaymentSendFailure::ParameterError (mut a, ) => {
				PaymentSendFailure::ParameterError (
					crate::lightning::util::errors::APIError::native_into(a),
				)
			},
			nativePaymentSendFailure::PathParameterError (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { let mut local_a_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_0 }); };
				PaymentSendFailure::PathParameterError (
					local_a.into(),
				)
			},
			nativePaymentSendFailure::AllFailedResendSafe (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { crate::lightning::util::errors::APIError::native_into(item) }); };
				PaymentSendFailure::AllFailedResendSafe (
					local_a.into(),
				)
			},
			nativePaymentSendFailure::DuplicatePayment => PaymentSendFailure::DuplicatePayment,
			nativePaymentSendFailure::PartialFailure {mut results, mut failed_paths_retry, mut payment_id, } => {
				let mut local_results = Vec::new(); for mut item in results.drain(..) { local_results.push( { let mut local_results_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_results_0 }); };
				let mut local_failed_paths_retry = crate::lightning::routing::router::RouteParameters { inner: if failed_paths_retry.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((failed_paths_retry.unwrap())) } }, is_owned: true };
				PaymentSendFailure::PartialFailure {
					results: local_results.into(),
					failed_paths_retry: local_failed_paths_retry,
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
				}
			},
		}
	}
}
/// Frees any resources used by the PaymentSendFailure
#[no_mangle]
pub extern "C" fn PaymentSendFailure_free(this_ptr: PaymentSendFailure) { }
/// Creates a copy of the PaymentSendFailure
#[no_mangle]
pub extern "C" fn PaymentSendFailure_clone(orig: &PaymentSendFailure) -> PaymentSendFailure {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new ParameterError-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_parameter_error(a: crate::lightning::util::errors::APIError) -> PaymentSendFailure {
	PaymentSendFailure::ParameterError(a, )
}
#[no_mangle]
/// Utility method to constructs a new PathParameterError-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_path_parameter_error(a: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ) -> PaymentSendFailure {
	PaymentSendFailure::PathParameterError(a, )
}
#[no_mangle]
/// Utility method to constructs a new AllFailedResendSafe-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_all_failed_resend_safe(a: crate::c_types::derived::CVec_APIErrorZ) -> PaymentSendFailure {
	PaymentSendFailure::AllFailedResendSafe(a, )
}
#[no_mangle]
/// Utility method to constructs a new DuplicatePayment-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_duplicate_payment() -> PaymentSendFailure {
	PaymentSendFailure::DuplicatePayment}
#[no_mangle]
/// Utility method to constructs a new PartialFailure-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_partial_failure(results: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ, failed_paths_retry: crate::lightning::routing::router::RouteParameters, payment_id: crate::c_types::ThirtyTwoBytes) -> PaymentSendFailure {
	PaymentSendFailure::PartialFailure {
		results,
		failed_paths_retry,
		payment_id,
	}
}
