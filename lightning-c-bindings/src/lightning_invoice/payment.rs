// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A module for paying Lightning invoices and sending spontaneous payments.
//!
//! Defines an [`InvoicePayer`] utility for sending payments, parameterized by [`Payer`] and
//! [`Router`] traits. Implementations of [`Payer`] provide the payer's node id, channels, and means
//! to send a payment over a [`Route`]. Implementations of [`Router`] find a [`Route`] between payer
//! and payee using information provided by the payer and from the payee's [`Invoice`], when
//! applicable.
//!
//! [`InvoicePayer`] uses its [`Router`] parameterization for optionally notifying scorers upon
//! receiving the [`Event::PaymentPathFailed`] and [`Event::PaymentPathSuccessful`] events.
//! It also does the same for payment probe failure and success events using [`Event::ProbeFailed`]
//! and [`Event::ProbeSuccessful`].
//!
//! [`InvoicePayer`] is capable of retrying failed payments. It accomplishes this by implementing
//! [`EventHandler`] which decorates a user-provided handler. It will intercept any
//! [`Event::PaymentPathFailed`] events and retry the failed paths for a fixed number of total
//! attempts or until retry is no longer possible. In such a situation, [`InvoicePayer`] will pass
//! along the events to the user-provided handler.
//!
//! # Example
//!
//! ```
//! # extern crate lightning;
//! # extern crate lightning_invoice;
//! # extern crate secp256k1;
//! #
//! # use lightning::io;
//! # use lightning::ln::{PaymentHash, PaymentPreimage, PaymentSecret};
//! # use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
//! # use lightning::ln::msgs::LightningError;
//! # use lightning::routing::gossip::NodeId;
//! # use lightning::routing::router::{InFlightHtlcs, Route, RouteHop, RouteParameters, Router};
//! # use lightning::routing::scoring::{ChannelUsage, Score};
//! # use lightning::util::events::{Event, EventHandler, EventsProvider};
//! # use lightning::util::logger::{Logger, Record};
//! # use lightning::util::ser::{Writeable, Writer};
//! # use lightning_invoice::Invoice;
//! # use lightning_invoice::payment::{InvoicePayer, Payer, Retry};
//! # use secp256k1::PublicKey;
//! # use std::cell::RefCell;
//! # use std::ops::Deref;
//! #
//! # struct FakeEventProvider {}
//! # impl EventsProvider for FakeEventProvider {
//! #     fn process_pending_events<H: Deref>(&self, handler: H) where H::Target: EventHandler {}
//! # }
//! #
//! # struct FakePayer {}
//! # impl Payer for FakePayer {
//! #     fn node_id(&self) -> PublicKey { unimplemented!() }
//! #     fn first_hops(&self) -> Vec<ChannelDetails> { unimplemented!() }
//! #     fn send_payment(
//! #         &self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>,
//! #         payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn send_spontaneous_payment(
//! #         &self, route: &Route, payment_preimage: PaymentPreimage, payment_id: PaymentId,
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn retry_payment(
//! #         &self, route: &Route, payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! #     fn abandon_payment(&self, payment_id: PaymentId) { unimplemented!() }
//! #     fn inflight_htlcs(&self) -> InFlightHtlcs { unimplemented!() }
//! # }
//! #
//! # struct FakeRouter {}
//! # impl Router for FakeRouter {
//! #     fn find_route(
//! #         &self, payer: &PublicKey, params: &RouteParameters,
//! #         first_hops: Option<&[&ChannelDetails]>, _inflight_htlcs: InFlightHtlcs
//! #     ) -> Result<Route, LightningError> { unimplemented!() }
//! #     fn notify_payment_path_failed(&self, path: &[&RouteHop], short_channel_id: u64) {  unimplemented!() }
//! #     fn notify_payment_path_successful(&self, path: &[&RouteHop]) {  unimplemented!() }
//! #     fn notify_payment_probe_successful(&self, path: &[&RouteHop]) {  unimplemented!() }
//! #     fn notify_payment_probe_failed(&self, path: &[&RouteHop], short_channel_id: u64) { unimplemented!() }
//! # }
//! #
//! # struct FakeScorer {}
//! # impl Writeable for FakeScorer {
//! #     fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> { unimplemented!(); }
//! # }
//! # impl Score for FakeScorer {
//! #     fn channel_penalty_msat(
//! #         &self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId, _usage: ChannelUsage
//! #     ) -> u64 { 0 }
//! #     fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! #     fn payment_path_successful(&mut self, _path: &[&RouteHop]) {}
//! #     fn probe_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! #     fn probe_successful(&mut self, _path: &[&RouteHop]) {}
//! # }
//! #
//! # struct FakeLogger {}
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! #
//! # fn main() {
//! let event_handler = |event: Event| {
//!     match event {
//!         Event::PaymentPathFailed { .. } => println!(\"payment failed after retries\"),
//!         Event::PaymentSent { .. } => println!(\"payment successful\"),
//!         _ => {},
//!     }
//! };
//! # let payer = FakePayer {};
//! # let router = FakeRouter {};
//! # let scorer = RefCell::new(FakeScorer {});
//! # let logger = FakeLogger {};
//! let invoice_payer = InvoicePayer::new(&payer, router, &logger, event_handler, Retry::Attempts(2));
//!
//! let invoice = \"...\";
//! if let Ok(invoice) = invoice.parse::<Invoice>() {
//!     invoice_payer.pay_invoice(&invoice).unwrap();
//!
//! # let event_provider = FakeEventProvider {};
//!     loop {
//!         event_provider.process_pending_events(&invoice_payer);
//!     }
//! }
//! # }
//! ```
//!
//! # Note
//!
//! The [`Route`] is computed before each payment attempt. Any updates affecting path finding such
//! as updates to the network graph or changes to channel scores should be applied prior to
//! retries, typically by way of composing [`EventHandler`]s accordingly.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_invoice::payment::InvoicePayer as nativeInvoicePayerImport;
pub(crate) type nativeInvoicePayer = nativeInvoicePayerImport<crate::lightning_invoice::payment::Payer, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger, crate::lightning::util::events::EventHandler>;

/// A utility for paying [`Invoice`]s and sending spontaneous payments.
///
/// See [module-level documentation] for details.
///
/// [module-level documentation]: crate::payment
#[must_use]
#[repr(C)]
pub struct InvoicePayer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoicePayer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoicePayer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoicePayer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoicePayer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoicePayer_free(this_obj: InvoicePayer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoicePayer_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoicePayer) };
}
#[allow(unused)]
impl InvoicePayer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoicePayer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoicePayer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoicePayer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// A trait defining behavior of an [`Invoice`] payer.
///
/// While the behavior of [`InvoicePayer`] provides idempotency of duplicate `send_*payment` calls
/// with the same [`PaymentHash`], it is up to the `Payer` to provide idempotency across restarts.
///
/// [`ChannelManager`] provides idempotency for duplicate payments with the same [`PaymentId`].
///
/// In order to trivially ensure idempotency for payments, the default `Payer` implementation
/// reuses the [`PaymentHash`] bytes as the [`PaymentId`]. Custom implementations wishing to
/// provide payment idempotency with a different idempotency key (i.e. [`PaymentId`]) should map
/// the [`Invoice`] or spontaneous payment target pubkey to their own idempotency key.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
#[repr(C)]
pub struct Payer {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the payer's node id.
	#[must_use]
	pub node_id: extern "C" fn (this_arg: *const c_void) -> crate::c_types::PublicKey,
	/// Returns the payer's channels.
	#[must_use]
	pub first_hops: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_ChannelDetailsZ,
	/// Sends a payment over the Lightning Network using the given [`Route`].
	///
	/// Note that payment_secret (or a relevant inner pointer) may be NULL or all-0s to represent None
	#[must_use]
	pub send_payment: extern "C" fn (this_arg: *const c_void, route: &crate::lightning::routing::router::Route, payment_hash: crate::c_types::ThirtyTwoBytes, payment_secret: crate::c_types::ThirtyTwoBytes, payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ,
	/// Sends a spontaneous payment over the Lightning Network using the given [`Route`].
	#[must_use]
	pub send_spontaneous_payment: extern "C" fn (this_arg: *const c_void, route: &crate::lightning::routing::router::Route, payment_preimage: crate::c_types::ThirtyTwoBytes, payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ,
	/// Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	#[must_use]
	pub retry_payment: extern "C" fn (this_arg: *const c_void, route: &crate::lightning::routing::router::Route, payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ,
	/// Signals that no further retries for the given payment will occur.
	pub abandon_payment: extern "C" fn (this_arg: *const c_void, payment_id: crate::c_types::ThirtyTwoBytes),
	/// Construct an [`InFlightHtlcs`] containing information about currently used up liquidity
	/// across payments.
	#[must_use]
	pub inflight_htlcs: extern "C" fn (this_arg: *const c_void) -> crate::lightning::routing::router::InFlightHtlcs,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Payer {}
unsafe impl Sync for Payer {}
#[no_mangle]
pub(crate) extern "C" fn Payer_clone_fields(orig: &Payer) -> Payer {
	Payer {
		this_arg: orig.this_arg,
		node_id: Clone::clone(&orig.node_id),
		first_hops: Clone::clone(&orig.first_hops),
		send_payment: Clone::clone(&orig.send_payment),
		send_spontaneous_payment: Clone::clone(&orig.send_spontaneous_payment),
		retry_payment: Clone::clone(&orig.retry_payment),
		abandon_payment: Clone::clone(&orig.abandon_payment),
		inflight_htlcs: Clone::clone(&orig.inflight_htlcs),
		free: Clone::clone(&orig.free),
	}
}

use lightning_invoice::payment::Payer as rustPayer;
impl rustPayer for Payer {
	fn node_id(&self) -> secp256k1::PublicKey {
		let mut ret = (self.node_id)(self.this_arg);
		ret.into_rust()
	}
	fn first_hops(&self) -> Vec<lightning::ln::channelmanager::ChannelDetails> {
		let mut ret = (self.first_hops)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
		local_ret
	}
	fn send_payment(&self, mut route: &lightning::routing::router::Route, mut payment_hash: lightning::ln::PaymentHash, mut payment_secret: &Option<lightning::ln::PaymentSecret>, mut payment_id: lightning::ln::channelmanager::PaymentId) -> Result<(), lightning::ln::channelmanager::PaymentSendFailure> {
		let mut local_payment_secret = if payment_secret.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_secret.unwrap()).0 } } };
		let mut ret = (self.send_payment)(self.this_arg, &crate::lightning::routing::router::Route { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route as *const lightning::routing::router::Route<>) as *mut _) }, is_owned: false }, crate::c_types::ThirtyTwoBytes { data: payment_hash.0 }, local_payment_secret, crate::c_types::ThirtyTwoBytes { data: payment_id.0 });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn send_spontaneous_payment(&self, mut route: &lightning::routing::router::Route, mut payment_preimage: lightning::ln::PaymentPreimage, mut payment_id: lightning::ln::channelmanager::PaymentId) -> Result<(), lightning::ln::channelmanager::PaymentSendFailure> {
		let mut ret = (self.send_spontaneous_payment)(self.this_arg, &crate::lightning::routing::router::Route { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route as *const lightning::routing::router::Route<>) as *mut _) }, is_owned: false }, crate::c_types::ThirtyTwoBytes { data: payment_preimage.0 }, crate::c_types::ThirtyTwoBytes { data: payment_id.0 });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn retry_payment(&self, mut route: &lightning::routing::router::Route, mut payment_id: lightning::ln::channelmanager::PaymentId) -> Result<(), lightning::ln::channelmanager::PaymentSendFailure> {
		let mut ret = (self.retry_payment)(self.this_arg, &crate::lightning::routing::router::Route { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route as *const lightning::routing::router::Route<>) as *mut _) }, is_owned: false }, crate::c_types::ThirtyTwoBytes { data: payment_id.0 });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn abandon_payment(&self, mut payment_id: lightning::ln::channelmanager::PaymentId) {
		(self.abandon_payment)(self.this_arg, crate::c_types::ThirtyTwoBytes { data: payment_id.0 })
	}
	fn inflight_htlcs(&self) -> lightning::routing::router::InFlightHtlcs {
		let mut ret = (self.inflight_htlcs)(self.this_arg);
		*unsafe { Box::from_raw(ret.take_inner()) }
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Payer {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Payer_free(this_ptr: Payer) { }
impl Drop for Payer {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Strategies available to retry payment path failures for an [`Invoice`].
///
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Retry {
	/// Max number of attempts to retry payment.
	///
	/// Note that this is the number of *path* failures, not full payment retries. For multi-path
	/// payments, if this is less than the total number of paths, we will never even retry all of the
	/// payment's paths.
	Attempts(
		usize),
	/// Time elapsed before abandoning retries for a payment.
	Timeout(
		u64),
}
use lightning_invoice::payment::Retry as RetryImport;
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
/// An error that may occur when making a payment.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentError {
	/// An error resulting from the provided [`Invoice`] or payment hash.
	Invoice(
		crate::c_types::Str),
	/// An error occurring when finding a route.
	Routing(
		crate::lightning::ln::msgs::LightningError),
	/// An error occurring when sending a payment.
	Sending(
		crate::lightning::ln::channelmanager::PaymentSendFailure),
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
			PaymentError::Routing (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentError::Routing (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
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
			PaymentError::Routing (mut a, ) => {
				nativePaymentError::Routing (
					*unsafe { Box::from_raw(a.take_inner()) },
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
			nativePaymentError::Routing (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentError::Routing (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativePaymentError::Sending (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentError::Sending (
					crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(a_nonref),
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
			nativePaymentError::Routing (mut a, ) => {
				PaymentError::Routing (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativePaymentError::Sending (mut a, ) => {
				PaymentError::Sending (
					crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(a),
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
#[no_mangle]
/// Utility method to constructs a new Invoice-variant PaymentError
pub extern "C" fn PaymentError_invoice(a: crate::c_types::Str) -> PaymentError {
	PaymentError::Invoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new Routing-variant PaymentError
pub extern "C" fn PaymentError_routing(a: crate::lightning::ln::msgs::LightningError) -> PaymentError {
	PaymentError::Routing(a, )
}
#[no_mangle]
/// Utility method to constructs a new Sending-variant PaymentError
pub extern "C" fn PaymentError_sending(a: crate::lightning::ln::channelmanager::PaymentSendFailure) -> PaymentError {
	PaymentError::Sending(a, )
}
/// Creates an invoice payer that retries failed payment paths.
///
/// Will forward any [`Event::PaymentPathFailed`] events to the decorated `event_handler` once
/// `retry` has been exceeded for a given [`Invoice`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_new(mut payer: crate::lightning_invoice::payment::Payer, mut router: crate::lightning::routing::router::Router, mut logger: crate::lightning::util::logger::Logger, mut event_handler: crate::lightning::util::events::EventHandler, mut retry: crate::lightning_invoice::payment::Retry) -> crate::lightning_invoice::payment::InvoicePayer {
	let mut ret = lightning_invoice::payment::InvoicePayer::new(payer, router, logger, event_handler, retry.into_native());
	crate::lightning_invoice::payment::InvoicePayer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Pays the given [`Invoice`], caching it for later use in case a retry is needed.
///
/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. Once the payment completes or fails, you must ensure that
/// a second payment with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see
/// [`Self::pay_invoice_with_id`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_invoice(this_arg: &crate::lightning_invoice::payment::InvoicePayer, invoice: &crate::lightning_invoice::Invoice) -> crate::c_types::derived::CResult_PaymentIdPaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_invoice(invoice.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given [`Invoice`] with a custom idempotency key, caching the invoice for later use
/// in case a retry is needed.
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
/// has never been paid before.
///
/// See [`Self::pay_invoice`] for a variant which uses the [`PaymentHash`] for the idempotency
/// token.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_invoice_with_id(this_arg: &crate::lightning_invoice::payment::InvoicePayer, invoice: &crate::lightning_invoice::Invoice, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_invoice_with_id(invoice.get_native_ref(), ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given zero-value [`Invoice`] using the given amount, caching it for later use in
/// case a retry is needed.
///
/// [`Invoice::payment_hash`] is used as the [`PaymentId`], which ensures idempotency as long
/// as the payment is still pending. Once the payment completes or fails, you must ensure that
/// a second payment with the same [`PaymentHash`] is never sent.
///
/// If you wish to use a different payment idempotency token, see
/// [`Self::pay_zero_value_invoice_with_id`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_zero_value_invoice(this_arg: &crate::lightning_invoice::payment::InvoicePayer, invoice: &crate::lightning_invoice::Invoice, mut amount_msats: u64) -> crate::c_types::derived::CResult_PaymentIdPaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_zero_value_invoice(invoice.get_native_ref(), amount_msats);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given zero-value [`Invoice`] using the given amount and custom idempotency key,
/// caching the invoice for later use in case a retry is needed.
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`Invoice::payment_hash`] is unique and the same [`PaymentHash`]
/// has never been paid before.
///
/// See [`Self::pay_zero_value_invoice`] for a variant which uses the [`PaymentHash`] for the
/// idempotency token.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_zero_value_invoice_with_id(this_arg: &crate::lightning_invoice::payment::InvoicePayer, invoice: &crate::lightning_invoice::Invoice, mut amount_msats: u64, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_zero_value_invoice_with_id(invoice.get_native_ref(), amount_msats, ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays `pubkey` an amount using the hash of the given preimage, caching it for later use in
/// case a retry is needed.
///
/// The hash of the [`PaymentPreimage`] is used as the [`PaymentId`], which ensures idempotency
/// as long as the payment is still pending. Once the payment completes or fails, you must
/// ensure that a second payment with the same [`PaymentPreimage`] is never sent.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_pubkey(this_arg: &crate::lightning_invoice::payment::InvoicePayer, mut pubkey: crate::c_types::PublicKey, mut payment_preimage: crate::c_types::ThirtyTwoBytes, mut amount_msats: u64, mut final_cltv_expiry_delta: u32) -> crate::c_types::derived::CResult_PaymentIdPaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_pubkey(pubkey.into_rust(), ::lightning::ln::PaymentPreimage(payment_preimage.data), amount_msats, final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays `pubkey` an amount using the hash of the given preimage and a custom idempotency key,
/// caching the invoice for later use in case a retry is needed.
///
/// Note that idempotency is only guaranteed as long as the payment is still pending. Once the
/// payment completes or fails, no idempotency guarantees are made.
///
/// You should ensure that the [`PaymentPreimage`] is unique and the corresponding
/// [`PaymentHash`] has never been paid before.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_pubkey_with_id(this_arg: &crate::lightning_invoice::payment::InvoicePayer, mut pubkey: crate::c_types::PublicKey, mut payment_preimage: crate::c_types::ThirtyTwoBytes, mut payment_id: crate::c_types::ThirtyTwoBytes, mut amount_msats: u64, mut final_cltv_expiry_delta: u32) -> crate::c_types::derived::CResult_NonePaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_pubkey_with_id(pubkey.into_rust(), ::lightning::ln::PaymentPreimage(payment_preimage.data), ::lightning::ln::channelmanager::PaymentId(payment_id.data), amount_msats, final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Removes the payment cached by the given payment hash.
///
/// Should be called once a payment has failed or succeeded if not using [`InvoicePayer`] as an
/// [`EventHandler`]. Otherwise, calling this method is unnecessary.
#[no_mangle]
pub extern "C" fn InvoicePayer_remove_cached_payment(this_arg: &crate::lightning_invoice::payment::InvoicePayer, payment_hash: *const [u8; 32]) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.remove_cached_payment(&::lightning::ln::PaymentHash(unsafe { *payment_hash }))
}

impl From<nativeInvoicePayer> for crate::lightning::util::events::EventHandler {
	fn from(obj: nativeInvoicePayer) -> Self {
		let mut rust_obj = InvoicePayer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InvoicePayer_as_EventHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(InvoicePayer_free_void);
		ret
	}
}
/// Constructs a new EventHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn InvoicePayer_as_EventHandler(this_arg: &InvoicePayer) -> crate::lightning::util::events::EventHandler {
	crate::lightning::util::events::EventHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_event: InvoicePayer_EventHandler_handle_event,
	}
}

extern "C" fn InvoicePayer_EventHandler_handle_event(this_arg: *const c_void, mut event: crate::lightning::util::events::Event) {
	<nativeInvoicePayer as lightning::util::events::EventHandler<>>::handle_event(unsafe { &mut *(this_arg as *mut nativeInvoicePayer) }, event.into_native())
}

