// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A module for paying Lightning invoices.
//!
//! Defines an [`InvoicePayer`] utility for paying invoices, parameterized by [`Payer`] and
//! [`Router`] traits. Implementations of [`Payer`] provide the payer's node id, channels, and means
//! to send a payment over a [`Route`]. Implementations of [`Router`] find a [`Route`] between payer
//! and payee using information provided by the payer and from the payee's [`Invoice`].
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
//! # use lightning::ln::{PaymentHash, PaymentSecret};
//! # use lightning::ln::channelmanager::{ChannelDetails, PaymentId, PaymentSendFailure};
//! # use lightning::ln::msgs::LightningError;
//! # use lightning::routing::{self, LockableScore};
//! # use lightning::routing::network_graph::NodeId;
//! # use lightning::routing::router::{Route, RouteHop, RouteParameters};
//! # use lightning::util::events::{Event, EventHandler, EventsProvider};
//! # use lightning::util::logger::{Logger, Record};
//! # use lightning_invoice::Invoice;
//! # use lightning_invoice::payment::{InvoicePayer, Payer, RetryAttempts, Router};
//! # use secp256k1::key::PublicKey;
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
//! #         &self, route: &Route, payment_hash: PaymentHash, payment_secret: &Option<PaymentSecret>
//! #     ) -> Result<PaymentId, PaymentSendFailure> { unimplemented!() }
//! #     fn retry_payment(
//! #         &self, route: &Route, payment_id: PaymentId
//! #     ) -> Result<(), PaymentSendFailure> { unimplemented!() }
//! # }
//! #
//! # struct FakeRouter {};
//! # impl<S: routing::Score> Router<S> for FakeRouter {
//! #     fn find_route(
//! #         &self, payer: &PublicKey, params: &RouteParameters,
//! #         first_hops: Option<&[&ChannelDetails]>, scorer: &S
//! #     ) -> Result<Route, LightningError> { unimplemented!() }
//! # }
//! #
//! # struct FakeScorer {};
//! # impl lightning::util::ser::Writeable for FakeScorer {
//! #     fn write<W: lightning::util::ser::Writer>(&self, _: &mut W) -> Result<(), std::io::Error> { unreachable!(); }
//! # }
//! # impl routing::Score for FakeScorer {
//! #     fn channel_penalty_msat(
//! #         &self, _short_channel_id: u64, _source: &NodeId, _target: &NodeId
//! #     ) -> u64 { 0 }
//! #     fn payment_path_failed(&mut self, _path: &[&RouteHop], _short_channel_id: u64) {}
//! # }
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! #
//! # fn main() {
//! let event_handler = |event: &Event| {
//!     match event {
//!         Event::PaymentPathFailed { .. } => println!(\"payment failed after retries\"),
//!         Event::PaymentSent { .. } => println!(\"payment successful\"),
//!         _ => {},
//!     }
//! };
//! # let payer = FakePayer {};
//! # let router = FakeRouter {};
//! # let scorer = LockableScore::new(FakeScorer {});
//! # let logger = FakeLogger {};
//! let invoice_payer = InvoicePayer::new(&payer, router, &scorer, &logger, event_handler, RetryAttempts(2));
//!
//! let invoice = \"...\";
//! let invoice = invoice.parse::<Invoice>().unwrap();
//! invoice_payer.pay_invoice(&invoice).unwrap();
//!
//! # let event_provider = FakeEventProvider {};
//! loop {
//!     event_provider.process_pending_events(&invoice_payer);
//! }
//! # }
//! ```
//!
//! # Note
//!
//! The [`Route`] is computed before each payment attempt. Any updates affecting path finding such
//! as updates to the network graph or changes to channel scores should be applied prior to
//! retries, typically by way of composing [`EventHandler`]s accordingly.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning_invoice::payment::InvoicePayer as nativeInvoicePayerImport;
pub(crate) type nativeInvoicePayer = nativeInvoicePayerImport<crate::lightning_invoice::payment::Payer, crate::lightning_invoice::payment::Router, crate::lightning::routing::Score, &'static lightning::routing::LockableScore<crate::lightning::routing::Score>, crate::lightning::util::logger::Logger, crate::lightning::util::events::EventHandler>;

/// A utility for paying [`Invoice]`s.
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
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInvoicePayer); }
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
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A trait defining behavior of an [`Invoice`] payer.
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
	pub send_payment: extern "C" fn (this_arg: *const c_void, route: &crate::lightning::routing::router::Route, payment_hash: crate::c_types::ThirtyTwoBytes, payment_secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_PaymentIdPaymentSendFailureZ,
	/// Retries a failed payment path for the [`PaymentId`] using the given [`Route`].
	#[must_use]
	pub retry_payment: extern "C" fn (this_arg: *const c_void, route: &crate::lightning::routing::router::Route, payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ,
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
		retry_payment: Clone::clone(&orig.retry_payment),
		free: Clone::clone(&orig.free),
	}
}

use lightning_invoice::payment::Payer as rustPayer;
impl rustPayer for Payer {
	fn node_id(&self) -> secp256k1::key::PublicKey {
		let mut ret = (self.node_id)(self.this_arg);
		ret.into_rust()
	}
	fn first_hops(&self) -> Vec<lightning::ln::channelmanager::ChannelDetails> {
		let mut ret = (self.first_hops)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
		local_ret
	}
	fn send_payment(&self, mut route: &lightning::routing::router::Route, mut payment_hash: lightning::ln::PaymentHash, mut payment_secret: &Option<lightning::ln::PaymentSecret>) -> Result<lightning::ln::channelmanager::PaymentId, lightning::ln::channelmanager::PaymentSendFailure> {
		let mut local_payment_secret = if payment_secret.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_secret.unwrap()).0 } } };
		let mut ret = (self.send_payment)(self.this_arg, &crate::lightning::routing::router::Route { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route as *const lightning::routing::router::Route<>) as *mut _) }, is_owned: false }, crate::c_types::ThirtyTwoBytes { data: payment_hash.0 }, local_payment_secret);
		let mut local_ret = match ret.result_ok { true => Ok( { ::lightning::ln::channelmanager::PaymentId((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).data) }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn retry_payment(&self, mut route: &lightning::routing::router::Route, mut payment_id: lightning::ln::channelmanager::PaymentId) -> Result<(), lightning::ln::channelmanager::PaymentSendFailure> {
		let mut ret = (self.retry_payment)(self.this_arg, &crate::lightning::routing::router::Route { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route as *const lightning::routing::router::Route<>) as *mut _) }, is_owned: false }, crate::c_types::ThirtyTwoBytes { data: payment_id.0 });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Payer {
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
/// A trait defining behavior for routing an [`Invoice`] payment.
#[repr(C)]
pub struct Router {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Finds a [`Route`] between `payer` and `payee` for a payment with the given values.
	///
	/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
	#[must_use]
	pub find_route: extern "C" fn (this_arg: *const c_void, payer: crate::c_types::PublicKey, params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, scorer: &crate::lightning::routing::Score) -> crate::c_types::derived::CResult_RouteLightningErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Router {}
unsafe impl Sync for Router {}
#[no_mangle]
pub(crate) extern "C" fn Router_clone_fields(orig: &Router) -> Router {
	Router {
		this_arg: orig.this_arg,
		find_route: Clone::clone(&orig.find_route),
		free: Clone::clone(&orig.free),
	}
}

use lightning_invoice::payment::Router as rustRouter;
impl rustRouter<crate::lightning::routing::Score> for Router {
	fn find_route(&self, mut payer: &secp256k1::key::PublicKey, mut params: &lightning::routing::router::RouteParameters, mut first_hops: Option<&[&lightning::ln::channelmanager::ChannelDetails]>, mut scorer: &crate::lightning::routing::Score) -> Result<lightning::routing::router::Route, lightning::ln::msgs::LightningError> {
		let mut local_first_hops_base = if first_hops.is_none() { SmartPtr::null() } else { SmartPtr::from_obj( { let mut local_first_hops_0 = Vec::new(); for item in (first_hops.unwrap()).iter() { local_first_hops_0.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::ln::channelmanager::ChannelDetails<>) as *mut _) }, is_owned: false } }); }; local_first_hops_0.into() }) }; let mut local_first_hops = *local_first_hops_base;
		let mut ret = (self.find_route)(self.this_arg, crate::c_types::PublicKey::from_rust(&payer), &crate::lightning::routing::router::RouteParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((params as *const lightning::routing::router::RouteParameters<>) as *mut _) }, is_owned: false }, local_first_hops, scorer);
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Router {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Router_free(this_ptr: Router) { }
impl Drop for Router {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning_invoice::payment::RetryAttempts as nativeRetryAttemptsImport;
pub(crate) type nativeRetryAttempts = nativeRetryAttemptsImport;

/// Number of attempts to retry payment path failures for an [`Invoice`].
///
/// Note that this is the number of *path* failures, not full payment retries. For multi-path
/// payments, if this is less than the total number of paths, we will never even retry all of the
/// payment's paths.
#[must_use]
#[repr(C)]
pub struct RetryAttempts {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRetryAttempts,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RetryAttempts {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRetryAttempts>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RetryAttempts, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RetryAttempts_free(this_obj: RetryAttempts) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RetryAttempts_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRetryAttempts); }
}
#[allow(unused)]
impl RetryAttempts {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRetryAttempts {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRetryAttempts {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRetryAttempts {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn RetryAttempts_get_a(this_ptr: &RetryAttempts) -> usize {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn RetryAttempts_set_a(this_ptr: &mut RetryAttempts, mut val: usize) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new RetryAttempts given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RetryAttempts_new(mut a_arg: usize) -> RetryAttempts {
	RetryAttempts { inner: ObjOps::heap_alloc(lightning_invoice::payment::RetryAttempts (
		a_arg,
	)), is_owned: true }
}
impl Clone for RetryAttempts {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRetryAttempts>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RetryAttempts_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRetryAttempts)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RetryAttempts
pub extern "C" fn RetryAttempts_clone(orig: &RetryAttempts) -> RetryAttempts {
	orig.clone()
}
/// Checks if two RetryAttemptss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RetryAttempts_eq(a: &RetryAttempts, b: &RetryAttempts) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two RetryAttemptss contain equal inner contents.
#[no_mangle]
pub extern "C" fn RetryAttempts_hash(o: &RetryAttempts) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// An error that may occur when making a payment.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum PaymentError {
	/// An error resulting from the provided [`Invoice`] or payment hash.
	Invoice(crate::c_types::Str),
	/// An error occurring when finding a route.
	Routing(crate::lightning::ln::msgs::LightningError),
	/// An error occurring when sending a payment.
	Sending(crate::lightning::ln::channelmanager::PaymentSendFailure),
}
use lightning_invoice::payment::PaymentError as nativePaymentError;
impl PaymentError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentError {
		match self {
			PaymentError::Invoice (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativePaymentError::Invoice (
					a_nonref.into_str(),
				)
			},
			PaymentError::Routing (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativePaymentError::Routing (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			PaymentError::Sending (ref a, ) => {
				let mut a_nonref = (*a).clone();
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
				let mut a_nonref = (*a).clone();
				PaymentError::Invoice (
					a_nonref.into(),
				)
			},
			nativePaymentError::Routing (ref a, ) => {
				let mut a_nonref = (*a).clone();
				PaymentError::Routing (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativePaymentError::Sending (ref a, ) => {
				let mut a_nonref = (*a).clone();
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
/// `retry_attempts` has been exceeded for a given [`Invoice`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_new(mut payer: crate::lightning_invoice::payment::Payer, mut router: crate::lightning_invoice::payment::Router, scorer: &crate::lightning::routing::LockableScore, mut logger: crate::lightning::util::logger::Logger, mut event_handler: crate::lightning::util::events::EventHandler, mut retry_attempts: crate::lightning_invoice::payment::RetryAttempts) -> InvoicePayer {
	let mut ret = lightning_invoice::payment::InvoicePayer::new(payer, router, scorer.get_native_ref(), logger, event_handler, *unsafe { Box::from_raw(retry_attempts.take_inner()) });
	InvoicePayer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Pays the given [`Invoice`], caching it for later use in case a retry is needed.
///
/// You should ensure that the `invoice.payment_hash()` is unique and the same payment_hash has
/// never been paid before. Because [`InvoicePayer`] is stateless no effort is made to do so
/// for you.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_invoice(this_arg: &InvoicePayer, invoice: &crate::lightning_invoice::Invoice) -> crate::c_types::derived::CResult_PaymentIdPaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_invoice(invoice.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Pays the given zero-value [`Invoice`] using the given amount, caching it for later use in
/// case a retry is needed.
///
/// You should ensure that the `invoice.payment_hash()` is unique and the same payment_hash has
/// never been paid before. Because [`InvoicePayer`] is stateless no effort is made to do so
/// for you.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoicePayer_pay_zero_value_invoice(this_arg: &InvoicePayer, invoice: &crate::lightning_invoice::Invoice, mut amount_msats: u64) -> crate::c_types::derived::CResult_PaymentIdPaymentErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.pay_zero_value_invoice(invoice.get_native_ref(), amount_msats);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::payment::PaymentError::native_into(e) }).into() };
	local_ret
}

/// Removes the payment cached by the given payment hash.
///
/// Should be called once a payment has failed or succeeded if not using [`InvoicePayer`] as an
/// [`EventHandler`]. Otherwise, calling this method is unnecessary.
#[no_mangle]
pub extern "C" fn InvoicePayer_remove_cached_payment(this_arg: &InvoicePayer, payment_hash: *const [u8; 32]) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.remove_cached_payment(&::lightning::ln::PaymentHash(unsafe { *payment_hash }))
}

impl From<nativeInvoicePayer> for crate::lightning::util::events::EventHandler {
	fn from(obj: nativeInvoicePayer) -> Self {
		let mut rust_obj = InvoicePayer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InvoicePayer_as_EventHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
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

extern "C" fn InvoicePayer_EventHandler_handle_event(this_arg: *const c_void, event: &crate::lightning::util::events::Event) {
	<nativeInvoicePayer as lightning::util::events::EventHandler<>>::handle_event(unsafe { &mut *(this_arg as *mut nativeInvoicePayer) }, &event.to_native())
}

