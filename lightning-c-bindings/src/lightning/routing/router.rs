// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! The router finds paths within a [`NetworkGraph`] for a payment.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::routing::router::DefaultRouter as nativeDefaultRouterImport;
pub(crate) type nativeDefaultRouter = nativeDefaultRouterImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger, crate::lightning::sign::EntropySource, crate::lightning::routing::scoring::LockableScore>;

/// A [`Router`] implemented using [`find_route`].
#[must_use]
#[repr(C)]
pub struct DefaultRouter {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDefaultRouter,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DefaultRouter {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDefaultRouter>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DefaultRouter, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DefaultRouter_free(this_obj: DefaultRouter) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DefaultRouter_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDefaultRouter) };
}
#[allow(unused)]
impl DefaultRouter {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDefaultRouter {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDefaultRouter {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDefaultRouter {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Creates a new router.
#[must_use]
#[no_mangle]
pub extern "C" fn DefaultRouter_new(network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut logger: crate::lightning::util::logger::Logger, mut entropy_source: crate::lightning::sign::EntropySource, mut scorer: crate::lightning::routing::scoring::LockableScore, mut score_params: crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> crate::lightning::routing::router::DefaultRouter {
	let mut ret = lightning::routing::router::DefaultRouter::new(network_graph.get_native_ref(), logger, entropy_source, scorer, *unsafe { Box::from_raw(score_params.take_inner()) });
	crate::lightning::routing::router::DefaultRouter { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeDefaultRouter> for crate::lightning::routing::router::Router {
	fn from(obj: nativeDefaultRouter) -> Self {
		let rust_obj = crate::lightning::routing::router::DefaultRouter { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = DefaultRouter_as_Router(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(DefaultRouter_free_void);
		ret
	}
}
/// Constructs a new Router which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Router must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DefaultRouter_as_Router(this_arg: &DefaultRouter) -> crate::lightning::routing::router::Router {
	crate::lightning::routing::router::Router {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		find_route: DefaultRouter_Router_find_route,
		find_route_with_id: DefaultRouter_Router_find_route_with_id,
		create_blinded_payment_paths: DefaultRouter_Router_create_blinded_payment_paths,
		MessageRouter: crate::lightning::onion_message::messenger::MessageRouter {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			find_path: DefaultRouter_MessageRouter_find_path,
			create_blinded_paths: DefaultRouter_MessageRouter_create_blinded_paths,
		},
	}
}

#[must_use]
extern "C" fn DefaultRouter_Router_find_route(this_arg: *const c_void, mut payer: crate::c_types::PublicKey, route_params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut inflight_htlcs: crate::lightning::routing::router::InFlightHtlcs) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == core::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut ret = <nativeDefaultRouter as lightning::routing::router::Router<>>::find_route(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, &payer.into_rust(), route_params.get_native_ref(), local_first_hops, *unsafe { Box::from_raw(inflight_htlcs.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn DefaultRouter_Router_find_route_with_id(this_arg: *const c_void, mut payer: crate::c_types::PublicKey, route_params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut inflight_htlcs: crate::lightning::routing::router::InFlightHtlcs, mut _payment_hash: crate::c_types::ThirtyTwoBytes, mut _payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == core::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut ret = <nativeDefaultRouter as lightning::routing::router::Router<>>::find_route_with_id(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, &payer.into_rust(), route_params.get_native_ref(), local_first_hops, *unsafe { Box::from_raw(inflight_htlcs.take_inner()) }, ::lightning::ln::PaymentHash(_payment_hash.data), ::lightning::ln::channelmanager::PaymentId(_payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn DefaultRouter_Router_create_blinded_payment_paths(this_arg: *const c_void, mut recipient: crate::c_types::PublicKey, mut first_hops: crate::c_types::derived::CVec_ChannelDetailsZ, mut tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, mut amount_msats: u64) -> crate::c_types::derived::CResult_CVec_C2Tuple_BlindedPayInfoBlindedPathZZNoneZ {
	let mut local_first_hops = Vec::new(); for mut item in first_hops.into_rust().drain(..) { local_first_hops.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = <nativeDefaultRouter as lightning::routing::router::Router<>>::create_blinded_payment_paths(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, recipient.into_rust(), local_first_hops, *unsafe { Box::from_raw(tlvs.take_inner()) }, amount_msats, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_ret_0_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativeDefaultRouter> for crate::lightning::onion_message::messenger::MessageRouter {
	fn from(obj: nativeDefaultRouter) -> Self {
		let rust_obj = crate::lightning::routing::router::DefaultRouter { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = DefaultRouter_as_MessageRouter(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(DefaultRouter_free_void);
		ret
	}
}
/// Constructs a new MessageRouter which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageRouter must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DefaultRouter_as_MessageRouter(this_arg: &DefaultRouter) -> crate::lightning::onion_message::messenger::MessageRouter {
	crate::lightning::onion_message::messenger::MessageRouter {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		find_path: DefaultRouter_MessageRouter_find_path,
		create_blinded_paths: DefaultRouter_MessageRouter_create_blinded_paths,
	}
}

#[must_use]
extern "C" fn DefaultRouter_MessageRouter_find_path(this_arg: *const c_void, mut sender: crate::c_types::PublicKey, mut peers: crate::c_types::derived::CVec_PublicKeyZ, mut destination: crate::lightning::onion_message::messenger::Destination) -> crate::c_types::derived::CResult_OnionMessagePathNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { item.into_rust() }); };
	let mut ret = <nativeDefaultRouter as lightning::onion_message::messenger::MessageRouter<>>::find_path(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, sender.into_rust(), local_peers, destination.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::OnionMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn DefaultRouter_MessageRouter_create_blinded_paths(this_arg: *const c_void, mut recipient: crate::c_types::PublicKey, mut peers: crate::c_types::derived::CVec_PublicKeyZ) -> crate::c_types::derived::CResult_CVec_BlindedPathZNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { item.into_rust() }); };
	let mut ret = <nativeDefaultRouter as lightning::onion_message::messenger::MessageRouter<>>::create_blinded_paths(unsafe { &mut *(this_arg as *mut nativeDefaultRouter) }, recipient.into_rust(), local_peers, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// A trait defining behavior for routing a payment.
#[repr(C)]
pub struct Router {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	///
	/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub find_route: extern "C" fn (this_arg: *const c_void, payer: crate::c_types::PublicKey, route_params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, inflight_htlcs: crate::lightning::routing::router::InFlightHtlcs) -> crate::c_types::derived::CResult_RouteLightningErrorZ,
	/// Finds a [`Route`] for a payment between the given `payer` and a payee.
	///
	/// The `payee` and the payment's value are given in [`RouteParameters::payment_params`]
	/// and [`RouteParameters::final_value_msat`], respectively.
	///
	/// Includes a [`PaymentHash`] and a [`PaymentId`] to be able to correlate the request with a specific
	/// payment.
	///
	/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub find_route_with_id: extern "C" fn (this_arg: *const c_void, payer: crate::c_types::PublicKey, route_params: &crate::lightning::routing::router::RouteParameters, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, inflight_htlcs: crate::lightning::routing::router::InFlightHtlcs, _payment_hash: crate::c_types::ThirtyTwoBytes, _payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_RouteLightningErrorZ,
	/// Creates [`BlindedPath`]s for payment to the `recipient` node. The channels in `first_hops`
	/// are assumed to be with the `recipient`'s peers. The payment secret and any constraints are
	/// given in `tlvs`.
	pub create_blinded_payment_paths: extern "C" fn (this_arg: *const c_void, recipient: crate::c_types::PublicKey, first_hops: crate::c_types::derived::CVec_ChannelDetailsZ, tlvs: crate::lightning::blinded_path::payment::ReceiveTlvs, amount_msats: u64) -> crate::c_types::derived::CResult_CVec_C2Tuple_BlindedPayInfoBlindedPathZZNoneZ,
	/// Implementation of MessageRouter for this object.
	pub MessageRouter: crate::lightning::onion_message::messenger::MessageRouter,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Router {}
unsafe impl Sync for Router {}
#[allow(unused)]
pub(crate) fn Router_clone_fields(orig: &Router) -> Router {
	Router {
		this_arg: orig.this_arg,
		find_route: Clone::clone(&orig.find_route),
		find_route_with_id: Clone::clone(&orig.find_route_with_id),
		create_blinded_payment_paths: Clone::clone(&orig.create_blinded_payment_paths),
		MessageRouter: crate::lightning::onion_message::messenger::MessageRouter_clone_fields(&orig.MessageRouter),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::onion_message::messenger::MessageRouter for Router {
	fn find_path(&self, mut sender: bitcoin::secp256k1::PublicKey, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut destination: lightning::onion_message::messenger::Destination) -> Result<lightning::onion_message::messenger::OnionMessagePath, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.MessageRouter.find_path)(self.MessageRouter.this_arg, crate::c_types::PublicKey::from_rust(&sender), local_peers.into(), crate::lightning::onion_message::messenger::Destination::native_into(destination));
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn create_blinded_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<lightning::blinded_path::BlindedPath>, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.MessageRouter.create_blinded_paths)(self.MessageRouter.this_arg, crate::c_types::PublicKey::from_rust(&recipient), local_peers.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

use lightning::routing::router::Router as rustRouter;
impl rustRouter for Router {
	fn find_route(&self, mut payer: &bitcoin::secp256k1::PublicKey, mut route_params: &lightning::routing::router::RouteParameters, mut first_hops: Option<&[&lightning::ln::channelmanager::ChannelDetails]>, mut inflight_htlcs: lightning::routing::router::InFlightHtlcs) -> Result<lightning::routing::router::Route, lightning::ln::msgs::LightningError> {
		let mut local_first_hops_base = if first_hops.is_none() { SmartPtr::null() } else { SmartPtr::from_obj( { let mut local_first_hops_0 = Vec::new(); for item in (first_hops.unwrap()).iter() { local_first_hops_0.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::ln::channelmanager::ChannelDetails<>) as *mut _) }, is_owned: false } }); }; local_first_hops_0.into() }) }; let mut local_first_hops = *local_first_hops_base;
		let mut ret = (self.find_route)(self.this_arg, crate::c_types::PublicKey::from_rust(&payer), &crate::lightning::routing::router::RouteParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route_params as *const lightning::routing::router::RouteParameters<>) as *mut _) }, is_owned: false }, local_first_hops, crate::lightning::routing::router::InFlightHtlcs { inner: ObjOps::heap_alloc(inflight_htlcs), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn find_route_with_id(&self, mut payer: &bitcoin::secp256k1::PublicKey, mut route_params: &lightning::routing::router::RouteParameters, mut first_hops: Option<&[&lightning::ln::channelmanager::ChannelDetails]>, mut inflight_htlcs: lightning::routing::router::InFlightHtlcs, mut _payment_hash: lightning::ln::PaymentHash, mut _payment_id: lightning::ln::channelmanager::PaymentId) -> Result<lightning::routing::router::Route, lightning::ln::msgs::LightningError> {
		let mut local_first_hops_base = if first_hops.is_none() { SmartPtr::null() } else { SmartPtr::from_obj( { let mut local_first_hops_0 = Vec::new(); for item in (first_hops.unwrap()).iter() { local_first_hops_0.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::ln::channelmanager::ChannelDetails<>) as *mut _) }, is_owned: false } }); }; local_first_hops_0.into() }) }; let mut local_first_hops = *local_first_hops_base;
		let mut ret = (self.find_route_with_id)(self.this_arg, crate::c_types::PublicKey::from_rust(&payer), &crate::lightning::routing::router::RouteParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((route_params as *const lightning::routing::router::RouteParameters<>) as *mut _) }, is_owned: false }, local_first_hops, crate::lightning::routing::router::InFlightHtlcs { inner: ObjOps::heap_alloc(inflight_htlcs), is_owned: true }, crate::c_types::ThirtyTwoBytes { data: _payment_hash.0 }, crate::c_types::ThirtyTwoBytes { data: _payment_id.0 });
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).take_inner()) } })};
		local_ret
	}
	fn create_blinded_payment_paths<T:bitcoin::secp256k1::Signing + bitcoin::secp256k1::Verification>(&self, mut recipient: bitcoin::secp256k1::PublicKey, mut first_hops: Vec<lightning::ln::channelmanager::ChannelDetails>, mut tlvs: lightning::blinded_path::payment::ReceiveTlvs, mut amount_msats: u64, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<T>) -> Result<Vec<(lightning::offers::invoice::BlindedPayInfo, lightning::blinded_path::BlindedPath)>, ()> {
		let mut local_first_hops = Vec::new(); for mut item in first_hops.drain(..) { local_first_hops.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut ret = (self.create_blinded_payment_paths)(self.this_arg, crate::c_types::PublicKey::from_rust(&recipient), local_first_hops.into(), crate::lightning::blinded_path::payment::ReceiveTlvs { inner: ObjOps::heap_alloc(tlvs), is_owned: true }, amount_msats);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item.to_rust(); let mut local_ret_0_0 = (*unsafe { Box::from_raw(orig_ret_0_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_ret_0_0_1.take_inner()) }); local_ret_0_0 }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Router {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for Router {
	fn deref_mut(&mut self) -> &mut Self {
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

use lightning::routing::router::ScorerAccountingForInFlightHtlcs as nativeScorerAccountingForInFlightHtlcsImport;
pub(crate) type nativeScorerAccountingForInFlightHtlcs = nativeScorerAccountingForInFlightHtlcsImport<'static, crate::lightning::routing::scoring::ScoreLookUp>;

/// [`ScoreLookUp`] implementation that factors in in-flight HTLC liquidity.
///
/// Useful for custom [`Router`] implementations to wrap their [`ScoreLookUp`] on-the-fly when calling
/// [`find_route`].
///
/// [`ScoreLookUp`]: crate::routing::scoring::ScoreLookUp
#[must_use]
#[repr(C)]
pub struct ScorerAccountingForInFlightHtlcs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeScorerAccountingForInFlightHtlcs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ScorerAccountingForInFlightHtlcs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeScorerAccountingForInFlightHtlcs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ScorerAccountingForInFlightHtlcs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ScorerAccountingForInFlightHtlcs_free(this_obj: ScorerAccountingForInFlightHtlcs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ScorerAccountingForInFlightHtlcs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeScorerAccountingForInFlightHtlcs) };
}
#[allow(unused)]
impl ScorerAccountingForInFlightHtlcs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeScorerAccountingForInFlightHtlcs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeScorerAccountingForInFlightHtlcs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeScorerAccountingForInFlightHtlcs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Initialize a new `ScorerAccountingForInFlightHtlcs`.
#[must_use]
#[no_mangle]
pub extern "C" fn ScorerAccountingForInFlightHtlcs_new(mut scorer: crate::lightning::routing::scoring::ScoreLookUp, inflight_htlcs: &crate::lightning::routing::router::InFlightHtlcs) -> crate::lightning::routing::router::ScorerAccountingForInFlightHtlcs {
	let mut ret = lightning::routing::router::ScorerAccountingForInFlightHtlcs::new(scorer, inflight_htlcs.get_native_ref());
	crate::lightning::routing::router::ScorerAccountingForInFlightHtlcs { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeScorerAccountingForInFlightHtlcs> for crate::lightning::routing::scoring::ScoreLookUp {
	fn from(obj: nativeScorerAccountingForInFlightHtlcs) -> Self {
		let rust_obj = crate::lightning::routing::router::ScorerAccountingForInFlightHtlcs { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ScorerAccountingForInFlightHtlcs_as_ScoreLookUp(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ScorerAccountingForInFlightHtlcs_free_void);
		ret
	}
}
/// Constructs a new ScoreLookUp which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreLookUp must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ScorerAccountingForInFlightHtlcs_as_ScoreLookUp(this_arg: &ScorerAccountingForInFlightHtlcs) -> crate::lightning::routing::scoring::ScoreLookUp {
	crate::lightning::routing::scoring::ScoreLookUp {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: ScorerAccountingForInFlightHtlcs_ScoreLookUp_channel_penalty_msat,
	}
}

#[must_use]
extern "C" fn ScorerAccountingForInFlightHtlcs_ScoreLookUp_channel_penalty_msat(this_arg: *const c_void, candidate: &crate::lightning::routing::router::CandidateRouteHop, mut usage: crate::lightning::routing::scoring::ChannelUsage, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
	let mut ret = <nativeScorerAccountingForInFlightHtlcs as lightning::routing::scoring::ScoreLookUp<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeScorerAccountingForInFlightHtlcs) }, &candidate.to_native(), *unsafe { Box::from_raw(usage.take_inner()) }, score_params.get_native_ref());
	ret
}


use lightning::routing::router::InFlightHtlcs as nativeInFlightHtlcsImport;
pub(crate) type nativeInFlightHtlcs = nativeInFlightHtlcsImport;

/// A data structure for tracking in-flight HTLCs. May be used during pathfinding to account for
/// in-use channel liquidity.
#[must_use]
#[repr(C)]
pub struct InFlightHtlcs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInFlightHtlcs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InFlightHtlcs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInFlightHtlcs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InFlightHtlcs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InFlightHtlcs_free(this_obj: InFlightHtlcs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InFlightHtlcs_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInFlightHtlcs) };
}
#[allow(unused)]
impl InFlightHtlcs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInFlightHtlcs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInFlightHtlcs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInFlightHtlcs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for InFlightHtlcs {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInFlightHtlcs>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InFlightHtlcs_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInFlightHtlcs)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InFlightHtlcs
pub extern "C" fn InFlightHtlcs_clone(orig: &InFlightHtlcs) -> InFlightHtlcs {
	orig.clone()
}
/// Constructs an empty `InFlightHtlcs`.
#[must_use]
#[no_mangle]
pub extern "C" fn InFlightHtlcs_new() -> crate::lightning::routing::router::InFlightHtlcs {
	let mut ret = lightning::routing::router::InFlightHtlcs::new();
	crate::lightning::routing::router::InFlightHtlcs { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Takes in a path with payer's node id and adds the path's details to `InFlightHtlcs`.
#[no_mangle]
pub extern "C" fn InFlightHtlcs_process_path(this_arg: &mut crate::lightning::routing::router::InFlightHtlcs, path: &crate::lightning::routing::router::Path, mut payer_node_id: crate::c_types::PublicKey) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::router::nativeInFlightHtlcs)) }.process_path(path.get_native_ref(), payer_node_id.into_rust())
}

/// Adds a known HTLC given the public key of the HTLC source, target, and short channel
/// id.
#[no_mangle]
pub extern "C" fn InFlightHtlcs_add_inflight_htlc(this_arg: &mut crate::lightning::routing::router::InFlightHtlcs, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut channel_scid: u64, mut used_msat: u64) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::router::nativeInFlightHtlcs)) }.add_inflight_htlc(source.get_native_ref(), target.get_native_ref(), channel_scid, used_msat)
}

/// Returns liquidity in msat given the public key of the HTLC source, target, and short channel
/// id.
#[must_use]
#[no_mangle]
pub extern "C" fn InFlightHtlcs_used_liquidity_msat(this_arg: &crate::lightning::routing::router::InFlightHtlcs, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut channel_scid: u64) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.used_liquidity_msat(source.get_native_ref(), target.get_native_ref(), channel_scid);
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

#[no_mangle]
/// Serialize the InFlightHtlcs object into a byte array which can be read by InFlightHtlcs_read
pub extern "C" fn InFlightHtlcs_write(obj: &crate::lightning::routing::router::InFlightHtlcs) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InFlightHtlcs_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInFlightHtlcs) })
}
#[no_mangle]
/// Read a InFlightHtlcs from a byte array, created by InFlightHtlcs_write
pub extern "C" fn InFlightHtlcs_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InFlightHtlcsDecodeErrorZ {
	let res: Result<lightning::routing::router::InFlightHtlcs, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::InFlightHtlcs { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::RouteHop as nativeRouteHopImport;
pub(crate) type nativeRouteHop = nativeRouteHopImport;

/// A hop in a route, and additional metadata about it. \"Hop\" is defined as a node and the channel
/// that leads to it.
#[must_use]
#[repr(C)]
pub struct RouteHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHop_free(this_obj: RouteHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteHop) };
}
#[allow(unused)]
impl RouteHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_get_pubkey(this_ptr: &RouteHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().pubkey;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_set_pubkey(this_ptr: &mut RouteHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.pubkey = val.into_rust();
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_get_node_features(this_ptr: &RouteHop) -> crate::lightning::ln::features::NodeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_features;
	crate::lightning::ln::features::NodeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::NodeFeatures<>) as *mut _) }, is_owned: false }
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_set_node_features(this_ptr: &mut RouteHop, mut val: crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_short_channel_id(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_short_channel_id(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_channel_features(this_ptr: &RouteHop) -> crate::lightning::ln::features::ChannelFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_features;
	crate::lightning::ln::features::ChannelFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::ChannelFeatures<>) as *mut _) }, is_owned: false }
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_channel_features(this_ptr: &mut RouteHop, mut val: crate::lightning::ln::features::ChannelFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
/// If this is the last hop in [`Path::hops`]:
/// * if we're sending to a [`BlindedPath`], this is the fee paid for use of the entire blinded path
/// * otherwise, this is the full value of this [`Path`]'s part of the payment
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn RouteHop_get_fee_msat(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_msat;
	*inner_val
}
/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
/// If this is the last hop in [`Path::hops`]:
/// * if we're sending to a [`BlindedPath`], this is the fee paid for use of the entire blinded path
/// * otherwise, this is the full value of this [`Path`]'s part of the payment
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn RouteHop_set_fee_msat(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_msat = val;
}
/// The CLTV delta added for this hop.
/// If this is the last hop in [`Path::hops`]:
/// * if we're sending to a [`BlindedPath`], this is the CLTV delta for the entire blinded path
/// * otherwise, this is the CLTV delta expected at the destination
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn RouteHop_get_cltv_expiry_delta(this_ptr: &RouteHop) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The CLTV delta added for this hop.
/// If this is the last hop in [`Path::hops`]:
/// * if we're sending to a [`BlindedPath`], this is the CLTV delta for the entire blinded path
/// * otherwise, this is the CLTV delta expected at the destination
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn RouteHop_set_cltv_expiry_delta(this_ptr: &mut RouteHop, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Indicates whether this hop is possibly announced in the public network graph.
///
/// Will be `true` if there is a possibility that the channel is publicly known, i.e., if we
/// either know for sure it's announced in the public graph, or if any public channels exist
/// for which the given `short_channel_id` could be an alias for. Will be `false` if we believe
/// the channel to be unannounced.
///
/// Will be `true` for objects serialized with LDK version 0.0.116 and before.
#[no_mangle]
pub extern "C" fn RouteHop_get_maybe_announced_channel(this_ptr: &RouteHop) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().maybe_announced_channel;
	*inner_val
}
/// Indicates whether this hop is possibly announced in the public network graph.
///
/// Will be `true` if there is a possibility that the channel is publicly known, i.e., if we
/// either know for sure it's announced in the public graph, or if any public channels exist
/// for which the given `short_channel_id` could be an alias for. Will be `false` if we believe
/// the channel to be unannounced.
///
/// Will be `true` for objects serialized with LDK version 0.0.116 and before.
#[no_mangle]
pub extern "C" fn RouteHop_set_maybe_announced_channel(this_ptr: &mut RouteHop, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.maybe_announced_channel = val;
}
/// Constructs a new RouteHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHop_new(mut pubkey_arg: crate::c_types::PublicKey, mut node_features_arg: crate::lightning::ln::features::NodeFeatures, mut short_channel_id_arg: u64, mut channel_features_arg: crate::lightning::ln::features::ChannelFeatures, mut fee_msat_arg: u64, mut cltv_expiry_delta_arg: u32, mut maybe_announced_channel_arg: bool) -> RouteHop {
	RouteHop { inner: ObjOps::heap_alloc(nativeRouteHop {
		pubkey: pubkey_arg.into_rust(),
		node_features: *unsafe { Box::from_raw(node_features_arg.take_inner()) },
		short_channel_id: short_channel_id_arg,
		channel_features: *unsafe { Box::from_raw(channel_features_arg.take_inner()) },
		fee_msat: fee_msat_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		maybe_announced_channel: maybe_announced_channel_arg,
	}), is_owned: true }
}
impl Clone for RouteHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHop>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHop
pub extern "C" fn RouteHop_clone(orig: &RouteHop) -> RouteHop {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteHop object
pub extern "C" fn RouteHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::RouteHop }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteHop.
#[no_mangle]
pub extern "C" fn RouteHop_hash(o: &RouteHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHop_eq(a: &RouteHop, b: &RouteHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the RouteHop object into a byte array which can be read by RouteHop_read
pub extern "C" fn RouteHop_write(obj: &crate::lightning::routing::router::RouteHop) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RouteHop_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRouteHop) })
}
#[no_mangle]
/// Read a RouteHop from a byte array, created by RouteHop_write
pub extern "C" fn RouteHop_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteHopDecodeErrorZ {
	let res: Result<lightning::routing::router::RouteHop, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::BlindedTail as nativeBlindedTailImport;
pub(crate) type nativeBlindedTail = nativeBlindedTailImport;

/// The blinded portion of a [`Path`], if we're routing to a recipient who provided blinded paths in
/// their [`Bolt12Invoice`].
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct BlindedTail {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedTail,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedTail {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedTail>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedTail, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedTail_free(this_obj: BlindedTail) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedTail_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedTail) };
}
#[allow(unused)]
impl BlindedTail {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedTail {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedTail {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedTail {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The hops of the [`BlindedPath`] provided by the recipient.
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn BlindedTail_get_hops(this_ptr: &BlindedTail) -> crate::c_types::derived::CVec_BlindedHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().hops;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::blinded_path::BlindedHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::blinded_path::BlindedHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The hops of the [`BlindedPath`] provided by the recipient.
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn BlindedTail_set_hops(this_ptr: &mut BlindedTail, mut val: crate::c_types::derived::CVec_BlindedHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.hops = local_val;
}
/// The blinding point of the [`BlindedPath`] provided by the recipient.
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn BlindedTail_get_blinding_point(this_ptr: &BlindedTail) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinding_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The blinding point of the [`BlindedPath`] provided by the recipient.
///
/// [`BlindedPath`]: crate::blinded_path::BlindedPath
#[no_mangle]
pub extern "C" fn BlindedTail_set_blinding_point(this_ptr: &mut BlindedTail, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinding_point = val.into_rust();
}
/// Excess CLTV delta added to the recipient's CLTV expiry to deter intermediate nodes from
/// inferring the destination. May be 0.
#[no_mangle]
pub extern "C" fn BlindedTail_get_excess_final_cltv_expiry_delta(this_ptr: &BlindedTail) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().excess_final_cltv_expiry_delta;
	*inner_val
}
/// Excess CLTV delta added to the recipient's CLTV expiry to deter intermediate nodes from
/// inferring the destination. May be 0.
#[no_mangle]
pub extern "C" fn BlindedTail_set_excess_final_cltv_expiry_delta(this_ptr: &mut BlindedTail, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.excess_final_cltv_expiry_delta = val;
}
/// The total amount paid on this [`Path`], excluding the fees.
#[no_mangle]
pub extern "C" fn BlindedTail_get_final_value_msat(this_ptr: &BlindedTail) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().final_value_msat;
	*inner_val
}
/// The total amount paid on this [`Path`], excluding the fees.
#[no_mangle]
pub extern "C" fn BlindedTail_set_final_value_msat(this_ptr: &mut BlindedTail, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.final_value_msat = val;
}
/// Constructs a new BlindedTail given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedTail_new(mut hops_arg: crate::c_types::derived::CVec_BlindedHopZ, mut blinding_point_arg: crate::c_types::PublicKey, mut excess_final_cltv_expiry_delta_arg: u32, mut final_value_msat_arg: u64) -> BlindedTail {
	let mut local_hops_arg = Vec::new(); for mut item in hops_arg.into_rust().drain(..) { local_hops_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	BlindedTail { inner: ObjOps::heap_alloc(nativeBlindedTail {
		hops: local_hops_arg,
		blinding_point: blinding_point_arg.into_rust(),
		excess_final_cltv_expiry_delta: excess_final_cltv_expiry_delta_arg,
		final_value_msat: final_value_msat_arg,
	}), is_owned: true }
}
impl Clone for BlindedTail {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedTail>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedTail_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedTail)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedTail
pub extern "C" fn BlindedTail_clone(orig: &BlindedTail) -> BlindedTail {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedTail object
pub extern "C" fn BlindedTail_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::BlindedTail }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedTail.
#[no_mangle]
pub extern "C" fn BlindedTail_hash(o: &BlindedTail) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedTails contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedTail_eq(a: &BlindedTail, b: &BlindedTail) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BlindedTail object into a byte array which can be read by BlindedTail_read
pub extern "C" fn BlindedTail_write(obj: &crate::lightning::routing::router::BlindedTail) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedTail_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedTail) })
}
#[no_mangle]
/// Read a BlindedTail from a byte array, created by BlindedTail_write
pub extern "C" fn BlindedTail_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedTailDecodeErrorZ {
	let res: Result<lightning::routing::router::BlindedTail, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::BlindedTail { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::Path as nativePathImport;
pub(crate) type nativePath = nativePathImport;

/// A path in a [`Route`] to the payment recipient. Must always be at least length one.
/// If no [`Path::blinded_tail`] is present, then [`Path::hops`] length may be up to 19.
#[must_use]
#[repr(C)]
pub struct Path {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Path {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Path, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Path_free(this_obj: Path) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Path_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePath) };
}
#[allow(unused)]
impl Path {
	pub(crate) fn get_native_ref(&self) -> &'static nativePath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The list of unblinded hops in this [`Path`]. Must be at least length one.
#[no_mangle]
pub extern "C" fn Path_get_hops(this_ptr: &Path) -> crate::c_types::derived::CVec_RouteHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().hops;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The list of unblinded hops in this [`Path`]. Must be at least length one.
#[no_mangle]
pub extern "C" fn Path_set_hops(this_ptr: &mut Path, mut val: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.hops = local_val;
}
/// The blinded path at which this path terminates, if we're sending to one, and its metadata.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Path_get_blinded_tail(this_ptr: &Path) -> crate::lightning::routing::router::BlindedTail {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().blinded_tail;
	let mut local_inner_val = crate::lightning::routing::router::BlindedTail { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::router::BlindedTail<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The blinded path at which this path terminates, if we're sending to one, and its metadata.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Path_set_blinded_tail(this_ptr: &mut Path, mut val: crate::lightning::routing::router::BlindedTail) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.blinded_tail = local_val;
}
/// Constructs a new Path given each field
///
/// Note that blinded_tail_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Path_new(mut hops_arg: crate::c_types::derived::CVec_RouteHopZ, mut blinded_tail_arg: crate::lightning::routing::router::BlindedTail) -> Path {
	let mut local_hops_arg = Vec::new(); for mut item in hops_arg.into_rust().drain(..) { local_hops_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_blinded_tail_arg = if blinded_tail_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(blinded_tail_arg.take_inner()) } }) };
	Path { inner: ObjOps::heap_alloc(nativePath {
		hops: local_hops_arg,
		blinded_tail: local_blinded_tail_arg,
	}), is_owned: true }
}
impl Clone for Path {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Path_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Path
pub extern "C" fn Path_clone(orig: &Path) -> Path {
	orig.clone()
}
/// Get a string which allows debug introspection of a Path object
pub extern "C" fn Path_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::Path }).into()}
/// Generates a non-cryptographic 64-bit hash of the Path.
#[no_mangle]
pub extern "C" fn Path_hash(o: &Path) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Paths contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Path_eq(a: &Path, b: &Path) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Gets the fees for a given path, excluding any excess paid to the recipient.
#[must_use]
#[no_mangle]
pub extern "C" fn Path_fee_msat(this_arg: &crate::lightning::routing::router::Path) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fee_msat();
	ret
}

/// Gets the total amount paid on this [`Path`], excluding the fees.
#[must_use]
#[no_mangle]
pub extern "C" fn Path_final_value_msat(this_arg: &crate::lightning::routing::router::Path) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.final_value_msat();
	ret
}

/// Gets the final hop's CLTV expiry delta.
#[must_use]
#[no_mangle]
pub extern "C" fn Path_final_cltv_expiry_delta(this_arg: &crate::lightning::routing::router::Path) -> crate::c_types::derived::COption_u32Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.final_cltv_expiry_delta();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { ret.unwrap() }) };
	local_ret
}


use lightning::routing::router::Route as nativeRouteImport;
pub(crate) type nativeRoute = nativeRouteImport;

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[must_use]
#[repr(C)]
pub struct Route {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoute,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Route {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRoute>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Route, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Route_free(this_obj: Route) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Route_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRoute) };
}
#[allow(unused)]
impl Route {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRoute {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRoute {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRoute {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The list of [`Path`]s taken for a single (potentially-)multi-part payment. If no
/// [`BlindedTail`]s are present, then the pubkey of the last [`RouteHop`] in each path must be
/// the same.
#[no_mangle]
pub extern "C" fn Route_get_paths(this_ptr: &Route) -> crate::c_types::derived::CVec_PathZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().paths;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The list of [`Path`]s taken for a single (potentially-)multi-part payment. If no
/// [`BlindedTail`]s are present, then the pubkey of the last [`RouteHop`] in each path must be
/// the same.
#[no_mangle]
pub extern "C" fn Route_set_paths(this_ptr: &mut Route, mut val: crate::c_types::derived::CVec_PathZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.paths = local_val;
}
/// The `route_params` parameter passed to [`find_route`].
///
/// This is used by `ChannelManager` to track information which may be required for retries.
///
/// Will be `None` for objects serialized with LDK versions prior to 0.0.117.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Route_get_route_params(this_ptr: &Route) -> crate::lightning::routing::router::RouteParameters {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().route_params;
	let mut local_inner_val = crate::lightning::routing::router::RouteParameters { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::router::RouteParameters<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The `route_params` parameter passed to [`find_route`].
///
/// This is used by `ChannelManager` to track information which may be required for retries.
///
/// Will be `None` for objects serialized with LDK versions prior to 0.0.117.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn Route_set_route_params(this_ptr: &mut Route, mut val: crate::lightning::routing::router::RouteParameters) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.route_params = local_val;
}
/// Constructs a new Route given each field
///
/// Note that route_params_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Route_new(mut paths_arg: crate::c_types::derived::CVec_PathZ, mut route_params_arg: crate::lightning::routing::router::RouteParameters) -> Route {
	let mut local_paths_arg = Vec::new(); for mut item in paths_arg.into_rust().drain(..) { local_paths_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_route_params_arg = if route_params_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(route_params_arg.take_inner()) } }) };
	Route { inner: ObjOps::heap_alloc(nativeRoute {
		paths: local_paths_arg,
		route_params: local_route_params_arg,
	}), is_owned: true }
}
impl Clone for Route {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRoute>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Route_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRoute)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Route
pub extern "C" fn Route_clone(orig: &Route) -> Route {
	orig.clone()
}
/// Get a string which allows debug introspection of a Route object
pub extern "C" fn Route_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::Route }).into()}
/// Generates a non-cryptographic 64-bit hash of the Route.
#[no_mangle]
pub extern "C" fn Route_hash(o: &Route) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Routes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Route_eq(a: &Route, b: &Route) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the total amount of fees paid on this [`Route`].
///
/// For objects serialized with LDK 0.0.117 and after, this includes any extra payment made to
/// the recipient, which can happen in excess of the amount passed to [`find_route`] via
/// [`RouteParameters::final_value_msat`], if we had to reach the [`htlc_minimum_msat`] limits.
///
/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
#[must_use]
#[no_mangle]
pub extern "C" fn Route_get_total_fees(this_arg: &crate::lightning::routing::router::Route) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_total_fees();
	ret
}

/// Returns the total amount paid on this [`Route`], excluding the fees.
///
/// Might be more than requested as part of the given [`RouteParameters::final_value_msat`] if
/// we had to reach the [`htlc_minimum_msat`] limits.
///
/// [`htlc_minimum_msat`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#the-channel_update-message
#[must_use]
#[no_mangle]
pub extern "C" fn Route_get_total_amount(this_arg: &crate::lightning::routing::router::Route) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_total_amount();
	ret
}

#[no_mangle]
/// Serialize the Route object into a byte array which can be read by Route_read
pub extern "C" fn Route_write(obj: &crate::lightning::routing::router::Route) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Route_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRoute) })
}
#[no_mangle]
/// Read a Route from a byte array, created by Route_write
pub extern "C" fn Route_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteDecodeErrorZ {
	let res: Result<lightning::routing::router::Route, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::RouteParameters as nativeRouteParametersImport;
pub(crate) type nativeRouteParameters = nativeRouteParametersImport;

/// Parameters needed to find a [`Route`].
///
/// Passed to [`find_route`] and [`build_route_from_hops`].
#[must_use]
#[repr(C)]
pub struct RouteParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteParameters_free(this_obj: RouteParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteParameters) };
}
#[allow(unused)]
impl RouteParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The parameters of the failed payment path.
#[no_mangle]
pub extern "C" fn RouteParameters_get_payment_params(this_ptr: &RouteParameters) -> crate::lightning::routing::router::PaymentParameters {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_params;
	crate::lightning::routing::router::PaymentParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::router::PaymentParameters<>) as *mut _) }, is_owned: false }
}
/// The parameters of the failed payment path.
#[no_mangle]
pub extern "C" fn RouteParameters_set_payment_params(this_ptr: &mut RouteParameters, mut val: crate::lightning::routing::router::PaymentParameters) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_params = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The amount in msats sent on the failed payment path.
#[no_mangle]
pub extern "C" fn RouteParameters_get_final_value_msat(this_ptr: &RouteParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().final_value_msat;
	*inner_val
}
/// The amount in msats sent on the failed payment path.
#[no_mangle]
pub extern "C" fn RouteParameters_set_final_value_msat(this_ptr: &mut RouteParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.final_value_msat = val;
}
/// The maximum total fees, in millisatoshi, that may accrue during route finding.
///
/// This limit also applies to the total fees that may arise while retrying failed payment
/// paths.
///
/// Note that values below a few sats may result in some paths being spuriously ignored.
#[no_mangle]
pub extern "C" fn RouteParameters_get_max_total_routing_fee_msat(this_ptr: &RouteParameters) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_total_routing_fee_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximum total fees, in millisatoshi, that may accrue during route finding.
///
/// This limit also applies to the total fees that may arise while retrying failed payment
/// paths.
///
/// Note that values below a few sats may result in some paths being spuriously ignored.
#[no_mangle]
pub extern "C" fn RouteParameters_set_max_total_routing_fee_msat(this_ptr: &mut RouteParameters, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_total_routing_fee_msat = local_val;
}
/// Constructs a new RouteParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteParameters_new(mut payment_params_arg: crate::lightning::routing::router::PaymentParameters, mut final_value_msat_arg: u64, mut max_total_routing_fee_msat_arg: crate::c_types::derived::COption_u64Z) -> RouteParameters {
	let mut local_max_total_routing_fee_msat_arg = if max_total_routing_fee_msat_arg.is_some() { Some( { max_total_routing_fee_msat_arg.take() }) } else { None };
	RouteParameters { inner: ObjOps::heap_alloc(nativeRouteParameters {
		payment_params: *unsafe { Box::from_raw(payment_params_arg.take_inner()) },
		final_value_msat: final_value_msat_arg,
		max_total_routing_fee_msat: local_max_total_routing_fee_msat_arg,
	}), is_owned: true }
}
impl Clone for RouteParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteParameters
pub extern "C" fn RouteParameters_clone(orig: &RouteParameters) -> RouteParameters {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteParameters object
pub extern "C" fn RouteParameters_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::RouteParameters }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteParameters.
#[no_mangle]
pub extern "C" fn RouteParameters_hash(o: &RouteParameters) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteParameterss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteParameters_eq(a: &RouteParameters, b: &RouteParameters) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Constructs [`RouteParameters`] from the given [`PaymentParameters`] and a payment amount.
///
/// [`Self::max_total_routing_fee_msat`] defaults to 1% of the payment amount + 50 sats
#[must_use]
#[no_mangle]
pub extern "C" fn RouteParameters_from_payment_params_and_value(mut payment_params: crate::lightning::routing::router::PaymentParameters, mut final_value_msat: u64) -> crate::lightning::routing::router::RouteParameters {
	let mut ret = lightning::routing::router::RouteParameters::from_payment_params_and_value(*unsafe { Box::from_raw(payment_params.take_inner()) }, final_value_msat);
	crate::lightning::routing::router::RouteParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the RouteParameters object into a byte array which can be read by RouteParameters_read
pub extern "C" fn RouteParameters_write(obj: &crate::lightning::routing::router::RouteParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RouteParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRouteParameters) })
}
#[no_mangle]
/// Read a RouteParameters from a byte array, created by RouteParameters_write
pub extern "C" fn RouteParameters_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteParametersDecodeErrorZ {
	let res: Result<lightning::routing::router::RouteParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::RouteParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Maximum total CTLV difference we allow for a full payment path.

#[no_mangle]
pub static DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA: u32 = lightning::routing::router::DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA;
/// Maximum number of paths we allow an (MPP) payment to have.

#[no_mangle]
pub static DEFAULT_MAX_PATH_COUNT: u8 = lightning::routing::router::DEFAULT_MAX_PATH_COUNT;

use lightning::routing::router::PaymentParameters as nativePaymentParametersImport;
pub(crate) type nativePaymentParameters = nativePaymentParametersImport;

/// Information used to route a payment.
#[must_use]
#[repr(C)]
pub struct PaymentParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePaymentParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PaymentParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePaymentParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PaymentParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PaymentParameters_free(this_obj: PaymentParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePaymentParameters) };
}
#[allow(unused)]
impl PaymentParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativePaymentParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePaymentParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePaymentParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Information about the payee, such as their features and route hints for their channels.
#[no_mangle]
pub extern "C" fn PaymentParameters_get_payee(this_ptr: &PaymentParameters) -> crate::lightning::routing::router::Payee {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payee;
	crate::lightning::routing::router::Payee::from_native(inner_val)
}
/// Information about the payee, such as their features and route hints for their channels.
#[no_mangle]
pub extern "C" fn PaymentParameters_set_payee(this_ptr: &mut PaymentParameters, mut val: crate::lightning::routing::router::Payee) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payee = val.into_native();
}
/// Expiration of a payment to the payee, in seconds relative to the UNIX epoch.
#[no_mangle]
pub extern "C" fn PaymentParameters_get_expiry_time(this_ptr: &PaymentParameters) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().expiry_time;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// Expiration of a payment to the payee, in seconds relative to the UNIX epoch.
#[no_mangle]
pub extern "C" fn PaymentParameters_set_expiry_time(this_ptr: &mut PaymentParameters, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.expiry_time = local_val;
}
/// The maximum total CLTV delta we accept for the route.
/// Defaults to [`DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA`].
#[no_mangle]
pub extern "C" fn PaymentParameters_get_max_total_cltv_expiry_delta(this_ptr: &PaymentParameters) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_total_cltv_expiry_delta;
	*inner_val
}
/// The maximum total CLTV delta we accept for the route.
/// Defaults to [`DEFAULT_MAX_TOTAL_CLTV_EXPIRY_DELTA`].
#[no_mangle]
pub extern "C" fn PaymentParameters_set_max_total_cltv_expiry_delta(this_ptr: &mut PaymentParameters, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_total_cltv_expiry_delta = val;
}
/// The maximum number of paths that may be used by (MPP) payments.
/// Defaults to [`DEFAULT_MAX_PATH_COUNT`].
#[no_mangle]
pub extern "C" fn PaymentParameters_get_max_path_count(this_ptr: &PaymentParameters) -> u8 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_path_count;
	*inner_val
}
/// The maximum number of paths that may be used by (MPP) payments.
/// Defaults to [`DEFAULT_MAX_PATH_COUNT`].
#[no_mangle]
pub extern "C" fn PaymentParameters_set_max_path_count(this_ptr: &mut PaymentParameters, mut val: u8) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_path_count = val;
}
/// Selects the maximum share of a channel's total capacity which will be sent over a channel,
/// as a power of 1/2. A higher value prefers to send the payment using more MPP parts whereas
/// a lower value prefers to send larger MPP parts, potentially saturating channels and
/// increasing failure probability for those paths.
///
/// Note that this restriction will be relaxed during pathfinding after paths which meet this
/// restriction have been found. While paths which meet this criteria will be searched for, it
/// is ultimately up to the scorer to select them over other paths.
///
/// A value of 0 will allow payments up to and including a channel's total announced usable
/// capacity, a value of one will only use up to half its capacity, two 1/4, etc.
///
/// Default value: 2
#[no_mangle]
pub extern "C" fn PaymentParameters_get_max_channel_saturation_power_of_half(this_ptr: &PaymentParameters) -> u8 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().max_channel_saturation_power_of_half;
	*inner_val
}
/// Selects the maximum share of a channel's total capacity which will be sent over a channel,
/// as a power of 1/2. A higher value prefers to send the payment using more MPP parts whereas
/// a lower value prefers to send larger MPP parts, potentially saturating channels and
/// increasing failure probability for those paths.
///
/// Note that this restriction will be relaxed during pathfinding after paths which meet this
/// restriction have been found. While paths which meet this criteria will be searched for, it
/// is ultimately up to the scorer to select them over other paths.
///
/// A value of 0 will allow payments up to and including a channel's total announced usable
/// capacity, a value of one will only use up to half its capacity, two 1/4, etc.
///
/// Default value: 2
#[no_mangle]
pub extern "C" fn PaymentParameters_set_max_channel_saturation_power_of_half(this_ptr: &mut PaymentParameters, mut val: u8) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.max_channel_saturation_power_of_half = val;
}
/// A list of SCIDs which this payment was previously attempted over and which caused the
/// payment to fail. Future attempts for the same payment shouldn't be relayed through any of
/// these SCIDs.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn PaymentParameters_get_previously_failed_channels(this_ptr: &PaymentParameters) -> crate::c_types::derived::CVec_u64Z {
	let mut inner_val = this_ptr.get_native_mut_ref().previously_failed_channels.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// A list of SCIDs which this payment was previously attempted over and which caused the
/// payment to fail. Future attempts for the same payment shouldn't be relayed through any of
/// these SCIDs.
#[no_mangle]
pub extern "C" fn PaymentParameters_set_previously_failed_channels(this_ptr: &mut PaymentParameters, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.previously_failed_channels = local_val;
}
/// A list of indices corresponding to blinded paths in [`Payee::Blinded::route_hints`] which this
/// payment was previously attempted over and which caused the payment to fail. Future attempts
/// for the same payment shouldn't be relayed through any of these blinded paths.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn PaymentParameters_get_previously_failed_blinded_path_idxs(this_ptr: &PaymentParameters) -> crate::c_types::derived::CVec_u64Z {
	let mut inner_val = this_ptr.get_native_mut_ref().previously_failed_blinded_path_idxs.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// A list of indices corresponding to blinded paths in [`Payee::Blinded::route_hints`] which this
/// payment was previously attempted over and which caused the payment to fail. Future attempts
/// for the same payment shouldn't be relayed through any of these blinded paths.
#[no_mangle]
pub extern "C" fn PaymentParameters_set_previously_failed_blinded_path_idxs(this_ptr: &mut PaymentParameters, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.previously_failed_blinded_path_idxs = local_val;
}
/// Constructs a new PaymentParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentParameters_new(mut payee_arg: crate::lightning::routing::router::Payee, mut expiry_time_arg: crate::c_types::derived::COption_u64Z, mut max_total_cltv_expiry_delta_arg: u32, mut max_path_count_arg: u8, mut max_channel_saturation_power_of_half_arg: u8, mut previously_failed_channels_arg: crate::c_types::derived::CVec_u64Z, mut previously_failed_blinded_path_idxs_arg: crate::c_types::derived::CVec_u64Z) -> PaymentParameters {
	let mut local_expiry_time_arg = if expiry_time_arg.is_some() { Some( { expiry_time_arg.take() }) } else { None };
	let mut local_previously_failed_channels_arg = Vec::new(); for mut item in previously_failed_channels_arg.into_rust().drain(..) { local_previously_failed_channels_arg.push( { item }); };
	let mut local_previously_failed_blinded_path_idxs_arg = Vec::new(); for mut item in previously_failed_blinded_path_idxs_arg.into_rust().drain(..) { local_previously_failed_blinded_path_idxs_arg.push( { item }); };
	PaymentParameters { inner: ObjOps::heap_alloc(nativePaymentParameters {
		payee: payee_arg.into_native(),
		expiry_time: local_expiry_time_arg,
		max_total_cltv_expiry_delta: max_total_cltv_expiry_delta_arg,
		max_path_count: max_path_count_arg,
		max_channel_saturation_power_of_half: max_channel_saturation_power_of_half_arg,
		previously_failed_channels: local_previously_failed_channels_arg,
		previously_failed_blinded_path_idxs: local_previously_failed_blinded_path_idxs_arg,
	}), is_owned: true }
}
impl Clone for PaymentParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePaymentParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PaymentParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePaymentParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PaymentParameters
pub extern "C" fn PaymentParameters_clone(orig: &PaymentParameters) -> PaymentParameters {
	orig.clone()
}
/// Get a string which allows debug introspection of a PaymentParameters object
pub extern "C" fn PaymentParameters_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::PaymentParameters }).into()}
/// Generates a non-cryptographic 64-bit hash of the PaymentParameters.
#[no_mangle]
pub extern "C" fn PaymentParameters_hash(o: &PaymentParameters) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two PaymentParameterss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn PaymentParameters_eq(a: &PaymentParameters, b: &PaymentParameters) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the PaymentParameters object into a byte array which can be read by PaymentParameters_read
pub extern "C" fn PaymentParameters_write(obj: &crate::lightning::routing::router::PaymentParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn PaymentParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePaymentParameters) })
}
#[no_mangle]
/// Read a PaymentParameters from a byte array, created by PaymentParameters_write
pub extern "C" fn PaymentParameters_read(ser: crate::c_types::u8slice, arg: u32) -> crate::c_types::derived::CResult_PaymentParametersDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::routing::router::PaymentParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::PaymentParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Creates a payee with the node id of the given `pubkey`.
///
/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
/// provided.
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentParameters_from_node_id(mut payee_pubkey: crate::c_types::PublicKey, mut final_cltv_expiry_delta: u32) -> crate::lightning::routing::router::PaymentParameters {
	let mut ret = lightning::routing::router::PaymentParameters::from_node_id(payee_pubkey.into_rust(), final_cltv_expiry_delta);
	crate::lightning::routing::router::PaymentParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a payee with the node id of the given `pubkey` to use for keysend payments.
///
/// The `final_cltv_expiry_delta` should match the expected final CLTV delta the recipient has
/// provided.
///
/// Note that MPP keysend is not widely supported yet. The `allow_mpp` lets you choose
/// whether your router will be allowed to find a multi-part route for this payment. If you
/// set `allow_mpp` to true, you should ensure a payment secret is set on send, likely via
/// [`RecipientOnionFields::secret_only`].
///
/// [`RecipientOnionFields::secret_only`]: crate::ln::channelmanager::RecipientOnionFields::secret_only
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentParameters_for_keysend(mut payee_pubkey: crate::c_types::PublicKey, mut final_cltv_expiry_delta: u32, mut allow_mpp: bool) -> crate::lightning::routing::router::PaymentParameters {
	let mut ret = lightning::routing::router::PaymentParameters::for_keysend(payee_pubkey.into_rust(), final_cltv_expiry_delta, allow_mpp);
	crate::lightning::routing::router::PaymentParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates parameters for paying to a blinded payee from the provided invoice. Sets
/// [`Payee::Blinded::route_hints`], [`Payee::Blinded::features`], and
/// [`PaymentParameters::expiry_time`].
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentParameters_from_bolt12_invoice(invoice: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::routing::router::PaymentParameters {
	let mut ret = lightning::routing::router::PaymentParameters::from_bolt12_invoice(invoice.get_native_ref());
	crate::lightning::routing::router::PaymentParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates parameters for paying to a blinded payee from the provided blinded route hints.
#[must_use]
#[no_mangle]
pub extern "C" fn PaymentParameters_blinded(mut blinded_route_hints: crate::c_types::derived::CVec_C2Tuple_BlindedPayInfoBlindedPathZZ) -> crate::lightning::routing::router::PaymentParameters {
	let mut local_blinded_route_hints = Vec::new(); for mut item in blinded_route_hints.into_rust().drain(..) { local_blinded_route_hints.push( { let (mut orig_blinded_route_hints_0_0, mut orig_blinded_route_hints_0_1) = item.to_rust(); let mut local_blinded_route_hints_0 = (*unsafe { Box::from_raw(orig_blinded_route_hints_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_blinded_route_hints_0_1.take_inner()) }); local_blinded_route_hints_0 }); };
	let mut ret = lightning::routing::router::PaymentParameters::blinded(local_blinded_route_hints);
	crate::lightning::routing::router::PaymentParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// The recipient of a payment, differing based on whether they've hidden their identity with route
/// blinding.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Payee {
	/// The recipient provided blinded paths and payinfo to reach them. The blinded paths themselves
	/// will be included in the final [`Route`].
	Blinded {
		/// Aggregated routing info and blinded paths, for routing to the payee without knowing their
		/// node id.
		route_hints: crate::c_types::derived::CVec_C2Tuple_BlindedPayInfoBlindedPathZZ,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice. May be `None` if the invoice does not contain any
		/// features.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		features: crate::lightning::ln::features::Bolt12InvoiceFeatures,
	},
	/// The recipient included these route hints in their BOLT11 invoice.
	Clear {
		/// The node id of the payee.
		node_id: crate::c_types::PublicKey,
		/// Hints for routing to the payee, containing channels connecting the payee to public nodes.
		route_hints: crate::c_types::derived::CVec_RouteHintZ,
		/// Features supported by the payee.
		///
		/// May be set from the payee's invoice or via [`for_keysend`]. May be `None` if the invoice
		/// does not contain any features.
		///
		/// [`for_keysend`]: PaymentParameters::for_keysend
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		features: crate::lightning::ln::features::Bolt11InvoiceFeatures,
		/// The minimum CLTV delta at the end of the route. This value must not be zero.
		final_cltv_expiry_delta: u32,
	},
}
use lightning::routing::router::Payee as PayeeImport;
pub(crate) type nativePayee = PayeeImport;

impl Payee {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePayee {
		match self {
			Payee::Blinded {ref route_hints, ref features, } => {
				let mut route_hints_nonref = Clone::clone(route_hints);
				let mut local_route_hints_nonref = Vec::new(); for mut item in route_hints_nonref.into_rust().drain(..) { local_route_hints_nonref.push( { let (mut orig_route_hints_nonref_0_0, mut orig_route_hints_nonref_0_1) = item.to_rust(); let mut local_route_hints_nonref_0 = (*unsafe { Box::from_raw(orig_route_hints_nonref_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_route_hints_nonref_0_1.take_inner()) }); local_route_hints_nonref_0 }); };
				let mut features_nonref = Clone::clone(features);
				let mut local_features_nonref = if features_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(features_nonref.take_inner()) } }) };
				nativePayee::Blinded {
					route_hints: local_route_hints_nonref,
					features: local_features_nonref,
				}
			},
			Payee::Clear {ref node_id, ref route_hints, ref features, ref final_cltv_expiry_delta, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut route_hints_nonref = Clone::clone(route_hints);
				let mut local_route_hints_nonref = Vec::new(); for mut item in route_hints_nonref.into_rust().drain(..) { local_route_hints_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut features_nonref = Clone::clone(features);
				let mut local_features_nonref = if features_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(features_nonref.take_inner()) } }) };
				let mut final_cltv_expiry_delta_nonref = Clone::clone(final_cltv_expiry_delta);
				nativePayee::Clear {
					node_id: node_id_nonref.into_rust(),
					route_hints: local_route_hints_nonref,
					features: local_features_nonref,
					final_cltv_expiry_delta: final_cltv_expiry_delta_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePayee {
		match self {
			Payee::Blinded {mut route_hints, mut features, } => {
				let mut local_route_hints = Vec::new(); for mut item in route_hints.into_rust().drain(..) { local_route_hints.push( { let (mut orig_route_hints_0_0, mut orig_route_hints_0_1) = item.to_rust(); let mut local_route_hints_0 = (*unsafe { Box::from_raw(orig_route_hints_0_0.take_inner()) }, *unsafe { Box::from_raw(orig_route_hints_0_1.take_inner()) }); local_route_hints_0 }); };
				let mut local_features = if features.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(features.take_inner()) } }) };
				nativePayee::Blinded {
					route_hints: local_route_hints,
					features: local_features,
				}
			},
			Payee::Clear {mut node_id, mut route_hints, mut features, mut final_cltv_expiry_delta, } => {
				let mut local_route_hints = Vec::new(); for mut item in route_hints.into_rust().drain(..) { local_route_hints.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut local_features = if features.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(features.take_inner()) } }) };
				nativePayee::Clear {
					node_id: node_id.into_rust(),
					route_hints: local_route_hints,
					features: local_features,
					final_cltv_expiry_delta: final_cltv_expiry_delta,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &PayeeImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativePayee) };
		match native {
			nativePayee::Blinded {ref route_hints, ref features, } => {
				let mut route_hints_nonref = Clone::clone(route_hints);
				let mut local_route_hints_nonref = Vec::new(); for mut item in route_hints_nonref.drain(..) { local_route_hints_nonref.push( { let (mut orig_route_hints_nonref_0_0, mut orig_route_hints_nonref_0_1) = item; let mut local_route_hints_nonref_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_route_hints_nonref_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_route_hints_nonref_0_1), is_owned: true }).into(); local_route_hints_nonref_0 }); };
				let mut features_nonref = Clone::clone(features);
				let mut local_features_nonref = crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: if features_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((features_nonref.unwrap())) } }, is_owned: true };
				Payee::Blinded {
					route_hints: local_route_hints_nonref.into(),
					features: local_features_nonref,
				}
			},
			nativePayee::Clear {ref node_id, ref route_hints, ref features, ref final_cltv_expiry_delta, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut route_hints_nonref = Clone::clone(route_hints);
				let mut local_route_hints_nonref = Vec::new(); for mut item in route_hints_nonref.drain(..) { local_route_hints_nonref.push( { crate::lightning::routing::router::RouteHint { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut features_nonref = Clone::clone(features);
				let mut local_features_nonref = crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: if features_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((features_nonref.unwrap())) } }, is_owned: true };
				let mut final_cltv_expiry_delta_nonref = Clone::clone(final_cltv_expiry_delta);
				Payee::Clear {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					route_hints: local_route_hints_nonref.into(),
					features: local_features_nonref,
					final_cltv_expiry_delta: final_cltv_expiry_delta_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePayee) -> Self {
		match native {
			nativePayee::Blinded {mut route_hints, mut features, } => {
				let mut local_route_hints = Vec::new(); for mut item in route_hints.drain(..) { local_route_hints.push( { let (mut orig_route_hints_0_0, mut orig_route_hints_0_1) = item; let mut local_route_hints_0 = (crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(orig_route_hints_0_0), is_owned: true }, crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(orig_route_hints_0_1), is_owned: true }).into(); local_route_hints_0 }); };
				let mut local_features = crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: if features.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((features.unwrap())) } }, is_owned: true };
				Payee::Blinded {
					route_hints: local_route_hints.into(),
					features: local_features,
				}
			},
			nativePayee::Clear {mut node_id, mut route_hints, mut features, mut final_cltv_expiry_delta, } => {
				let mut local_route_hints = Vec::new(); for mut item in route_hints.drain(..) { local_route_hints.push( { crate::lightning::routing::router::RouteHint { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut local_features = crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: if features.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((features.unwrap())) } }, is_owned: true };
				Payee::Clear {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					route_hints: local_route_hints.into(),
					features: local_features,
					final_cltv_expiry_delta: final_cltv_expiry_delta,
				}
			},
		}
	}
}
/// Frees any resources used by the Payee
#[no_mangle]
pub extern "C" fn Payee_free(this_ptr: Payee) { }
/// Creates a copy of the Payee
#[no_mangle]
pub extern "C" fn Payee_clone(orig: &Payee) -> Payee {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Payee_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Payee)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Payee_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Payee) };
}
#[no_mangle]
/// Utility method to constructs a new Blinded-variant Payee
pub extern "C" fn Payee_blinded(route_hints: crate::c_types::derived::CVec_C2Tuple_BlindedPayInfoBlindedPathZZ, features: crate::lightning::ln::features::Bolt12InvoiceFeatures) -> Payee {
	Payee::Blinded {
		route_hints,
		features,
	}
}
#[no_mangle]
/// Utility method to constructs a new Clear-variant Payee
pub extern "C" fn Payee_clear(node_id: crate::c_types::PublicKey, route_hints: crate::c_types::derived::CVec_RouteHintZ, features: crate::lightning::ln::features::Bolt11InvoiceFeatures, final_cltv_expiry_delta: u32) -> Payee {
	Payee::Clear {
		node_id,
		route_hints,
		features,
		final_cltv_expiry_delta,
	}
}
/// Get a string which allows debug introspection of a Payee object
pub extern "C" fn Payee_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::Payee }).into()}
/// Generates a non-cryptographic 64-bit hash of the Payee.
#[no_mangle]
pub extern "C" fn Payee_hash(o: &Payee) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Payees contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Payee_eq(a: &Payee, b: &Payee) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::routing::router::RouteHint as nativeRouteHintImport;
pub(crate) type nativeRouteHint = nativeRouteHintImport;

/// A list of hops along a payment path terminating with a channel to the recipient.
#[must_use]
#[repr(C)]
pub struct RouteHint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHint_free(this_obj: RouteHint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHint_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteHint) };
}
#[allow(unused)]
impl RouteHint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn RouteHint_get_a(this_ptr: &RouteHint) -> crate::c_types::derived::CVec_RouteHintHopZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::routing::router::RouteHintHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::routing::router::RouteHintHop<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
#[no_mangle]
pub extern "C" fn RouteHint_set_a(this_ptr: &mut RouteHint, mut val: crate::c_types::derived::CVec_RouteHintHopZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = local_val;
}
/// Constructs a new RouteHint given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHint_new(mut a_arg: crate::c_types::derived::CVec_RouteHintHopZ) -> RouteHint {
	let mut local_a_arg = Vec::new(); for mut item in a_arg.into_rust().drain(..) { local_a_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	RouteHint { inner: ObjOps::heap_alloc(lightning::routing::router::RouteHint (
		local_a_arg,
	)), is_owned: true }
}
impl Clone for RouteHint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHint>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteHint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHint
pub extern "C" fn RouteHint_clone(orig: &RouteHint) -> RouteHint {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteHint object
pub extern "C" fn RouteHint_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::RouteHint }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteHint.
#[no_mangle]
pub extern "C" fn RouteHint_hash(o: &RouteHint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHint_eq(a: &RouteHint, b: &RouteHint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the RouteHint object into a byte array which can be read by RouteHint_read
pub extern "C" fn RouteHint_write(obj: &crate::lightning::routing::router::RouteHint) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RouteHint_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRouteHint) })
}
#[no_mangle]
/// Read a RouteHint from a byte array, created by RouteHint_write
pub extern "C" fn RouteHint_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteHintDecodeErrorZ {
	let res: Result<lightning::routing::router::RouteHint, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::RouteHint { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::RouteHintHop as nativeRouteHintHopImport;
pub(crate) type nativeRouteHintHop = nativeRouteHintHopImport;

/// A channel descriptor for a hop along a payment path.
///
/// While this generally comes from BOLT 11's `r` field, this struct includes more fields than are
/// available in BOLT 11. Thus, encoding and decoding this via `lightning-invoice` is lossy, as
/// fields not supported in BOLT 11 will be stripped.
#[must_use]
#[repr(C)]
pub struct RouteHintHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHintHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHintHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHintHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHintHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHintHop_free(this_obj: RouteHintHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHintHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRouteHintHop) };
}
#[allow(unused)]
impl RouteHintHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHintHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHintHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHintHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_get_src_node_id(this_ptr: &RouteHintHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().src_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_set_src_node_id(this_ptr: &mut RouteHintHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.src_node_id = val.into_rust();
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_short_channel_id(this_ptr: &RouteHintHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_short_channel_id(this_ptr: &mut RouteHintHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_fees(this_ptr: &RouteHintHop) -> crate::lightning::routing::gossip::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fees;
	crate::lightning::routing::gossip::RoutingFees { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::gossip::RoutingFees<>) as *mut _) }, is_owned: false }
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_fees(this_ptr: &mut RouteHintHop, mut val: crate::lightning::routing::gossip::RoutingFees) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_cltv_expiry_delta(this_ptr: &RouteHintHop) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_cltv_expiry_delta(this_ptr: &mut RouteHintHop, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_minimum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_minimum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = local_val;
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_maximum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_maximum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = local_val;
}
/// Constructs a new RouteHintHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHintHop_new(mut src_node_id_arg: crate::c_types::PublicKey, mut short_channel_id_arg: u64, mut fees_arg: crate::lightning::routing::gossip::RoutingFees, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: crate::c_types::derived::COption_u64Z, mut htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z) -> RouteHintHop {
	let mut local_htlc_minimum_msat_arg = if htlc_minimum_msat_arg.is_some() { Some( { htlc_minimum_msat_arg.take() }) } else { None };
	let mut local_htlc_maximum_msat_arg = if htlc_maximum_msat_arg.is_some() { Some( { htlc_maximum_msat_arg.take() }) } else { None };
	RouteHintHop { inner: ObjOps::heap_alloc(nativeRouteHintHop {
		src_node_id: src_node_id_arg.into_rust(),
		short_channel_id: short_channel_id_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: local_htlc_minimum_msat_arg,
		htlc_maximum_msat: local_htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for RouteHintHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHintHop>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHintHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeRouteHintHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHintHop
pub extern "C" fn RouteHintHop_clone(orig: &RouteHintHop) -> RouteHintHop {
	orig.clone()
}
/// Get a string which allows debug introspection of a RouteHintHop object
pub extern "C" fn RouteHintHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::RouteHintHop }).into()}
/// Generates a non-cryptographic 64-bit hash of the RouteHintHop.
#[no_mangle]
pub extern "C" fn RouteHintHop_hash(o: &RouteHintHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHintHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHintHop_eq(a: &RouteHintHop, b: &RouteHintHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the RouteHintHop object into a byte array which can be read by RouteHintHop_read
pub extern "C" fn RouteHintHop_write(obj: &crate::lightning::routing::router::RouteHintHop) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn RouteHintHop_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRouteHintHop) })
}
#[no_mangle]
/// Read a RouteHintHop from a byte array, created by RouteHintHop_write
pub extern "C" fn RouteHintHop_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteHintHopDecodeErrorZ {
	let res: Result<lightning::routing::router::RouteHintHop, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::RouteHintHop { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::router::FirstHopCandidate as nativeFirstHopCandidateImport;
pub(crate) type nativeFirstHopCandidate = nativeFirstHopCandidateImport<'static>;

/// A [`CandidateRouteHop::FirstHop`] entry.
#[must_use]
#[repr(C)]
pub struct FirstHopCandidate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFirstHopCandidate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for FirstHopCandidate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFirstHopCandidate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the FirstHopCandidate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn FirstHopCandidate_free(this_obj: FirstHopCandidate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FirstHopCandidate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeFirstHopCandidate) };
}
#[allow(unused)]
impl FirstHopCandidate {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFirstHopCandidate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFirstHopCandidate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFirstHopCandidate {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for FirstHopCandidate {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeFirstHopCandidate>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FirstHopCandidate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeFirstHopCandidate)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the FirstHopCandidate
pub extern "C" fn FirstHopCandidate_clone(orig: &FirstHopCandidate) -> FirstHopCandidate {
	orig.clone()
}
/// Get a string which allows debug introspection of a FirstHopCandidate object
pub extern "C" fn FirstHopCandidate_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::FirstHopCandidate }).into()}

use lightning::routing::router::PublicHopCandidate as nativePublicHopCandidateImport;
pub(crate) type nativePublicHopCandidate = nativePublicHopCandidateImport<'static>;

/// A [`CandidateRouteHop::PublicHop`] entry.
#[must_use]
#[repr(C)]
pub struct PublicHopCandidate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePublicHopCandidate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PublicHopCandidate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePublicHopCandidate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PublicHopCandidate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PublicHopCandidate_free(this_obj: PublicHopCandidate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PublicHopCandidate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePublicHopCandidate) };
}
#[allow(unused)]
impl PublicHopCandidate {
	pub(crate) fn get_native_ref(&self) -> &'static nativePublicHopCandidate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePublicHopCandidate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePublicHopCandidate {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The short channel ID of the channel, i.e. the identifier by which we refer to this
/// channel.
#[no_mangle]
pub extern "C" fn PublicHopCandidate_get_short_channel_id(this_ptr: &PublicHopCandidate) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short channel ID of the channel, i.e. the identifier by which we refer to this
/// channel.
#[no_mangle]
pub extern "C" fn PublicHopCandidate_set_short_channel_id(this_ptr: &mut PublicHopCandidate, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
impl Clone for PublicHopCandidate {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePublicHopCandidate>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PublicHopCandidate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePublicHopCandidate)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PublicHopCandidate
pub extern "C" fn PublicHopCandidate_clone(orig: &PublicHopCandidate) -> PublicHopCandidate {
	orig.clone()
}
/// Get a string which allows debug introspection of a PublicHopCandidate object
pub extern "C" fn PublicHopCandidate_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::PublicHopCandidate }).into()}

use lightning::routing::router::PrivateHopCandidate as nativePrivateHopCandidateImport;
pub(crate) type nativePrivateHopCandidate = nativePrivateHopCandidateImport<'static>;

/// A [`CandidateRouteHop::PrivateHop`] entry.
#[must_use]
#[repr(C)]
pub struct PrivateHopCandidate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePrivateHopCandidate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PrivateHopCandidate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePrivateHopCandidate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PrivateHopCandidate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PrivateHopCandidate_free(this_obj: PrivateHopCandidate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrivateHopCandidate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePrivateHopCandidate) };
}
#[allow(unused)]
impl PrivateHopCandidate {
	pub(crate) fn get_native_ref(&self) -> &'static nativePrivateHopCandidate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePrivateHopCandidate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePrivateHopCandidate {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for PrivateHopCandidate {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePrivateHopCandidate>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrivateHopCandidate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativePrivateHopCandidate)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PrivateHopCandidate
pub extern "C" fn PrivateHopCandidate_clone(orig: &PrivateHopCandidate) -> PrivateHopCandidate {
	orig.clone()
}
/// Get a string which allows debug introspection of a PrivateHopCandidate object
pub extern "C" fn PrivateHopCandidate_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::PrivateHopCandidate }).into()}

use lightning::routing::router::BlindedPathCandidate as nativeBlindedPathCandidateImport;
pub(crate) type nativeBlindedPathCandidate = nativeBlindedPathCandidateImport<'static>;

/// A [`CandidateRouteHop::Blinded`] entry.
#[must_use]
#[repr(C)]
pub struct BlindedPathCandidate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPathCandidate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedPathCandidate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPathCandidate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPathCandidate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPathCandidate_free(this_obj: BlindedPathCandidate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPathCandidate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPathCandidate) };
}
#[allow(unused)]
impl BlindedPathCandidate {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPathCandidate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPathCandidate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPathCandidate {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for BlindedPathCandidate {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPathCandidate>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPathCandidate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedPathCandidate)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPathCandidate
pub extern "C" fn BlindedPathCandidate_clone(orig: &BlindedPathCandidate) -> BlindedPathCandidate {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedPathCandidate object
pub extern "C" fn BlindedPathCandidate_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::BlindedPathCandidate }).into()}

use lightning::routing::router::OneHopBlindedPathCandidate as nativeOneHopBlindedPathCandidateImport;
pub(crate) type nativeOneHopBlindedPathCandidate = nativeOneHopBlindedPathCandidateImport<'static>;

/// A [`CandidateRouteHop::OneHopBlinded`] entry.
#[must_use]
#[repr(C)]
pub struct OneHopBlindedPathCandidate {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOneHopBlindedPathCandidate,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OneHopBlindedPathCandidate {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOneHopBlindedPathCandidate>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OneHopBlindedPathCandidate, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OneHopBlindedPathCandidate_free(this_obj: OneHopBlindedPathCandidate) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OneHopBlindedPathCandidate_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOneHopBlindedPathCandidate) };
}
#[allow(unused)]
impl OneHopBlindedPathCandidate {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOneHopBlindedPathCandidate {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOneHopBlindedPathCandidate {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOneHopBlindedPathCandidate {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for OneHopBlindedPathCandidate {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOneHopBlindedPathCandidate>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OneHopBlindedPathCandidate_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOneHopBlindedPathCandidate)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OneHopBlindedPathCandidate
pub extern "C" fn OneHopBlindedPathCandidate_clone(orig: &OneHopBlindedPathCandidate) -> OneHopBlindedPathCandidate {
	orig.clone()
}
/// Get a string which allows debug introspection of a OneHopBlindedPathCandidate object
pub extern "C" fn OneHopBlindedPathCandidate_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::OneHopBlindedPathCandidate }).into()}
/// A wrapper around the various hop representations.
///
/// Can be used to examine the properties of a hop,
/// potentially to decide whether to include it in a route.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum CandidateRouteHop {
	/// A hop from the payer, where the outbound liquidity is known.
	FirstHop(
		crate::lightning::routing::router::FirstHopCandidate),
	/// A hop found in the [`ReadOnlyNetworkGraph`].
	PublicHop(
		crate::lightning::routing::router::PublicHopCandidate),
	/// A private hop communicated by the payee, generally via a BOLT 11 invoice.
	///
	/// Because BOLT 11 route hints can take multiple hops to get to the destination, this may not
	/// terminate at the payee.
	PrivateHop(
		crate::lightning::routing::router::PrivateHopCandidate),
	/// A blinded path which starts with an introduction point and ultimately terminates with the
	/// payee.
	///
	/// Because we don't know the payee's identity, [`CandidateRouteHop::target`] will return
	/// `None` in this state.
	///
	/// Because blinded paths are \"all or nothing\", and we cannot use just one part of a blinded
	/// path, the full path is treated as a single [`CandidateRouteHop`].
	Blinded(
		crate::lightning::routing::router::BlindedPathCandidate),
	/// Similar to [`Self::Blinded`], but the path here only has one hop.
	///
	/// While we treat this similarly to [`CandidateRouteHop::Blinded`] in many respects (e.g.
	/// returning `None` from [`CandidateRouteHop::target`]), in this case we do actually know the
	/// payee's identity - it's the introduction point!
	///
	/// [`BlindedPayInfo`] provided for 1-hop blinded paths is ignored because it is meant to apply
	/// to the hops *between* the introduction node and the destination.
	///
	/// This primarily exists to track that we need to included a blinded path at the end of our
	/// [`Route`], even though it doesn't actually add an additional hop in the payment.
	OneHopBlinded(
		crate::lightning::routing::router::OneHopBlindedPathCandidate),
}
use lightning::routing::router::CandidateRouteHop as CandidateRouteHopImport;
pub(crate) type nativeCandidateRouteHop = CandidateRouteHopImport<'static>;

impl CandidateRouteHop {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeCandidateRouteHop {
		match self {
			CandidateRouteHop::FirstHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeCandidateRouteHop::FirstHop (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			CandidateRouteHop::PublicHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeCandidateRouteHop::PublicHop (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			CandidateRouteHop::PrivateHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeCandidateRouteHop::PrivateHop (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			CandidateRouteHop::Blinded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeCandidateRouteHop::Blinded (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			CandidateRouteHop::OneHopBlinded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeCandidateRouteHop::OneHopBlinded (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeCandidateRouteHop {
		match self {
			CandidateRouteHop::FirstHop (mut a, ) => {
				nativeCandidateRouteHop::FirstHop (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			CandidateRouteHop::PublicHop (mut a, ) => {
				nativeCandidateRouteHop::PublicHop (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			CandidateRouteHop::PrivateHop (mut a, ) => {
				nativeCandidateRouteHop::PrivateHop (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			CandidateRouteHop::Blinded (mut a, ) => {
				nativeCandidateRouteHop::Blinded (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			CandidateRouteHop::OneHopBlinded (mut a, ) => {
				nativeCandidateRouteHop::OneHopBlinded (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &CandidateRouteHopImport<'_>) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeCandidateRouteHop) };
		match native {
			nativeCandidateRouteHop::FirstHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				CandidateRouteHop::FirstHop (
					crate::lightning::routing::router::FirstHopCandidate { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeCandidateRouteHop::PublicHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				CandidateRouteHop::PublicHop (
					crate::lightning::routing::router::PublicHopCandidate { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeCandidateRouteHop::PrivateHop (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				CandidateRouteHop::PrivateHop (
					crate::lightning::routing::router::PrivateHopCandidate { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeCandidateRouteHop::Blinded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				CandidateRouteHop::Blinded (
					crate::lightning::routing::router::BlindedPathCandidate { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeCandidateRouteHop::OneHopBlinded (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				CandidateRouteHop::OneHopBlinded (
					crate::lightning::routing::router::OneHopBlindedPathCandidate { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeCandidateRouteHop) -> Self {
		match native {
			nativeCandidateRouteHop::FirstHop (mut a, ) => {
				CandidateRouteHop::FirstHop (
					crate::lightning::routing::router::FirstHopCandidate { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeCandidateRouteHop::PublicHop (mut a, ) => {
				CandidateRouteHop::PublicHop (
					crate::lightning::routing::router::PublicHopCandidate { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeCandidateRouteHop::PrivateHop (mut a, ) => {
				CandidateRouteHop::PrivateHop (
					crate::lightning::routing::router::PrivateHopCandidate { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeCandidateRouteHop::Blinded (mut a, ) => {
				CandidateRouteHop::Blinded (
					crate::lightning::routing::router::BlindedPathCandidate { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeCandidateRouteHop::OneHopBlinded (mut a, ) => {
				CandidateRouteHop::OneHopBlinded (
					crate::lightning::routing::router::OneHopBlindedPathCandidate { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the CandidateRouteHop
#[no_mangle]
pub extern "C" fn CandidateRouteHop_free(this_ptr: CandidateRouteHop) { }
/// Creates a copy of the CandidateRouteHop
#[no_mangle]
pub extern "C" fn CandidateRouteHop_clone(orig: &CandidateRouteHop) -> CandidateRouteHop {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CandidateRouteHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const CandidateRouteHop)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CandidateRouteHop_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut CandidateRouteHop) };
}
#[no_mangle]
/// Utility method to constructs a new FirstHop-variant CandidateRouteHop
pub extern "C" fn CandidateRouteHop_first_hop(a: crate::lightning::routing::router::FirstHopCandidate) -> CandidateRouteHop {
	CandidateRouteHop::FirstHop(a, )
}
#[no_mangle]
/// Utility method to constructs a new PublicHop-variant CandidateRouteHop
pub extern "C" fn CandidateRouteHop_public_hop(a: crate::lightning::routing::router::PublicHopCandidate) -> CandidateRouteHop {
	CandidateRouteHop::PublicHop(a, )
}
#[no_mangle]
/// Utility method to constructs a new PrivateHop-variant CandidateRouteHop
pub extern "C" fn CandidateRouteHop_private_hop(a: crate::lightning::routing::router::PrivateHopCandidate) -> CandidateRouteHop {
	CandidateRouteHop::PrivateHop(a, )
}
#[no_mangle]
/// Utility method to constructs a new Blinded-variant CandidateRouteHop
pub extern "C" fn CandidateRouteHop_blinded(a: crate::lightning::routing::router::BlindedPathCandidate) -> CandidateRouteHop {
	CandidateRouteHop::Blinded(a, )
}
#[no_mangle]
/// Utility method to constructs a new OneHopBlinded-variant CandidateRouteHop
pub extern "C" fn CandidateRouteHop_one_hop_blinded(a: crate::lightning::routing::router::OneHopBlindedPathCandidate) -> CandidateRouteHop {
	CandidateRouteHop::OneHopBlinded(a, )
}
/// Get a string which allows debug introspection of a CandidateRouteHop object
pub extern "C" fn CandidateRouteHop_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::routing::router::CandidateRouteHop }).into()}
/// Returns the globally unique short channel ID for this hop, if one is known.
///
/// This only returns `Some` if the channel is public (either our own, or one we've learned
/// from the public network graph), and thus the short channel ID we have for this channel is
/// globally unique and identifies this channel in a global namespace.
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_globally_unique_short_channel_id(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> crate::c_types::derived::COption_u64Z {
	let mut ret = this_arg.to_native().globally_unique_short_channel_id();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Returns the required difference in HTLC CLTV expiry between the [`Self::source`] and the
/// next-hop for an HTLC taking this hop.
///
/// This is the time that the node(s) in this hop have to claim the HTLC on-chain if the
/// next-hop goes on chain with a payment preimage.
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_cltv_expiry_delta(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> u32 {
	let mut ret = this_arg.to_native().cltv_expiry_delta();
	ret
}

/// Returns the minimum amount that can be sent over this hop, in millisatoshis.
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_htlc_minimum_msat(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> u64 {
	let mut ret = this_arg.to_native().htlc_minimum_msat();
	ret
}

/// Returns the fees that must be paid to route an HTLC over this channel.
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_fees(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> crate::lightning::routing::gossip::RoutingFees {
	let mut ret = this_arg.to_native().fees();
	crate::lightning::routing::gossip::RoutingFees { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the source node id of current hop.
///
/// Source node id refers to the node forwarding the HTLC through this hop.
///
/// For [`Self::FirstHop`] we return payer's node id.
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_source(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = this_arg.to_native().source();
	crate::lightning::routing::gossip::NodeId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the target node id of this hop, if known.
///
/// Target node id refers to the node receiving the HTLC after this hop.
///
/// For [`Self::Blinded`] we return `None` because the ultimate destination after the blinded
/// path is unknown.
///
/// For [`Self::OneHopBlinded`] we return `None` because the target is the same as the source,
/// and such a return value would be somewhat nonsensical.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn CandidateRouteHop_target(this_arg: &crate::lightning::routing::router::CandidateRouteHop) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = this_arg.to_native().target();
	let mut local_ret = crate::lightning::routing::gossip::NodeId { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Finds a route from us (payer) to the given target node (payee).
///
/// If the payee provided features in their invoice, they should be provided via the `payee` field
/// in the given [`RouteParameters::payment_params`].
/// Without this, MPP will only be used if the payee's features are available in the network graph.
///
/// Private routing paths between a public node and the target may be included in the `payee` field
/// of [`RouteParameters::payment_params`].
///
/// If some channels aren't announced, it may be useful to fill in `first_hops` with the results
/// from [`ChannelManager::list_usable_channels`]. If it is filled in, the view of these channels
/// from `network_graph` will be ignored, and only those in `first_hops` will be used.
///
/// The fees on channels from us to the next hop are ignored as they are assumed to all be equal.
/// However, the enabled/disabled bit on such channels as well as the `htlc_minimum_msat` /
/// `htlc_maximum_msat` *are* checked as they may change based on the receiving node.
///
/// # Panics
///
/// Panics if first_hops contains channels without `short_channel_id`s;
/// [`ChannelManager::list_usable_channels`] will never include such channels.
///
/// [`ChannelManager::list_usable_channels`]: crate::ln::channelmanager::ChannelManager::list_usable_channels
/// [`Event::PaymentPathFailed`]: crate::events::Event::PaymentPathFailed
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
///
/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn find_route(mut our_node_pubkey: crate::c_types::PublicKey, route_params: &crate::lightning::routing::router::RouteParameters, network_graph: &crate::lightning::routing::gossip::NetworkGraph, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut logger: crate::lightning::util::logger::Logger, scorer: &crate::lightning::routing::scoring::ScoreLookUp, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, random_seed_bytes: *const [u8; 32]) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == core::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut ret = lightning::routing::router::find_route::<crate::lightning::util::logger::Logger, crate::lightning::util::logger::Logger, crate::lightning::routing::scoring::ScoreLookUp>(&our_node_pubkey.into_rust(), route_params.get_native_ref(), network_graph.get_native_ref(), local_first_hops, logger, scorer, score_params.get_native_ref(), unsafe { &*random_seed_bytes});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Construct a route from us (payer) to the target node (payee) via the given hops (which should
/// exclude the payer, but include the payee). This may be useful, e.g., for probing the chosen path.
///
/// Re-uses logic from `find_route`, so the restrictions described there also apply here.
#[no_mangle]
pub extern "C" fn build_route_from_hops(mut our_node_pubkey: crate::c_types::PublicKey, mut hops: crate::c_types::derived::CVec_PublicKeyZ, route_params: &crate::lightning::routing::router::RouteParameters, network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut logger: crate::lightning::util::logger::Logger, random_seed_bytes: *const [u8; 32]) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_hops = Vec::new(); for mut item in hops.into_rust().drain(..) { local_hops.push( { item.into_rust() }); };
	let mut ret = lightning::routing::router::build_route_from_hops::<crate::lightning::util::logger::Logger, crate::lightning::util::logger::Logger>(&our_node_pubkey.into_rust(), &local_hops[..], route_params.get_native_ref(), network_graph.get_native_ref(), logger, unsafe { &*random_seed_bytes});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

