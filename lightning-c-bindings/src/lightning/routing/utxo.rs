// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module contains traits for LDK to access UTXOs to check gossip data is correct.
//!
//! When lightning nodes gossip channel information, they resist DoS attacks by checking that each
//! channel matches a UTXO on-chain, requiring at least some marginal on-chain transacting in
//! order to announce a channel. This module handles that checking.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An error when accessing the chain via [`UtxoLookup`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum UtxoLookupError {
	/// The requested chain is unknown.
	UnknownChain,
	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}
use lightning::routing::utxo::UtxoLookupError as UtxoLookupErrorImport;
pub(crate) type nativeUtxoLookupError = UtxoLookupErrorImport;

impl UtxoLookupError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeUtxoLookupError {
		match self {
			UtxoLookupError::UnknownChain => nativeUtxoLookupError::UnknownChain,
			UtxoLookupError::UnknownTx => nativeUtxoLookupError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeUtxoLookupError {
		match self {
			UtxoLookupError::UnknownChain => nativeUtxoLookupError::UnknownChain,
			UtxoLookupError::UnknownTx => nativeUtxoLookupError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeUtxoLookupError) -> Self {
		match native {
			nativeUtxoLookupError::UnknownChain => UtxoLookupError::UnknownChain,
			nativeUtxoLookupError::UnknownTx => UtxoLookupError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeUtxoLookupError) -> Self {
		match native {
			nativeUtxoLookupError::UnknownChain => UtxoLookupError::UnknownChain,
			nativeUtxoLookupError::UnknownTx => UtxoLookupError::UnknownTx,
		}
	}
}
/// Creates a copy of the UtxoLookupError
#[no_mangle]
pub extern "C" fn UtxoLookupError_clone(orig: &UtxoLookupError) -> UtxoLookupError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoLookupError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const UtxoLookupError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoLookupError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut UtxoLookupError) };
}
#[no_mangle]
/// Utility method to constructs a new UnknownChain-variant UtxoLookupError
pub extern "C" fn UtxoLookupError_unknown_chain() -> UtxoLookupError {
	UtxoLookupError::UnknownChain}
#[no_mangle]
/// Utility method to constructs a new UnknownTx-variant UtxoLookupError
pub extern "C" fn UtxoLookupError_unknown_tx() -> UtxoLookupError {
	UtxoLookupError::UnknownTx}
/// The result of a [`UtxoLookup::get_utxo`] call. A call may resolve either synchronously,
/// returning the `Sync` variant, or asynchronously, returning an [`UtxoFuture`] in the `Async`
/// variant.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum UtxoResult {
	/// A result which was resolved synchronously. It either includes a [`TxOut`] for the output
	/// requested or a [`UtxoLookupError`].
	Sync(
		crate::c_types::derived::CResult_TxOutUtxoLookupErrorZ),
	/// A result which will be resolved asynchronously. It includes a [`UtxoFuture`], a `clone` of
	/// which you must keep locally and call [`UtxoFuture::resolve`] on once the lookup completes.
	///
	/// Note that in order to avoid runaway memory usage, the number of parallel checks is limited,
	/// but only fairly loosely. Because a pending checks block all message processing, leaving
	/// checks pending for an extended time may cause DoS of other functions. It is recommended you
	/// keep a tight timeout on lookups, on the order of a few seconds.
	Async(
		crate::lightning::routing::utxo::UtxoFuture),
}
use lightning::routing::utxo::UtxoResult as UtxoResultImport;
pub(crate) type nativeUtxoResult = UtxoResultImport;

impl UtxoResult {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeUtxoResult {
		match self {
			UtxoResult::Sync (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = match a_nonref.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut a_nonref.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut a_nonref.contents.err)) }).into_native() })};
				nativeUtxoResult::Sync (
					local_a_nonref,
				)
			},
			UtxoResult::Async (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeUtxoResult::Async (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeUtxoResult {
		match self {
			UtxoResult::Sync (mut a, ) => {
				let mut local_a = match a.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut a.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut a.contents.err)) }).into_native() })};
				nativeUtxoResult::Sync (
					local_a,
				)
			},
			UtxoResult::Async (mut a, ) => {
				nativeUtxoResult::Async (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeUtxoResult) -> Self {
		match native {
			nativeUtxoResult::Sync (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut local_a_nonref = match a_nonref { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::TxOut::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::routing::utxo::UtxoLookupError::native_into(e) }).into() };
				UtxoResult::Sync (
					local_a_nonref,
				)
			},
			nativeUtxoResult::Async (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				UtxoResult::Async (
					crate::lightning::routing::utxo::UtxoFuture { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeUtxoResult) -> Self {
		match native {
			nativeUtxoResult::Sync (mut a, ) => {
				let mut local_a = match a { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::TxOut::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::routing::utxo::UtxoLookupError::native_into(e) }).into() };
				UtxoResult::Sync (
					local_a,
				)
			},
			nativeUtxoResult::Async (mut a, ) => {
				UtxoResult::Async (
					crate::lightning::routing::utxo::UtxoFuture { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the UtxoResult
#[no_mangle]
pub extern "C" fn UtxoResult_free(this_ptr: UtxoResult) { }
/// Creates a copy of the UtxoResult
#[no_mangle]
pub extern "C" fn UtxoResult_clone(orig: &UtxoResult) -> UtxoResult {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoResult_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const UtxoResult)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoResult_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut UtxoResult) };
}
#[no_mangle]
/// Utility method to constructs a new Sync-variant UtxoResult
pub extern "C" fn UtxoResult_sync(a: crate::c_types::derived::CResult_TxOutUtxoLookupErrorZ) -> UtxoResult {
	UtxoResult::Sync(a, )
}
#[no_mangle]
/// Utility method to constructs a new Async-variant UtxoResult
pub extern "C" fn UtxoResult_async(a: crate::lightning::routing::utxo::UtxoFuture) -> UtxoResult {
	UtxoResult::Async(a, )
}
/// The `UtxoLookup` trait defines behavior for accessing on-chain UTXOs.
#[repr(C)]
pub struct UtxoLookup {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `chain_hash` is for a different chain or if such a transaction output is
	/// unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	pub get_utxo: extern "C" fn (this_arg: *const c_void, chain_hash: *const [u8; 32], short_channel_id: u64) -> crate::lightning::routing::utxo::UtxoResult,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for UtxoLookup {}
unsafe impl Sync for UtxoLookup {}
#[allow(unused)]
pub(crate) fn UtxoLookup_clone_fields(orig: &UtxoLookup) -> UtxoLookup {
	UtxoLookup {
		this_arg: orig.this_arg,
		get_utxo: Clone::clone(&orig.get_utxo),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::utxo::UtxoLookup as rustUtxoLookup;
impl rustUtxoLookup for UtxoLookup {
	fn get_utxo(&self, mut chain_hash: &bitcoin::blockdata::constants::ChainHash, mut short_channel_id: u64) -> lightning::routing::utxo::UtxoResult {
		let mut ret = (self.get_utxo)(self.this_arg, chain_hash.as_bytes(), short_channel_id);
		ret.into_native()
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for UtxoLookup {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for UtxoLookup {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn UtxoLookup_free(this_ptr: UtxoLookup) { }
impl Drop for UtxoLookup {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::routing::utxo::UtxoFuture as nativeUtxoFutureImport;
pub(crate) type nativeUtxoFuture = nativeUtxoFutureImport;

/// Represents a future resolution of a [`UtxoLookup::get_utxo`] query resolving async.
///
/// See [`UtxoResult::Async`] and [`UtxoFuture::resolve`] for more info.
#[must_use]
#[repr(C)]
pub struct UtxoFuture {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUtxoFuture,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for UtxoFuture {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUtxoFuture>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UtxoFuture, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UtxoFuture_free(this_obj: UtxoFuture) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoFuture_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUtxoFuture) };
}
#[allow(unused)]
impl UtxoFuture {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUtxoFuture {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUtxoFuture {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUtxoFuture {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for UtxoFuture {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUtxoFuture>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UtxoFuture_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUtxoFuture)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UtxoFuture
pub extern "C" fn UtxoFuture_clone(orig: &UtxoFuture) -> UtxoFuture {
	orig.clone()
}
/// Builds a new future for later resolution.
#[must_use]
#[no_mangle]
pub extern "C" fn UtxoFuture_new() -> crate::lightning::routing::utxo::UtxoFuture {
	let mut ret = lightning::routing::utxo::UtxoFuture::new();
	crate::lightning::routing::utxo::UtxoFuture { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Resolves this future against the given `graph` and with the given `result`.
///
/// This is identical to calling [`UtxoFuture::resolve`] with a dummy `gossip`, disabling
/// forwarding the validated gossip message onwards to peers.
///
/// Because this may cause the [`NetworkGraph`]'s [`processing_queue_high`] to flip, in order
/// to allow us to interact with peers again, you should call [`PeerManager::process_events`]
/// after this.
///
/// [`processing_queue_high`]: crate::ln::msgs::RoutingMessageHandler::processing_queue_high
/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
#[no_mangle]
pub extern "C" fn UtxoFuture_resolve_without_forwarding(this_arg: &crate::lightning::routing::utxo::UtxoFuture, graph: &crate::lightning::routing::gossip::NetworkGraph, mut result: crate::c_types::derived::CResult_TxOutUtxoLookupErrorZ) {
	let mut local_result = match result.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut result.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut result.contents.err)) }).into_native() })};
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.resolve_without_forwarding(graph.get_native_ref(), local_result)
}

/// Resolves this future against the given `graph` and with the given `result`.
///
/// The given `gossip` is used to broadcast any validated messages onwards to all peers which
/// have available buffer space.
///
/// Because this may cause the [`NetworkGraph`]'s [`processing_queue_high`] to flip, in order
/// to allow us to interact with peers again, you should call [`PeerManager::process_events`]
/// after this.
///
/// [`processing_queue_high`]: crate::ln::msgs::RoutingMessageHandler::processing_queue_high
/// [`PeerManager::process_events`]: crate::ln::peer_handler::PeerManager::process_events
#[no_mangle]
pub extern "C" fn UtxoFuture_resolve(this_arg: &crate::lightning::routing::utxo::UtxoFuture, graph: &crate::lightning::routing::gossip::NetworkGraph, gossip: &crate::lightning::routing::gossip::P2PGossipSync, mut result: crate::c_types::derived::CResult_TxOutUtxoLookupErrorZ) {
	let mut local_result = match result.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut result.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut result.contents.err)) }).into_native() })};
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.resolve(graph.get_native_ref(), gossip.get_native_ref(), local_result)
}

