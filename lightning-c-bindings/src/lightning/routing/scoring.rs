// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for scoring payment channels.
//!
//! [`ProbabilisticScorer`] may be given to [`find_route`] to score payment channels during path
//! finding when a custom [`Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate bitcoin;
//! #
//! # use lightning::routing::gossip::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters};
//! # use lightning::chain::keysinterface::{KeysManager, KeysInterface};
//! # use lightning::util::logger::{Logger, Record};
//! # use bitcoin::secp256k1::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, route_params: RouteParameters, network_graph: NetworkGraph<&FakeLogger>) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let params = ProbabilisticScoringParameters::default();
//! let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
//!
//! // Or use custom channel penalties.
//! let params = ProbabilisticScoringParameters {
//!     liquidity_penalty_multiplier_msat: 2 * 1000,
//!     ..ProbabilisticScoringParameters::default()
//! };
//! let scorer = ProbabilisticScorer::new(params, &network_graph, &logger);
//! # let random_seed_bytes = [42u8; 32];
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer, &random_seed_bytes);
//! # }
//! ```
//!
//! # Note
//!
//! Persisting when built with feature `no-std` and restoring without it, or vice versa, uses
//! different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An interface used to score payment channels for path finding.
///
///\tScoring is in terms of fees willing to be paid in order to avoid routing through a channel.
#[repr(C)]
pub struct Score {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the fee in msats willing to be paid to avoid routing `send_amt_msat` through the
	/// given channel in the direction from `source` to `target`.
	///
	/// The channel's capacity (less any other MPP parts that are also being considered for use in
	/// the same payment) is given by `capacity_msat`. It may be determined from various sources
	/// such as a chain data, network gossip, or invoice hints. For invoice hints, a capacity near
	/// [`u64::max_value`] is given to indicate sufficient capacity for the invoice's full amount.
	/// Thus, implementations should be overflow-safe.
	#[must_use]
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, usage: crate::lightning::routing::scoring::ChannelUsage) -> u64,
	/// Handles updating channel penalties after failing to route through a channel.
	pub payment_path_failed: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: u64),
	/// Handles updating channel penalties after successfully routing along a path.
	pub payment_path_successful: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ),
	/// Handles updating channel penalties after a probe over the given path failed.
	pub probe_failed: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: u64),
	/// Handles updating channel penalties after a probe over the given path succeeded.
	pub probe_successful: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ),
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Score {}
unsafe impl Sync for Score {}
#[no_mangle]
pub(crate) extern "C" fn Score_clone_fields(orig: &Score) -> Score {
	Score {
		this_arg: orig.this_arg,
		channel_penalty_msat: Clone::clone(&orig.channel_penalty_msat),
		payment_path_failed: Clone::clone(&orig.payment_path_failed),
		payment_path_successful: Clone::clone(&orig.payment_path_successful),
		probe_failed: Clone::clone(&orig.probe_failed),
		probe_successful: Clone::clone(&orig.probe_successful),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::util::ser::Writeable for Score {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}

use lightning::routing::scoring::Score as rustScore;
impl rustScore for Score {
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut source: &lightning::routing::gossip::NodeId, mut target: &lightning::routing::gossip::NodeId, mut usage: lightning::routing::scoring::ChannelUsage) -> u64 {
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, crate::lightning::routing::scoring::ChannelUsage { inner: ObjOps::heap_alloc(usage), is_owned: true });
		ret
	}
	fn payment_path_failed(&mut self, mut path: &[&lightning::routing::router::RouteHop], mut short_channel_id: u64) {
		let mut local_path = Vec::new(); for item in path.iter() { local_path.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
		(self.payment_path_failed)(self.this_arg, local_path.into(), short_channel_id)
	}
	fn payment_path_successful(&mut self, mut path: &[&lightning::routing::router::RouteHop]) {
		let mut local_path = Vec::new(); for item in path.iter() { local_path.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
		(self.payment_path_successful)(self.this_arg, local_path.into())
	}
	fn probe_failed(&mut self, mut path: &[&lightning::routing::router::RouteHop], mut short_channel_id: u64) {
		let mut local_path = Vec::new(); for item in path.iter() { local_path.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
		(self.probe_failed)(self.this_arg, local_path.into(), short_channel_id)
	}
	fn probe_successful(&mut self, mut path: &[&lightning::routing::router::RouteHop]) {
		let mut local_path = Vec::new(); for item in path.iter() { local_path.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
		(self.probe_successful)(self.this_arg, local_path.into())
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Score {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Score_free(this_ptr: Score) { }
impl Drop for Score {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A scorer that is accessed under a lock.
///
/// Needed so that calls to [`Score::channel_penalty_msat`] in [`find_route`] can be made while
/// having shared ownership of a scorer but without requiring internal locking in [`Score`]
/// implementations. Internal locking would be detrimental to route finding performance and could
/// result in [`Score::channel_penalty_msat`] returning a different value for the same channel.
///
/// [`find_route`]: crate::routing::router::find_route
#[repr(C)]
pub struct LockableScore {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the locked scorer.
	#[must_use]
	pub lock: extern "C" fn (this_arg: *const c_void) -> crate::lightning::routing::scoring::Score,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for LockableScore {}
unsafe impl Sync for LockableScore {}
#[no_mangle]
pub(crate) extern "C" fn LockableScore_clone_fields(orig: &LockableScore) -> LockableScore {
	LockableScore {
		this_arg: orig.this_arg,
		lock: Clone::clone(&orig.lock),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::scoring::LockableScore as rustLockableScore;
impl<'a> rustLockableScore<'a> for LockableScore {
	type Locked = crate::lightning::routing::scoring::Score;
	fn lock(&'a self) -> crate::lightning::routing::scoring::Score {
		let mut ret = (self.lock)(self.this_arg);
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for LockableScore {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn LockableScore_free(this_ptr: LockableScore) { }
impl Drop for LockableScore {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Refers to a scorer that is accessible under lock and also writeable to disk
///
/// We need this trait to be able to pass in a scorer to `lightning-background-processor` that will enable us to
/// use the Persister to persist it.
#[repr(C)]
pub struct WriteableScore {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Implementation of LockableScore for this object.
	pub LockableScore: crate::lightning::routing::scoring::LockableScore,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for WriteableScore {}
unsafe impl Sync for WriteableScore {}
#[no_mangle]
pub(crate) extern "C" fn WriteableScore_clone_fields(orig: &WriteableScore) -> WriteableScore {
	WriteableScore {
		this_arg: orig.this_arg,
		LockableScore: crate::lightning::routing::scoring::LockableScore_clone_fields(&orig.LockableScore),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl<'a> lightning::routing::scoring::LockableScore<'a> for WriteableScore {
	type Locked = crate::lightning::routing::scoring::Score;
	fn lock(&'a self) -> crate::lightning::routing::scoring::Score {
		let mut ret = (self.LockableScore.lock)(self.LockableScore.this_arg);
		ret
	}
}
impl lightning::util::ser::Writeable for WriteableScore {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}

use lightning::routing::scoring::WriteableScore as rustWriteableScore;
impl<'a> rustWriteableScore<'a> for WriteableScore {
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for WriteableScore {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn WriteableScore_free(this_ptr: WriteableScore) { }
impl Drop for WriteableScore {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::routing::scoring::MultiThreadedLockableScore as nativeMultiThreadedLockableScoreImport;
pub(crate) type nativeMultiThreadedLockableScore = nativeMultiThreadedLockableScoreImport<crate::lightning::routing::scoring::Score>;

/// A concrete implementation of [`LockableScore`] which supports multi-threading.
#[must_use]
#[repr(C)]
pub struct MultiThreadedLockableScore {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMultiThreadedLockableScore,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MultiThreadedLockableScore {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMultiThreadedLockableScore>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MultiThreadedLockableScore, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_free(this_obj: MultiThreadedLockableScore) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MultiThreadedLockableScore_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMultiThreadedLockableScore); }
}
#[allow(unused)]
impl MultiThreadedLockableScore {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMultiThreadedLockableScore {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMultiThreadedLockableScore {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMultiThreadedLockableScore {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::routing::scoring::MultiThreadedScoreLock as nativeMultiThreadedScoreLockImport;
pub(crate) type nativeMultiThreadedScoreLock = nativeMultiThreadedScoreLockImport<'static, crate::lightning::routing::scoring::Score>;

/// A locked `MultiThreadedLockableScore`.
#[must_use]
#[repr(C)]
pub struct MultiThreadedScoreLock {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMultiThreadedScoreLock,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MultiThreadedScoreLock {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMultiThreadedScoreLock>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MultiThreadedScoreLock, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLock_free(this_obj: MultiThreadedScoreLock) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MultiThreadedScoreLock_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMultiThreadedScoreLock); }
}
#[allow(unused)]
impl MultiThreadedScoreLock {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMultiThreadedScoreLock {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMultiThreadedScoreLock {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMultiThreadedScoreLock {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl From<nativeMultiThreadedScoreLock> for crate::lightning::routing::scoring::Score {
	fn from(obj: nativeMultiThreadedScoreLock) -> Self {
		let mut rust_obj = MultiThreadedScoreLock { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedScoreLock_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(MultiThreadedScoreLock_free_void);
		ret
	}
}
/// Constructs a new Score which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Score must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLock_as_Score(this_arg: &MultiThreadedScoreLock) -> crate::lightning::routing::scoring::Score {
	crate::lightning::routing::scoring::Score {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: MultiThreadedScoreLock_Score_channel_penalty_msat,
		payment_path_failed: MultiThreadedScoreLock_Score_payment_path_failed,
		payment_path_successful: MultiThreadedScoreLock_Score_payment_path_successful,
		probe_failed: MultiThreadedScoreLock_Score_probe_failed,
		probe_successful: MultiThreadedScoreLock_Score_probe_successful,
		write: MultiThreadedScoreLock_write_void,
	}
}

#[must_use]
extern "C" fn MultiThreadedScoreLock_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage) -> u64 {
	let mut ret = <nativeMultiThreadedScoreLock as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLock) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) });
	ret
}
extern "C" fn MultiThreadedScoreLock_Score_payment_path_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeMultiThreadedScoreLock as lightning::routing::scoring::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLock) }, &local_path[..], short_channel_id)
}
extern "C" fn MultiThreadedScoreLock_Score_payment_path_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeMultiThreadedScoreLock as lightning::routing::scoring::Score<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLock) }, &local_path[..])
}
extern "C" fn MultiThreadedScoreLock_Score_probe_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeMultiThreadedScoreLock as lightning::routing::scoring::Score<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLock) }, &local_path[..], short_channel_id)
}
extern "C" fn MultiThreadedScoreLock_Score_probe_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeMultiThreadedScoreLock as lightning::routing::scoring::Score<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLock) }, &local_path[..])
}

#[no_mangle]
/// Serialize the MultiThreadedScoreLock object into a byte array which can be read by MultiThreadedScoreLock_read
pub extern "C" fn MultiThreadedScoreLock_write(obj: &crate::lightning::routing::scoring::MultiThreadedScoreLock) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn MultiThreadedScoreLock_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeMultiThreadedScoreLock) })
}
impl From<nativeMultiThreadedLockableScore> for crate::lightning::routing::scoring::LockableScore {
	fn from(obj: nativeMultiThreadedLockableScore) -> Self {
		let mut rust_obj = MultiThreadedLockableScore { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedLockableScore_as_LockableScore(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(MultiThreadedLockableScore_free_void);
		ret
	}
}
/// Constructs a new LockableScore which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned LockableScore must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_as_LockableScore(this_arg: &MultiThreadedLockableScore) -> crate::lightning::routing::scoring::LockableScore {
	crate::lightning::routing::scoring::LockableScore {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		lock: MultiThreadedLockableScore_LockableScore_lock,
	}
}

#[must_use]
extern "C" fn MultiThreadedLockableScore_LockableScore_lock(this_arg: *const c_void) -> crate::lightning::routing::scoring::Score {
	let mut ret = <nativeMultiThreadedLockableScore as lightning::routing::scoring::LockableScore<>>::lock(unsafe { &mut *(this_arg as *mut nativeMultiThreadedLockableScore) }, );
	Into::into(ret)
}

/// Creates a new [`MultiThreadedLockableScore`] given an underlying [`Score`].
#[must_use]
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_new(mut score: crate::lightning::routing::scoring::Score) -> crate::lightning::routing::scoring::MultiThreadedLockableScore {
	let mut ret = lightning::routing::scoring::MultiThreadedLockableScore::new(score);
	crate::lightning::routing::scoring::MultiThreadedLockableScore { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::routing::scoring::ChannelUsage as nativeChannelUsageImport;
pub(crate) type nativeChannelUsage = nativeChannelUsageImport;

/// Proposed use of a channel passed as a parameter to [`Score::channel_penalty_msat`].
#[must_use]
#[repr(C)]
pub struct ChannelUsage {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelUsage,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelUsage {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelUsage>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelUsage, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelUsage_free(this_obj: ChannelUsage) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelUsage_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelUsage); }
}
#[allow(unused)]
impl ChannelUsage {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelUsage {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelUsage {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelUsage {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The amount to send through the channel, denominated in millisatoshis.
#[no_mangle]
pub extern "C" fn ChannelUsage_get_amount_msat(this_ptr: &ChannelUsage) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().amount_msat;
	*inner_val
}
/// The amount to send through the channel, denominated in millisatoshis.
#[no_mangle]
pub extern "C" fn ChannelUsage_set_amount_msat(this_ptr: &mut ChannelUsage, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.amount_msat = val;
}
/// Total amount, denominated in millisatoshis, already allocated to send through the channel
/// as part of a multi-path payment.
#[no_mangle]
pub extern "C" fn ChannelUsage_get_inflight_htlc_msat(this_ptr: &ChannelUsage) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inflight_htlc_msat;
	*inner_val
}
/// Total amount, denominated in millisatoshis, already allocated to send through the channel
/// as part of a multi-path payment.
#[no_mangle]
pub extern "C" fn ChannelUsage_set_inflight_htlc_msat(this_ptr: &mut ChannelUsage, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inflight_htlc_msat = val;
}
/// The effective capacity of the channel.
#[no_mangle]
pub extern "C" fn ChannelUsage_get_effective_capacity(this_ptr: &ChannelUsage) -> crate::lightning::routing::gossip::EffectiveCapacity {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().effective_capacity;
	crate::lightning::routing::gossip::EffectiveCapacity::from_native(inner_val)
}
/// The effective capacity of the channel.
#[no_mangle]
pub extern "C" fn ChannelUsage_set_effective_capacity(this_ptr: &mut ChannelUsage, mut val: crate::lightning::routing::gossip::EffectiveCapacity) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.effective_capacity = val.into_native();
}
/// Constructs a new ChannelUsage given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelUsage_new(mut amount_msat_arg: u64, mut inflight_htlc_msat_arg: u64, mut effective_capacity_arg: crate::lightning::routing::gossip::EffectiveCapacity) -> ChannelUsage {
	ChannelUsage { inner: ObjOps::heap_alloc(nativeChannelUsage {
		amount_msat: amount_msat_arg,
		inflight_htlc_msat: inflight_htlc_msat_arg,
		effective_capacity: effective_capacity_arg.into_native(),
	}), is_owned: true }
}
impl Clone for ChannelUsage {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelUsage>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelUsage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelUsage)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelUsage
pub extern "C" fn ChannelUsage_clone(orig: &ChannelUsage) -> ChannelUsage {
	orig.clone()
}

use lightning::routing::scoring::FixedPenaltyScorer as nativeFixedPenaltyScorerImport;
pub(crate) type nativeFixedPenaltyScorer = nativeFixedPenaltyScorerImport;

/// [`Score`] implementation that uses a fixed penalty.
#[must_use]
#[repr(C)]
pub struct FixedPenaltyScorer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFixedPenaltyScorer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for FixedPenaltyScorer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFixedPenaltyScorer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the FixedPenaltyScorer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_free(this_obj: FixedPenaltyScorer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FixedPenaltyScorer_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeFixedPenaltyScorer); }
}
#[allow(unused)]
impl FixedPenaltyScorer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFixedPenaltyScorer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFixedPenaltyScorer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFixedPenaltyScorer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for FixedPenaltyScorer {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeFixedPenaltyScorer>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FixedPenaltyScorer_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeFixedPenaltyScorer)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the FixedPenaltyScorer
pub extern "C" fn FixedPenaltyScorer_clone(orig: &FixedPenaltyScorer) -> FixedPenaltyScorer {
	orig.clone()
}
/// Creates a new scorer using `penalty_msat`.
#[must_use]
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_with_penalty(mut penalty_msat: u64) -> crate::lightning::routing::scoring::FixedPenaltyScorer {
	let mut ret = lightning::routing::scoring::FixedPenaltyScorer::with_penalty(penalty_msat);
	crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeFixedPenaltyScorer> for crate::lightning::routing::scoring::Score {
	fn from(obj: nativeFixedPenaltyScorer) -> Self {
		let mut rust_obj = FixedPenaltyScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = FixedPenaltyScorer_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(FixedPenaltyScorer_free_void);
		ret
	}
}
/// Constructs a new Score which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Score must be freed before this_arg is
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_as_Score(this_arg: &FixedPenaltyScorer) -> crate::lightning::routing::scoring::Score {
	crate::lightning::routing::scoring::Score {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: FixedPenaltyScorer_Score_channel_penalty_msat,
		payment_path_failed: FixedPenaltyScorer_Score_payment_path_failed,
		payment_path_successful: FixedPenaltyScorer_Score_payment_path_successful,
		probe_failed: FixedPenaltyScorer_Score_probe_failed,
		probe_successful: FixedPenaltyScorer_Score_probe_successful,
		write: FixedPenaltyScorer_write_void,
	}
}

#[must_use]
extern "C" fn FixedPenaltyScorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage) -> u64 {
	let mut ret = <nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) });
	ret
}
extern "C" fn FixedPenaltyScorer_Score_payment_path_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local_path[..], short_channel_id)
}
extern "C" fn FixedPenaltyScorer_Score_payment_path_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local_path[..])
}
extern "C" fn FixedPenaltyScorer_Score_probe_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local_path[..], short_channel_id)
}
extern "C" fn FixedPenaltyScorer_Score_probe_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local_path[..])
}

#[no_mangle]
/// Serialize the FixedPenaltyScorer object into a byte array which can be read by FixedPenaltyScorer_read
pub extern "C" fn FixedPenaltyScorer_write(obj: &crate::lightning::routing::scoring::FixedPenaltyScorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn FixedPenaltyScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFixedPenaltyScorer) })
}
#[no_mangle]
/// Read a FixedPenaltyScorer from a byte array, created by FixedPenaltyScorer_write
pub extern "C" fn FixedPenaltyScorer_read(ser: crate::c_types::u8slice, arg: u64) -> crate::c_types::derived::CResult_FixedPenaltyScorerDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::routing::scoring::FixedPenaltyScorer, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::scoring::ProbabilisticScorer as nativeProbabilisticScorerImport;
pub(crate) type nativeProbabilisticScorer = nativeProbabilisticScorerImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>;

/// [`Score`] implementation using channel success probability distributions.
///
/// Based on *Optimally Reliable & Cheap Payment Flows on the Lightning Network* by Rene Pickhardt
/// and Stefan Richter [[1]]. Given the uncertainty of channel liquidity balances, probability
/// distributions are defined based on knowledge learned from successful and unsuccessful attempts.
/// Then the negative `log10` of the success probability is used to determine the cost of routing a
/// specific HTLC amount through a channel.
///
/// Knowledge about channel liquidity balances takes the form of upper and lower bounds on the
/// possible liquidity. Certainty of the bounds is decreased over time using a decay function. See
/// [`ProbabilisticScoringParameters`] for details.
///
/// Since the scorer aims to learn the current channel liquidity balances, it works best for nodes
/// with high payment volume or that actively probe the [`NetworkGraph`]. Nodes with low payment
/// volume are more likely to experience failed payment paths, which would need to be retried.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// [1]: https://arxiv.org/abs/2107.05322
#[must_use]
#[repr(C)]
pub struct ProbabilisticScorer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeProbabilisticScorer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ProbabilisticScorer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeProbabilisticScorer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ProbabilisticScorer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_free(this_obj: ProbabilisticScorer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScorer_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeProbabilisticScorer); }
}
#[allow(unused)]
impl ProbabilisticScorer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeProbabilisticScorer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeProbabilisticScorer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeProbabilisticScorer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::routing::scoring::ProbabilisticScoringParameters as nativeProbabilisticScoringParametersImport;
pub(crate) type nativeProbabilisticScoringParameters = nativeProbabilisticScoringParametersImport;

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure base, liquidity, and amount penalties, the sum of which comprises the channel
/// penalty (i.e., the amount in msats willing to be paid to avoid routing through the channel).
///
/// The penalty applied to any channel by the [`ProbabilisticScorer`] is the sum of each of the
/// parameters here.
#[must_use]
#[repr(C)]
pub struct ProbabilisticScoringParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeProbabilisticScoringParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ProbabilisticScoringParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeProbabilisticScoringParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ProbabilisticScoringParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_free(this_obj: ProbabilisticScoringParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeProbabilisticScoringParameters); }
}
#[allow(unused)]
impl ProbabilisticScoringParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeProbabilisticScoringParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeProbabilisticScoringParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeProbabilisticScoringParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// A fixed penalty in msats to apply to each channel.
///
/// Default value: 500 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_base_penalty_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_msat;
	*inner_val
}
/// A fixed penalty in msats to apply to each channel.
///
/// Default value: 500 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_base_penalty_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_msat = val;
}
/// A multiplier used with the payment amount to calculate a fixed penalty applied to each
/// channel, in excess of the [`base_penalty_msat`].
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^30`ths of the payment amount.
///
/// ie `base_penalty_amount_multiplier_msat * amount_msat / 2^30`
///
/// Default value: 8,192 msat
///
/// [`base_penalty_msat`]: Self::base_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_base_penalty_amount_multiplier_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_amount_multiplier_msat;
	*inner_val
}
/// A multiplier used with the payment amount to calculate a fixed penalty applied to each
/// channel, in excess of the [`base_penalty_msat`].
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^30`ths of the payment amount.
///
/// ie `base_penalty_amount_multiplier_msat * amount_msat / 2^30`
///
/// Default value: 8,192 msat
///
/// [`base_penalty_msat`]: Self::base_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_base_penalty_amount_multiplier_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_amount_multiplier_msat = val;
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for a payment to determine the liquidity penalty.
///
/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
/// lower bounding the success probability to `0.01`) when the amount falls within the
/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
/// result in a `u64::max_value` penalty, however.
///
/// Default value: 40,000 msat
///
/// [`liquidity_offset_half_life`]: Self::liquidity_offset_half_life
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_liquidity_penalty_multiplier_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_penalty_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for a payment to determine the liquidity penalty.
///
/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
/// lower bounding the success probability to `0.01`) when the amount falls within the
/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
/// result in a `u64::max_value` penalty, however.
///
/// Default value: 40,000 msat
///
/// [`liquidity_offset_half_life`]: Self::liquidity_offset_half_life
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_liquidity_penalty_multiplier_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_penalty_multiplier_msat = val;
}
/// The time required to elapse before any knowledge learned about channel liquidity balances is
/// cut in half.
///
/// The bounds are defined in terms of offsets and are initially zero. Increasing the offsets
/// gives tighter bounds on the channel liquidity balance. Thus, halving the offsets decreases
/// the certainty of the channel liquidity balance.
///
/// Default value: 1 hour
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
/// liquidity knowledge will never decay except when the bounds cross.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_liquidity_offset_half_life(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_offset_half_life;
	inner_val.as_secs()
}
/// The time required to elapse before any knowledge learned about channel liquidity balances is
/// cut in half.
///
/// The bounds are defined in terms of offsets and are initially zero. Increasing the offsets
/// gives tighter bounds on the channel liquidity balance. Thus, halving the offsets decreases
/// the certainty of the channel liquidity balance.
///
/// Default value: 1 hour
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
/// liquidity knowledge will never decay except when the bounds cross.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_liquidity_offset_half_life(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_offset_half_life = core::time::Duration::from_secs(val);
}
/// A multiplier used in conjunction with a payment amount and the negative `log10` of the
/// channel's success probability for the payment to determine the amount penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^20`ths of the payment amount, weighted by the negative `log10` of the
/// success probability.
///
/// `-log10(success_probability) * liquidity_penalty_amount_multiplier_msat * amount_msat / 2^20`
///
/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
/// the amount will result in a penalty of the multiplier. And, as the success probability
/// decreases, the negative `log10` weighting will increase dramatically. For higher success
/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
/// fall below `1`.
///
/// Default value: 256 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_liquidity_penalty_amount_multiplier_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_penalty_amount_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with a payment amount and the negative `log10` of the
/// channel's success probability for the payment to determine the amount penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^20`ths of the payment amount, weighted by the negative `log10` of the
/// success probability.
///
/// `-log10(success_probability) * liquidity_penalty_amount_multiplier_msat * amount_msat / 2^20`
///
/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
/// the amount will result in a penalty of the multiplier. And, as the success probability
/// decreases, the negative `log10` weighting will increase dramatically. For higher success
/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
/// fall below `1`.
///
/// Default value: 256 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_liquidity_penalty_amount_multiplier_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_penalty_amount_multiplier_msat = val;
}
/// This penalty is applied when `htlc_maximum_msat` is equal to or larger than half of the
/// channel's capacity, which makes us prefer nodes with a smaller `htlc_maximum_msat`. We
/// treat such nodes preferentially as this makes balance discovery attacks harder to execute,
/// thereby creating an incentive to restrict `htlc_maximum_msat` and improve privacy.
///
/// Default value: 250 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_anti_probing_penalty_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().anti_probing_penalty_msat;
	*inner_val
}
/// This penalty is applied when `htlc_maximum_msat` is equal to or larger than half of the
/// channel's capacity, which makes us prefer nodes with a smaller `htlc_maximum_msat`. We
/// treat such nodes preferentially as this makes balance discovery attacks harder to execute,
/// thereby creating an incentive to restrict `htlc_maximum_msat` and improve privacy.
///
/// Default value: 250 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_anti_probing_penalty_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.anti_probing_penalty_msat = val;
}
/// This penalty is applied when the amount we're attempting to send over a channel exceeds our
/// current estimate of the channel's available liquidity.
///
/// Note that in this case all other penalties, including the
/// [`liquidity_penalty_multiplier_msat`] and [`liquidity_penalty_amount_multiplier_msat`]-based
/// penalties, as well as the [`base_penalty_msat`] and the [`anti_probing_penalty_msat`], if
/// applicable, are still included in the overall penalty.
///
/// If you wish to avoid creating paths with such channels entirely, setting this to a value of
/// `u64::max_value()` will guarantee that.
///
/// Default value: 1_0000_0000_000 msat (1 Bitcoin)
///
/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
/// [`base_penalty_msat`]: Self::base_penalty_msat
/// [`anti_probing_penalty_msat`]: Self::anti_probing_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_considered_impossible_penalty_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().considered_impossible_penalty_msat;
	*inner_val
}
/// This penalty is applied when the amount we're attempting to send over a channel exceeds our
/// current estimate of the channel's available liquidity.
///
/// Note that in this case all other penalties, including the
/// [`liquidity_penalty_multiplier_msat`] and [`liquidity_penalty_amount_multiplier_msat`]-based
/// penalties, as well as the [`base_penalty_msat`] and the [`anti_probing_penalty_msat`], if
/// applicable, are still included in the overall penalty.
///
/// If you wish to avoid creating paths with such channels entirely, setting this to a value of
/// `u64::max_value()` will guarantee that.
///
/// Default value: 1_0000_0000_000 msat (1 Bitcoin)
///
/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
/// [`base_penalty_msat`]: Self::base_penalty_msat
/// [`anti_probing_penalty_msat`]: Self::anti_probing_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_set_considered_impossible_penalty_msat(this_ptr: &mut ProbabilisticScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.considered_impossible_penalty_msat = val;
}
impl Clone for ProbabilisticScoringParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeProbabilisticScoringParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeProbabilisticScoringParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ProbabilisticScoringParameters
pub extern "C" fn ProbabilisticScoringParameters_clone(orig: &ProbabilisticScoringParameters) -> ProbabilisticScoringParameters {
	orig.clone()
}
/// Creates a new scorer using the given scoring parameters for sending payments from a node
/// through a network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_new(mut params: crate::lightning::routing::scoring::ProbabilisticScoringParameters, network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::routing::scoring::ProbabilisticScorer {
	let mut ret = lightning::routing::scoring::ProbabilisticScorer::new(*unsafe { Box::from_raw(params.take_inner()) }, network_graph.get_native_ref(), logger);
	crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Dump the contents of this scorer into the configured logger.
///
/// Note that this writes roughly one line per channel for which we have a liquidity estimate,
/// which may be a substantial amount of log output.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_debug_log_liquidity_stats(this_arg: &crate::lightning::routing::scoring::ProbabilisticScorer) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.debug_log_liquidity_stats()
}

/// Query the estimated minimum and maximum liquidity available for sending a payment over the
/// channel with `scid` towards the given `target` node.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_estimated_channel_liquidity_range(this_arg: &crate::lightning::routing::scoring::ProbabilisticScorer, mut scid: u64, target: &crate::lightning::routing::gossip::NodeId) -> crate::c_types::derived::COption_C2Tuple_u64u64ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.estimated_channel_liquidity_range(scid, target.get_native_ref());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_u64u64ZZ::None } else { crate::c_types::derived::COption_C2Tuple_u64u64ZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_ret_0 = (orig_ret_0_0, orig_ret_0_1).into(); local_ret_0 }) };
	local_ret
}

/// Marks the node with the given `node_id` as banned, i.e.,
/// it will be avoided during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_add_banned(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScorer, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScorer)) }.add_banned(node_id.get_native_ref())
}

/// Removes the node with the given `node_id` from the list of nodes to avoid.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_remove_banned(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScorer, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScorer)) }.remove_banned(node_id.get_native_ref())
}

/// Sets a manual penalty for the given node.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_set_manual_penalty(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScorer, node_id: &crate::lightning::routing::gossip::NodeId, mut penalty: u64) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScorer)) }.set_manual_penalty(node_id.get_native_ref(), penalty)
}

/// Removes the node with the given `node_id` from the list of manual penalties.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_remove_manual_penalty(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScorer, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScorer)) }.remove_manual_penalty(node_id.get_native_ref())
}

/// Clears the list of manual penalties that are applied during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_clear_manual_penalties(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScorer) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScorer)) }.clear_manual_penalties()
}

/// Marks all nodes in the given list as banned, i.e.,
/// they will be avoided during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_add_banned_from_list(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringParameters, mut node_ids: crate::c_types::derived::CVec_NodeIdZ) {
	let mut local_node_ids = Vec::new(); for mut item in node_ids.into_rust().drain(..) { local_node_ids.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringParameters)) }.add_banned_from_list(local_node_ids)
}

/// Creates a "default" ProbabilisticScoringParameters. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_default() -> ProbabilisticScoringParameters {
	ProbabilisticScoringParameters { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
impl From<nativeProbabilisticScorer> for crate::lightning::routing::scoring::Score {
	fn from(obj: nativeProbabilisticScorer) -> Self {
		let mut rust_obj = ProbabilisticScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ProbabilisticScorer_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ProbabilisticScorer_free_void);
		ret
	}
}
/// Constructs a new Score which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Score must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_as_Score(this_arg: &ProbabilisticScorer) -> crate::lightning::routing::scoring::Score {
	crate::lightning::routing::scoring::Score {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: ProbabilisticScorer_Score_channel_penalty_msat,
		payment_path_failed: ProbabilisticScorer_Score_payment_path_failed,
		payment_path_successful: ProbabilisticScorer_Score_payment_path_successful,
		probe_failed: ProbabilisticScorer_Score_probe_failed,
		probe_successful: ProbabilisticScorer_Score_probe_successful,
		write: ProbabilisticScorer_write_void,
	}
}

#[must_use]
extern "C" fn ProbabilisticScorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage) -> u64 {
	let mut ret = <nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) });
	ret
}
extern "C" fn ProbabilisticScorer_Score_payment_path_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, &local_path[..], short_channel_id)
}
extern "C" fn ProbabilisticScorer_Score_payment_path_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, &local_path[..])
}
extern "C" fn ProbabilisticScorer_Score_probe_failed(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, &local_path[..], short_channel_id)
}
extern "C" fn ProbabilisticScorer_Score_probe_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, &local_path[..])
}

mod approx {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
#[no_mangle]
/// Serialize the ProbabilisticScorer object into a byte array which can be read by ProbabilisticScorer_read
pub extern "C" fn ProbabilisticScorer_write(obj: &crate::lightning::routing::scoring::ProbabilisticScorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ProbabilisticScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeProbabilisticScorer) })
}
#[no_mangle]
/// Read a ProbabilisticScorer from a byte array, created by ProbabilisticScorer_write
pub extern "C" fn ProbabilisticScorer_read(ser: crate::c_types::u8slice, arg_a: crate::lightning::routing::scoring::ProbabilisticScoringParameters, arg_b: &crate::lightning::routing::gossip::NetworkGraph, arg_c: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_ProbabilisticScorerDecodeErrorZ {
	let arg_a_conv = *unsafe { Box::from_raw(arg_a.take_inner()) };
	let arg_b_conv = arg_b.get_native_ref();
	let arg_c_conv = arg_c;
	let arg_conv = (arg_a_conv, arg_b_conv, arg_c_conv);
	let res: Result<lightning::routing::scoring::ProbabilisticScorer<&lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
