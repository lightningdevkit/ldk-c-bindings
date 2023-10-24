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
//! finding when a custom [`ScoreLookUp`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate bitcoin;
//! #
//! # use lightning::routing::gossip::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringFeeParameters, ProbabilisticScoringDecayParameters};
//! # use lightning::sign::KeysManager;
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
//! let params = ProbabilisticScoringFeeParameters::default();
//! let decay_params = ProbabilisticScoringDecayParameters::default();
//! let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
//!
//! // Or use custom channel penalties.
//! let params = ProbabilisticScoringFeeParameters {
//! \tliquidity_penalty_multiplier_msat: 2 * 1000,
//! \t..ProbabilisticScoringFeeParameters::default()
//! };
//! let decay_params = ProbabilisticScoringDecayParameters::default();
//! let scorer = ProbabilisticScorer::new(decay_params, &network_graph, &logger);
//! # let random_seed_bytes = [42u8; 32];
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer, &params, &random_seed_bytes);
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
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An interface used to score payment channels for path finding.
///
/// `ScoreLookUp` is used to determine the penalty for a given channel.
///
/// Scoring is in terms of fees willing to be paid in order to avoid routing through a channel.
#[repr(C)]
pub struct ScoreLookUp {
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
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, usage: crate::lightning::routing::scoring::ChannelUsage, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ScoreLookUp {}
unsafe impl Sync for ScoreLookUp {}
#[allow(unused)]
pub(crate) fn ScoreLookUp_clone_fields(orig: &ScoreLookUp) -> ScoreLookUp {
	ScoreLookUp {
		this_arg: orig.this_arg,
		channel_penalty_msat: Clone::clone(&orig.channel_penalty_msat),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::scoring::ScoreLookUp as rustScoreLookUp;
impl rustScoreLookUp for ScoreLookUp {
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut source: &lightning::routing::gossip::NodeId, mut target: &lightning::routing::gossip::NodeId, mut usage: lightning::routing::scoring::ChannelUsage, mut score_params: &lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, crate::lightning::routing::scoring::ChannelUsage { inner: ObjOps::heap_alloc(usage), is_owned: true }, &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((score_params as *const lightning::routing::scoring::ProbabilisticScoringFeeParameters<>) as *mut _) }, is_owned: false });
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for ScoreLookUp {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for ScoreLookUp {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ScoreLookUp_free(this_ptr: ScoreLookUp) { }
impl Drop for ScoreLookUp {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// `ScoreUpdate` is used to update the scorer's internal state after a payment attempt.
#[repr(C)]
pub struct ScoreUpdate {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handles updating channel penalties after failing to route through a channel.
	pub payment_path_failed: extern "C" fn (this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, short_channel_id: u64),
	/// Handles updating channel penalties after successfully routing along a path.
	pub payment_path_successful: extern "C" fn (this_arg: *mut c_void, path: &crate::lightning::routing::router::Path),
	/// Handles updating channel penalties after a probe over the given path failed.
	pub probe_failed: extern "C" fn (this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, short_channel_id: u64),
	/// Handles updating channel penalties after a probe over the given path succeeded.
	pub probe_successful: extern "C" fn (this_arg: *mut c_void, path: &crate::lightning::routing::router::Path),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ScoreUpdate {}
unsafe impl Sync for ScoreUpdate {}
#[allow(unused)]
pub(crate) fn ScoreUpdate_clone_fields(orig: &ScoreUpdate) -> ScoreUpdate {
	ScoreUpdate {
		this_arg: orig.this_arg,
		payment_path_failed: Clone::clone(&orig.payment_path_failed),
		payment_path_successful: Clone::clone(&orig.payment_path_successful),
		probe_failed: Clone::clone(&orig.probe_failed),
		probe_successful: Clone::clone(&orig.probe_successful),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::scoring::ScoreUpdate as rustScoreUpdate;
impl rustScoreUpdate for ScoreUpdate {
	fn payment_path_failed(&mut self, mut path: &lightning::routing::router::Path, mut short_channel_id: u64) {
		(self.payment_path_failed)(self.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false }, short_channel_id)
	}
	fn payment_path_successful(&mut self, mut path: &lightning::routing::router::Path) {
		(self.payment_path_successful)(self.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false })
	}
	fn probe_failed(&mut self, mut path: &lightning::routing::router::Path, mut short_channel_id: u64) {
		(self.probe_failed)(self.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false }, short_channel_id)
	}
	fn probe_successful(&mut self, mut path: &lightning::routing::router::Path) {
		(self.probe_successful)(self.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for ScoreUpdate {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for ScoreUpdate {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ScoreUpdate_free(this_ptr: ScoreUpdate) { }
impl Drop for ScoreUpdate {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait which can both lookup and update routing channel penalty scores.
///
/// This is used in places where both bounds are required and implemented for all types which
/// implement [`ScoreLookUp`] and [`ScoreUpdate`].
///
/// Bindings users may need to manually implement this for their custom scoring implementations.
#[repr(C)]
pub struct Score {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Implementation of ScoreLookUp for this object.
	pub ScoreLookUp: crate::lightning::routing::scoring::ScoreLookUp,
	/// Implementation of ScoreUpdate for this object.
	pub ScoreUpdate: crate::lightning::routing::scoring::ScoreUpdate,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Score {}
unsafe impl Sync for Score {}
#[allow(unused)]
pub(crate) fn Score_clone_fields(orig: &Score) -> Score {
	Score {
		this_arg: orig.this_arg,
		ScoreLookUp: crate::lightning::routing::scoring::ScoreLookUp_clone_fields(&orig.ScoreLookUp),
		ScoreUpdate: crate::lightning::routing::scoring::ScoreUpdate_clone_fields(&orig.ScoreUpdate),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::routing::scoring::ScoreLookUp for Score {
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut source: &lightning::routing::gossip::NodeId, mut target: &lightning::routing::gossip::NodeId, mut usage: lightning::routing::scoring::ChannelUsage, mut score_params: &lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
		let mut ret = (self.ScoreLookUp.channel_penalty_msat)(self.ScoreLookUp.this_arg, short_channel_id, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }, crate::lightning::routing::scoring::ChannelUsage { inner: ObjOps::heap_alloc(usage), is_owned: true }, &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((score_params as *const lightning::routing::scoring::ProbabilisticScoringFeeParameters<>) as *mut _) }, is_owned: false });
		ret
	}
}
impl lightning::routing::scoring::ScoreUpdate for Score {
	fn payment_path_failed(&mut self, mut path: &lightning::routing::router::Path, mut short_channel_id: u64) {
		(self.ScoreUpdate.payment_path_failed)(self.ScoreUpdate.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false }, short_channel_id)
	}
	fn payment_path_successful(&mut self, mut path: &lightning::routing::router::Path) {
		(self.ScoreUpdate.payment_path_successful)(self.ScoreUpdate.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false })
	}
	fn probe_failed(&mut self, mut path: &lightning::routing::router::Path, mut short_channel_id: u64) {
		(self.ScoreUpdate.probe_failed)(self.ScoreUpdate.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false }, short_channel_id)
	}
	fn probe_successful(&mut self, mut path: &lightning::routing::router::Path) {
		(self.ScoreUpdate.probe_successful)(self.ScoreUpdate.this_arg, &crate::lightning::routing::router::Path { inner: unsafe { ObjOps::nonnull_ptr_to_inner((path as *const lightning::routing::router::Path<>) as *mut _) }, is_owned: false })
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
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Score {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for Score {
	fn deref_mut(&mut self) -> &mut Self {
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
/// Needed so that calls to [`ScoreLookUp::channel_penalty_msat`] in [`find_route`] can be made while
/// having shared ownership of a scorer but without requiring internal locking in [`ScoreUpdate`]
/// implementations. Internal locking would be detrimental to route finding performance and could
/// result in [`ScoreLookUp::channel_penalty_msat`] returning a different value for the same channel.
///
/// [`find_route`]: crate::routing::router::find_route
#[repr(C)]
pub struct LockableScore {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns read locked scorer.
	pub read_lock: extern "C" fn (this_arg: *const c_void) -> crate::lightning::routing::scoring::ScoreLookUp,
	/// Returns write locked scorer.
	pub write_lock: extern "C" fn (this_arg: *const c_void) -> crate::lightning::routing::scoring::ScoreUpdate,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for LockableScore {}
unsafe impl Sync for LockableScore {}
#[allow(unused)]
pub(crate) fn LockableScore_clone_fields(orig: &LockableScore) -> LockableScore {
	LockableScore {
		this_arg: orig.this_arg,
		read_lock: Clone::clone(&orig.read_lock),
		write_lock: Clone::clone(&orig.write_lock),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::scoring::LockableScore as rustLockableScore;
impl<'a> rustLockableScore<'a> for LockableScore {
	type ScoreUpdate = crate::lightning::routing::scoring::ScoreUpdate;
	type ScoreLookUp = crate::lightning::routing::scoring::ScoreLookUp;
	type WriteLocked = crate::lightning::routing::scoring::ScoreUpdate;
	type ReadLocked = crate::lightning::routing::scoring::ScoreLookUp;
	fn read_lock(&'a self) -> crate::lightning::routing::scoring::ScoreLookUp {
		let mut ret = (self.read_lock)(self.this_arg);
		ret
	}
	fn write_lock(&'a self) -> crate::lightning::routing::scoring::ScoreUpdate {
		let mut ret = (self.write_lock)(self.this_arg);
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
impl core::ops::DerefMut for LockableScore {
	fn deref_mut(&mut self) -> &mut Self {
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
#[allow(unused)]
pub(crate) fn WriteableScore_clone_fields(orig: &WriteableScore) -> WriteableScore {
	WriteableScore {
		this_arg: orig.this_arg,
		LockableScore: crate::lightning::routing::scoring::LockableScore_clone_fields(&orig.LockableScore),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl<'a> lightning::routing::scoring::LockableScore<'a> for WriteableScore {
	type ScoreUpdate = crate::lightning::routing::scoring::ScoreUpdate;
	type ScoreLookUp = crate::lightning::routing::scoring::ScoreLookUp;
	type WriteLocked = crate::lightning::routing::scoring::ScoreUpdate;
	type ReadLocked = crate::lightning::routing::scoring::ScoreLookUp;
	fn read_lock(&'a self) -> crate::lightning::routing::scoring::ScoreLookUp {
		let mut ret = (self.LockableScore.read_lock)(self.LockableScore.this_arg);
		ret
	}
	fn write_lock(&'a self) -> crate::lightning::routing::scoring::ScoreUpdate {
		let mut ret = (self.LockableScore.write_lock)(self.LockableScore.this_arg);
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
impl core::ops::DerefMut for WriteableScore {
	fn deref_mut(&mut self) -> &mut Self {
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMultiThreadedLockableScore) };
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
impl From<nativeMultiThreadedLockableScore> for crate::lightning::routing::scoring::LockableScore {
	fn from(obj: nativeMultiThreadedLockableScore) -> Self {
		let rust_obj = crate::lightning::routing::scoring::MultiThreadedLockableScore { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedLockableScore_as_LockableScore(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
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
		read_lock: MultiThreadedLockableScore_LockableScore_read_lock,
		write_lock: MultiThreadedLockableScore_LockableScore_write_lock,
	}
}

#[must_use]
extern "C" fn MultiThreadedLockableScore_LockableScore_read_lock(this_arg: *const c_void) -> crate::lightning::routing::scoring::ScoreLookUp {
	let mut ret = <nativeMultiThreadedLockableScore as lightning::routing::scoring::LockableScore<>>::read_lock(unsafe { &mut *(this_arg as *mut nativeMultiThreadedLockableScore) }, );
	Into::into(ret)
}
#[must_use]
extern "C" fn MultiThreadedLockableScore_LockableScore_write_lock(this_arg: *const c_void) -> crate::lightning::routing::scoring::ScoreUpdate {
	let mut ret = <nativeMultiThreadedLockableScore as lightning::routing::scoring::LockableScore<>>::write_lock(unsafe { &mut *(this_arg as *mut nativeMultiThreadedLockableScore) }, );
	Into::into(ret)
}

#[no_mangle]
/// Serialize the MultiThreadedLockableScore object into a byte array which can be read by MultiThreadedLockableScore_read
pub extern "C" fn MultiThreadedLockableScore_write(obj: &crate::lightning::routing::scoring::MultiThreadedLockableScore) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn MultiThreadedLockableScore_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeMultiThreadedLockableScore) })
}
impl From<nativeMultiThreadedLockableScore> for crate::lightning::routing::scoring::WriteableScore {
	fn from(obj: nativeMultiThreadedLockableScore) -> Self {
		let rust_obj = crate::lightning::routing::scoring::MultiThreadedLockableScore { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedLockableScore_as_WriteableScore(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(MultiThreadedLockableScore_free_void);
		ret
	}
}
/// Constructs a new WriteableScore which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned WriteableScore must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_as_WriteableScore(this_arg: &MultiThreadedLockableScore) -> crate::lightning::routing::scoring::WriteableScore {
	crate::lightning::routing::scoring::WriteableScore {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		LockableScore: crate::lightning::routing::scoring::LockableScore {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			read_lock: MultiThreadedLockableScore_LockableScore_read_lock,
			write_lock: MultiThreadedLockableScore_LockableScore_write_lock,
		},
		write: MultiThreadedLockableScore_write_void,
	}
}


/// Creates a new [`MultiThreadedLockableScore`] given an underlying [`Score`].
#[must_use]
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_new(mut score: crate::lightning::routing::scoring::Score) -> crate::lightning::routing::scoring::MultiThreadedLockableScore {
	let mut ret = lightning::routing::scoring::MultiThreadedLockableScore::new(score);
	crate::lightning::routing::scoring::MultiThreadedLockableScore { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::routing::scoring::MultiThreadedScoreLockRead as nativeMultiThreadedScoreLockReadImport;
pub(crate) type nativeMultiThreadedScoreLockRead = nativeMultiThreadedScoreLockReadImport<'static, crate::lightning::routing::scoring::Score>;

/// A locked `MultiThreadedLockableScore`.
#[must_use]
#[repr(C)]
pub struct MultiThreadedScoreLockRead {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMultiThreadedScoreLockRead,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MultiThreadedScoreLockRead {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMultiThreadedScoreLockRead>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MultiThreadedScoreLockRead, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLockRead_free(this_obj: MultiThreadedScoreLockRead) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MultiThreadedScoreLockRead_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMultiThreadedScoreLockRead) };
}
#[allow(unused)]
impl MultiThreadedScoreLockRead {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMultiThreadedScoreLockRead {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMultiThreadedScoreLockRead {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMultiThreadedScoreLockRead {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::routing::scoring::MultiThreadedScoreLockWrite as nativeMultiThreadedScoreLockWriteImport;
pub(crate) type nativeMultiThreadedScoreLockWrite = nativeMultiThreadedScoreLockWriteImport<'static, crate::lightning::routing::scoring::Score>;

/// A locked `MultiThreadedLockableScore`.
#[must_use]
#[repr(C)]
pub struct MultiThreadedScoreLockWrite {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMultiThreadedScoreLockWrite,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MultiThreadedScoreLockWrite {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMultiThreadedScoreLockWrite>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MultiThreadedScoreLockWrite, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLockWrite_free(this_obj: MultiThreadedScoreLockWrite) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MultiThreadedScoreLockWrite_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMultiThreadedScoreLockWrite) };
}
#[allow(unused)]
impl MultiThreadedScoreLockWrite {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMultiThreadedScoreLockWrite {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMultiThreadedScoreLockWrite {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMultiThreadedScoreLockWrite {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl From<nativeMultiThreadedScoreLockRead> for crate::lightning::routing::scoring::ScoreLookUp {
	fn from(obj: nativeMultiThreadedScoreLockRead) -> Self {
		let rust_obj = crate::lightning::routing::scoring::MultiThreadedScoreLockRead { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedScoreLockRead_as_ScoreLookUp(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(MultiThreadedScoreLockRead_free_void);
		ret
	}
}
/// Constructs a new ScoreLookUp which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreLookUp must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLockRead_as_ScoreLookUp(this_arg: &MultiThreadedScoreLockRead) -> crate::lightning::routing::scoring::ScoreLookUp {
	crate::lightning::routing::scoring::ScoreLookUp {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: MultiThreadedScoreLockRead_ScoreLookUp_channel_penalty_msat,
	}
}

#[must_use]
extern "C" fn MultiThreadedScoreLockRead_ScoreLookUp_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
	let mut ret = <nativeMultiThreadedScoreLockRead as lightning::routing::scoring::ScoreLookUp<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLockRead) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) }, score_params.get_native_ref());
	ret
}

#[no_mangle]
/// Serialize the MultiThreadedScoreLockWrite object into a byte array which can be read by MultiThreadedScoreLockWrite_read
pub extern "C" fn MultiThreadedScoreLockWrite_write(obj: &crate::lightning::routing::scoring::MultiThreadedScoreLockWrite) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn MultiThreadedScoreLockWrite_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeMultiThreadedScoreLockWrite) })
}
impl From<nativeMultiThreadedScoreLockWrite> for crate::lightning::routing::scoring::ScoreUpdate {
	fn from(obj: nativeMultiThreadedScoreLockWrite) -> Self {
		let rust_obj = crate::lightning::routing::scoring::MultiThreadedScoreLockWrite { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MultiThreadedScoreLockWrite_as_ScoreUpdate(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(MultiThreadedScoreLockWrite_free_void);
		ret
	}
}
/// Constructs a new ScoreUpdate which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreUpdate must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MultiThreadedScoreLockWrite_as_ScoreUpdate(this_arg: &MultiThreadedScoreLockWrite) -> crate::lightning::routing::scoring::ScoreUpdate {
	crate::lightning::routing::scoring::ScoreUpdate {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		payment_path_failed: MultiThreadedScoreLockWrite_ScoreUpdate_payment_path_failed,
		payment_path_successful: MultiThreadedScoreLockWrite_ScoreUpdate_payment_path_successful,
		probe_failed: MultiThreadedScoreLockWrite_ScoreUpdate_probe_failed,
		probe_successful: MultiThreadedScoreLockWrite_ScoreUpdate_probe_successful,
	}
}

extern "C" fn MultiThreadedScoreLockWrite_ScoreUpdate_payment_path_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeMultiThreadedScoreLockWrite as lightning::routing::scoring::ScoreUpdate<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLockWrite) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn MultiThreadedScoreLockWrite_ScoreUpdate_payment_path_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeMultiThreadedScoreLockWrite as lightning::routing::scoring::ScoreUpdate<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLockWrite) }, path.get_native_ref())
}
extern "C" fn MultiThreadedScoreLockWrite_ScoreUpdate_probe_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeMultiThreadedScoreLockWrite as lightning::routing::scoring::ScoreUpdate<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLockWrite) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn MultiThreadedScoreLockWrite_ScoreUpdate_probe_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeMultiThreadedScoreLockWrite as lightning::routing::scoring::ScoreUpdate<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeMultiThreadedScoreLockWrite) }, path.get_native_ref())
}


use lightning::routing::scoring::ChannelUsage as nativeChannelUsageImport;
pub(crate) type nativeChannelUsage = nativeChannelUsageImport;

/// Proposed use of a channel passed as a parameter to [`ScoreLookUp::channel_penalty_msat`].
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelUsage) };
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelUsage)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelUsage
pub extern "C" fn ChannelUsage_clone(orig: &ChannelUsage) -> ChannelUsage {
	orig.clone()
}

use lightning::routing::scoring::FixedPenaltyScorer as nativeFixedPenaltyScorerImport;
pub(crate) type nativeFixedPenaltyScorer = nativeFixedPenaltyScorerImport;

/// [`ScoreLookUp`] implementation that uses a fixed penalty.
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeFixedPenaltyScorer) };
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeFixedPenaltyScorer)).clone() })) as *mut c_void
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

impl From<nativeFixedPenaltyScorer> for crate::lightning::routing::scoring::ScoreLookUp {
	fn from(obj: nativeFixedPenaltyScorer) -> Self {
		let rust_obj = crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = FixedPenaltyScorer_as_ScoreLookUp(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(FixedPenaltyScorer_free_void);
		ret
	}
}
/// Constructs a new ScoreLookUp which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreLookUp must be freed before this_arg is
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_as_ScoreLookUp(this_arg: &FixedPenaltyScorer) -> crate::lightning::routing::scoring::ScoreLookUp {
	crate::lightning::routing::scoring::ScoreLookUp {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: FixedPenaltyScorer_ScoreLookUp_channel_penalty_msat,
	}
}

#[must_use]
extern "C" fn FixedPenaltyScorer_ScoreLookUp_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
	let mut ret = <nativeFixedPenaltyScorer as lightning::routing::scoring::ScoreLookUp<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) }, score_params.get_native_ref());
	ret
}

impl From<nativeFixedPenaltyScorer> for crate::lightning::routing::scoring::ScoreUpdate {
	fn from(obj: nativeFixedPenaltyScorer) -> Self {
		let rust_obj = crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = FixedPenaltyScorer_as_ScoreUpdate(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(FixedPenaltyScorer_free_void);
		ret
	}
}
/// Constructs a new ScoreUpdate which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreUpdate must be freed before this_arg is
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_as_ScoreUpdate(this_arg: &FixedPenaltyScorer) -> crate::lightning::routing::scoring::ScoreUpdate {
	crate::lightning::routing::scoring::ScoreUpdate {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		payment_path_failed: FixedPenaltyScorer_ScoreUpdate_payment_path_failed,
		payment_path_successful: FixedPenaltyScorer_ScoreUpdate_payment_path_successful,
		probe_failed: FixedPenaltyScorer_ScoreUpdate_probe_failed,
		probe_successful: FixedPenaltyScorer_ScoreUpdate_probe_successful,
	}
}

extern "C" fn FixedPenaltyScorer_ScoreUpdate_payment_path_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeFixedPenaltyScorer as lightning::routing::scoring::ScoreUpdate<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn FixedPenaltyScorer_ScoreUpdate_payment_path_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeFixedPenaltyScorer as lightning::routing::scoring::ScoreUpdate<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, path.get_native_ref())
}
extern "C" fn FixedPenaltyScorer_ScoreUpdate_probe_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeFixedPenaltyScorer as lightning::routing::scoring::ScoreUpdate<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn FixedPenaltyScorer_ScoreUpdate_probe_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeFixedPenaltyScorer as lightning::routing::scoring::ScoreUpdate<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, path.get_native_ref())
}

#[no_mangle]
/// Serialize the FixedPenaltyScorer object into a byte array which can be read by FixedPenaltyScorer_read
pub extern "C" fn FixedPenaltyScorer_write(obj: &crate::lightning::routing::scoring::FixedPenaltyScorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn FixedPenaltyScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFixedPenaltyScorer) })
}
#[no_mangle]
/// Read a FixedPenaltyScorer from a byte array, created by FixedPenaltyScorer_write
pub extern "C" fn FixedPenaltyScorer_read(ser: crate::c_types::u8slice, arg: u64) -> crate::c_types::derived::CResult_FixedPenaltyScorerDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::routing::scoring::FixedPenaltyScorer, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::routing::scoring::ProbabilisticScorer as nativeProbabilisticScorerImport;
pub(crate) type nativeProbabilisticScorer = nativeProbabilisticScorerImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>;

/// [`ScoreLookUp`] implementation using channel success probability distributions.
///
/// Channels are tracked with upper and lower liquidity bounds - when an HTLC fails at a channel,
/// we learn that the upper-bound on the available liquidity is lower than the amount of the HTLC.
/// When a payment is forwarded through a channel (but fails later in the route), we learn the
/// lower-bound on the channel's available liquidity must be at least the value of the HTLC.
///
/// These bounds are then used to determine a success probability using the formula from
/// *Optimally Reliable & Cheap Payment Flows on the Lightning Network* by Rene Pickhardt
/// and Stefan Richter [[1]] (i.e. `(upper_bound - payment_amount) / (upper_bound - lower_bound)`).
///6762, 1070
/// This probability is combined with the [`liquidity_penalty_multiplier_msat`] and
/// [`liquidity_penalty_amount_multiplier_msat`] parameters to calculate a concrete penalty in
/// milli-satoshis. The penalties, when added across all hops, have the property of being linear in
/// terms of the entire path's success probability. This allows the router to directly compare
/// penalties for different paths. See the documentation of those parameters for the exact formulas.
///
/// The liquidity bounds are decayed by halving them every [`liquidity_offset_half_life`].
///
/// Further, we track the history of our upper and lower liquidity bounds for each channel,
/// allowing us to assign a second penalty (using [`historical_liquidity_penalty_multiplier_msat`]
/// and [`historical_liquidity_penalty_amount_multiplier_msat`]) based on the same probability
/// formula, but using the history of a channel rather than our latest estimates for the liquidity
/// bounds.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// [1]: https://arxiv.org/abs/2107.05322
/// [`liquidity_penalty_multiplier_msat`]: ProbabilisticScoringFeeParameters::liquidity_penalty_multiplier_msat
/// [`liquidity_penalty_amount_multiplier_msat`]: ProbabilisticScoringFeeParameters::liquidity_penalty_amount_multiplier_msat
/// [`liquidity_offset_half_life`]: ProbabilisticScoringDecayParameters::liquidity_offset_half_life
/// [`historical_liquidity_penalty_multiplier_msat`]: ProbabilisticScoringFeeParameters::historical_liquidity_penalty_multiplier_msat
/// [`historical_liquidity_penalty_amount_multiplier_msat`]: ProbabilisticScoringFeeParameters::historical_liquidity_penalty_amount_multiplier_msat
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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeProbabilisticScorer) };
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

use lightning::routing::scoring::ProbabilisticScoringFeeParameters as nativeProbabilisticScoringFeeParametersImport;
pub(crate) type nativeProbabilisticScoringFeeParameters = nativeProbabilisticScoringFeeParametersImport;

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure base, liquidity, and amount penalties, the sum of which comprises the channel
/// penalty (i.e., the amount in msats willing to be paid to avoid routing through the channel).
///
/// The penalty applied to any channel by the [`ProbabilisticScorer`] is the sum of each of the
/// parameters here.
#[must_use]
#[repr(C)]
pub struct ProbabilisticScoringFeeParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeProbabilisticScoringFeeParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ProbabilisticScoringFeeParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeProbabilisticScoringFeeParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ProbabilisticScoringFeeParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_free(this_obj: ProbabilisticScoringFeeParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringFeeParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeProbabilisticScoringFeeParameters) };
}
#[allow(unused)]
impl ProbabilisticScoringFeeParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeProbabilisticScoringFeeParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeProbabilisticScoringFeeParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeProbabilisticScoringFeeParameters {
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
pub extern "C" fn ProbabilisticScoringFeeParameters_get_base_penalty_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_msat;
	*inner_val
}
/// A fixed penalty in msats to apply to each channel.
///
/// Default value: 500 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_base_penalty_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_msat = val;
}
/// A multiplier used with the total amount flowing over a channel to calculate a fixed penalty
/// applied to each channel, in excess of the [`base_penalty_msat`].
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^30`ths of the total amount flowing over a channel (i.e. the payment
/// amount plus the amount of any other HTLCs flowing we sent over the same channel).
///
/// ie `base_penalty_amount_multiplier_msat * amount_msat / 2^30`
///
/// Default value: 8,192 msat
///
/// [`base_penalty_msat`]: Self::base_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_base_penalty_amount_multiplier_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_amount_multiplier_msat;
	*inner_val
}
/// A multiplier used with the total amount flowing over a channel to calculate a fixed penalty
/// applied to each channel, in excess of the [`base_penalty_msat`].
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^30`ths of the total amount flowing over a channel (i.e. the payment
/// amount plus the amount of any other HTLCs flowing we sent over the same channel).
///
/// ie `base_penalty_amount_multiplier_msat * amount_msat / 2^30`
///
/// Default value: 8,192 msat
///
/// [`base_penalty_msat`]: Self::base_penalty_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_base_penalty_amount_multiplier_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_amount_multiplier_msat = val;
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for a payment, as determined by our latest estimates of the channel's
/// liquidity, to determine the liquidity penalty.
///
/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
/// lower bounding the success probability to `0.01`) when the amount falls within the
/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
/// result in a `u64::max_value` penalty, however.
///
/// `-log10(success_probability) * liquidity_penalty_multiplier_msat`
///
/// Default value: 30,000 msat
///
/// [`liquidity_offset_half_life`]: ProbabilisticScoringDecayParameters::liquidity_offset_half_life
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_liquidity_penalty_multiplier_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_penalty_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for a payment, as determined by our latest estimates of the channel's
/// liquidity, to determine the liquidity penalty.
///
/// The penalty is based in part on the knowledge learned from prior successful and unsuccessful
/// payments. This knowledge is decayed over time based on [`liquidity_offset_half_life`]. The
/// penalty is effectively limited to `2 * liquidity_penalty_multiplier_msat` (corresponding to
/// lower bounding the success probability to `0.01`) when the amount falls within the
/// uncertainty bounds of the channel liquidity balance. Amounts above the upper bound will
/// result in a `u64::max_value` penalty, however.
///
/// `-log10(success_probability) * liquidity_penalty_multiplier_msat`
///
/// Default value: 30,000 msat
///
/// [`liquidity_offset_half_life`]: ProbabilisticScoringDecayParameters::liquidity_offset_half_life
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_liquidity_penalty_multiplier_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_penalty_multiplier_msat = val;
}
/// A multiplier used in conjunction with the total amount flowing over a channel and the
/// negative `log10` of the channel's success probability for the payment, as determined by our
/// latest estimates of the channel's liquidity, to determine the amount penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^20`ths of the amount flowing over this channel, weighted by the negative
/// `log10` of the success probability.
///
/// `-log10(success_probability) * liquidity_penalty_amount_multiplier_msat * amount_msat / 2^20`
///
/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
/// the amount will result in a penalty of the multiplier. And, as the success probability
/// decreases, the negative `log10` weighting will increase dramatically. For higher success
/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
/// fall below `1`.
///
/// Default value: 192 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_liquidity_penalty_amount_multiplier_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_penalty_amount_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with the total amount flowing over a channel and the
/// negative `log10` of the channel's success probability for the payment, as determined by our
/// latest estimates of the channel's liquidity, to determine the amount penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost (i.e.,
/// fees plus penalty) for large payments. The penalty is computed as the product of this
/// multiplier and `2^20`ths of the amount flowing over this channel, weighted by the negative
/// `log10` of the success probability.
///
/// `-log10(success_probability) * liquidity_penalty_amount_multiplier_msat * amount_msat / 2^20`
///
/// In practice, this means for 0.1 success probability (`-log10(0.1) == 1`) each `2^20`th of
/// the amount will result in a penalty of the multiplier. And, as the success probability
/// decreases, the negative `log10` weighting will increase dramatically. For higher success
/// probabilities, the multiplier will have a decreasing effect as the negative `log10` will
/// fall below `1`.
///
/// Default value: 192 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_liquidity_penalty_amount_multiplier_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_penalty_amount_multiplier_msat = val;
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for the payment, as determined based on the history of our estimates of the
/// channel's available liquidity, to determine a penalty.
///
/// This penalty is similar to [`liquidity_penalty_multiplier_msat`], however, instead of using
/// only our latest estimate for the current liquidity available in the channel, it estimates
/// success probability based on the estimated liquidity available in the channel through
/// history. Specifically, every time we update our liquidity bounds on a given channel, we
/// track which of several buckets those bounds fall into, exponentially decaying the
/// probability of each bucket as new samples are added.
///
/// Default value: 10,000 msat
///
/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_historical_liquidity_penalty_multiplier_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().historical_liquidity_penalty_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with the negative `log10` of the channel's success
/// probability for the payment, as determined based on the history of our estimates of the
/// channel's available liquidity, to determine a penalty.
///
/// This penalty is similar to [`liquidity_penalty_multiplier_msat`], however, instead of using
/// only our latest estimate for the current liquidity available in the channel, it estimates
/// success probability based on the estimated liquidity available in the channel through
/// history. Specifically, every time we update our liquidity bounds on a given channel, we
/// track which of several buckets those bounds fall into, exponentially decaying the
/// probability of each bucket as new samples are added.
///
/// Default value: 10,000 msat
///
/// [`liquidity_penalty_multiplier_msat`]: Self::liquidity_penalty_multiplier_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_historical_liquidity_penalty_multiplier_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.historical_liquidity_penalty_multiplier_msat = val;
}
/// A multiplier used in conjunction with the total amount flowing over a channel and the
/// negative `log10` of the channel's success probability for the payment, as determined based
/// on the history of our estimates of the channel's available liquidity, to determine a
/// penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost for
/// large payments. The penalty is computed as the product of this multiplier and `2^20`ths
/// of the amount flowing over this channel, weighted by the negative `log10` of the success
/// probability.
///
/// This penalty is similar to [`liquidity_penalty_amount_multiplier_msat`], however, instead
/// of using only our latest estimate for the current liquidity available in the channel, it
/// estimates success probability based on the estimated liquidity available in the channel
/// through history. Specifically, every time we update our liquidity bounds on a given
/// channel, we track which of several buckets those bounds fall into, exponentially decaying
/// the probability of each bucket as new samples are added.
///
/// Default value: 64 msat
///
/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_historical_liquidity_penalty_amount_multiplier_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().historical_liquidity_penalty_amount_multiplier_msat;
	*inner_val
}
/// A multiplier used in conjunction with the total amount flowing over a channel and the
/// negative `log10` of the channel's success probability for the payment, as determined based
/// on the history of our estimates of the channel's available liquidity, to determine a
/// penalty.
///
/// The purpose of the amount penalty is to avoid having fees dominate the channel cost for
/// large payments. The penalty is computed as the product of this multiplier and `2^20`ths
/// of the amount flowing over this channel, weighted by the negative `log10` of the success
/// probability.
///
/// This penalty is similar to [`liquidity_penalty_amount_multiplier_msat`], however, instead
/// of using only our latest estimate for the current liquidity available in the channel, it
/// estimates success probability based on the estimated liquidity available in the channel
/// through history. Specifically, every time we update our liquidity bounds on a given
/// channel, we track which of several buckets those bounds fall into, exponentially decaying
/// the probability of each bucket as new samples are added.
///
/// Default value: 64 msat
///
/// [`liquidity_penalty_amount_multiplier_msat`]: Self::liquidity_penalty_amount_multiplier_msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_historical_liquidity_penalty_amount_multiplier_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.historical_liquidity_penalty_amount_multiplier_msat = val;
}
/// This penalty is applied when `htlc_maximum_msat` is equal to or larger than half of the
/// channel's capacity, (ie. htlc_maximum_msat >= 0.5 * channel_capacity) which makes us
/// prefer nodes with a smaller `htlc_maximum_msat`. We treat such nodes preferentially
/// as this makes balance discovery attacks harder to execute, thereby creating an incentive
/// to restrict `htlc_maximum_msat` and improve privacy.
///
/// Default value: 250 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_anti_probing_penalty_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().anti_probing_penalty_msat;
	*inner_val
}
/// This penalty is applied when `htlc_maximum_msat` is equal to or larger than half of the
/// channel's capacity, (ie. htlc_maximum_msat >= 0.5 * channel_capacity) which makes us
/// prefer nodes with a smaller `htlc_maximum_msat`. We treat such nodes preferentially
/// as this makes balance discovery attacks harder to execute, thereby creating an incentive
/// to restrict `htlc_maximum_msat` and improve privacy.
///
/// Default value: 250 msat
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_anti_probing_penalty_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.anti_probing_penalty_msat = val;
}
/// This penalty is applied when the total amount flowing over a channel exceeds our current
/// estimate of the channel's available liquidity. The total amount is the amount of the
/// current HTLC plus any HTLCs which we've sent over the same channel.
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
pub extern "C" fn ProbabilisticScoringFeeParameters_get_considered_impossible_penalty_msat(this_ptr: &ProbabilisticScoringFeeParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().considered_impossible_penalty_msat;
	*inner_val
}
/// This penalty is applied when the total amount flowing over a channel exceeds our current
/// estimate of the channel's available liquidity. The total amount is the amount of the
/// current HTLC plus any HTLCs which we've sent over the same channel.
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
pub extern "C" fn ProbabilisticScoringFeeParameters_set_considered_impossible_penalty_msat(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.considered_impossible_penalty_msat = val;
}
/// In order to calculate most of the scores above, we must first convert a lower and upper
/// bound on the available liquidity in a channel into the probability that we think a payment
/// will succeed. That probability is derived from a Probability Density Function for where we
/// think the liquidity in a channel likely lies, given such bounds.
///
/// If this flag is set, that PDF is simply a constant - we assume that the actual available
/// liquidity in a channel is just as likely to be at any point between our lower and upper
/// bounds.
///
/// If this flag is *not* set, that PDF is `(x - 0.5*capacity) ^ 2`. That is, we use an
/// exponential curve which expects the liquidity of a channel to lie \"at the edges\". This
/// matches experimental results - most routing nodes do not aggressively rebalance their
/// channels and flows in the network are often unbalanced, leaving liquidity usually
/// unavailable.
///
/// Thus, for the \"best\" routes, leave this flag `false`. However, the flag does imply a number
/// of floating-point multiplications in the hottest routing code, which may lead to routing
/// performance degradation on some machines.
///
/// Default value: false
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_get_linear_success_probability(this_ptr: &ProbabilisticScoringFeeParameters) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().linear_success_probability;
	*inner_val
}
/// In order to calculate most of the scores above, we must first convert a lower and upper
/// bound on the available liquidity in a channel into the probability that we think a payment
/// will succeed. That probability is derived from a Probability Density Function for where we
/// think the liquidity in a channel likely lies, given such bounds.
///
/// If this flag is set, that PDF is simply a constant - we assume that the actual available
/// liquidity in a channel is just as likely to be at any point between our lower and upper
/// bounds.
///
/// If this flag is *not* set, that PDF is `(x - 0.5*capacity) ^ 2`. That is, we use an
/// exponential curve which expects the liquidity of a channel to lie \"at the edges\". This
/// matches experimental results - most routing nodes do not aggressively rebalance their
/// channels and flows in the network are often unbalanced, leaving liquidity usually
/// unavailable.
///
/// Thus, for the \"best\" routes, leave this flag `false`. However, the flag does imply a number
/// of floating-point multiplications in the hottest routing code, which may lead to routing
/// performance degradation on some machines.
///
/// Default value: false
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_linear_success_probability(this_ptr: &mut ProbabilisticScoringFeeParameters, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.linear_success_probability = val;
}
impl Clone for ProbabilisticScoringFeeParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeProbabilisticScoringFeeParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringFeeParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeProbabilisticScoringFeeParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ProbabilisticScoringFeeParameters
pub extern "C" fn ProbabilisticScoringFeeParameters_clone(orig: &ProbabilisticScoringFeeParameters) -> ProbabilisticScoringFeeParameters {
	orig.clone()
}
/// Creates a "default" ProbabilisticScoringFeeParameters. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_default() -> ProbabilisticScoringFeeParameters {
	ProbabilisticScoringFeeParameters { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
/// Marks the node with the given `node_id` as banned,
/// i.e it will be avoided during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_add_banned(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.add_banned(node_id.get_native_ref())
}

/// Marks all nodes in the given list as banned, i.e.,
/// they will be avoided during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_add_banned_from_list(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, mut node_ids: crate::c_types::derived::CVec_NodeIdZ) {
	let mut local_node_ids = Vec::new(); for mut item in node_ids.into_rust().drain(..) { local_node_ids.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.add_banned_from_list(local_node_ids)
}

/// Removes the node with the given `node_id` from the list of nodes to avoid.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_remove_banned(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.remove_banned(node_id.get_native_ref())
}

/// Sets a manual penalty for the given node.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_set_manual_penalty(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, node_id: &crate::lightning::routing::gossip::NodeId, mut penalty: u64) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.set_manual_penalty(node_id.get_native_ref(), penalty)
}

/// Removes the node with the given `node_id` from the list of manual penalties.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_remove_manual_penalty(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters, node_id: &crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.remove_manual_penalty(node_id.get_native_ref())
}

/// Clears the list of manual penalties that are applied during path finding.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringFeeParameters_clear_manual_penalties(this_arg: &mut crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::scoring::nativeProbabilisticScoringFeeParameters)) }.clear_manual_penalties()
}


use lightning::routing::scoring::ProbabilisticScoringDecayParameters as nativeProbabilisticScoringDecayParametersImport;
pub(crate) type nativeProbabilisticScoringDecayParameters = nativeProbabilisticScoringDecayParametersImport;

/// Parameters for configuring [`ProbabilisticScorer`].
///
/// Used to configure decay parameters that are static throughout the lifetime of the scorer.
/// these decay parameters affect the score of the channel penalty and are not changed on a
/// per-route penalty cost call.
#[must_use]
#[repr(C)]
pub struct ProbabilisticScoringDecayParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeProbabilisticScoringDecayParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ProbabilisticScoringDecayParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeProbabilisticScoringDecayParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ProbabilisticScoringDecayParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_free(this_obj: ProbabilisticScoringDecayParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringDecayParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeProbabilisticScoringDecayParameters) };
}
#[allow(unused)]
impl ProbabilisticScoringDecayParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeProbabilisticScoringDecayParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeProbabilisticScoringDecayParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeProbabilisticScoringDecayParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// If we aren't learning any new datapoints for a channel, the historical liquidity bounds
/// tracking can simply live on with increasingly stale data. Instead, when a channel has not
/// seen a liquidity estimate update for this amount of time, the historical datapoints are
/// decayed by half.
/// For an example of historical_no_updates_half_life being used see [`historical_estimated_channel_liquidity_probabilities`]
///
/// Note that after 16 or more half lives all historical data will be completely gone.
///
/// Default value: 14 days
///
/// [`historical_estimated_channel_liquidity_probabilities`]: ProbabilisticScorerUsingTime::historical_estimated_channel_liquidity_probabilities
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_get_historical_no_updates_half_life(this_ptr: &ProbabilisticScoringDecayParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().historical_no_updates_half_life;
	inner_val.as_secs()
}
/// If we aren't learning any new datapoints for a channel, the historical liquidity bounds
/// tracking can simply live on with increasingly stale data. Instead, when a channel has not
/// seen a liquidity estimate update for this amount of time, the historical datapoints are
/// decayed by half.
/// For an example of historical_no_updates_half_life being used see [`historical_estimated_channel_liquidity_probabilities`]
///
/// Note that after 16 or more half lives all historical data will be completely gone.
///
/// Default value: 14 days
///
/// [`historical_estimated_channel_liquidity_probabilities`]: ProbabilisticScorerUsingTime::historical_estimated_channel_liquidity_probabilities
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_set_historical_no_updates_half_life(this_ptr: &mut ProbabilisticScoringDecayParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.historical_no_updates_half_life = core::time::Duration::from_secs(val);
}
/// Whenever this amount of time elapses since the last update to a channel's liquidity bounds,
/// the distance from the bounds to \"zero\" is cut in half. In other words, the lower-bound on
/// the available liquidity is halved and the upper-bound moves half-way to the channel's total
/// capacity.
///
/// Because halving the liquidity bounds grows the uncertainty on the channel's liquidity,
/// the penalty for an amount within the new bounds may change. See the [`ProbabilisticScorer`]
/// struct documentation for more info on the way the liquidity bounds are used.
///
/// For example, if the channel's capacity is 1 million sats, and the current upper and lower
/// liquidity bounds are 200,000 sats and 600,000 sats, after this amount of time the upper
/// and lower liquidity bounds will be decayed to 100,000 and 800,000 sats.
///
/// Default value: 6 hours
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
/// liquidity knowledge will never decay except when the bounds cross.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_get_liquidity_offset_half_life(this_ptr: &ProbabilisticScoringDecayParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_offset_half_life;
	inner_val.as_secs()
}
/// Whenever this amount of time elapses since the last update to a channel's liquidity bounds,
/// the distance from the bounds to \"zero\" is cut in half. In other words, the lower-bound on
/// the available liquidity is halved and the upper-bound moves half-way to the channel's total
/// capacity.
///
/// Because halving the liquidity bounds grows the uncertainty on the channel's liquidity,
/// the penalty for an amount within the new bounds may change. See the [`ProbabilisticScorer`]
/// struct documentation for more info on the way the liquidity bounds are used.
///
/// For example, if the channel's capacity is 1 million sats, and the current upper and lower
/// liquidity bounds are 200,000 sats and 600,000 sats, after this amount of time the upper
/// and lower liquidity bounds will be decayed to 100,000 and 800,000 sats.
///
/// Default value: 6 hours
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, the channel
/// liquidity knowledge will never decay except when the bounds cross.
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_set_liquidity_offset_half_life(this_ptr: &mut ProbabilisticScoringDecayParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.liquidity_offset_half_life = core::time::Duration::from_secs(val);
}
/// Constructs a new ProbabilisticScoringDecayParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_new(mut historical_no_updates_half_life_arg: u64, mut liquidity_offset_half_life_arg: u64) -> ProbabilisticScoringDecayParameters {
	ProbabilisticScoringDecayParameters { inner: ObjOps::heap_alloc(nativeProbabilisticScoringDecayParameters {
		historical_no_updates_half_life: core::time::Duration::from_secs(historical_no_updates_half_life_arg),
		liquidity_offset_half_life: core::time::Duration::from_secs(liquidity_offset_half_life_arg),
	}), is_owned: true }
}
impl Clone for ProbabilisticScoringDecayParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeProbabilisticScoringDecayParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ProbabilisticScoringDecayParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeProbabilisticScoringDecayParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ProbabilisticScoringDecayParameters
pub extern "C" fn ProbabilisticScoringDecayParameters_clone(orig: &ProbabilisticScoringDecayParameters) -> ProbabilisticScoringDecayParameters {
	orig.clone()
}
/// Creates a "default" ProbabilisticScoringDecayParameters. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScoringDecayParameters_default() -> ProbabilisticScoringDecayParameters {
	ProbabilisticScoringDecayParameters { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
/// Creates a new scorer using the given scoring parameters for sending payments from a node
/// through a network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_new(mut decay_params: crate::lightning::routing::scoring::ProbabilisticScoringDecayParameters, network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::routing::scoring::ProbabilisticScorer {
	let mut ret = lightning::routing::scoring::ProbabilisticScorer::new(*unsafe { Box::from_raw(decay_params.take_inner()) }, network_graph.get_native_ref(), logger);
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

/// Query the historical estimated minimum and maximum liquidity available for sending a
/// payment over the channel with `scid` towards the given `target` node.
///
/// Returns two sets of 32 buckets. The first set describes the lower-bound liquidity history,
/// the second set describes the upper-bound liquidity history. Each bucket describes the
/// relative frequency at which we've seen a liquidity bound in the bucket's range relative to
/// the channel's total capacity, on an arbitrary scale. Because the values are slowly decayed,
/// more recent data points are weighted more heavily than older datapoints.
///
/// Note that the range of each bucket varies by its location to provide more granular results
/// at the edges of a channel's capacity, where it is more likely to sit.
///
/// When scoring, the estimated probability that an upper-/lower-bound lies in a given bucket
/// is calculated by dividing that bucket's value with the total value of all buckets.
///
/// For example, using a lower bucket count for illustrative purposes, a value of
/// `[0, 0, 0, ..., 0, 32]` indicates that we believe the probability of a bound being very
/// close to the channel's capacity to be 100%, and have never (recently) seen it in any other
/// bucket. A value of `[31, 0, 0, ..., 0, 0, 32]` indicates we've seen the bound being both
/// in the top and bottom bucket, and roughly with similar (recent) frequency.
///
/// Because the datapoints are decayed slowly over time, values will eventually return to
/// `Some(([1; 32], [1; 32]))` and then to `None` once no datapoints remain.
///
/// In order to fetch a single success probability from the buckets provided here, as used in
/// the scoring model, see [`Self::historical_estimated_payment_success_probability`].
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_historical_estimated_channel_liquidity_probabilities(this_arg: &crate::lightning::routing::scoring::ProbabilisticScorer, mut scid: u64, target: &crate::lightning::routing::gossip::NodeId) -> crate::c_types::derived::COption_C2Tuple_ThirtyTwoU16sThirtyTwoU16sZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.historical_estimated_channel_liquidity_probabilities(scid, target.get_native_ref());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C2Tuple_ThirtyTwoU16sThirtyTwoU16sZZ::None } else { crate::c_types::derived::COption_C2Tuple_ThirtyTwoU16sThirtyTwoU16sZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (ret.unwrap()); let mut local_ret_0 = (crate::c_types::ThirtyTwoU16s { data: orig_ret_0_0 }, crate::c_types::ThirtyTwoU16s { data: orig_ret_0_1 }).into(); local_ret_0 }) };
	local_ret
}

/// Query the probability of payment success sending the given `amount_msat` over the channel
/// with `scid` towards the given `target` node, based on the historical estimated liquidity
/// bounds.
///
/// These are the same bounds as returned by
/// [`Self::historical_estimated_channel_liquidity_probabilities`] (but not those returned by
/// [`Self::estimated_channel_liquidity_range`]).
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_historical_estimated_payment_success_probability(this_arg: &crate::lightning::routing::scoring::ProbabilisticScorer, mut scid: u64, target: &crate::lightning::routing::gossip::NodeId, mut amount_msat: u64, params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> crate::c_types::derived::COption_f64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.historical_estimated_payment_success_probability(scid, target.get_native_ref(), amount_msat, params.get_native_ref());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_f64Z::None } else { crate::c_types::derived::COption_f64Z::Some( { ret.unwrap() }) };
	local_ret
}

impl From<nativeProbabilisticScorer> for crate::lightning::routing::scoring::ScoreLookUp {
	fn from(obj: nativeProbabilisticScorer) -> Self {
		let rust_obj = crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ProbabilisticScorer_as_ScoreLookUp(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ProbabilisticScorer_free_void);
		ret
	}
}
/// Constructs a new ScoreLookUp which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreLookUp must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_as_ScoreLookUp(this_arg: &ProbabilisticScorer) -> crate::lightning::routing::scoring::ScoreLookUp {
	crate::lightning::routing::scoring::ScoreLookUp {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: ProbabilisticScorer_ScoreLookUp_channel_penalty_msat,
	}
}

#[must_use]
extern "C" fn ProbabilisticScorer_ScoreLookUp_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, source: &crate::lightning::routing::gossip::NodeId, target: &crate::lightning::routing::gossip::NodeId, mut usage: crate::lightning::routing::scoring::ChannelUsage, score_params: &crate::lightning::routing::scoring::ProbabilisticScoringFeeParameters) -> u64 {
	let mut ret = <nativeProbabilisticScorer as lightning::routing::scoring::ScoreLookUp<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, short_channel_id, source.get_native_ref(), target.get_native_ref(), *unsafe { Box::from_raw(usage.take_inner()) }, score_params.get_native_ref());
	ret
}

impl From<nativeProbabilisticScorer> for crate::lightning::routing::scoring::ScoreUpdate {
	fn from(obj: nativeProbabilisticScorer) -> Self {
		let rust_obj = crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ProbabilisticScorer_as_ScoreUpdate(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(ProbabilisticScorer_free_void);
		ret
	}
}
/// Constructs a new ScoreUpdate which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ScoreUpdate must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_as_ScoreUpdate(this_arg: &ProbabilisticScorer) -> crate::lightning::routing::scoring::ScoreUpdate {
	crate::lightning::routing::scoring::ScoreUpdate {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		payment_path_failed: ProbabilisticScorer_ScoreUpdate_payment_path_failed,
		payment_path_successful: ProbabilisticScorer_ScoreUpdate_payment_path_successful,
		probe_failed: ProbabilisticScorer_ScoreUpdate_probe_failed,
		probe_successful: ProbabilisticScorer_ScoreUpdate_probe_successful,
	}
}

extern "C" fn ProbabilisticScorer_ScoreUpdate_payment_path_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeProbabilisticScorer as lightning::routing::scoring::ScoreUpdate<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn ProbabilisticScorer_ScoreUpdate_payment_path_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeProbabilisticScorer as lightning::routing::scoring::ScoreUpdate<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, path.get_native_ref())
}
extern "C" fn ProbabilisticScorer_ScoreUpdate_probe_failed(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path, mut short_channel_id: u64) {
	<nativeProbabilisticScorer as lightning::routing::scoring::ScoreUpdate<>>::probe_failed(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, path.get_native_ref(), short_channel_id)
}
extern "C" fn ProbabilisticScorer_ScoreUpdate_probe_successful(this_arg: *mut c_void, path: &crate::lightning::routing::router::Path) {
	<nativeProbabilisticScorer as lightning::routing::scoring::ScoreUpdate<>>::probe_successful(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, path.get_native_ref())
}

impl From<nativeProbabilisticScorer> for crate::lightning::routing::scoring::Score {
	fn from(obj: nativeProbabilisticScorer) -> Self {
		let rust_obj = crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ProbabilisticScorer_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
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
		ScoreLookUp: crate::lightning::routing::scoring::ScoreLookUp {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			channel_penalty_msat: ProbabilisticScorer_ScoreLookUp_channel_penalty_msat,
		},
		ScoreUpdate: crate::lightning::routing::scoring::ScoreUpdate {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			payment_path_failed: ProbabilisticScorer_ScoreUpdate_payment_path_failed,
			payment_path_successful: ProbabilisticScorer_ScoreUpdate_payment_path_successful,
			probe_failed: ProbabilisticScorer_ScoreUpdate_probe_failed,
			probe_successful: ProbabilisticScorer_ScoreUpdate_probe_successful,
		},
		write: ProbabilisticScorer_write_void,
	}
}


mod approx {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod bucketed_history {

use alloc::str::FromStr;
use alloc::string::String;
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
#[allow(unused)]
pub(crate) extern "C" fn ProbabilisticScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeProbabilisticScorer) })
}
#[no_mangle]
/// Read a ProbabilisticScorer from a byte array, created by ProbabilisticScorer_write
pub extern "C" fn ProbabilisticScorer_read(ser: crate::c_types::u8slice, arg_a: crate::lightning::routing::scoring::ProbabilisticScoringDecayParameters, arg_b: &crate::lightning::routing::gossip::NetworkGraph, arg_c: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_ProbabilisticScorerDecodeErrorZ {
	let arg_a_conv = *unsafe { Box::from_raw(arg_a.take_inner()) };
	let arg_b_conv = arg_b.get_native_ref();
	let arg_c_conv = arg_c;
	let arg_conv = (arg_a_conv, arg_b_conv, arg_c_conv);
	let res: Result<lightning::routing::scoring::ProbabilisticScorer<&lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
