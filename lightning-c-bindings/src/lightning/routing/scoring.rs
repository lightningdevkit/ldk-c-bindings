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
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{ProbabilisticScorer, ProbabilisticScoringParameters, Scorer, ScoringParameters};
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, route_params: RouteParameters, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let params = ProbabilisticScoringParameters::default();
//! let scorer = ProbabilisticScorer::new(params, &network_graph);
//!
//! // Or use custom channel penalties.
//! let params = ProbabilisticScoringParameters {
//!     liquidity_penalty_multiplier_msat: 2 * 1000,
//!     ..ProbabilisticScoringParameters::default()
//! };
//! let scorer = ProbabilisticScorer::new(params, &network_graph);
//!
//! let route = find_route(&payer, &route_params, &network_graph, None, &logger, &scorer);
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
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64, send_amt_msat: u64, capacity_msat: u64, source: &crate::lightning::routing::network_graph::NodeId, target: &crate::lightning::routing::network_graph::NodeId) -> u64,
	/// Handles updating channel penalties after failing to route through a channel.
	pub payment_path_failed: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: u64),
	/// Handles updating channel penalties after successfully routing along a path.
	pub payment_path_successful: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ),
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
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut send_amt_msat: u64, mut capacity_msat: u64, mut source: &lightning::routing::network_graph::NodeId, mut target: &lightning::routing::network_graph::NodeId) -> u64 {
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, send_amt_msat, capacity_msat, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false });
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
/// Creates a new [`MultiThreadedLockableScore`] given an underlying [`Score`].
#[must_use]
#[no_mangle]
pub extern "C" fn MultiThreadedLockableScore_new(mut score: crate::lightning::routing::scoring::Score) -> MultiThreadedLockableScore {
	let mut ret = lightning::routing::scoring::MultiThreadedLockableScore::new(score);
	MultiThreadedLockableScore { inner: ObjOps::heap_alloc(ret), is_owned: true }
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
#[no_mangle]
/// Serialize the FixedPenaltyScorer object into a byte array which can be read by FixedPenaltyScorer_read
pub extern "C" fn FixedPenaltyScorer_write(obj: &FixedPenaltyScorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn FixedPenaltyScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeFixedPenaltyScorer) })
}
#[no_mangle]
/// Read a FixedPenaltyScorer from a byte array, created by FixedPenaltyScorer_write
pub extern "C" fn FixedPenaltyScorer_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_FixedPenaltyScorerDecodeErrorZ {
	let res: Result<lightning::routing::scoring::FixedPenaltyScorer, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::FixedPenaltyScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new scorer using `penalty_msat`.
#[must_use]
#[no_mangle]
pub extern "C" fn FixedPenaltyScorer_with_penalty(mut penalty_msat: u64) -> FixedPenaltyScorer {
	let mut ret = lightning::routing::scoring::FixedPenaltyScorer::with_penalty(penalty_msat);
	FixedPenaltyScorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
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
		write: FixedPenaltyScorer_write_void,
	}
}

#[must_use]
extern "C" fn FixedPenaltyScorer_Score_channel_penalty_msat(this_arg: *const c_void, unused_0: u64, unused_1: u64, unused_2: u64, unused_3: &crate::lightning::routing::network_graph::NodeId, unused_4: &crate::lightning::routing::network_graph::NodeId) -> u64 {
	let mut ret = <nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, unused_0, unused_1, unused_2, unused_3.get_native_ref(), unused_4.get_native_ref());
	ret
}
extern "C" fn FixedPenaltyScorer_Score_payment_path_failed(this_arg: *mut c_void, mut _path: crate::c_types::derived::CVec_RouteHopZ, mut _short_channel_id: u64) {
	let mut local__path = Vec::new(); for mut item in _path.as_slice().iter() { local__path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local__path[..], _short_channel_id)
}
extern "C" fn FixedPenaltyScorer_Score_payment_path_successful(this_arg: *mut c_void, mut _path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local__path = Vec::new(); for mut item in _path.as_slice().iter() { local__path.push( { item.get_native_ref() }); };
	<nativeFixedPenaltyScorer as lightning::routing::scoring::Score<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeFixedPenaltyScorer) }, &local__path[..])
}


use lightning::routing::scoring::Scorer as nativeScorerImport;
pub(crate) type nativeScorer = nativeScorerImport;

/// [`Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage and [`ScoringParameters`] for customization.
///
/// # Note
///
/// Mixing the `no-std` feature between serialization and deserialization results in undefined
/// behavior.
///
/// [module-level documentation]: crate::routing::scoring
#[must_use]
#[repr(C)]
pub struct Scorer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeScorer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Scorer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeScorer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Scorer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Scorer_free(this_obj: Scorer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Scorer_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeScorer); }
}
#[allow(unused)]
impl Scorer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeScorer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeScorer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeScorer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::routing::scoring::ScoringParameters as nativeScoringParametersImport;
pub(crate) type nativeScoringParameters = nativeScoringParametersImport;

/// Parameters for configuring [`Scorer`].
#[must_use]
#[repr(C)]
pub struct ScoringParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeScoringParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ScoringParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeScoringParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ScoringParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ScoringParameters_free(this_obj: ScoringParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ScoringParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeScoringParameters); }
}
#[allow(unused)]
impl ScoringParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeScoringParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeScoringParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeScoringParameters {
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
pub extern "C" fn ScoringParameters_get_base_penalty_msat(this_ptr: &ScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_msat;
	*inner_val
}
/// A fixed penalty in msats to apply to each channel.
///
/// Default value: 500 msat
#[no_mangle]
pub extern "C" fn ScoringParameters_set_base_penalty_msat(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_msat = val;
}
/// A penalty in msats to apply to a channel upon failing to relay a payment.
///
/// This accumulates for each failure but may be reduced over time based on
/// [`failure_penalty_half_life`] or when successfully routing through a channel.
///
/// Default value: 1,024,000 msat
///
/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
#[no_mangle]
pub extern "C" fn ScoringParameters_get_failure_penalty_msat(this_ptr: &ScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().failure_penalty_msat;
	*inner_val
}
/// A penalty in msats to apply to a channel upon failing to relay a payment.
///
/// This accumulates for each failure but may be reduced over time based on
/// [`failure_penalty_half_life`] or when successfully routing through a channel.
///
/// Default value: 1,024,000 msat
///
/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
#[no_mangle]
pub extern "C" fn ScoringParameters_set_failure_penalty_msat(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.failure_penalty_msat = val;
}
/// When the amount being sent over a channel is this many 1024ths of the total channel
/// capacity, we begin applying [`overuse_penalty_msat_per_1024th`].
///
/// Default value: 128 1024ths (i.e. begin penalizing when an HTLC uses 1/8th of a channel)
///
/// [`overuse_penalty_msat_per_1024th`]: Self::overuse_penalty_msat_per_1024th
#[no_mangle]
pub extern "C" fn ScoringParameters_get_overuse_penalty_start_1024th(this_ptr: &ScoringParameters) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().overuse_penalty_start_1024th;
	*inner_val
}
/// When the amount being sent over a channel is this many 1024ths of the total channel
/// capacity, we begin applying [`overuse_penalty_msat_per_1024th`].
///
/// Default value: 128 1024ths (i.e. begin penalizing when an HTLC uses 1/8th of a channel)
///
/// [`overuse_penalty_msat_per_1024th`]: Self::overuse_penalty_msat_per_1024th
#[no_mangle]
pub extern "C" fn ScoringParameters_set_overuse_penalty_start_1024th(this_ptr: &mut ScoringParameters, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.overuse_penalty_start_1024th = val;
}
/// A penalty applied, per whole 1024ths of the channel capacity which the amount being sent
/// over the channel exceeds [`overuse_penalty_start_1024th`] by.
///
/// Default value: 20 msat (i.e. 2560 msat penalty to use 1/4th of a channel, 7680 msat penalty
///                to use half a channel, and 12,560 msat penalty to use 3/4ths of a channel)
///
/// [`overuse_penalty_start_1024th`]: Self::overuse_penalty_start_1024th
#[no_mangle]
pub extern "C" fn ScoringParameters_get_overuse_penalty_msat_per_1024th(this_ptr: &ScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().overuse_penalty_msat_per_1024th;
	*inner_val
}
/// A penalty applied, per whole 1024ths of the channel capacity which the amount being sent
/// over the channel exceeds [`overuse_penalty_start_1024th`] by.
///
/// Default value: 20 msat (i.e. 2560 msat penalty to use 1/4th of a channel, 7680 msat penalty
///                to use half a channel, and 12,560 msat penalty to use 3/4ths of a channel)
///
/// [`overuse_penalty_start_1024th`]: Self::overuse_penalty_start_1024th
#[no_mangle]
pub extern "C" fn ScoringParameters_set_overuse_penalty_msat_per_1024th(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.overuse_penalty_msat_per_1024th = val;
}
/// The time required to elapse before any accumulated [`failure_penalty_msat`] penalties are
/// cut in half.
///
/// Successfully routing through a channel will immediately cut the penalty in half as well.
///
/// Default value: 1 hour
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, this penalty will
/// never decay.
///
/// [`failure_penalty_msat`]: Self::failure_penalty_msat
#[no_mangle]
pub extern "C" fn ScoringParameters_get_failure_penalty_half_life(this_ptr: &ScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().failure_penalty_half_life;
	inner_val.as_secs()
}
/// The time required to elapse before any accumulated [`failure_penalty_msat`] penalties are
/// cut in half.
///
/// Successfully routing through a channel will immediately cut the penalty in half as well.
///
/// Default value: 1 hour
///
/// # Note
///
/// When built with the `no-std` feature, time will never elapse. Therefore, this penalty will
/// never decay.
///
/// [`failure_penalty_msat`]: Self::failure_penalty_msat
#[no_mangle]
pub extern "C" fn ScoringParameters_set_failure_penalty_half_life(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.failure_penalty_half_life = core::time::Duration::from_secs(val);
}
/// Constructs a new ScoringParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ScoringParameters_new(mut base_penalty_msat_arg: u64, mut failure_penalty_msat_arg: u64, mut overuse_penalty_start_1024th_arg: u16, mut overuse_penalty_msat_per_1024th_arg: u64, mut failure_penalty_half_life_arg: u64) -> ScoringParameters {
	ScoringParameters { inner: ObjOps::heap_alloc(nativeScoringParameters {
		base_penalty_msat: base_penalty_msat_arg,
		failure_penalty_msat: failure_penalty_msat_arg,
		overuse_penalty_start_1024th: overuse_penalty_start_1024th_arg,
		overuse_penalty_msat_per_1024th: overuse_penalty_msat_per_1024th_arg,
		failure_penalty_half_life: core::time::Duration::from_secs(failure_penalty_half_life_arg),
	}), is_owned: true }
}
#[no_mangle]
/// Serialize the ScoringParameters object into a byte array which can be read by ScoringParameters_read
pub extern "C" fn ScoringParameters_write(obj: &ScoringParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ScoringParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeScoringParameters) })
}
#[no_mangle]
/// Read a ScoringParameters from a byte array, created by ScoringParameters_write
pub extern "C" fn ScoringParameters_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ScoringParametersDecodeErrorZ {
	let res: Result<lightning::routing::scoring::ScoringParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::ScoringParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new scorer using the given scoring parameters.
#[must_use]
#[no_mangle]
pub extern "C" fn Scorer_new(mut params: crate::lightning::routing::scoring::ScoringParameters) -> Scorer {
	let mut ret = lightning::routing::scoring::Scorer::new(*unsafe { Box::from_raw(params.take_inner()) });
	Scorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a "default" Scorer. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn Scorer_default() -> Scorer {
	Scorer { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
/// Creates a "default" ScoringParameters. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn ScoringParameters_default() -> ScoringParameters {
	ScoringParameters { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
}
impl From<nativeScorer> for crate::lightning::routing::scoring::Score {
	fn from(obj: nativeScorer) -> Self {
		let mut rust_obj = Scorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = Scorer_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(Scorer_free_void);
		ret
	}
}
/// Constructs a new Score which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Score must be freed before this_arg is
#[no_mangle]
pub extern "C" fn Scorer_as_Score(this_arg: &Scorer) -> crate::lightning::routing::scoring::Score {
	crate::lightning::routing::scoring::Score {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: Scorer_Score_channel_penalty_msat,
		payment_path_failed: Scorer_Score_payment_path_failed,
		payment_path_successful: Scorer_Score_payment_path_successful,
		write: Scorer_write_void,
	}
}

#[must_use]
extern "C" fn Scorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, mut send_amt_msat: u64, mut capacity_msat: u64, _source: &crate::lightning::routing::network_graph::NodeId, _target: &crate::lightning::routing::network_graph::NodeId) -> u64 {
	let mut ret = <nativeScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeScorer) }, short_channel_id, send_amt_msat, capacity_msat, _source.get_native_ref(), _target.get_native_ref());
	ret
}
extern "C" fn Scorer_Score_payment_path_failed(this_arg: *mut c_void, mut _path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local__path = Vec::new(); for mut item in _path.as_slice().iter() { local__path.push( { item.get_native_ref() }); };
	<nativeScorer as lightning::routing::scoring::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeScorer) }, &local__path[..], short_channel_id)
}
extern "C" fn Scorer_Score_payment_path_successful(this_arg: *mut c_void, mut path: crate::c_types::derived::CVec_RouteHopZ) {
	let mut local_path = Vec::new(); for mut item in path.as_slice().iter() { local_path.push( { item.get_native_ref() }); };
	<nativeScorer as lightning::routing::scoring::Score<>>::payment_path_successful(unsafe { &mut *(this_arg as *mut nativeScorer) }, &local_path[..])
}

#[no_mangle]
/// Serialize the Scorer object into a byte array which can be read by Scorer_read
pub extern "C" fn Scorer_write(obj: &Scorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Scorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeScorer) })
}
#[no_mangle]
/// Read a Scorer from a byte array, created by Scorer_write
pub extern "C" fn Scorer_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ScorerDecodeErrorZ {
	let res: Result<lightning::routing::scoring::Scorer, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::Scorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::scoring::ProbabilisticScorer as nativeProbabilisticScorerImport;
pub(crate) type nativeProbabilisticScorer = nativeProbabilisticScorerImport<&'static lightning::routing::network_graph::NetworkGraph>;

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
/// A multiplier used to determine the amount in msats willing to be paid to avoid routing
/// through a channel, as per multiplying by the negative `log10` of the channel's success
/// probability for a payment.
///
/// The success probability is determined by the effective channel capacity, the payment amount,
/// and knowledge learned from prior successful and unsuccessful payments. The lower bound of
/// the success probability is 0.01, effectively limiting the penalty to the range
/// `0..=2*liquidity_penalty_multiplier_msat`. The knowledge learned is decayed over time based
/// on [`liquidity_offset_half_life`].
///
/// Default value: 10,000 msat
///
/// [`liquidity_offset_half_life`]: Self::liquidity_offset_half_life
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_get_liquidity_penalty_multiplier_msat(this_ptr: &ProbabilisticScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().liquidity_penalty_multiplier_msat;
	*inner_val
}
/// A multiplier used to determine the amount in msats willing to be paid to avoid routing
/// through a channel, as per multiplying by the negative `log10` of the channel's success
/// probability for a payment.
///
/// The success probability is determined by the effective channel capacity, the payment amount,
/// and knowledge learned from prior successful and unsuccessful payments. The lower bound of
/// the success probability is 0.01, effectively limiting the penalty to the range
/// `0..=2*liquidity_penalty_multiplier_msat`. The knowledge learned is decayed over time based
/// on [`liquidity_offset_half_life`].
///
/// Default value: 10,000 msat
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
/// Constructs a new ProbabilisticScoringParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScoringParameters_new(mut liquidity_penalty_multiplier_msat_arg: u64, mut liquidity_offset_half_life_arg: u64) -> ProbabilisticScoringParameters {
	ProbabilisticScoringParameters { inner: ObjOps::heap_alloc(nativeProbabilisticScoringParameters {
		liquidity_penalty_multiplier_msat: liquidity_penalty_multiplier_msat_arg,
		liquidity_offset_half_life: core::time::Duration::from_secs(liquidity_offset_half_life_arg),
	}), is_owned: true }
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
#[no_mangle]
/// Serialize the ProbabilisticScoringParameters object into a byte array which can be read by ProbabilisticScoringParameters_read
pub extern "C" fn ProbabilisticScoringParameters_write(obj: &ProbabilisticScoringParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ProbabilisticScoringParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeProbabilisticScoringParameters) })
}
#[no_mangle]
/// Read a ProbabilisticScoringParameters from a byte array, created by ProbabilisticScoringParameters_write
pub extern "C" fn ProbabilisticScoringParameters_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ProbabilisticScoringParametersDecodeErrorZ {
	let res: Result<lightning::routing::scoring::ProbabilisticScoringParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::ProbabilisticScoringParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new scorer using the given scoring parameters for sending payments from a node
/// through a network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn ProbabilisticScorer_new(mut params: crate::lightning::routing::scoring::ProbabilisticScoringParameters, network_graph: &crate::lightning::routing::network_graph::NetworkGraph) -> ProbabilisticScorer {
	let mut ret = lightning::routing::scoring::ProbabilisticScorer::new(*unsafe { Box::from_raw(params.take_inner()) }, network_graph.get_native_ref());
	ProbabilisticScorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
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
		write: ProbabilisticScorer_write_void,
	}
}

#[must_use]
extern "C" fn ProbabilisticScorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, mut amount_msat: u64, mut capacity_msat: u64, source: &crate::lightning::routing::network_graph::NodeId, target: &crate::lightning::routing::network_graph::NodeId) -> u64 {
	let mut ret = <nativeProbabilisticScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeProbabilisticScorer) }, short_channel_id, amount_msat, capacity_msat, source.get_native_ref(), target.get_native_ref());
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

#[no_mangle]
/// Serialize the ProbabilisticScorer object into a byte array which can be read by ProbabilisticScorer_read
pub extern "C" fn ProbabilisticScorer_write(obj: &ProbabilisticScorer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ProbabilisticScorer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeProbabilisticScorer) })
}
#[no_mangle]
/// Read a ProbabilisticScorer from a byte array, created by ProbabilisticScorer_write
pub extern "C" fn ProbabilisticScorer_read(ser: crate::c_types::u8slice, arg_a: crate::lightning::routing::scoring::ProbabilisticScoringParameters, arg_b: &crate::lightning::routing::network_graph::NetworkGraph) -> crate::c_types::derived::CResult_ProbabilisticScorerDecodeErrorZ {
	let arg_a_conv = *unsafe { Box::from_raw(arg_a.take_inner()) };
	let arg_b_conv = arg_b.get_native_ref();
	let arg_conv = (arg_a_conv, arg_b_conv);
	let res: Result<lightning::routing::scoring::ProbabilisticScorer<&lightning::routing::network_graph::NetworkGraph>, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scoring::ProbabilisticScorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
mod time {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
