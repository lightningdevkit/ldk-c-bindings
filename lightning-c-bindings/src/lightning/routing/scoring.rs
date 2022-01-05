// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for scoring payment channels.
//!
//! [`Scorer`] may be given to [`find_route`] to score payment channels during path finding when a
//! custom [`Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scoring::{Scorer, ScoringParameters};
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, params: RouteParameters, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalties.
//! let scorer = Scorer::default();
//!
//! // Or use custom channel penalties.
//! let scorer = Scorer::new(ScoringParameters {
//!     base_penalty_msat: 1000,
//!     failure_penalty_msat: 2 * 1024 * 1000,
//!     ..ScoringParameters::default()
//! });
//!
//! let route = find_route(&payer, &params, &network_graph, None, &logger, &scorer);
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
	/// The channel's capacity (less any other MPP parts which are also being considered for use in
	/// the same payment) is given by `channel_capacity_msat`. It may be guessed from various
	/// sources or assumed from no data at all.
	///
	/// For hints provided in the invoice, we assume the channel has sufficient capacity to accept
	/// the invoice's full amount, and provide a `channel_capacity_msat` of `None`. In all other
	/// cases it is set to `Some`, even if we're guessing at the channel value.
	///
	/// Your code should be overflow-safe through a `channel_capacity_msat` of 21 million BTC.
	#[must_use]
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64, send_amt_msat: u64, channel_capacity_msat: crate::c_types::derived::COption_u64Z, source: &crate::lightning::routing::network_graph::NodeId, target: &crate::lightning::routing::network_graph::NodeId) -> u64,
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
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut send_amt_msat: u64, mut channel_capacity_msat: Option<u64>, mut source: &lightning::routing::network_graph::NodeId, mut target: &lightning::routing::network_graph::NodeId) -> u64 {
		let mut local_channel_capacity_msat = if channel_capacity_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { channel_capacity_msat.unwrap() }) };
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, send_amt_msat, local_channel_capacity_msat, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false });
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


use lightning::routing::scoring::Scorer as nativeScorerImport;
pub(crate) type nativeScorer = nativeScorerImport;

/// [`Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
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
extern "C" fn Scorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, mut send_amt_msat: u64, mut chan_capacity_opt: crate::c_types::derived::COption_u64Z, _source: &crate::lightning::routing::network_graph::NodeId, _target: &crate::lightning::routing::network_graph::NodeId) -> u64 {
	let mut local_chan_capacity_opt = if chan_capacity_opt.is_some() { Some( { chan_capacity_opt.take() }) } else { None };
	let mut ret = <nativeScorer as lightning::routing::scoring::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeScorer) }, short_channel_id, send_amt_msat, local_chan_capacity_opt, _source.get_native_ref(), _target.get_native_ref());
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
mod time {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
