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
//! custom [`routing::Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::{RouteParameters, find_route};
//! # use lightning::routing::scorer::{Scorer, ScoringParameters};
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
//! If persisting [`Scorer`], it must be restored using the same [`Time`] parameterization. Using a
//! different type results in undefined behavior. Specifically, persisting when built with feature
//! `no-std` and restoring without it, or vice versa, uses different types and thus is undefined.
//!
//! [`find_route`]: crate::routing::router::find_route

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

mod sealed {

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

}

use lightning::routing::scorer::Scorer as nativeScorerImport;
pub(crate) type nativeScorer = nativeScorerImport;

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available. Will further penalize channels that fail to relay payments.
///
/// See [module-level documentation] for usage.
///
/// [module-level documentation]: crate::routing::scorer
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
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::routing::scorer::ScoringParameters as nativeScoringParametersImport;
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
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A fixed penalty in msats to apply to each channel.
#[no_mangle]
pub extern "C" fn ScoringParameters_get_base_penalty_msat(this_ptr: &ScoringParameters) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_penalty_msat;
	*inner_val
}
/// A fixed penalty in msats to apply to each channel.
#[no_mangle]
pub extern "C" fn ScoringParameters_set_base_penalty_msat(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_penalty_msat = val;
}
/// A penalty in msats to apply to a channel upon failing to relay a payment.
///
/// This accumulates for each failure but may be reduced over time based on
/// [`failure_penalty_half_life`].
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
/// [`failure_penalty_half_life`].
///
/// [`failure_penalty_half_life`]: Self::failure_penalty_half_life
#[no_mangle]
pub extern "C" fn ScoringParameters_set_failure_penalty_msat(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.failure_penalty_msat = val;
}
/// The time required to elapse before any accumulated [`failure_penalty_msat`] penalties are
/// cut in half.
///
/// # Note
///
/// When time is an [`Eternity`], as is default when enabling feature `no-std`, it will never
/// elapse. Therefore, this penalty will never decay.
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
/// # Note
///
/// When time is an [`Eternity`], as is default when enabling feature `no-std`, it will never
/// elapse. Therefore, this penalty will never decay.
///
/// [`failure_penalty_msat`]: Self::failure_penalty_msat
#[no_mangle]
pub extern "C" fn ScoringParameters_set_failure_penalty_half_life(this_ptr: &mut ScoringParameters, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.failure_penalty_half_life = std::time::Duration::from_secs(val);
}
/// Constructs a new ScoringParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ScoringParameters_new(mut base_penalty_msat_arg: u64, mut failure_penalty_msat_arg: u64, mut failure_penalty_half_life_arg: u64) -> ScoringParameters {
	ScoringParameters { inner: ObjOps::heap_alloc(nativeScoringParameters {
		base_penalty_msat: base_penalty_msat_arg,
		failure_penalty_msat: failure_penalty_msat_arg,
		failure_penalty_half_life: std::time::Duration::from_secs(failure_penalty_half_life_arg),
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
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scorer::ScoringParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new scorer using the given scoring parameters.
#[must_use]
#[no_mangle]
pub extern "C" fn Scorer_new(mut params: crate::lightning::routing::scorer::ScoringParameters) -> Scorer {
	let mut ret = lightning::routing::scorer::Scorer::new(*unsafe { Box::from_raw(params.take_inner()) });
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
impl From<nativeScorer> for crate::lightning::routing::Score {
	fn from(obj: nativeScorer) -> Self {
		let mut rust_obj = Scorer { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = Scorer_as_Score(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(Scorer_free_void);
		ret
	}
}
/// Constructs a new Score which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Score must be freed before this_arg is
#[no_mangle]
pub extern "C" fn Scorer_as_Score(this_arg: &Scorer) -> crate::lightning::routing::Score {
	crate::lightning::routing::Score {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		channel_penalty_msat: Scorer_Score_channel_penalty_msat,
		payment_path_failed: Scorer_Score_payment_path_failed,
		write: Scorer_write_void,
	}
}

#[must_use]
extern "C" fn Scorer_Score_channel_penalty_msat(this_arg: *const c_void, mut short_channel_id: u64, _source: &crate::lightning::routing::network_graph::NodeId, _target: &crate::lightning::routing::network_graph::NodeId) -> u64 {
	let mut ret = <nativeScorer as lightning::routing::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeScorer) }, short_channel_id, _source.get_native_ref(), _target.get_native_ref());
	ret
}
extern "C" fn Scorer_Score_payment_path_failed(this_arg: *mut c_void, mut _path: crate::c_types::derived::CVec_RouteHopZ, mut short_channel_id: u64) {
	let mut local__path = Vec::new(); for mut item in _path.as_slice().iter() { local__path.push( { item.get_native_ref() }); };
	<nativeScorer as lightning::routing::Score<>>::payment_path_failed(unsafe { &mut *(this_arg as *mut nativeScorer) }, &local__path[..], short_channel_id)
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
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::scorer::Scorer { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
