// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for scoring payment channels.
//!
//! [`Scorer`] may be given to [`get_route`] to score payment channels during path finding when a
//! custom [`routing::Score`] implementation is not needed.
//!
//! # Example
//!
//! ```
//! # extern crate secp256k1;
//! #
//! # use lightning::routing::network_graph::NetworkGraph;
//! # use lightning::routing::router::get_route;
//! # use lightning::routing::scorer::Scorer;
//! # use lightning::util::logger::{Logger, Record};
//! # use secp256k1::key::PublicKey;
//! #
//! # struct FakeLogger {};
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # fn find_scored_route(payer: PublicKey, payee: PublicKey, network_graph: NetworkGraph) {
//! # let logger = FakeLogger {};
//! #
//! // Use the default channel penalty.
//! let scorer = Scorer::default();
//!
//! // Or use a custom channel penalty.
//! let scorer = Scorer::new(1_000);
//!
//! let route = get_route(&payer, &network_graph, &payee, None, None, &vec![], 1_000, 42, &logger, &scorer);
//! # }
//! ```
//!
//! [`get_route`]: crate::routing::router::get_route

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::routing::scorer::Scorer as nativeScorerImport;
type nativeScorer = nativeScorerImport;

/// [`routing::Score`] implementation that provides reasonable default behavior.
///
/// Used to apply a fixed penalty to each channel, thus avoiding long paths when shorter paths with
/// slightly higher fees are available.
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
extern "C" fn Scorer_free_void(this_ptr: *mut c_void) {
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
/// Creates a new scorer using `base_penalty_msat` as the channel penalty.
#[must_use]
#[no_mangle]
pub extern "C" fn Scorer_new(mut base_penalty_msat: u64) -> Scorer {
	let mut ret = lightning::routing::scorer::Scorer::new(base_penalty_msat);
	Scorer { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a "default" Scorer. See struct and individual field documentaiton for details on which values are used.
#[must_use]
#[no_mangle]
pub extern "C" fn Scorer_default() -> Scorer {
	Scorer { inner: ObjOps::heap_alloc(Default::default()), is_owned: true }
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
	}
}

#[must_use]
extern "C" fn Scorer_Score_channel_penalty_msat(this_arg: *const c_void, mut _short_channel_id: u64) -> u64 {
	let mut ret = <nativeScorer as lightning::routing::Score<>>::channel_penalty_msat(unsafe { &mut *(this_arg as *mut nativeScorer) }, _short_channel_id);
	ret
}

