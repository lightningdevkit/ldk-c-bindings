// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Traits and utility impls which allow other parts of rust-lightning to interact with the
//! blockchain.
//!
//! Includes traits for monitoring and receiving notifications of new blocks and block
//! disconnections, transaction broadcasting, and feerate information requests.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An interface to send a transaction to the Bitcoin network.
#[repr(C)]
pub struct BroadcasterInterface {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Sends a transaction out to (hopefully) be mined.
	pub broadcast_transaction: extern "C" fn (this_arg: *const c_void, tx: crate::c_types::Transaction),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for BroadcasterInterface {}
unsafe impl Sync for BroadcasterInterface {}
#[no_mangle]
pub(crate) extern "C" fn BroadcasterInterface_clone_fields(orig: &BroadcasterInterface) -> BroadcasterInterface {
	BroadcasterInterface {
		this_arg: orig.this_arg,
		broadcast_transaction: Clone::clone(&orig.broadcast_transaction),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::chaininterface::BroadcasterInterface as rustBroadcasterInterface;
impl rustBroadcasterInterface for BroadcasterInterface {
	fn broadcast_transaction(&self, mut tx: &bitcoin::blockdata::transaction::Transaction) {
		(self.broadcast_transaction)(self.this_arg, crate::c_types::Transaction::from_bitcoin(tx))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for BroadcasterInterface {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn BroadcasterInterface_free(this_ptr: BroadcasterInterface) { }
impl Drop for BroadcasterInterface {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An enum that represents the speed at which we want a transaction to confirm used for feerate
/// estimation.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum ConfirmationTarget {
	/// We are happy with this transaction confirming slowly when feerate drops some.
	Background,
	/// We'd like this transaction to confirm without major delay, but 12-18 blocks is fine.
	Normal,
	/// We'd like this transaction to confirm in the next few blocks.
	HighPriority,
}
use lightning::chain::chaininterface::ConfirmationTarget as nativeConfirmationTarget;
impl ConfirmationTarget {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
}
/// Creates a copy of the ConfirmationTarget
#[no_mangle]
pub extern "C" fn ConfirmationTarget_clone(orig: &ConfirmationTarget) -> ConfirmationTarget {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Background-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_background() -> ConfirmationTarget {
	ConfirmationTarget::Background}
#[no_mangle]
/// Utility method to constructs a new Normal-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_normal() -> ConfirmationTarget {
	ConfirmationTarget::Normal}
#[no_mangle]
/// Utility method to constructs a new HighPriority-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_high_priority() -> ConfirmationTarget {
	ConfirmationTarget::HighPriority}
/// Checks if two ConfirmationTargets contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ConfirmationTarget_eq(a: &ConfirmationTarget, b: &ConfirmationTarget) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// Note that all of the functions implemented here *must* be reentrant-safe (obviously - they're
/// called from inside the library in response to chain events, P2P events, or timer events).
#[repr(C)]
pub struct FeeEstimator {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets estimated satoshis of fee required per 1000 Weight-Units.
	///
	/// Must return a value no smaller than 253 (ie 1 satoshi-per-byte rounded up to ensure later
	/// round-downs don't put us below 1 satoshi-per-byte).
	///
	/// This method can be implemented with the following unit conversions:
	///  * max(satoshis-per-byte * 250, 253)
	///  * max(satoshis-per-kbyte / 4, 253)
	#[must_use]
	pub get_est_sat_per_1000_weight: extern "C" fn (this_arg: *const c_void, confirmation_target: crate::lightning::chain::chaininterface::ConfirmationTarget) -> u32,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for FeeEstimator {}
unsafe impl Sync for FeeEstimator {}
#[no_mangle]
pub(crate) extern "C" fn FeeEstimator_clone_fields(orig: &FeeEstimator) -> FeeEstimator {
	FeeEstimator {
		this_arg: orig.this_arg,
		get_est_sat_per_1000_weight: Clone::clone(&orig.get_est_sat_per_1000_weight),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::chaininterface::FeeEstimator as rustFeeEstimator;
impl rustFeeEstimator for FeeEstimator {
	fn get_est_sat_per_1000_weight(&self, mut confirmation_target: lightning::chain::chaininterface::ConfirmationTarget) -> u32 {
		let mut ret = (self.get_est_sat_per_1000_weight)(self.this_arg, crate::lightning::chain::chaininterface::ConfirmationTarget::native_into(confirmation_target));
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for FeeEstimator {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn FeeEstimator_free(this_ptr: FeeEstimator) { }
impl Drop for FeeEstimator {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Minimum relay fee as required by bitcoin network mempool policy.

#[no_mangle]
pub static MIN_RELAY_FEE_SAT_PER_1000_WEIGHT: u64 = lightning::chain::chaininterface::MIN_RELAY_FEE_SAT_PER_1000_WEIGHT;
