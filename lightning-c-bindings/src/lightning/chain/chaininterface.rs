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

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An interface to send a transaction to the Bitcoin network.
#[repr(C)]
pub struct BroadcasterInterface {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Sends a list of transactions out to (hopefully) be mined.
	/// This only needs to handle the actual broadcasting of transactions, LDK will automatically
	/// rebroadcast transactions that haven't made it into a block.
	///
	/// In some cases LDK may attempt to broadcast a transaction which double-spends another
	/// and this isn't a bug and can be safely ignored.
	///
	/// If more than one transaction is given, these transactions should be considered to be a
	/// package and broadcast together. Some of the transactions may or may not depend on each other,
	/// be sure to manage both cases correctly.
	///
	/// Bitcoin transaction packages are defined in BIP 331 and here:
	/// https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md
	pub broadcast_transactions: extern "C" fn (this_arg: *const c_void, txs: crate::c_types::derived::CVec_TransactionZ),
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
		broadcast_transactions: Clone::clone(&orig.broadcast_transactions),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::chaininterface::BroadcasterInterface as rustBroadcasterInterface;
impl rustBroadcasterInterface for BroadcasterInterface {
	fn broadcast_transactions(&self, mut txs: &[&bitcoin::blockdata::transaction::Transaction]) {
		let mut local_txs = Vec::new(); for item in txs.iter() { local_txs.push( { crate::c_types::Transaction::from_bitcoin((*item)) }); };
		(self.broadcast_transactions)(self.this_arg, local_txs.into())
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for BroadcasterInterface {
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
/// An enum that represents the priority at which we want a transaction to confirm used for feerate
/// estimation.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ConfirmationTarget {
	/// We'd like a transaction to confirm in the future, but don't want to commit most of the fees
	/// required to do so yet. The remaining fees will come via a Child-Pays-For-Parent (CPFP) fee
	/// bump of the transaction.
	///
	/// The feerate returned should be the absolute minimum feerate required to enter most node
	/// mempools across the network. Note that if you are not able to obtain this feerate estimate,
	/// you should likely use the furthest-out estimate allowed by your fee estimator.
	MempoolMinimum,
	/// We are happy with a transaction confirming slowly, at least within a day or so worth of
	/// blocks.
	Background,
	/// We'd like a transaction to confirm without major delayed, i.e., within the next 12-24 blocks.
	Normal,
	/// We'd like a transaction to confirm in the next few blocks.
	HighPriority,
}
use lightning::chain::chaininterface::ConfirmationTarget as ConfirmationTargetImport;
pub(crate) type nativeConfirmationTarget = ConfirmationTargetImport;

impl ConfirmationTarget {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::MempoolMinimum => nativeConfirmationTarget::MempoolMinimum,
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::MempoolMinimum => nativeConfirmationTarget::MempoolMinimum,
			ConfirmationTarget::Background => nativeConfirmationTarget::Background,
			ConfirmationTarget::Normal => nativeConfirmationTarget::Normal,
			ConfirmationTarget::HighPriority => nativeConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::MempoolMinimum => ConfirmationTarget::MempoolMinimum,
			nativeConfirmationTarget::Background => ConfirmationTarget::Background,
			nativeConfirmationTarget::Normal => ConfirmationTarget::Normal,
			nativeConfirmationTarget::HighPriority => ConfirmationTarget::HighPriority,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::MempoolMinimum => ConfirmationTarget::MempoolMinimum,
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
/// Utility method to constructs a new MempoolMinimum-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_mempool_minimum() -> ConfirmationTarget {
	ConfirmationTarget::MempoolMinimum}
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
/// Generates a non-cryptographic 64-bit hash of the ConfirmationTarget.
#[no_mangle]
pub extern "C" fn ConfirmationTarget_hash(o: &ConfirmationTarget) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two ConfirmationTargets contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ConfirmationTarget_eq(a: &ConfirmationTarget, b: &ConfirmationTarget) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// A trait which should be implemented to provide feerate information on a number of time
/// horizons.
///
/// If access to a local mempool is not feasible, feerate estimates should be fetched from a set of
/// third-parties hosting them. Note that this enables them to affect the propagation of your
/// pre-signed transactions at any time and therefore endangers the safety of channels funds. It
/// should be considered carefully as a deployment.
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
	/// LDK will wrap this method and ensure that the value returned is no smaller than 253
	/// (ie 1 satoshi-per-byte rounded up to ensure later round-downs don't put us below 1 satoshi-per-byte).
	///
	/// The following unit conversions can be used to convert to sats/KW:
	///  * satoshis-per-byte * 250
	///  * satoshis-per-kbyte / 4
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
impl core::ops::Deref for FeeEstimator {
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
/// Minimum feerate that takes a sane approach to bitcoind weight-to-vbytes rounding.
/// See the following Core Lightning commit for an explanation:
/// <https://github.com/ElementsProject/lightning/commit/2e687b9b352c9092b5e8bd4a688916ac50b44af0>

#[no_mangle]
pub static FEERATE_FLOOR_SATS_PER_KW: u32 = lightning::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
