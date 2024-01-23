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
use alloc::string::String;
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
	/// <https://github.com/bitcoin/bitcoin/blob/master/doc/policy/packages.md>
	pub broadcast_transactions: extern "C" fn (this_arg: *const c_void, txs: crate::c_types::derived::CVec_TransactionZ),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for BroadcasterInterface {}
unsafe impl Sync for BroadcasterInterface {}
#[allow(unused)]
pub(crate) fn BroadcasterInterface_clone_fields(orig: &BroadcasterInterface) -> BroadcasterInterface {
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
impl core::ops::DerefMut for BroadcasterInterface {
	fn deref_mut(&mut self) -> &mut Self {
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
	/// We have some funds available on chain which we need to spend prior to some expiry time at
	/// which point our counterparty may be able to steal them. Generally we have in the high tens
	/// to low hundreds of blocks to get our transaction on-chain, but we shouldn't risk too low a
	/// fee - this should be a relatively high priority feerate.
	OnChainSweep,
	/// This is the lowest feerate we will allow our channel counterparty to have in an anchor
	/// channel in order to close the channel if a channel party goes away.
	///
	/// This needs to be sufficient to get into the mempool when the channel needs to
	/// be force-closed. Setting too high may result in force-closures if our counterparty attempts
	/// to use a lower feerate. Because this is for anchor channels, we can always bump the feerate
	/// later; the feerate here only needs to be sufficient to enter the mempool.
	///
	/// A good estimate is the expected mempool minimum at the time of force-closure. Obviously this
	/// is not an estimate which is very easy to calculate because we do not know the future. Using
	/// a simple long-term fee estimate or tracking of the mempool minimum is a good approach to
	/// ensure you can always close the channel. A future change to Bitcoin's P2P network
	/// (package relay) may obviate the need for this entirely.
	MinAllowedAnchorChannelRemoteFee,
	/// The lowest feerate we will allow our channel counterparty to have in a non-anchor channel.
	///
	/// This is the feerate on the transaction which we (or our counterparty) will broadcast in
	/// order to close the channel if a channel party goes away. Setting this value too high will
	/// cause immediate force-closures in order to avoid having an unbroadcastable state.
	///
	/// This feerate represents the fee we pick now, which must be sufficient to enter a block at an
	/// arbitrary time in the future. Obviously this is not an estimate which is very easy to
	/// calculate. This can leave channels subject to being unable to close if feerates rise, and in
	/// general you should prefer anchor channels to ensure you can increase the feerate when the
	/// transactions need broadcasting.
	///
	/// Do note some fee estimators round up to the next full sat/vbyte (ie 250 sats per kw),
	/// causing occasional issues with feerate disagreements between an initiator that wants a
	/// feerate of 1.1 sat/vbyte and a receiver that wants 1.1 rounded up to 2. If your fee
	/// estimator rounds subtracting 250 to your desired feerate here can help avoid this issue.
	///
	/// [`ChannelConfig::max_dust_htlc_exposure`]: crate::util::config::ChannelConfig::max_dust_htlc_exposure
	MinAllowedNonAnchorChannelRemoteFee,
	/// This is the feerate on the transaction which we (or our counterparty) will broadcast in
	/// order to close the channel if a channel party goes away.
	///
	/// This needs to be sufficient to get into the mempool when the channel needs to
	/// be force-closed. Setting too low may result in force-closures. Because this is for anchor
	/// channels, it can be a low value as we can always bump the feerate later.
	///
	/// A good estimate is the expected mempool minimum at the time of force-closure. Obviously this
	/// is not an estimate which is very easy to calculate because we do not know the future. Using
	/// a simple long-term fee estimate or tracking of the mempool minimum is a good approach to
	/// ensure you can always close the channel. A future change to Bitcoin's P2P network
	/// (package relay) may obviate the need for this entirely.
	AnchorChannelFee,
	/// Lightning is built around the ability to broadcast a transaction in the future to close our
	/// channel and claim all pending funds. In order to do so, non-anchor channels are built with
	/// transactions which we need to be able to broadcast at some point in the future.
	///
	/// This feerate represents the fee we pick now, which must be sufficient to enter a block at an
	/// arbitrary time in the future. Obviously this is not an estimate which is very easy to
	/// calculate, so most lightning nodes use some relatively high-priority feerate using the
	/// current mempool. This leaves channels subject to being unable to close if feerates rise, and
	/// in general you should prefer anchor channels to ensure you can increase the feerate when the
	/// transactions need broadcasting.
	///
	/// Since this should represent the feerate of a channel close that does not need fee
	/// bumping, this is also used as an upper bound for our attempted feerate when doing cooperative
	/// closure of any channel.
	NonAnchorChannelFee,
	/// When cooperatively closing a channel, this is the minimum feerate we will accept.
	/// Recommended at least within a day or so worth of blocks.
	///
	/// This will also be used when initiating a cooperative close of a channel. When closing a
	/// channel you can override this fee by using
	/// [`ChannelManager::close_channel_with_feerate_and_script`].
	///
	/// [`ChannelManager::close_channel_with_feerate_and_script`]: crate::ln::channelmanager::ChannelManager::close_channel_with_feerate_and_script
	ChannelCloseMinimum,
}
use lightning::chain::chaininterface::ConfirmationTarget as ConfirmationTargetImport;
pub(crate) type nativeConfirmationTarget = ConfirmationTargetImport;

impl ConfirmationTarget {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::OnChainSweep => nativeConfirmationTarget::OnChainSweep,
			ConfirmationTarget::MinAllowedAnchorChannelRemoteFee => nativeConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
			ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => nativeConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
			ConfirmationTarget::AnchorChannelFee => nativeConfirmationTarget::AnchorChannelFee,
			ConfirmationTarget::NonAnchorChannelFee => nativeConfirmationTarget::NonAnchorChannelFee,
			ConfirmationTarget::ChannelCloseMinimum => nativeConfirmationTarget::ChannelCloseMinimum,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeConfirmationTarget {
		match self {
			ConfirmationTarget::OnChainSweep => nativeConfirmationTarget::OnChainSweep,
			ConfirmationTarget::MinAllowedAnchorChannelRemoteFee => nativeConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
			ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => nativeConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
			ConfirmationTarget::AnchorChannelFee => nativeConfirmationTarget::AnchorChannelFee,
			ConfirmationTarget::NonAnchorChannelFee => nativeConfirmationTarget::NonAnchorChannelFee,
			ConfirmationTarget::ChannelCloseMinimum => nativeConfirmationTarget::ChannelCloseMinimum,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &ConfirmationTargetImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeConfirmationTarget) };
		match native {
			nativeConfirmationTarget::OnChainSweep => ConfirmationTarget::OnChainSweep,
			nativeConfirmationTarget::MinAllowedAnchorChannelRemoteFee => ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
			nativeConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
			nativeConfirmationTarget::AnchorChannelFee => ConfirmationTarget::AnchorChannelFee,
			nativeConfirmationTarget::NonAnchorChannelFee => ConfirmationTarget::NonAnchorChannelFee,
			nativeConfirmationTarget::ChannelCloseMinimum => ConfirmationTarget::ChannelCloseMinimum,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeConfirmationTarget) -> Self {
		match native {
			nativeConfirmationTarget::OnChainSweep => ConfirmationTarget::OnChainSweep,
			nativeConfirmationTarget::MinAllowedAnchorChannelRemoteFee => ConfirmationTarget::MinAllowedAnchorChannelRemoteFee,
			nativeConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee => ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee,
			nativeConfirmationTarget::AnchorChannelFee => ConfirmationTarget::AnchorChannelFee,
			nativeConfirmationTarget::NonAnchorChannelFee => ConfirmationTarget::NonAnchorChannelFee,
			nativeConfirmationTarget::ChannelCloseMinimum => ConfirmationTarget::ChannelCloseMinimum,
		}
	}
}
/// Creates a copy of the ConfirmationTarget
#[no_mangle]
pub extern "C" fn ConfirmationTarget_clone(orig: &ConfirmationTarget) -> ConfirmationTarget {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ConfirmationTarget_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ConfirmationTarget)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ConfirmationTarget_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ConfirmationTarget) };
}
#[no_mangle]
/// Utility method to constructs a new OnChainSweep-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_on_chain_sweep() -> ConfirmationTarget {
	ConfirmationTarget::OnChainSweep}
#[no_mangle]
/// Utility method to constructs a new MinAllowedAnchorChannelRemoteFee-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_min_allowed_anchor_channel_remote_fee() -> ConfirmationTarget {
	ConfirmationTarget::MinAllowedAnchorChannelRemoteFee}
#[no_mangle]
/// Utility method to constructs a new MinAllowedNonAnchorChannelRemoteFee-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_min_allowed_non_anchor_channel_remote_fee() -> ConfirmationTarget {
	ConfirmationTarget::MinAllowedNonAnchorChannelRemoteFee}
#[no_mangle]
/// Utility method to constructs a new AnchorChannelFee-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_anchor_channel_fee() -> ConfirmationTarget {
	ConfirmationTarget::AnchorChannelFee}
#[no_mangle]
/// Utility method to constructs a new NonAnchorChannelFee-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_non_anchor_channel_fee() -> ConfirmationTarget {
	ConfirmationTarget::NonAnchorChannelFee}
#[no_mangle]
/// Utility method to constructs a new ChannelCloseMinimum-variant ConfirmationTarget
pub extern "C" fn ConfirmationTarget_channel_close_minimum() -> ConfirmationTarget {
	ConfirmationTarget::ChannelCloseMinimum}
/// Get a string which allows debug introspection of a ConfirmationTarget object
pub extern "C" fn ConfirmationTarget_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::chain::chaininterface::ConfirmationTarget }).into()}
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
#[allow(unused)]
pub(crate) fn FeeEstimator_clone_fields(orig: &FeeEstimator) -> FeeEstimator {
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
impl core::ops::DerefMut for FeeEstimator {
	fn deref_mut(&mut self) -> &mut Self {
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
