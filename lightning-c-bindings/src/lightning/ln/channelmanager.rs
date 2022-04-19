// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! The top-level channel management and payment tracking stuff lives here.
//!
//! The ChannelManager is the main chunk of logic implementing the lightning protocol and is
//! responsible for tracking which channels are open, HTLCs are in flight and reestablishing those
//! upon reconnect to the relevant peer(s).
//!
//! It does not manage routing logic (see routing::router::get_route for that) nor does it manage constructing
//! on-chain transactions (it only monitors the chain to watch for any force-closes that might
//! imply it needs to fail HTLCs/payments/channels it manages).
//!

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod inbound_payment {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning::ln::channelmanager::ChannelManager as nativeChannelManagerImport;
pub(crate) type nativeChannelManager = nativeChannelManagerImport<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>;

/// Manager which keeps track of a number of channels and sends messages to the appropriate
/// channel, also tracking HTLC preimages and forwarding onion packets appropriately.
///
/// Implements ChannelMessageHandler, handling the multi-channel parts and passing things through
/// to individual Channels.
///
/// Implements Writeable to write out all channel state to disk. Implies peer_disconnected() for
/// all peers during write/read (though does not modify this instance, only the instance being
/// serialized). This will result in any channels which have not yet exchanged funding_created (ie
/// called funding_transaction_generated for outbound channels).
///
/// Note that you can be a bit lazier about writing out ChannelManager than you can be with
/// ChannelMonitors. With ChannelMonitors you MUST write each monitor update out to disk before
/// returning from chain::Watch::watch_/update_channel, with ChannelManagers, writing updates
/// happens out-of-band (and will prevent any other ChannelManager operations from occurring during
/// the serialization process). If the deserialized version is out-of-date compared to the
/// ChannelMonitors passed by reference to read(), those channels will be force-closed based on the
/// ChannelMonitor state and no funds will be lost (mod on-chain transaction fees).
///
/// Note that the deserializer is only implemented for (BlockHash, ChannelManager), which
/// tells you the last block hash which was block_connect()ed. You MUST rescan any blocks along
/// the \"reorg path\" (ie call block_disconnected() until you get to a common block and then call
/// block_connected() to step towards your best block) upon deserialization before using the
/// object!
///
/// Note that ChannelManager is responsible for tracking liveness of its channels and generating
/// ChannelUpdate messages informing peers that the channel is temporarily disabled. To avoid
/// spam due to quick disconnection/reconnection, updates are not sent until the channel has been
/// offline for a full minute. In order to track this, you must call
/// timer_tick_occurred roughly once per minute, though it doesn't have to be perfect.
///
/// Rather than using a plain ChannelManager, it is preferable to use either a SimpleArcChannelManager
/// a SimpleRefChannelManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefChannelManager, and use a
/// SimpleArcChannelManager when you require a ChannelManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
#[must_use]
#[repr(C)]
pub struct ChannelManager {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelManager,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelManager {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelManager>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelManager, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelManager_free(this_obj: ChannelManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelManager_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelManager); }
}
#[allow(unused)]
impl ChannelManager {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelManager {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelManager {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelManager {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::channelmanager::ChainParameters as nativeChainParametersImport;
pub(crate) type nativeChainParameters = nativeChainParametersImport;

/// Chain-related parameters used to construct a new `ChannelManager`.
///
/// Typically, the block-specific parameters are derived from the best block hash for the network,
/// as a newly constructed `ChannelManager` will not have created any channels yet. These parameters
/// are not needed when deserializing a previously constructed `ChannelManager`.
#[must_use]
#[repr(C)]
pub struct ChainParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChainParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChainParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChainParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChainParameters_free(this_obj: ChainParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChainParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainParameters); }
}
#[allow(unused)]
impl ChainParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChainParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChainParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChainParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The network for determining the `chain_hash` in Lightning messages.
#[no_mangle]
pub extern "C" fn ChainParameters_get_network(this_ptr: &ChainParameters) -> crate::bitcoin::network::Network {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().network;
	crate::bitcoin::network::Network::from_bitcoin(inner_val)
}
/// The network for determining the `chain_hash` in Lightning messages.
#[no_mangle]
pub extern "C" fn ChainParameters_set_network(this_ptr: &mut ChainParameters, mut val: crate::bitcoin::network::Network) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.network = val.into_bitcoin();
}
/// The hash and height of the latest block successfully connected.
///
/// Used to track on-chain channel funding outputs and send payments with reliable timelocks.
#[no_mangle]
pub extern "C" fn ChainParameters_get_best_block(this_ptr: &ChainParameters) -> crate::lightning::chain::BestBlock {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().best_block;
	crate::lightning::chain::BestBlock { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::chain::BestBlock<>) as *mut _) }, is_owned: false }
}
/// The hash and height of the latest block successfully connected.
///
/// Used to track on-chain channel funding outputs and send payments with reliable timelocks.
#[no_mangle]
pub extern "C" fn ChainParameters_set_best_block(this_ptr: &mut ChainParameters, mut val: crate::lightning::chain::BestBlock) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.best_block = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ChainParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChainParameters_new(mut network_arg: crate::bitcoin::network::Network, mut best_block_arg: crate::lightning::chain::BestBlock) -> ChainParameters {
	ChainParameters { inner: ObjOps::heap_alloc(nativeChainParameters {
		network: network_arg.into_bitcoin(),
		best_block: *unsafe { Box::from_raw(best_block_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for ChainParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChainParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChainParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChainParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChainParameters
pub extern "C" fn ChainParameters_clone(orig: &ChainParameters) -> ChainParameters {
	orig.clone()
}
/// The amount of time in blocks we require our counterparty wait to claim their money (ie time
/// between when we, or our watchtower, must check for them having broadcast a theft transaction).
///
/// This can be increased (but not decreased) through [`ChannelHandshakeConfig::our_to_self_delay`]
///
/// [`ChannelHandshakeConfig::our_to_self_delay`]: crate::util::config::ChannelHandshakeConfig::our_to_self_delay

#[no_mangle]
pub static BREAKDOWN_TIMEOUT: u16 = lightning::ln::channelmanager::BREAKDOWN_TIMEOUT;
/// The minimum number of blocks between an inbound HTLC's CLTV and the corresponding outbound
/// HTLC's CLTV. The current default represents roughly seven hours of blocks at six blocks/hour.
///
/// This can be increased (but not decreased) through [`ChannelConfig::cltv_expiry_delta`]
///
/// [`ChannelConfig::cltv_expiry_delta`]: crate::util::config::ChannelConfig::cltv_expiry_delta

#[no_mangle]
pub static MIN_CLTV_EXPIRY_DELTA: u16 = lightning::ln::channelmanager::MIN_CLTV_EXPIRY_DELTA;
/// Minimum CLTV difference between the current block height and received inbound payments.
/// Invoices generated for payment to us must set their `min_final_cltv_expiry` field to at least
/// this value.

#[no_mangle]
pub static MIN_FINAL_CLTV_EXPIRY: u32 = lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY;

use lightning::ln::channelmanager::CounterpartyForwardingInfo as nativeCounterpartyForwardingInfoImport;
pub(crate) type nativeCounterpartyForwardingInfo = nativeCounterpartyForwardingInfoImport;

/// Information needed for constructing an invoice route hint for this channel.
#[must_use]
#[repr(C)]
pub struct CounterpartyForwardingInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCounterpartyForwardingInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for CounterpartyForwardingInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCounterpartyForwardingInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CounterpartyForwardingInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_free(this_obj: CounterpartyForwardingInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyForwardingInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeCounterpartyForwardingInfo); }
}
#[allow(unused)]
impl CounterpartyForwardingInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCounterpartyForwardingInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCounterpartyForwardingInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCounterpartyForwardingInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Base routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_fee_base_msat(this_ptr: &CounterpartyForwardingInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base routing fee in millisatoshis.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_fee_base_msat(this_ptr: &mut CounterpartyForwardingInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_fee_proportional_millionths(this_ptr: &CounterpartyForwardingInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Amount in millionths of a satoshi the channel will charge per transferred satoshi.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_fee_proportional_millionths(this_ptr: &mut CounterpartyForwardingInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
/// `cltv_expiry_delta` for more details.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_get_cltv_expiry_delta(this_ptr: &CounterpartyForwardingInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The minimum difference in cltv_expiry between an ingoing HTLC and its outgoing counterpart,
/// such that the outgoing HTLC is forwardable to this counterparty. See `msgs::ChannelUpdate`'s
/// `cltv_expiry_delta` for more details.
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_set_cltv_expiry_delta(this_ptr: &mut CounterpartyForwardingInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Constructs a new CounterpartyForwardingInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyForwardingInfo_new(mut fee_base_msat_arg: u32, mut fee_proportional_millionths_arg: u32, mut cltv_expiry_delta_arg: u16) -> CounterpartyForwardingInfo {
	CounterpartyForwardingInfo { inner: ObjOps::heap_alloc(nativeCounterpartyForwardingInfo {
		fee_base_msat: fee_base_msat_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
	}), is_owned: true }
}
impl Clone for CounterpartyForwardingInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCounterpartyForwardingInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyForwardingInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCounterpartyForwardingInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CounterpartyForwardingInfo
pub extern "C" fn CounterpartyForwardingInfo_clone(orig: &CounterpartyForwardingInfo) -> CounterpartyForwardingInfo {
	orig.clone()
}

use lightning::ln::channelmanager::ChannelCounterparty as nativeChannelCounterpartyImport;
pub(crate) type nativeChannelCounterparty = nativeChannelCounterpartyImport;

/// Channel parameters which apply to our counterparty. These are split out from [`ChannelDetails`]
/// to better separate parameters.
#[must_use]
#[repr(C)]
pub struct ChannelCounterparty {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelCounterparty,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelCounterparty {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelCounterparty>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelCounterparty, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_free(this_obj: ChannelCounterparty) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelCounterparty_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelCounterparty); }
}
#[allow(unused)]
impl ChannelCounterparty {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelCounterparty {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelCounterparty {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelCounterparty {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_node_id(this_ptr: &ChannelCounterparty) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_node_id(this_ptr: &mut ChannelCounterparty, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_id = val.into_rust();
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_features(this_ptr: &ChannelCounterparty) -> crate::lightning::ln::features::InitFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning::ln::features::InitFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::InitFeatures<>) as *mut _) }, is_owned: false }
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_features(this_ptr: &mut ChannelCounterparty, mut val: crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The value, in satoshis, that must always be held in the channel for our counterparty. This
/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
///
/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_unspendable_punishment_reserve(this_ptr: &ChannelCounterparty) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().unspendable_punishment_reserve;
	*inner_val
}
/// The value, in satoshis, that must always be held in the channel for our counterparty. This
/// value ensures that if our counterparty broadcasts a revoked state, we can punish them by
/// claiming at least this value on chain.
///
/// This value is not included in [`inbound_capacity_msat`] as it can never be spent.
///
/// [`inbound_capacity_msat`]: ChannelDetails::inbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_unspendable_punishment_reserve(this_ptr: &mut ChannelCounterparty, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.unspendable_punishment_reserve = val;
}
/// Information on the fees and requirements that the counterparty requires when forwarding
/// payments to us through this channel.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_forwarding_info(this_ptr: &ChannelCounterparty) -> crate::lightning::ln::channelmanager::CounterpartyForwardingInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().forwarding_info;
	let mut local_inner_val = crate::lightning::ln::channelmanager::CounterpartyForwardingInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::channelmanager::CounterpartyForwardingInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Information on the fees and requirements that the counterparty requires when forwarding
/// payments to us through this channel.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_forwarding_info(this_ptr: &mut ChannelCounterparty, mut val: crate::lightning::ln::channelmanager::CounterpartyForwardingInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.forwarding_info = local_val;
}
/// Constructs a new ChannelCounterparty given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelCounterparty_new(mut node_id_arg: crate::c_types::PublicKey, mut features_arg: crate::lightning::ln::features::InitFeatures, mut unspendable_punishment_reserve_arg: u64, mut forwarding_info_arg: crate::lightning::ln::channelmanager::CounterpartyForwardingInfo) -> ChannelCounterparty {
	let mut local_forwarding_info_arg = if forwarding_info_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(forwarding_info_arg.take_inner()) } }) };
	ChannelCounterparty { inner: ObjOps::heap_alloc(nativeChannelCounterparty {
		node_id: node_id_arg.into_rust(),
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		unspendable_punishment_reserve: unspendable_punishment_reserve_arg,
		forwarding_info: local_forwarding_info_arg,
	}), is_owned: true }
}
impl Clone for ChannelCounterparty {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelCounterparty>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelCounterparty_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelCounterparty)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelCounterparty
pub extern "C" fn ChannelCounterparty_clone(orig: &ChannelCounterparty) -> ChannelCounterparty {
	orig.clone()
}

use lightning::ln::channelmanager::ChannelDetails as nativeChannelDetailsImport;
pub(crate) type nativeChannelDetails = nativeChannelDetailsImport;

/// Details of a channel, as returned by ChannelManager::list_channels and ChannelManager::list_usable_channels
#[must_use]
#[repr(C)]
pub struct ChannelDetails {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelDetails,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelDetails {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelDetails>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelDetails, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelDetails_free(this_obj: ChannelDetails) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelDetails_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelDetails); }
}
#[allow(unused)]
impl ChannelDetails {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelDetails {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelDetails {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelDetails {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_id(this_ptr: &ChannelDetails) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_id;
	inner_val
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_id = val.data;
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_counterparty(this_ptr: &ChannelDetails) -> crate::lightning::ln::channelmanager::ChannelCounterparty {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().counterparty;
	crate::lightning::ln::channelmanager::ChannelCounterparty { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::channelmanager::ChannelCounterparty<>) as *mut _) }, is_owned: false }
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_counterparty(this_ptr: &mut ChannelDetails, mut val: crate::lightning::ln::channelmanager::ChannelCounterparty) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The Channel's funding transaction output, if we've negotiated the funding transaction with
/// our counterparty already.
///
/// Note that, if this has been set, `channel_id` will be equivalent to
/// `funding_txo.unwrap().to_channel_id()`.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_get_funding_txo(this_ptr: &ChannelDetails) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_txo;
	let mut local_inner_val = crate::lightning::chain::transaction::OutPoint { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::chain::transaction::OutPoint<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The Channel's funding transaction output, if we've negotiated the funding transaction with
/// our counterparty already.
///
/// Note that, if this has been set, `channel_id` will be equivalent to
/// `funding_txo.unwrap().to_channel_id()`.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_set_funding_txo(this_ptr: &mut ChannelDetails, mut val: crate::lightning::chain::transaction::OutPoint) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_txo = local_val;
}
/// The features which this channel operates with. See individual features for more info.
///
/// `None` until negotiation completes and the channel type is finalized.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_type(this_ptr: &ChannelDetails) -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_type;
	let mut local_inner_val = crate::lightning::ln::features::ChannelTypeFeatures { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::features::ChannelTypeFeatures<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The features which this channel operates with. See individual features for more info.
///
/// `None` until negotiation completes and the channel type is finalized.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_type(this_ptr: &mut ChannelDetails, mut val: crate::lightning::ln::features::ChannelTypeFeatures) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_type = local_val;
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
///
/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
/// payments instead of this. See [`get_inbound_payment_scid`].
///
/// [`inbound_scid_alias`]: Self::inbound_scid_alias
/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
#[no_mangle]
pub extern "C" fn ChannelDetails_get_short_channel_id(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
///
/// Note that if [`inbound_scid_alias`] is set, it must be used for invoices and inbound
/// payments instead of this. See [`get_inbound_payment_scid`].
///
/// [`inbound_scid_alias`]: Self::inbound_scid_alias
/// [`get_inbound_payment_scid`]: Self::get_inbound_payment_scid
#[no_mangle]
pub extern "C" fn ChannelDetails_set_short_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = local_val;
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
/// when they see a payment to be routed to us.
///
/// Our counterparty may choose to rotate this value at any time, though will always recognize
/// previous values for inbound payment forwarding.
///
/// [`short_channel_id`]: Self::short_channel_id
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_scid_alias(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_scid_alias;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// An optional [`short_channel_id`] alias for this channel, randomly generated by our
/// counterparty and usable in place of [`short_channel_id`] in invoice route hints. Our
/// counterparty will recognize the alias provided here in place of the [`short_channel_id`]
/// when they see a payment to be routed to us.
///
/// Our counterparty may choose to rotate this value at any time, though will always recognize
/// previous values for inbound payment forwarding.
///
/// [`short_channel_id`]: Self::short_channel_id
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_scid_alias(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_scid_alias = local_val;
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_value_satoshis(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_value_satoshis;
	*inner_val
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_value_satoshis(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_value_satoshis = val;
}
/// The value, in satoshis, that must always be held in the channel for us. This value ensures
/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
/// this value on chain.
///
/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelDetails_get_unspendable_punishment_reserve(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().unspendable_punishment_reserve;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The value, in satoshis, that must always be held in the channel for us. This value ensures
/// that if we broadcast a revoked state, our counterparty can punish us by claiming at least
/// this value on chain.
///
/// This value is not included in [`outbound_capacity_msat`] as it can never be spent.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`outbound_capacity_msat`]: ChannelDetails::outbound_capacity_msat
#[no_mangle]
pub extern "C" fn ChannelDetails_set_unspendable_punishment_reserve(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.unspendable_punishment_reserve = local_val;
}
/// The `user_channel_id` passed in to create_channel, or 0 if the channel was inbound.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_user_channel_id(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().user_channel_id;
	*inner_val
}
/// The `user_channel_id` passed in to create_channel, or 0 if the channel was inbound.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_user_channel_id(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.user_channel_id = val;
}
/// Our total balance.  This is the amount we would get if we close the channel.
/// This value is not exact. Due to various in-flight changes and feerate changes, exactly this
/// amount is not likely to be recoverable on close.
///
/// This does not include any pending HTLCs which are not yet fully resolved (and, thus, whose
/// balance is not available for inclusion in new outbound HTLCs). This further does not include
/// any pending outgoing HTLCs which are awaiting some other resolution to be sent.
/// This does not consider any on-chain fees.
///
/// See also [`ChannelDetails::outbound_capacity_msat`]
#[no_mangle]
pub extern "C" fn ChannelDetails_get_balance_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().balance_msat;
	*inner_val
}
/// Our total balance.  This is the amount we would get if we close the channel.
/// This value is not exact. Due to various in-flight changes and feerate changes, exactly this
/// amount is not likely to be recoverable on close.
///
/// This does not include any pending HTLCs which are not yet fully resolved (and, thus, whose
/// balance is not available for inclusion in new outbound HTLCs). This further does not include
/// any pending outgoing HTLCs which are awaiting some other resolution to be sent.
/// This does not consider any on-chain fees.
///
/// See also [`ChannelDetails::outbound_capacity_msat`]
#[no_mangle]
pub extern "C" fn ChannelDetails_set_balance_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.balance_msat = val;
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// See also [`ChannelDetails::balance_msat`]
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_outbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outbound_capacity_msat;
	*inner_val
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// See also [`ChannelDetails::balance_msat`]
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_outbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outbound_capacity_msat = val;
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().inbound_capacity_msat;
	*inner_val
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, whose balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.inbound_capacity_msat = val;
}
/// The number of required confirmations on the funding transaction before the funding will be
/// considered \"locked\". This number is selected by the channel fundee (i.e. us if
/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
/// [`ChannelHandshakeLimits::max_minimum_depth`].
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`is_outbound`]: ChannelDetails::is_outbound
/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
#[no_mangle]
pub extern "C" fn ChannelDetails_get_confirmations_required(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().confirmations_required;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The number of required confirmations on the funding transaction before the funding will be
/// considered \"locked\". This number is selected by the channel fundee (i.e. us if
/// [`is_outbound`] is *not* set), and can be selected for inbound channels with
/// [`ChannelHandshakeConfig::minimum_depth`] or limited for outbound channels with
/// [`ChannelHandshakeLimits::max_minimum_depth`].
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
///
/// [`is_outbound`]: ChannelDetails::is_outbound
/// [`ChannelHandshakeConfig::minimum_depth`]: crate::util::config::ChannelHandshakeConfig::minimum_depth
/// [`ChannelHandshakeLimits::max_minimum_depth`]: crate::util::config::ChannelHandshakeLimits::max_minimum_depth
#[no_mangle]
pub extern "C" fn ChannelDetails_set_confirmations_required(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmations_required = local_val;
}
/// The number of blocks (after our commitment transaction confirms) that we will need to wait
/// until we can claim our funds after we force-close the channel. During this time our
/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
/// time to claim our non-HTLC-encumbered funds.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_force_close_spend_delay(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u16Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().force_close_spend_delay;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u16Z::None } else { crate::c_types::derived::COption_u16Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The number of blocks (after our commitment transaction confirms) that we will need to wait
/// until we can claim our funds after we force-close the channel. During this time our
/// counterparty is allowed to punish us if we broadcasted a stale state. If our counterparty
/// force-closes the channel and broadcasts a commitment transaction we do not have to wait any
/// time to claim our non-HTLC-encumbered funds.
///
/// This value will be `None` for outbound channels until the counterparty accepts the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_force_close_spend_delay(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u16Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.force_close_spend_delay = local_val;
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_outbound(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_outbound;
	*inner_val
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_outbound(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_outbound = val;
}
/// True if the channel is confirmed, funding_locked messages have been exchanged, and the
/// channel is not currently being shut down. `funding_locked` message exchange implies the
/// required confirmation count has been reached (and we were connected to the peer at some
/// point after the funding transaction received enough confirmations). The required
/// confirmation count is provided in [`confirmations_required`].
///
/// [`confirmations_required`]: ChannelDetails::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_funding_locked(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_funding_locked;
	*inner_val
}
/// True if the channel is confirmed, funding_locked messages have been exchanged, and the
/// channel is not currently being shut down. `funding_locked` message exchange implies the
/// required confirmation count has been reached (and we were connected to the peer at some
/// point after the funding transaction received enough confirmations). The required
/// confirmation count is provided in [`confirmations_required`].
///
/// [`confirmations_required`]: ChannelDetails::confirmations_required
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_funding_locked(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_funding_locked = val;
}
/// True if the channel is (a) confirmed and funding_locked messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_funding_locked`.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_usable(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_usable;
	*inner_val
}
/// True if the channel is (a) confirmed and funding_locked messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_funding_locked`.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_usable(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_usable = val;
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_public(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_public;
	*inner_val
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_public(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_public = val;
}
/// Constructs a new ChannelDetails given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut counterparty_arg: crate::lightning::ln::channelmanager::ChannelCounterparty, mut funding_txo_arg: crate::lightning::chain::transaction::OutPoint, mut channel_type_arg: crate::lightning::ln::features::ChannelTypeFeatures, mut short_channel_id_arg: crate::c_types::derived::COption_u64Z, mut inbound_scid_alias_arg: crate::c_types::derived::COption_u64Z, mut channel_value_satoshis_arg: u64, mut unspendable_punishment_reserve_arg: crate::c_types::derived::COption_u64Z, mut user_channel_id_arg: u64, mut balance_msat_arg: u64, mut outbound_capacity_msat_arg: u64, mut inbound_capacity_msat_arg: u64, mut confirmations_required_arg: crate::c_types::derived::COption_u32Z, mut force_close_spend_delay_arg: crate::c_types::derived::COption_u16Z, mut is_outbound_arg: bool, mut is_funding_locked_arg: bool, mut is_usable_arg: bool, mut is_public_arg: bool) -> ChannelDetails {
	let mut local_funding_txo_arg = if funding_txo_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(funding_txo_arg.take_inner()) } }) };
	let mut local_channel_type_arg = if channel_type_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(channel_type_arg.take_inner()) } }) };
	let mut local_short_channel_id_arg = if short_channel_id_arg.is_some() { Some( { short_channel_id_arg.take() }) } else { None };
	let mut local_inbound_scid_alias_arg = if inbound_scid_alias_arg.is_some() { Some( { inbound_scid_alias_arg.take() }) } else { None };
	let mut local_unspendable_punishment_reserve_arg = if unspendable_punishment_reserve_arg.is_some() { Some( { unspendable_punishment_reserve_arg.take() }) } else { None };
	let mut local_confirmations_required_arg = if confirmations_required_arg.is_some() { Some( { confirmations_required_arg.take() }) } else { None };
	let mut local_force_close_spend_delay_arg = if force_close_spend_delay_arg.is_some() { Some( { force_close_spend_delay_arg.take() }) } else { None };
	ChannelDetails { inner: ObjOps::heap_alloc(nativeChannelDetails {
		channel_id: channel_id_arg.data,
		counterparty: *unsafe { Box::from_raw(counterparty_arg.take_inner()) },
		funding_txo: local_funding_txo_arg,
		channel_type: local_channel_type_arg,
		short_channel_id: local_short_channel_id_arg,
		inbound_scid_alias: local_inbound_scid_alias_arg,
		channel_value_satoshis: channel_value_satoshis_arg,
		unspendable_punishment_reserve: local_unspendable_punishment_reserve_arg,
		user_channel_id: user_channel_id_arg,
		balance_msat: balance_msat_arg,
		outbound_capacity_msat: outbound_capacity_msat_arg,
		inbound_capacity_msat: inbound_capacity_msat_arg,
		confirmations_required: local_confirmations_required_arg,
		force_close_spend_delay: local_force_close_spend_delay_arg,
		is_outbound: is_outbound_arg,
		is_funding_locked: is_funding_locked_arg,
		is_usable: is_usable_arg,
		is_public: is_public_arg,
	}), is_owned: true }
}
impl Clone for ChannelDetails {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelDetails>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelDetails_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelDetails)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelDetails
pub extern "C" fn ChannelDetails_clone(orig: &ChannelDetails) -> ChannelDetails {
	orig.clone()
}
/// Gets the current SCID which should be used to identify this channel for inbound payments.
/// This should be used for providing invoice hints or in any other context where our
/// counterparty will forward a payment to us.
///
/// This is either the [`ChannelDetails::inbound_scid_alias`], if set, or the
/// [`ChannelDetails::short_channel_id`]. See those for more information.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_payment_scid(this_arg: &crate::lightning::ln::channelmanager::ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_inbound_payment_scid();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// If a payment fails to send, it can be in one of several states. This enum is returned as the
/// Err() type describing which state the payment is in, see the description of individual enum
/// states for more.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum PaymentSendFailure {
	/// A parameter which was passed to send_payment was invalid, preventing us from attempting to
	/// send the payment at all. No channel state has been changed or messages sent to peers, and
	/// once you've changed the parameter at error, you can freely retry the payment in full.
	ParameterError(crate::lightning::util::errors::APIError),
	/// A parameter in a single path which was passed to send_payment was invalid, preventing us
	/// from attempting to send the payment at all. No channel state has been changed or messages
	/// sent to peers, and once you've changed the parameter at error, you can freely retry the
	/// payment in full.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment.
	PathParameterError(crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ),
	/// All paths which were attempted failed to send, with no channel state change taking place.
	/// You can freely retry the payment in full (though you probably want to do so over different
	/// paths than the ones selected).
	AllFailedRetrySafe(crate::c_types::derived::CVec_APIErrorZ),
	/// Some paths which were attempted failed to send, though possibly not all. At least some
	/// paths have irrevocably committed to the HTLC and retrying the payment in full would result
	/// in over-/re-payment.
	///
	/// The results here are ordered the same as the paths in the route object which was passed to
	/// send_payment, and any Errs which are not APIError::MonitorUpdateFailed can be safely
	/// retried (though there is currently no API with which to do so).
	///
	/// Any entries which contain Err(APIError::MonitorUpdateFailed) or Ok(()) MUST NOT be retried
	/// as they will result in over-/re-payment. These HTLCs all either successfully sent (in the
	/// case of Ok(())) or will send once channel_monitor_updated is called on the next-hop channel
	/// with the latest update_id.
	PartialFailure {
		/// The errors themselves, in the same order as the route hops.
		results: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ,
		/// If some paths failed without irrevocably committing to the new HTLC(s), this will
		/// contain a [`RouteParameters`] object which can be used to calculate a new route that
		/// will pay all remaining unpaid balance.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		failed_paths_retry: crate::lightning::routing::router::RouteParameters,
		/// The payment id for the payment, which is now at least partially pending.
		payment_id: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::ln::channelmanager::PaymentSendFailure as nativePaymentSendFailure;
impl PaymentSendFailure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentSendFailure {
		match self {
			PaymentSendFailure::ParameterError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativePaymentSendFailure::ParameterError (
					a_nonref.into_native(),
				)
			},
			PaymentSendFailure::PathParameterError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_nonref_0 }); };
				nativePaymentSendFailure::PathParameterError (
					local_a_nonref,
				)
			},
			PaymentSendFailure::AllFailedRetrySafe (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { item.into_native() }); };
				nativePaymentSendFailure::AllFailedRetrySafe (
					local_a_nonref,
				)
			},
			PaymentSendFailure::PartialFailure {ref results, ref failed_paths_retry, ref payment_id, } => {
				let mut results_nonref = (*results).clone();
				let mut local_results_nonref = Vec::new(); for mut item in results_nonref.into_rust().drain(..) { local_results_nonref.push( { let mut local_results_nonref_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_results_nonref_0 }); };
				let mut failed_paths_retry_nonref = (*failed_paths_retry).clone();
				let mut local_failed_paths_retry_nonref = if failed_paths_retry_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(failed_paths_retry_nonref.take_inner()) } }) };
				let mut payment_id_nonref = (*payment_id).clone();
				nativePaymentSendFailure::PartialFailure {
					results: local_results_nonref,
					failed_paths_retry: local_failed_paths_retry_nonref,
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentSendFailure {
		match self {
			PaymentSendFailure::ParameterError (mut a, ) => {
				nativePaymentSendFailure::ParameterError (
					a.into_native(),
				)
			},
			PaymentSendFailure::PathParameterError (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { let mut local_a_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_0 }); };
				nativePaymentSendFailure::PathParameterError (
					local_a,
				)
			},
			PaymentSendFailure::AllFailedRetrySafe (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { item.into_native() }); };
				nativePaymentSendFailure::AllFailedRetrySafe (
					local_a,
				)
			},
			PaymentSendFailure::PartialFailure {mut results, mut failed_paths_retry, mut payment_id, } => {
				let mut local_results = Vec::new(); for mut item in results.into_rust().drain(..) { local_results.push( { let mut local_results_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_results_0 }); };
				let mut local_failed_paths_retry = if failed_paths_retry.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(failed_paths_retry.take_inner()) } }) };
				nativePaymentSendFailure::PartialFailure {
					results: local_results,
					failed_paths_retry: local_failed_paths_retry,
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePaymentSendFailure) -> Self {
		match native {
			nativePaymentSendFailure::ParameterError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				PaymentSendFailure::ParameterError (
					crate::lightning::util::errors::APIError::native_into(a_nonref),
				)
			},
			nativePaymentSendFailure::PathParameterError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_nonref_0 }); };
				PaymentSendFailure::PathParameterError (
					local_a_nonref.into(),
				)
			},
			nativePaymentSendFailure::AllFailedRetrySafe (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { crate::lightning::util::errors::APIError::native_into(item) }); };
				PaymentSendFailure::AllFailedRetrySafe (
					local_a_nonref.into(),
				)
			},
			nativePaymentSendFailure::PartialFailure {ref results, ref failed_paths_retry, ref payment_id, } => {
				let mut results_nonref = (*results).clone();
				let mut local_results_nonref = Vec::new(); for mut item in results_nonref.drain(..) { local_results_nonref.push( { let mut local_results_nonref_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_results_nonref_0 }); };
				let mut failed_paths_retry_nonref = (*failed_paths_retry).clone();
				let mut local_failed_paths_retry_nonref = crate::lightning::routing::router::RouteParameters { inner: if failed_paths_retry_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((failed_paths_retry_nonref.unwrap())) } }, is_owned: true };
				let mut payment_id_nonref = (*payment_id).clone();
				PaymentSendFailure::PartialFailure {
					results: local_results_nonref.into(),
					failed_paths_retry: local_failed_paths_retry_nonref,
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentSendFailure) -> Self {
		match native {
			nativePaymentSendFailure::ParameterError (mut a, ) => {
				PaymentSendFailure::ParameterError (
					crate::lightning::util::errors::APIError::native_into(a),
				)
			},
			nativePaymentSendFailure::PathParameterError (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { let mut local_a_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_0 }); };
				PaymentSendFailure::PathParameterError (
					local_a.into(),
				)
			},
			nativePaymentSendFailure::AllFailedRetrySafe (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { crate::lightning::util::errors::APIError::native_into(item) }); };
				PaymentSendFailure::AllFailedRetrySafe (
					local_a.into(),
				)
			},
			nativePaymentSendFailure::PartialFailure {mut results, mut failed_paths_retry, mut payment_id, } => {
				let mut local_results = Vec::new(); for mut item in results.drain(..) { local_results.push( { let mut local_results_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_results_0 }); };
				let mut local_failed_paths_retry = crate::lightning::routing::router::RouteParameters { inner: if failed_paths_retry.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((failed_paths_retry.unwrap())) } }, is_owned: true };
				PaymentSendFailure::PartialFailure {
					results: local_results.into(),
					failed_paths_retry: local_failed_paths_retry,
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
				}
			},
		}
	}
}
/// Frees any resources used by the PaymentSendFailure
#[no_mangle]
pub extern "C" fn PaymentSendFailure_free(this_ptr: PaymentSendFailure) { }
/// Creates a copy of the PaymentSendFailure
#[no_mangle]
pub extern "C" fn PaymentSendFailure_clone(orig: &PaymentSendFailure) -> PaymentSendFailure {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new ParameterError-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_parameter_error(a: crate::lightning::util::errors::APIError) -> PaymentSendFailure {
	PaymentSendFailure::ParameterError(a, )
}
#[no_mangle]
/// Utility method to constructs a new PathParameterError-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_path_parameter_error(a: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ) -> PaymentSendFailure {
	PaymentSendFailure::PathParameterError(a, )
}
#[no_mangle]
/// Utility method to constructs a new AllFailedRetrySafe-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_all_failed_retry_safe(a: crate::c_types::derived::CVec_APIErrorZ) -> PaymentSendFailure {
	PaymentSendFailure::AllFailedRetrySafe(a, )
}
#[no_mangle]
/// Utility method to constructs a new PartialFailure-variant PaymentSendFailure
pub extern "C" fn PaymentSendFailure_partial_failure(results: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ, failed_paths_retry: crate::lightning::routing::router::RouteParameters, payment_id: crate::c_types::ThirtyTwoBytes) -> PaymentSendFailure {
	PaymentSendFailure::PartialFailure {
		results,
		failed_paths_retry,
		payment_id,
	}
}

use lightning::ln::channelmanager::PhantomRouteHints as nativePhantomRouteHintsImport;
pub(crate) type nativePhantomRouteHints = nativePhantomRouteHintsImport;

/// Route hints used in constructing invoices for [phantom node payents].
///
/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
#[must_use]
#[repr(C)]
pub struct PhantomRouteHints {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePhantomRouteHints,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PhantomRouteHints {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePhantomRouteHints>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PhantomRouteHints, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_free(this_obj: PhantomRouteHints) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PhantomRouteHints_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePhantomRouteHints); }
}
#[allow(unused)]
impl PhantomRouteHints {
	pub(crate) fn get_native_ref(&self) -> &'static nativePhantomRouteHints {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePhantomRouteHints {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePhantomRouteHints {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The list of channels to be included in the invoice route hints.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_get_channels(this_ptr: &PhantomRouteHints) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channels;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::ln::channelmanager::ChannelDetails<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The list of channels to be included in the invoice route hints.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_set_channels(this_ptr: &mut PhantomRouteHints, mut val: crate::c_types::derived::CVec_ChannelDetailsZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channels = local_val;
}
/// A fake scid used for representing the phantom node's fake channel in generating the invoice
/// route hints.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_get_phantom_scid(this_ptr: &PhantomRouteHints) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().phantom_scid;
	*inner_val
}
/// A fake scid used for representing the phantom node's fake channel in generating the invoice
/// route hints.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_set_phantom_scid(this_ptr: &mut PhantomRouteHints, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.phantom_scid = val;
}
/// The pubkey of the real backing node that would ultimately receive the payment.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_get_real_node_pubkey(this_ptr: &PhantomRouteHints) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().real_node_pubkey;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The pubkey of the real backing node that would ultimately receive the payment.
#[no_mangle]
pub extern "C" fn PhantomRouteHints_set_real_node_pubkey(this_ptr: &mut PhantomRouteHints, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.real_node_pubkey = val.into_rust();
}
/// Constructs a new PhantomRouteHints given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomRouteHints_new(mut channels_arg: crate::c_types::derived::CVec_ChannelDetailsZ, mut phantom_scid_arg: u64, mut real_node_pubkey_arg: crate::c_types::PublicKey) -> PhantomRouteHints {
	let mut local_channels_arg = Vec::new(); for mut item in channels_arg.into_rust().drain(..) { local_channels_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	PhantomRouteHints { inner: ObjOps::heap_alloc(nativePhantomRouteHints {
		channels: local_channels_arg,
		phantom_scid: phantom_scid_arg,
		real_node_pubkey: real_node_pubkey_arg.into_rust(),
	}), is_owned: true }
}
impl Clone for PhantomRouteHints {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePhantomRouteHints>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PhantomRouteHints_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePhantomRouteHints)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PhantomRouteHints
pub extern "C" fn PhantomRouteHints_clone(orig: &PhantomRouteHints) -> PhantomRouteHints {
	orig.clone()
}
/// Constructs a new ChannelManager to hold several channels and route between them.
///
/// This is the main \"logic hub\" for all channel-related actions, and implements
/// ChannelMessageHandler.
///
/// Non-proportional fees are fixed according to our risk using the provided fee estimator.
///
/// panics if channel_value_satoshis is >= `MAX_FUNDING_SATOSHIS`!
///
/// Users need to notify the new ChannelManager when a new block is connected or
/// disconnected using its `block_connected` and `block_disconnected` methods, starting
/// from after `params.latest_hash`.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_new(mut fee_est: crate::lightning::chain::chaininterface::FeeEstimator, mut chain_monitor: crate::lightning::chain::Watch, mut tx_broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut config: crate::lightning::util::config::UserConfig, mut params: crate::lightning::ln::channelmanager::ChainParameters) -> crate::lightning::ln::channelmanager::ChannelManager {
	let mut ret = lightning::ln::channelmanager::ChannelManager::new(fee_est, chain_monitor, tx_broadcaster, logger, keys_manager, *unsafe { Box::from_raw(config.take_inner()) }, *unsafe { Box::from_raw(params.take_inner()) });
	crate::lightning::ln::channelmanager::ChannelManager { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Gets the current configuration applied to all new channels,  as
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_current_default_configuration(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::lightning::util::config::UserConfig {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_current_default_configuration();
	crate::lightning::util::config::UserConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::util::config::UserConfig<>) as *mut _) }, is_owned: false }
}

/// Creates a new outbound channel to the given remote node and with the given value.
///
/// `user_channel_id` will be provided back as in
/// [`Event::FundingGenerationReady::user_channel_id`] to allow tracking of which events
/// correspond with which `create_channel` call. Note that the `user_channel_id` defaults to 0
/// for inbound channels, so you may wish to avoid using 0 for `user_channel_id` here.
/// `user_channel_id` has no meaning inside of LDK, it is simply copied to events and otherwise
/// ignored.
///
/// Raises [`APIError::APIMisuseError`] when `channel_value_satoshis` > 2**24 or `push_msat` is
/// greater than `channel_value_satoshis * 1k` or `channel_value_satoshis < 1000`.
///
/// Note that we do not check if you are currently connected to the given peer. If no
/// connection is available, the outbound `open_channel` message may fail to send, resulting in
/// the channel eventually being silently forgotten (dropped on reload).
///
/// Returns the new Channel's temporary `channel_id`. This ID will appear as
/// [`Event::FundingGenerationReady::temporary_channel_id`] and in
/// [`ChannelDetails::channel_id`] until after
/// [`ChannelManager::funding_transaction_generated`] is called, swapping the Channel's ID for
/// one derived from the funding transaction's TXID. If the counterparty rejects the channel
/// immediately, this temporary ID will appear in [`Event::ChannelClosed::channel_id`].
///
/// [`Event::FundingGenerationReady::user_channel_id`]: events::Event::FundingGenerationReady::user_channel_id
/// [`Event::FundingGenerationReady::temporary_channel_id`]: events::Event::FundingGenerationReady::temporary_channel_id
/// [`Event::ChannelClosed::channel_id`]: events::Event::ChannelClosed::channel_id
///
/// Note that override_config (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_channel(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut their_network_key: crate::c_types::PublicKey, mut channel_value_satoshis: u64, mut push_msat: u64, mut user_channel_id: u64, mut override_config: crate::lightning::util::config::UserConfig) -> crate::c_types::derived::CResult__u832APIErrorZ {
	let mut local_override_config = if override_config.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(override_config.take_inner()) } }) };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_channel(their_network_key.into_rust(), channel_value_satoshis, push_msat, user_channel_id, local_override_config);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets the list of open channels, in random order. See ChannelDetail field documentation for
/// more information.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_list_channels(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_channels();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Gets the list of usable channels, in random order. Useful as an argument to
/// get_route to ensure non-announced channels are used.
///
/// These are guaranteed to have their [`ChannelDetails::is_usable`] value set to true, see the
/// documentation for [`ChannelDetails::is_usable`] for more info on exactly what the criteria
/// are.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_list_usable_channels(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_usable_channels();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
/// will be accepted on the given channel, and after additional timeout/the closing of all
/// pending HTLCs, the channel will be closed on chain.
///
///  * If we are the channel initiator, we will pay between our [`Background`] and
///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`Normal`] fee
///    estimate.
///  * If our counterparty is the channel initiator, we will require a channel closing
///    transaction feerate of at least our [`Background`] feerate or the feerate which
///    would appear on a force-closure transaction, whichever is lower. We will allow our
///    counterparty to pay as much fee as they'd like, however.
///
/// May generate a SendShutdown message event on success, which should be relayed.
///
/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_close_channel(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, channel_id: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.close_channel(unsafe { &*channel_id});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
/// will be accepted on the given channel, and after additional timeout/the closing of all
/// pending HTLCs, the channel will be closed on chain.
///
/// `target_feerate_sat_per_1000_weight` has different meanings depending on if we initiated
/// the channel being closed or not:
///  * If we are the channel initiator, we will pay at least this feerate on the closing
///    transaction. The upper-bound is set by
///    [`ChannelConfig::force_close_avoidance_max_fee_satoshis`] plus our [`Normal`] fee
///    estimate (or `target_feerate_sat_per_1000_weight`, if it is greater).
///  * If our counterparty is the channel initiator, we will refuse to accept a channel closure
///    transaction feerate below `target_feerate_sat_per_1000_weight` (or the feerate which
///    will appear on a force-closure transaction, whichever is lower).
///
/// May generate a SendShutdown message event on success, which should be relayed.
///
/// [`ChannelConfig::force_close_avoidance_max_fee_satoshis`]: crate::util::config::ChannelConfig::force_close_avoidance_max_fee_satoshis
/// [`Background`]: crate::chain::chaininterface::ConfirmationTarget::Background
/// [`Normal`]: crate::chain::chaininterface::ConfirmationTarget::Normal
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_close_channel_with_target_feerate(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, channel_id: *const [u8; 32], mut target_feerate_sats_per_1000_weight: u32) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.close_channel_with_target_feerate(unsafe { &*channel_id}, target_feerate_sats_per_1000_weight);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Force closes a channel, immediately broadcasting the latest local commitment transaction to
/// the chain and rejecting new HTLCs on the given channel. Fails if channel_id is unknown to the manager.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_force_close_channel(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, channel_id: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.force_close_channel(unsafe { &*channel_id});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Force close all channels, immediately broadcasting the latest local commitment transaction
/// for each to the chain and rejecting new HTLCs on each.
#[no_mangle]
pub extern "C" fn ChannelManager_force_close_all_channels(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.force_close_all_channels()
}

/// Sends a payment along a given route.
///
/// Value parameters are provided via the last hop in route, see documentation for RouteHop
/// fields for more info.
///
/// Note that if the payment_hash already exists elsewhere (eg you're sending a duplicative
/// payment), we don't do anything to stop you! We always try to ensure that if the provided
/// next hop knows the preimage to payment_hash they can claim an additional amount as
/// specified in the last hop in the route! Thus, you should probably do your own
/// payment_preimage tracking (which you should already be doing as they represent \"proof of
/// payment\") and prevent double-sends yourself.
///
/// May generate SendHTLCs message(s) event on success, which should be relayed.
///
/// Each path may have a different return value, and PaymentSendValue may return a Vec with
/// each entry matching the corresponding-index entry in the route paths, see
/// PaymentSendFailure for more info.
///
/// In general, a path may raise:
///  * APIError::RouteError when an invalid route or forwarding parameter (cltv_delta, fee,
///    node public key) is specified.
///  * APIError::ChannelUnavailable if the next-hop channel is not available for updates
///    (including due to previous monitor update failure or new permanent monitor update
///    failure).
///  * APIError::MonitorUpdateFailed if a new monitor update failure prevented sending the
///    relevant updates.
///
/// Note that depending on the type of the PaymentSendFailure the HTLC may have been
/// irrevocably committed to on our end. In such a case, do NOT retry the payment with a
/// different route unless you intend to pay twice!
///
/// payment_secret is unrelated to payment_hash (or PaymentPreimage) and exists to authenticate
/// the sender to the recipient and prevent payment-probing (deanonymization) attacks. For
/// newer nodes, it will be provided to you in the invoice. If you do not have one, the Route
/// must not contain multiple paths as multi-path payments require a recipient-provided
/// payment_secret.
/// If a payment_secret *is* provided, we assume that the invoice had the payment_secret feature
/// bit set (either as required or as available). If multiple paths are present in the Route,
/// we assume the invoice had the basic_mpp feature set.
///
/// Note that payment_secret (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_send_payment(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, route: &crate::lightning::routing::router::Route, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_PaymentIdPaymentSendFailureZ {
	let mut local_payment_secret = if payment_secret.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentSecret(payment_secret.data) }) };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.send_payment(route.get_native_ref(), ::lightning::ln::PaymentHash(payment_hash.data), &local_payment_secret);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}

/// Retries a payment along the given [`Route`].
///
/// Errors returned are a superset of those returned from [`send_payment`], so see
/// [`send_payment`] documentation for more details on errors. This method will also error if the
/// retry amount puts the payment more than 10% over the payment's total amount, if the payment
/// for the given `payment_id` cannot be found (likely due to timeout or success), or if
/// further retries have been disabled with [`abandon_payment`].
///
/// [`send_payment`]: [`ChannelManager::send_payment`]
/// [`abandon_payment`]: [`ChannelManager::abandon_payment`]
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_retry_payment(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, route: &crate::lightning::routing::router::Route, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.retry_payment(route.get_native_ref(), ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}

/// Signals that no further retries for the given payment will occur.
///
/// After this method returns, any future calls to [`retry_payment`] for the given `payment_id`
/// will fail with [`PaymentSendFailure::ParameterError`]. If no such event has been generated,
/// an [`Event::PaymentFailed`] event will be generated as soon as there are no remaining
/// pending HTLCs for this payment.
///
/// Note that calling this method does *not* prevent a payment from succeeding. You must still
/// wait until you receive either a [`Event::PaymentFailed`] or [`Event::PaymentSent`] event to
/// determine the ultimate status of a payment.
///
/// [`retry_payment`]: Self::retry_payment
/// [`Event::PaymentFailed`]: events::Event::PaymentFailed
/// [`Event::PaymentSent`]: events::Event::PaymentSent
#[no_mangle]
pub extern "C" fn ChannelManager_abandon_payment(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut payment_id: crate::c_types::ThirtyTwoBytes) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.abandon_payment(::lightning::ln::channelmanager::PaymentId(payment_id.data))
}

/// Send a spontaneous payment, which is a payment that does not require the recipient to have
/// generated an invoice. Optionally, you may specify the preimage. If you do choose to specify
/// the preimage, it must be a cryptographically secure random value that no intermediate node
/// would be able to guess -- otherwise, an intermediate node may claim the payment and it will
/// never reach the recipient.
///
/// See [`send_payment`] documentation for more details on the return value of this function.
///
/// Similar to regular payments, you MUST NOT reuse a `payment_preimage` value. See
/// [`send_payment`] for more information about the risks of duplicate preimage usage.
///
/// Note that `route` must have exactly one path.
///
/// [`send_payment`]: Self::send_payment
///
/// Note that payment_preimage (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_send_spontaneous_payment(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, route: &crate::lightning::routing::router::Route, mut payment_preimage: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	let mut local_payment_preimage = if payment_preimage.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentPreimage(payment_preimage.data) }) };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.send_spontaneous_payment(route.get_native_ref(), local_payment_preimage);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_1.0 }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}

/// Call this upon creation of a funding transaction for the given channel.
///
/// Returns an [`APIError::APIMisuseError`] if the funding_transaction spent non-SegWit outputs
/// or if no output was found which matches the parameters in [`Event::FundingGenerationReady`].
///
/// Returns [`APIError::ChannelUnavailable`] if a funding transaction has already been provided
/// for the channel or if the channel has been closed as indicated by [`Event::ChannelClosed`].
///
/// May panic if the output found in the funding transaction is duplicative with some other
/// channel (note that this should be trivially prevented by using unique funding transaction
/// keys per-channel).
///
/// Do NOT broadcast the funding transaction yourself. When we have safely received our
/// counterparty's signature the funding transaction will automatically be broadcast via the
/// [`BroadcasterInterface`] provided when this `ChannelManager` was constructed.
///
/// Note that this includes RBF or similar transaction replacement strategies - lightning does
/// not currently support replacing a funding transaction on an existing channel. Instead,
/// create a new channel with a conflicting funding transaction.
///
/// [`Event::FundingGenerationReady`]: crate::util::events::Event::FundingGenerationReady
/// [`Event::ChannelClosed`]: crate::util::events::Event::ChannelClosed
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_funding_transaction_generated(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, temporary_channel_id: *const [u8; 32], mut funding_transaction: crate::c_types::Transaction) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.funding_transaction_generated(unsafe { &*temporary_channel_id}, funding_transaction.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Regenerates channel_announcements and generates a signed node_announcement from the given
/// arguments, providing them in corresponding events via
/// [`get_and_clear_pending_msg_events`], if at least one public channel has been confirmed
/// on-chain. This effectively re-broadcasts all channel announcements and sends our node
/// announcement to ensure that the lightning P2P network is aware of the channels we have and
/// our network addresses.
///
/// `rgb` is a node \"color\" and `alias` is a printable human-readable string to describe this
/// node to humans. They carry no in-protocol meaning.
///
/// `addresses` represent the set (possibly empty) of socket addresses on which this node
/// accepts incoming connections. These will be included in the node_announcement, publicly
/// tying these addresses together and to this node. If you wish to preserve user privacy,
/// addresses should likely contain only Tor Onion addresses.
///
/// Panics if `addresses` is absurdly large (more than 500).
///
/// [`get_and_clear_pending_msg_events`]: MessageSendEventsProvider::get_and_clear_pending_msg_events
#[no_mangle]
pub extern "C" fn ChannelManager_broadcast_node_announcement(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut rgb: crate::c_types::ThreeBytes, mut alias: crate::c_types::ThirtyTwoBytes, mut addresses: crate::c_types::derived::CVec_NetAddressZ) {
	let mut local_addresses = Vec::new(); for mut item in addresses.into_rust().drain(..) { local_addresses.push( { item.into_native() }); };
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.broadcast_node_announcement(rgb.data, alias.data, local_addresses)
}

/// Processes HTLCs which are pending waiting on random forward delay.
///
/// Should only really ever be called in response to a PendingHTLCsForwardable event.
/// Will likely generate further events.
#[no_mangle]
pub extern "C" fn ChannelManager_process_pending_htlc_forwards(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.process_pending_htlc_forwards()
}

/// Performs actions which should happen on startup and roughly once per minute thereafter.
///
/// This currently includes:
///  * Increasing or decreasing the on-chain feerate estimates for our outbound channels,
///  * Broadcasting `ChannelUpdate` messages if we've been disconnected from our peer for more
///    than a minute, informing the network that they should no longer attempt to route over
///    the channel.
///
/// Note that this may cause reentrancy through `chain::Watch::update_channel` calls or feerate
/// estimate fetches.
#[no_mangle]
pub extern "C" fn ChannelManager_timer_tick_occurred(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.timer_tick_occurred()
}

/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
/// after a PaymentReceived event, failing the HTLC back to its origin and freeing resources
/// along the path (including in our own channel on which we received it).
/// Returns false if no payment was found to fail backwards, true if the process of failing the
/// HTLC backwards has been started.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_fail_htlc_backwards(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, payment_hash: *const [u8; 32]) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fail_htlc_backwards(&::lightning::ln::PaymentHash(unsafe { *payment_hash }));
	ret
}

/// Provides a payment preimage in response to [`Event::PaymentReceived`], generating any
/// [`MessageSendEvent`]s needed to claim the payment.
///
/// Note that if you did not set an `amount_msat` when calling [`create_inbound_payment`] or
/// [`create_inbound_payment_for_hash`] you must check that the amount in the `PaymentReceived`
/// event matches your expectation. If you fail to do so and call this method, you may provide
/// the sender \"proof-of-payment\" when they did not fulfill the full expected payment.
///
/// Returns whether any HTLCs were claimed, and thus if any new [`MessageSendEvent`]s are now
/// pending for processing via [`get_and_clear_pending_msg_events`].
///
/// [`Event::PaymentReceived`]: crate::util::events::Event::PaymentReceived
/// [`create_inbound_payment`]: Self::create_inbound_payment
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
/// [`get_and_clear_pending_msg_events`]: MessageSendEventsProvider::get_and_clear_pending_msg_events
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_claim_funds(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut payment_preimage: crate::c_types::ThirtyTwoBytes) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.claim_funds(::lightning::ln::PaymentPreimage(payment_preimage.data));
	ret
}

/// Gets the node_id held by this ChannelManager
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_our_node_id(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_our_node_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Called to accept a request to open a channel after [`Event::OpenChannelRequest`] has been
/// triggered.
///
/// The `temporary_channel_id` parameter indicates which inbound channel should be accepted.
///
/// For inbound channels, the `user_channel_id` parameter will be provided back in
/// [`Event::ChannelClosed::user_channel_id`] to allow tracking of which events correspond
/// with which `accept_inbound_channel` call.
///
/// [`Event::OpenChannelRequest`]: events::Event::OpenChannelRequest
/// [`Event::ChannelClosed::user_channel_id`]: events::Event::ChannelClosed::user_channel_id
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_accept_inbound_channel(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, temporary_channel_id: *const [u8; 32], mut user_channel_id: u64) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.accept_inbound_channel(unsafe { &*temporary_channel_id}, user_channel_id);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets a payment secret and payment hash for use in an invoice given to a third party wishing
/// to pay us.
///
/// This differs from [`create_inbound_payment_for_hash`] only in that it generates the
/// [`PaymentHash`] and [`PaymentPreimage`] for you.
///
/// The [`PaymentPreimage`] will ultimately be returned to you in the [`PaymentReceived`], which
/// will have the [`PaymentReceived::payment_preimage`] field filled in. That should then be
/// passed directly to [`claim_funds`].
///
/// See [`create_inbound_payment_for_hash`] for detailed documentation on behavior and requirements.
///
/// Note that a malicious eavesdropper can intuit whether an inbound payment was created by
/// `create_inbound_payment` or `create_inbound_payment_for_hash` based on runtime.
///
/// # Note
///
/// If you register an inbound payment with this method, then serialize the `ChannelManager`, then
/// deserialize it with a node running 0.0.103 and earlier, the payment will fail to be received.
///
/// Errors if `min_value_msat` is greater than total bitcoin supply.
///
/// [`claim_funds`]: Self::claim_funds
/// [`PaymentReceived`]: events::Event::PaymentReceived
/// [`PaymentReceived::payment_preimage`]: events::Event::PaymentReceived::payment_preimage
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_inbound_payment(local_min_value_msat, invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_1.0 }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Legacy version of [`create_inbound_payment`]. Use this method if you wish to share
/// serialized state with LDK node(s) running 0.0.103 and earlier.
///
/// May panic if `invoice_expiry_delta_secs` is greater than one year.
///
/// # Note
/// This method is deprecated and will be removed soon.
///
/// [`create_inbound_payment`]: Self::create_inbound_payment
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment_legacy(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_inbound_payment_legacy(local_min_value_msat, invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_0_1.0 }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets a [`PaymentSecret`] for a given [`PaymentHash`], for which the payment preimage is
/// stored external to LDK.
///
/// A [`PaymentReceived`] event will only be generated if the [`PaymentSecret`] matches a
/// payment secret fetched via this method or [`create_inbound_payment`], and which is at least
/// the `min_value_msat` provided here, if one is provided.
///
/// The [`PaymentHash`] (and corresponding [`PaymentPreimage`]) should be globally unique, though
/// note that LDK will not stop you from registering duplicate payment hashes for inbound
/// payments.
///
/// `min_value_msat` should be set if the invoice being generated contains a value. Any payment
/// received for the returned [`PaymentHash`] will be required to be at least `min_value_msat`
/// before a [`PaymentReceived`] event will be generated, ensuring that we do not provide the
/// sender \"proof-of-payment\" unless they have paid the required amount.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time. This should roughly match the expiry time set in the invoice.
/// After this many seconds, we will remove the inbound payment, resulting in any attempts to
/// pay the invoice failing. The BOLT spec suggests 3,600 secs as a default validity time for
/// invoices when no timeout is set.
///
/// Note that we use block header time to time-out pending inbound payments (with some margin
/// to compensate for the inaccuracy of block header timestamps). Thus, in practice we will
/// accept a payment and generate a [`PaymentReceived`] event for some time after the expiry.
/// If you need exact expiry semantics, you should enforce them upon receipt of
/// [`PaymentReceived`].
///
/// Note that invoices generated for inbound payments should have their `min_final_cltv_expiry`
/// set to at least [`MIN_FINAL_CLTV_EXPIRY`].
///
/// Note that a malicious eavesdropper can intuit whether an inbound payment was created by
/// `create_inbound_payment` or `create_inbound_payment_for_hash` based on runtime.
///
/// # Note
///
/// If you register an inbound payment with this method, then serialize the `ChannelManager`, then
/// deserialize it with a node running 0.0.103 and earlier, the payment will fail to be received.
///
/// Errors if `min_value_msat` is greater than total bitcoin supply.
///
/// [`create_inbound_payment`]: Self::create_inbound_payment
/// [`PaymentReceived`]: events::Event::PaymentReceived
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment_for_hash(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_PaymentSecretNoneZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_inbound_payment_for_hash(::lightning::ln::PaymentHash(payment_hash.data), local_min_value_msat, invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Legacy version of [`create_inbound_payment_for_hash`]. Use this method if you wish to share
/// serialized state with LDK node(s) running 0.0.103 and earlier.
///
/// May panic if `invoice_expiry_delta_secs` is greater than one year.
///
/// # Note
/// This method is deprecated and will be removed soon.
///
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment_for_hash_legacy(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_PaymentSecretAPIErrorZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.create_inbound_payment_for_hash_legacy(::lightning::ln::PaymentHash(payment_hash.data), local_min_value_msat, invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets an LDK-generated payment preimage from a payment hash and payment secret that were
/// previously returned from [`create_inbound_payment`].
///
/// [`create_inbound_payment`]: Self::create_inbound_payment
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_payment_preimage(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_PaymentPreimageAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_payment_preimage(::lightning::ln::PaymentHash(payment_hash.data), ::lightning::ln::PaymentSecret(payment_secret.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets a fake short channel id for use in receiving [phantom node payments]. These fake scids
/// are used when constructing the phantom invoice's route hints.
///
/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_phantom_scid(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_phantom_scid();
	ret
}

/// Gets route hints for use in receiving [phantom node payments].
///
/// [phantom node payments]: crate::chain::keysinterface::PhantomKeysManager
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_phantom_route_hints(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::lightning::ln::channelmanager::PhantomRouteHints {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_phantom_route_hints();
	crate::lightning::ln::channelmanager::PhantomRouteHints { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeChannelManager> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_MessageSendEventsProvider(this_arg: &ChannelManager) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: ChannelManager_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn ChannelManager_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeChannelManager as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeChannelManager> for crate::lightning::util::events::EventsProvider {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new EventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_EventsProvider(this_arg: &ChannelManager) -> crate::lightning::util::events::EventsProvider {
	crate::lightning::util::events::EventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		process_pending_events: ChannelManager_EventsProvider_process_pending_events,
	}
}

extern "C" fn ChannelManager_EventsProvider_process_pending_events(this_arg: *const c_void, mut handler: crate::lightning::util::events::EventHandler) {
	<nativeChannelManager as lightning::util::events::EventsProvider<>>::process_pending_events(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, handler)
}

impl From<nativeChannelManager> for crate::lightning::chain::Listen {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_Listen(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Listen which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Listen must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Listen(this_arg: &ChannelManager) -> crate::lightning::chain::Listen {
	crate::lightning::chain::Listen {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		block_connected: ChannelManager_Listen_block_connected,
		block_disconnected: ChannelManager_Listen_block_disconnected,
	}
}

extern "C" fn ChannelManager_Listen_block_connected(this_arg: *const c_void, mut block: crate::c_types::u8slice, mut height: u32) {
	<nativeChannelManager as lightning::chain::Listen<>>::block_connected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap(), height)
}
extern "C" fn ChannelManager_Listen_block_disconnected(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChannelManager as lightning::chain::Listen<>>::block_disconnected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}

impl From<nativeChannelManager> for crate::lightning::chain::Confirm {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_Confirm(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Confirm which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Confirm must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Confirm(this_arg: &ChannelManager) -> crate::lightning::chain::Confirm {
	crate::lightning::chain::Confirm {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		transactions_confirmed: ChannelManager_Confirm_transactions_confirmed,
		transaction_unconfirmed: ChannelManager_Confirm_transaction_unconfirmed,
		best_block_updated: ChannelManager_Confirm_best_block_updated,
		get_relevant_txids: ChannelManager_Confirm_get_relevant_txids,
	}
}

extern "C" fn ChannelManager_Confirm_transactions_confirmed(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeChannelManager as lightning::chain::Confirm<>>::transactions_confirmed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn ChannelManager_Confirm_best_block_updated(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChannelManager as lightning::chain::Confirm<>>::best_block_updated(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}
#[must_use]
extern "C" fn ChannelManager_Confirm_get_relevant_txids(this_arg: *const c_void) -> crate::c_types::derived::CVec_TxidZ {
	let mut ret = <nativeChannelManager as lightning::chain::Confirm<>>::get_relevant_txids(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: item.into_inner() } }); };
	local_ret.into()
}
extern "C" fn ChannelManager_Confirm_transaction_unconfirmed(this_arg: *const c_void, txid: *const [u8; 32]) {
	<nativeChannelManager as lightning::chain::Confirm<>>::transaction_unconfirmed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap())
}

/// Blocks until ChannelManager needs to be persisted or a timeout is reached. It returns a bool
/// indicating whether persistence is necessary. Only one listener on
/// `await_persistable_update` or `await_persistable_update_timeout` is guaranteed to be woken
/// up.
///
/// Note that this method is not available with the `no-std` feature.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_await_persistable_update_timeout(this_arg: &crate::lightning::ln::channelmanager::ChannelManager, mut max_wait: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.await_persistable_update_timeout(core::time::Duration::from_secs(max_wait));
	ret
}

/// Blocks until ChannelManager needs to be persisted. Only one listener on
/// `await_persistable_update` or `await_persistable_update_timeout` is guaranteed to be woken
/// up.
#[no_mangle]
pub extern "C" fn ChannelManager_await_persistable_update(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.await_persistable_update()
}

/// Gets the latest best block which was connected either via the [`chain::Listen`] or
/// [`chain::Confirm`] interfaces.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_current_best_block(this_arg: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::lightning::chain::BestBlock {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.current_best_block();
	crate::lightning::chain::BestBlock { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeChannelManager> for crate::lightning::ln::msgs::ChannelMessageHandler {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_ChannelMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new ChannelMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ChannelMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_ChannelMessageHandler(this_arg: &ChannelManager) -> crate::lightning::ln::msgs::ChannelMessageHandler {
	crate::lightning::ln::msgs::ChannelMessageHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_open_channel: ChannelManager_ChannelMessageHandler_handle_open_channel,
		handle_accept_channel: ChannelManager_ChannelMessageHandler_handle_accept_channel,
		handle_funding_created: ChannelManager_ChannelMessageHandler_handle_funding_created,
		handle_funding_signed: ChannelManager_ChannelMessageHandler_handle_funding_signed,
		handle_funding_locked: ChannelManager_ChannelMessageHandler_handle_funding_locked,
		handle_shutdown: ChannelManager_ChannelMessageHandler_handle_shutdown,
		handle_closing_signed: ChannelManager_ChannelMessageHandler_handle_closing_signed,
		handle_update_add_htlc: ChannelManager_ChannelMessageHandler_handle_update_add_htlc,
		handle_update_fulfill_htlc: ChannelManager_ChannelMessageHandler_handle_update_fulfill_htlc,
		handle_update_fail_htlc: ChannelManager_ChannelMessageHandler_handle_update_fail_htlc,
		handle_update_fail_malformed_htlc: ChannelManager_ChannelMessageHandler_handle_update_fail_malformed_htlc,
		handle_commitment_signed: ChannelManager_ChannelMessageHandler_handle_commitment_signed,
		handle_revoke_and_ack: ChannelManager_ChannelMessageHandler_handle_revoke_and_ack,
		handle_update_fee: ChannelManager_ChannelMessageHandler_handle_update_fee,
		handle_announcement_signatures: ChannelManager_ChannelMessageHandler_handle_announcement_signatures,
		peer_disconnected: ChannelManager_ChannelMessageHandler_peer_disconnected,
		peer_connected: ChannelManager_ChannelMessageHandler_peer_connected,
		handle_channel_reestablish: ChannelManager_ChannelMessageHandler_handle_channel_reestablish,
		handle_channel_update: ChannelManager_ChannelMessageHandler_handle_channel_update,
		handle_error: ChannelManager_ChannelMessageHandler_handle_error,
		MessageSendEventsProvider: crate::lightning::util::events::MessageSendEventsProvider {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: ChannelManager_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

extern "C" fn ChannelManager_ChannelMessageHandler_handle_open_channel(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::OpenChannel) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_open_channel(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), *unsafe { Box::from_raw(their_features.take_inner()) }, msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_accept_channel(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::AcceptChannel) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_accept_channel(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), *unsafe { Box::from_raw(their_features.take_inner()) }, msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_created(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingCreated) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_created(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_locked(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingLocked) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_locked(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_shutdown(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, their_features: &crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::Shutdown) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_shutdown(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), their_features.get_native_ref(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_closing_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ClosingSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_closing_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_add_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateAddHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_add_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fulfill_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFulfillHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fulfill_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fail_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fail_malformed_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailMalformedHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_malformed_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_commitment_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::CommitmentSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_commitment_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_revoke_and_ack(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::RevokeAndACK) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_revoke_and_ack(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fee(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFee) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fee(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_announcement_signatures(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::AnnouncementSignatures) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_announcement_signatures(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_channel_update(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ChannelUpdate) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_channel_reestablish(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ChannelReestablish) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_reestablish(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_peer_disconnected(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut no_connection_possible: bool) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), no_connection_possible)
}
extern "C" fn ChannelManager_ChannelMessageHandler_peer_connected(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, init_msg: &crate::lightning::ln::msgs::Init) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), init_msg.get_native_ref())
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_error(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ErrorMessage) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_error(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), msg.get_native_ref())
}

#[no_mangle]
/// Serialize the CounterpartyForwardingInfo object into a byte array which can be read by CounterpartyForwardingInfo_read
pub extern "C" fn CounterpartyForwardingInfo_write(obj: &crate::lightning::ln::channelmanager::CounterpartyForwardingInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn CounterpartyForwardingInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCounterpartyForwardingInfo) })
}
#[no_mangle]
/// Read a CounterpartyForwardingInfo from a byte array, created by CounterpartyForwardingInfo_write
pub extern "C" fn CounterpartyForwardingInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CounterpartyForwardingInfoDecodeErrorZ {
	let res: Result<lightning::ln::channelmanager::CounterpartyForwardingInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channelmanager::CounterpartyForwardingInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelCounterparty object into a byte array which can be read by ChannelCounterparty_read
pub extern "C" fn ChannelCounterparty_write(obj: &crate::lightning::ln::channelmanager::ChannelCounterparty) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelCounterparty_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelCounterparty) })
}
#[no_mangle]
/// Read a ChannelCounterparty from a byte array, created by ChannelCounterparty_write
pub extern "C" fn ChannelCounterparty_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelCounterpartyDecodeErrorZ {
	let res: Result<lightning::ln::channelmanager::ChannelCounterparty, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channelmanager::ChannelCounterparty { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelDetails object into a byte array which can be read by ChannelDetails_read
pub extern "C" fn ChannelDetails_write(obj: &crate::lightning::ln::channelmanager::ChannelDetails) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelDetails_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelDetails) })
}
#[no_mangle]
/// Read a ChannelDetails from a byte array, created by ChannelDetails_write
pub extern "C" fn ChannelDetails_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelDetailsDecodeErrorZ {
	let res: Result<lightning::ln::channelmanager::ChannelDetails, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the PhantomRouteHints object into a byte array which can be read by PhantomRouteHints_read
pub extern "C" fn PhantomRouteHints_write(obj: &crate::lightning::ln::channelmanager::PhantomRouteHints) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn PhantomRouteHints_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePhantomRouteHints) })
}
#[no_mangle]
/// Read a PhantomRouteHints from a byte array, created by PhantomRouteHints_write
pub extern "C" fn PhantomRouteHints_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PhantomRouteHintsDecodeErrorZ {
	let res: Result<lightning::ln::channelmanager::PhantomRouteHints, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::channelmanager::PhantomRouteHints { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelManager object into a byte array which can be read by ChannelManager_read
pub extern "C" fn ChannelManager_write(obj: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelManager_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelManager) })
}

use lightning::ln::channelmanager::ChannelManagerReadArgs as nativeChannelManagerReadArgsImport;
pub(crate) type nativeChannelManagerReadArgs = nativeChannelManagerReadArgsImport<'static, crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>;

/// Arguments for the creation of a ChannelManager that are not deserialized.
///
/// At a high-level, the process for deserializing a ChannelManager and resuming normal operation
/// is:
/// 1) Deserialize all stored [`ChannelMonitor`]s.
/// 2) Deserialize the [`ChannelManager`] by filling in this struct and calling:
///    `<(BlockHash, ChannelManager)>::read(reader, args)`
///    This may result in closing some channels if the [`ChannelMonitor`] is newer than the stored
///    [`ChannelManager`] state to ensure no loss of funds. Thus, transactions may be broadcasted.
/// 3) If you are not fetching full blocks, register all relevant [`ChannelMonitor`] outpoints the
///    same way you would handle a [`chain::Filter`] call using
///    [`ChannelMonitor::get_outputs_to_watch`] and [`ChannelMonitor::get_funding_txo`].
/// 4) Reconnect blocks on your [`ChannelMonitor`]s.
/// 5) Disconnect/connect blocks on the [`ChannelManager`].
/// 6) Re-persist the [`ChannelMonitor`]s to ensure the latest state is on disk.
///    Note that if you're using a [`ChainMonitor`] for your [`chain::Watch`] implementation, you
///    will likely accomplish this as a side-effect of calling [`chain::Watch::watch_channel`] in
///    the next step.
/// 7) Move the [`ChannelMonitor`]s into your local [`chain::Watch`]. If you're using a
///    [`ChainMonitor`], this is done by calling [`chain::Watch::watch_channel`].
///
/// Note that the ordering of #4-7 is not of importance, however all four must occur before you
/// call any other methods on the newly-deserialized [`ChannelManager`].
///
/// Note that because some channels may be closed during deserialization, it is critical that you
/// always deserialize only the latest version of a ChannelManager and ChannelMonitors available to
/// you. If you deserialize an old ChannelManager (during which force-closure transactions may be
/// broadcast), and then later deserialize a newer version of the same ChannelManager (which will
/// not force-close the same channels but consider them live), you may end up revoking a state for
/// which you've already broadcasted the transaction.
///
/// [`ChainMonitor`]: crate::chain::chainmonitor::ChainMonitor
#[must_use]
#[repr(C)]
pub struct ChannelManagerReadArgs {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelManagerReadArgs,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelManagerReadArgs {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelManagerReadArgs>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelManagerReadArgs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_free(this_obj: ChannelManagerReadArgs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelManagerReadArgs_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelManagerReadArgs); }
}
#[allow(unused)]
impl ChannelManagerReadArgs {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelManagerReadArgs {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelManagerReadArgs {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelManagerReadArgs {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The keys provider which will give us relevant keys. Some keys will be loaded during
/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
/// signing data.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_keys_manager(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::keysinterface::KeysInterface {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().keys_manager;
	inner_val
}
/// The keys provider which will give us relevant keys. Some keys will be loaded during
/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
/// signing data.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_keys_manager(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::keysinterface::KeysInterface) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.keys_manager = val;
}
/// The fee_estimator for use in the ChannelManager in the future.
///
/// No calls to the FeeEstimator will be made during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_fee_estimator(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::chaininterface::FeeEstimator {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_estimator;
	inner_val
}
/// The fee_estimator for use in the ChannelManager in the future.
///
/// No calls to the FeeEstimator will be made during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_fee_estimator(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::chaininterface::FeeEstimator) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_estimator = val;
}
/// The chain::Watch for use in the ChannelManager in the future.
///
/// No calls to the chain::Watch will be made during deserialization. It is assumed that
/// you have deserialized ChannelMonitors separately and will add them to your
/// chain::Watch after deserializing this ChannelManager.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_chain_monitor(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::Watch {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().chain_monitor;
	inner_val
}
/// The chain::Watch for use in the ChannelManager in the future.
///
/// No calls to the chain::Watch will be made during deserialization. It is assumed that
/// you have deserialized ChannelMonitors separately and will add them to your
/// chain::Watch after deserializing this ChannelManager.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_chain_monitor(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::Watch) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.chain_monitor = val;
}
/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
/// used to broadcast the latest local commitment transactions of channels which must be
/// force-closed during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_tx_broadcaster(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::chaininterface::BroadcasterInterface {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().tx_broadcaster;
	inner_val
}
/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
/// used to broadcast the latest local commitment transactions of channels which must be
/// force-closed during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_tx_broadcaster(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::chaininterface::BroadcasterInterface) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.tx_broadcaster = val;
}
/// The Logger for use in the ChannelManager and which may be used to log information during
/// deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_logger(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::util::logger::Logger {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().logger;
	inner_val
}
/// The Logger for use in the ChannelManager and which may be used to log information during
/// deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_logger(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::util::logger::Logger) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.logger = val;
}
/// Default settings used for new channels. Any existing channels will continue to use the
/// runtime settings which were stored when the ChannelManager was serialized.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_default_config(this_ptr: &ChannelManagerReadArgs) -> crate::lightning::util::config::UserConfig {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().default_config;
	crate::lightning::util::config::UserConfig { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::config::UserConfig<>) as *mut _) }, is_owned: false }
}
/// Default settings used for new channels. Any existing channels will continue to use the
/// runtime settings which were stored when the ChannelManager was serialized.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_default_config(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::util::config::UserConfig) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.default_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Simple utility function to create a ChannelManagerReadArgs which creates the monitor
/// HashMap for you. This is primarily useful for C bindings where it is not practical to
/// populate a HashMap directly from C.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_new(mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut fee_estimator: crate::lightning::chain::chaininterface::FeeEstimator, mut chain_monitor: crate::lightning::chain::Watch, mut tx_broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut default_config: crate::lightning::util::config::UserConfig, mut channel_monitors: crate::c_types::derived::CVec_ChannelMonitorZ) -> crate::lightning::ln::channelmanager::ChannelManagerReadArgs {
	let mut local_channel_monitors = Vec::new(); for mut item in channel_monitors.into_rust().drain(..) { local_channel_monitors.push( { item.get_native_mut_ref() }); };
	let mut ret = lightning::ln::channelmanager::ChannelManagerReadArgs::new(keys_manager, fee_estimator, chain_monitor, tx_broadcaster, logger, *unsafe { Box::from_raw(default_config.take_inner()) }, local_channel_monitors);
	crate::lightning::ln::channelmanager::ChannelManagerReadArgs { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Read a C2Tuple_BlockHashChannelManagerZ from a byte array, created by C2Tuple_BlockHashChannelManagerZ_write
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_read(ser: crate::c_types::u8slice, arg: crate::lightning::ln::channelmanager::ChannelManagerReadArgs) -> crate::c_types::derived::CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	let arg_conv = *unsafe { Box::from_raw(arg.take_inner()) };
	let res: Result<(bitcoin::hash_types::BlockHash, lightning::ln::channelmanager::ChannelManager<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>), lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_res_0_0, mut orig_res_0_1) = o; let mut local_res_0 = (crate::c_types::ThirtyTwoBytes { data: orig_res_0_0.into_inner() }, crate::lightning::ln::channelmanager::ChannelManager { inner: ObjOps::heap_alloc(orig_res_0_1), is_owned: true }).into(); local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
