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

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::ln::channelmanager::ChannelManager as nativeChannelManagerImport;
type nativeChannelManager = nativeChannelManagerImport<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChannelManager, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelManager_free(this_obj: ChannelManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelManager_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelManager); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelManager {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelManager {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::channelmanager::ChainParameters as nativeChainParametersImport;
type nativeChainParameters = nativeChainParametersImport;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChainParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChainParameters_free(this_obj: ChainParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChainParameters_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainParameters); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChainParameters {
	pub(crate) fn take_inner(mut self) -> *mut nativeChainParameters {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The network for determining the `chain_hash` in Lightning messages.
#[no_mangle]
pub extern "C" fn ChainParameters_get_network(this_ptr: &ChainParameters) -> crate::bitcoin::network::Network {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.network;
	crate::bitcoin::network::Network::from_bitcoin(inner_val)
}
/// The network for determining the `chain_hash` in Lightning messages.
#[no_mangle]
pub extern "C" fn ChainParameters_set_network(this_ptr: &mut ChainParameters, mut val: crate::bitcoin::network::Network) {
	unsafe { &mut *this_ptr.inner }.network = val.into_bitcoin();
}
/// The hash and height of the latest block successfully connected.
///
/// Used to track on-chain channel funding outputs and send payments with reliable timelocks.
#[no_mangle]
pub extern "C" fn ChainParameters_get_best_block(this_ptr: &ChainParameters) -> crate::lightning::chain::BestBlock {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.best_block;
	crate::lightning::chain::BestBlock { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// The hash and height of the latest block successfully connected.
///
/// Used to track on-chain channel funding outputs and send payments with reliable timelocks.
#[no_mangle]
pub extern "C" fn ChainParameters_set_best_block(this_ptr: &mut ChainParameters, mut val: crate::lightning::chain::BestBlock) {
	unsafe { &mut *this_ptr.inner }.best_block = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ChainParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChainParameters_new(mut network_arg: crate::bitcoin::network::Network, mut best_block_arg: crate::lightning::chain::BestBlock) -> ChainParameters {
	ChainParameters { inner: Box::into_raw(Box::new(nativeChainParameters {
		network: network_arg.into_bitcoin(),
		best_block: *unsafe { Box::from_raw(best_block_arg.take_inner()) },
	})), is_owned: true }
}
impl Clone for ChainParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChainParameters>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning::ln::channelmanager::ChannelCounterparty as nativeChannelCounterpartyImport;
type nativeChannelCounterparty = nativeChannelCounterpartyImport;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChannelCounterparty, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_free(this_obj: ChannelCounterparty) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelCounterparty_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelCounterparty); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelCounterparty {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelCounterparty {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_node_id(this_ptr: &ChannelCounterparty) -> crate::c_types::PublicKey {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of our counterparty
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_node_id(this_ptr: &mut ChannelCounterparty, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *this_ptr.inner }.node_id = val.into_rust();
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_get_features(this_ptr: &ChannelCounterparty) -> crate::lightning::ln::features::InitFeatures {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.features;
	crate::lightning::ln::features::InitFeatures { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// The Features the channel counterparty provided upon last connection.
/// Useful for routing as it is the most up-to-date copy of the counterparty's features and
/// many routing-relevant features are present in the init context.
#[no_mangle]
pub extern "C" fn ChannelCounterparty_set_features(this_ptr: &mut ChannelCounterparty, mut val: crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut *this_ptr.inner }.features = *unsafe { Box::from_raw(val.take_inner()) };
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.unspendable_punishment_reserve;
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
	unsafe { &mut *this_ptr.inner }.unspendable_punishment_reserve = val;
}
impl Clone for ChannelCounterparty {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelCounterparty>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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
type nativeChannelDetails = nativeChannelDetailsImport;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChannelDetails, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelDetails_free(this_obj: ChannelDetails) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelDetails_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelDetails); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelDetails {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelDetails {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_id(this_ptr: &ChannelDetails) -> *const [u8; 32] {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_id;
	inner_val
}
/// The channel's ID (prior to funding transaction generation, this is a random 32 bytes,
/// thereafter this is the txid of the funding transaction xor the funding transaction output).
/// Note that this means this value is *not* persistent - it can change once during the
/// lifetime of the channel.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *this_ptr.inner }.channel_id = val.data;
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_counterparty(this_ptr: &ChannelDetails) -> crate::lightning::ln::channelmanager::ChannelCounterparty {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.counterparty;
	crate::lightning::ln::channelmanager::ChannelCounterparty { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// Parameters which apply to our counterparty. See individual fields for more information.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_counterparty(this_ptr: &mut ChannelDetails, mut val: crate::lightning::ln::channelmanager::ChannelCounterparty) {
	unsafe { &mut *this_ptr.inner }.counterparty = *unsafe { Box::from_raw(val.take_inner()) };
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.funding_txo;
	let mut local_inner_val = crate::lightning::chain::transaction::OutPoint { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else {  { (inner_val.as_ref().unwrap()) } } as *const _) as *mut _ }, is_owned: false };
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
	unsafe { &mut *this_ptr.inner }.funding_txo = local_val;
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_short_channel_id(this_ptr: &ChannelDetails) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.short_channel_id;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else {  { crate::c_types::derived::COption_u64Z::Some(inner_val.unwrap()) } };
	local_inner_val
}
/// The position of the funding transaction in the chain. None if the funding transaction has
/// not yet been confirmed and the channel fully opened.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_short_channel_id(this_ptr: &mut ChannelDetails, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *this_ptr.inner }.short_channel_id = local_val;
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_get_channel_value_satoshis(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.channel_value_satoshis;
	*inner_val
}
/// The value, in satoshis, of this channel as appears in the funding output
#[no_mangle]
pub extern "C" fn ChannelDetails_set_channel_value_satoshis(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.channel_value_satoshis = val;
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.unspendable_punishment_reserve;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else {  { crate::c_types::derived::COption_u64Z::Some(inner_val.unwrap()) } };
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
	unsafe { &mut *this_ptr.inner }.unspendable_punishment_reserve = local_val;
}
/// The user_id passed in to create_channel, or 0 if the channel was inbound.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_user_id(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.user_id;
	*inner_val
}
/// The user_id passed in to create_channel, or 0 if the channel was inbound.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_user_id(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.user_id = val;
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_outbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.outbound_capacity_msat;
	*inner_val
}
/// The available outbound capacity for sending HTLCs to the remote peer. This does not include
/// any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
/// available for inclusion in new outbound HTLCs). This further does not include any pending
/// outgoing HTLCs which are awaiting some other resolution to be sent.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// conflict-avoidance policy, exactly this amount is not likely to be spendable. However, we
/// should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_outbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.outbound_capacity_msat = val;
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_inbound_capacity_msat(this_ptr: &ChannelDetails) -> u64 {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.inbound_capacity_msat;
	*inner_val
}
/// The available inbound capacity for the remote peer to send HTLCs to us. This does not
/// include any pending HTLCs which are not yet fully resolved (and, thus, who's balance is not
/// available for inclusion in new inbound HTLCs).
/// Note that there are some corner cases not fully handled here, so the actual available
/// inbound capacity may be slightly higher than this.
///
/// This value is not exact. Due to various in-flight changes, feerate changes, and our
/// counterparty's conflict-avoidance policy, exactly this amount is not likely to be spendable.
/// However, our counterparty should be able to spend nearly this amount.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_inbound_capacity_msat(this_ptr: &mut ChannelDetails, mut val: u64) {
	unsafe { &mut *this_ptr.inner }.inbound_capacity_msat = val;
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.confirmations_required;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else {  { crate::c_types::derived::COption_u32Z::Some(inner_val.unwrap()) } };
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
	unsafe { &mut *this_ptr.inner }.confirmations_required = local_val;
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.force_close_spend_delay;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u16Z::None } else {  { crate::c_types::derived::COption_u16Z::Some(inner_val.unwrap()) } };
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
	unsafe { &mut *this_ptr.inner }.force_close_spend_delay = local_val;
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_outbound(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.is_outbound;
	*inner_val
}
/// True if the channel was initiated (and thus funded) by us.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_outbound(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.is_outbound = val;
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
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.is_funding_locked;
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
	unsafe { &mut *this_ptr.inner }.is_funding_locked = val;
}
/// True if the channel is (a) confirmed and funding_locked messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_funding_locked`.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_usable(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.is_usable;
	*inner_val
}
/// True if the channel is (a) confirmed and funding_locked messages have been exchanged, (b)
/// the peer is connected, and (c) the channel is not currently negotiating a shutdown.
///
/// This is a strict superset of `is_funding_locked`.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_usable(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.is_usable = val;
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_get_is_public(this_ptr: &ChannelDetails) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.is_public;
	*inner_val
}
/// True if this channel is (or will be) publicly-announced.
#[no_mangle]
pub extern "C" fn ChannelDetails_set_is_public(this_ptr: &mut ChannelDetails, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.is_public = val;
}
/// Constructs a new ChannelDetails given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelDetails_new(mut channel_id_arg: crate::c_types::ThirtyTwoBytes, mut counterparty_arg: crate::lightning::ln::channelmanager::ChannelCounterparty, mut funding_txo_arg: crate::lightning::chain::transaction::OutPoint, mut short_channel_id_arg: crate::c_types::derived::COption_u64Z, mut channel_value_satoshis_arg: u64, mut unspendable_punishment_reserve_arg: crate::c_types::derived::COption_u64Z, mut user_id_arg: u64, mut outbound_capacity_msat_arg: u64, mut inbound_capacity_msat_arg: u64, mut confirmations_required_arg: crate::c_types::derived::COption_u32Z, mut force_close_spend_delay_arg: crate::c_types::derived::COption_u16Z, mut is_outbound_arg: bool, mut is_funding_locked_arg: bool, mut is_usable_arg: bool, mut is_public_arg: bool) -> ChannelDetails {
	let mut local_funding_txo_arg = if funding_txo_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(funding_txo_arg.take_inner()) } }) };
	let mut local_short_channel_id_arg = if short_channel_id_arg.is_some() { Some( { short_channel_id_arg.take() }) } else { None };
	let mut local_unspendable_punishment_reserve_arg = if unspendable_punishment_reserve_arg.is_some() { Some( { unspendable_punishment_reserve_arg.take() }) } else { None };
	let mut local_confirmations_required_arg = if confirmations_required_arg.is_some() { Some( { confirmations_required_arg.take() }) } else { None };
	let mut local_force_close_spend_delay_arg = if force_close_spend_delay_arg.is_some() { Some( { force_close_spend_delay_arg.take() }) } else { None };
	ChannelDetails { inner: Box::into_raw(Box::new(nativeChannelDetails {
		channel_id: channel_id_arg.data,
		counterparty: *unsafe { Box::from_raw(counterparty_arg.take_inner()) },
		funding_txo: local_funding_txo_arg,
		short_channel_id: local_short_channel_id_arg,
		channel_value_satoshis: channel_value_satoshis_arg,
		unspendable_punishment_reserve: local_unspendable_punishment_reserve_arg,
		user_id: user_id_arg,
		outbound_capacity_msat: outbound_capacity_msat_arg,
		inbound_capacity_msat: inbound_capacity_msat_arg,
		confirmations_required: local_confirmations_required_arg,
		force_close_spend_delay: local_force_close_spend_delay_arg,
		is_outbound: is_outbound_arg,
		is_funding_locked: is_funding_locked_arg,
		is_usable: is_usable_arg,
		is_public: is_public_arg,
	})), is_owned: true }
}
impl Clone for ChannelDetails {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelDetails>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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
	PartialFailure(crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ),
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
			PaymentSendFailure::PartialFailure (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.into_rust().drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_nonref_0 }); };
				nativePaymentSendFailure::PartialFailure (
					local_a_nonref,
				)
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
			PaymentSendFailure::PartialFailure (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.into_rust().drain(..) { local_a.push( { let mut local_a_0 = match item.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut item.contents.err)) }).into_native() })}; local_a_0 }); };
				nativePaymentSendFailure::PartialFailure (
					local_a,
				)
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
			nativePaymentSendFailure::PartialFailure (ref a, ) => {
				let mut a_nonref = (*a).clone();
				let mut local_a_nonref = Vec::new(); for mut item in a_nonref.drain(..) { local_a_nonref.push( { let mut local_a_nonref_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_nonref_0 }); };
				PaymentSendFailure::PartialFailure (
					local_a_nonref.into(),
				)
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
			nativePaymentSendFailure::PartialFailure (mut a, ) => {
				let mut local_a = Vec::new(); for mut item in a.drain(..) { local_a.push( { let mut local_a_0 = match item { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() }; local_a_0 }); };
				PaymentSendFailure::PartialFailure (
					local_a.into(),
				)
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
pub extern "C" fn PaymentSendFailure_partial_failure(a: crate::c_types::derived::CVec_CResult_NoneAPIErrorZZ) -> PaymentSendFailure {
	PaymentSendFailure::PartialFailure(a, )
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
pub extern "C" fn ChannelManager_new(mut fee_est: crate::lightning::chain::chaininterface::FeeEstimator, mut chain_monitor: crate::lightning::chain::Watch, mut tx_broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut config: crate::lightning::util::config::UserConfig, mut params: crate::lightning::ln::channelmanager::ChainParameters) -> ChannelManager {
	let mut ret = lightning::ln::channelmanager::ChannelManager::new(fee_est, chain_monitor, tx_broadcaster, logger, keys_manager, *unsafe { Box::from_raw(config.take_inner()) }, *unsafe { Box::from_raw(params.take_inner()) });
	ChannelManager { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Gets the current configuration applied to all new channels,  as
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_current_default_configuration(this_arg: &ChannelManager) -> crate::lightning::util::config::UserConfig {
	let mut ret = unsafe { &*this_arg.inner }.get_current_default_configuration();
	crate::lightning::util::config::UserConfig { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Creates a new outbound channel to the given remote node and with the given value.
///
/// user_id will be provided back as user_channel_id in FundingGenerationReady events to allow
/// tracking of which events correspond with which create_channel call. Note that the
/// user_channel_id defaults to 0 for inbound channels, so you may wish to avoid using 0 for
/// user_id here. user_id has no meaning inside of LDK, it is simply copied to events and
/// otherwise ignored.
///
/// If successful, will generate a SendOpenChannel message event, so you should probably poll
/// PeerManager::process_events afterwards.
///
/// Raises APIError::APIMisuseError when channel_value_satoshis > 2**24 or push_msat is
/// greater than channel_value_satoshis * 1k or channel_value_satoshis is < 1000.
///
/// Note that we do not check if you are currently connected to the given peer. If no
/// connection is available, the outbound `open_channel` message may fail to send, resulting in
/// the channel eventually being silently forgotten.
///
/// Note that override_config (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_channel(this_arg: &ChannelManager, mut their_network_key: crate::c_types::PublicKey, mut channel_value_satoshis: u64, mut push_msat: u64, mut user_id: u64, mut override_config: crate::lightning::util::config::UserConfig) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut local_override_config = if override_config.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(override_config.take_inner()) } }) };
	let mut ret = unsafe { &*this_arg.inner }.create_channel(their_network_key.into_rust(), channel_value_satoshis, push_msat, user_id, local_override_config);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets the list of open channels, in random order. See ChannelDetail field documentation for
/// more information.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_list_channels(this_arg: &ChannelManager) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = unsafe { &*this_arg.inner }.list_channels();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
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
pub extern "C" fn ChannelManager_list_usable_channels(this_arg: &ChannelManager) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = unsafe { &*this_arg.inner }.list_usable_channels();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}

/// Begins the process of closing a channel. After this call (plus some timeout), no new HTLCs
/// will be accepted on the given channel, and after additional timeout/the closing of all
/// pending HTLCs, the channel will be closed on chain.
///
/// May generate a SendShutdown message event on success, which should be relayed.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_close_channel(this_arg: &ChannelManager, channel_id: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.close_channel(unsafe { &*channel_id});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Force closes a channel, immediately broadcasting the latest local commitment transaction to
/// the chain and rejecting new HTLCs on the given channel. Fails if channel_id is unknown to the manager.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_force_close_channel(this_arg: &ChannelManager, channel_id: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.force_close_channel(unsafe { &*channel_id});
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Force close all channels, immediately broadcasting the latest local commitment transaction
/// for each to the chain and rejecting new HTLCs on each.
#[no_mangle]
pub extern "C" fn ChannelManager_force_close_all_channels(this_arg: &ChannelManager) {
	unsafe { &*this_arg.inner }.force_close_all_channels()
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
pub extern "C" fn ChannelManager_send_payment(this_arg: &ChannelManager, route: &crate::lightning::routing::router::Route, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut local_payment_secret = if payment_secret.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentSecret(payment_secret.data) }) };
	let mut ret = unsafe { &*this_arg.inner }.send_payment(unsafe { &*route.inner }, ::lightning::ln::PaymentHash(payment_hash.data), &local_payment_secret);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}

/// Call this upon creation of a funding transaction for the given channel.
///
/// Returns an [`APIError::APIMisuseError`] if the funding_transaction spent non-SegWit outputs
/// or if no output was found which matches the parameters in [`Event::FundingGenerationReady`].
///
/// Panics if a funding transaction has already been provided for this channel.
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
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_funding_transaction_generated(this_arg: &ChannelManager, temporary_channel_id: *const [u8; 32], mut funding_transaction: crate::c_types::Transaction) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.funding_transaction_generated(unsafe { &*temporary_channel_id}, funding_transaction.into_bitcoin());
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
pub extern "C" fn ChannelManager_broadcast_node_announcement(this_arg: &ChannelManager, mut rgb: crate::c_types::ThreeBytes, mut alias: crate::c_types::ThirtyTwoBytes, mut addresses: crate::c_types::derived::CVec_NetAddressZ) {
	let mut local_addresses = Vec::new(); for mut item in addresses.into_rust().drain(..) { local_addresses.push( { item.into_native() }); };
	unsafe { &*this_arg.inner }.broadcast_node_announcement(rgb.data, alias.data, local_addresses)
}

/// Processes HTLCs which are pending waiting on random forward delay.
///
/// Should only really ever be called in response to a PendingHTLCsForwardable event.
/// Will likely generate further events.
#[no_mangle]
pub extern "C" fn ChannelManager_process_pending_htlc_forwards(this_arg: &ChannelManager) {
	unsafe { &*this_arg.inner }.process_pending_htlc_forwards()
}

/// If a peer is disconnected we mark any channels with that peer as 'disabled'.
/// After some time, if channels are still disabled we need to broadcast a ChannelUpdate
/// to inform the network about the uselessness of these channels.
///
/// This method handles all the details, and must be called roughly once per minute.
///
/// Note that in some rare cases this may generate a `chain::Watch::update_channel` call.
#[no_mangle]
pub extern "C" fn ChannelManager_timer_tick_occurred(this_arg: &ChannelManager) {
	unsafe { &*this_arg.inner }.timer_tick_occurred()
}

/// Indicates that the preimage for payment_hash is unknown or the received amount is incorrect
/// after a PaymentReceived event, failing the HTLC back to its origin and freeing resources
/// along the path (including in our own channel on which we received it).
/// Returns false if no payment was found to fail backwards, true if the process of failing the
/// HTLC backwards has been started.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_fail_htlc_backwards(this_arg: &ChannelManager, payment_hash: *const [u8; 32]) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.fail_htlc_backwards(&::lightning::ln::PaymentHash(unsafe { *payment_hash }));
	ret
}

/// Provides a payment preimage in response to a PaymentReceived event, returning true and
/// generating message events for the net layer to claim the payment, if possible. Thus, you
/// should probably kick the net layer to go send messages if this returns true!
///
/// Note that if you did not set an `amount_msat` when calling [`create_inbound_payment`] or
/// [`create_inbound_payment_for_hash`] you must check that the amount in the `PaymentReceived`
/// event matches your expectation. If you fail to do so and call this method, you may provide
/// the sender \"proof-of-payment\" when they did not fulfill the full expected payment.
///
/// May panic if called except in response to a PaymentReceived event.
///
/// [`create_inbound_payment`]: Self::create_inbound_payment
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_claim_funds(this_arg: &ChannelManager, mut payment_preimage: crate::c_types::ThirtyTwoBytes) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.claim_funds(::lightning::ln::PaymentPreimage(payment_preimage.data));
	ret
}

/// Gets the node_id held by this ChannelManager
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_get_our_node_id(this_arg: &ChannelManager) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*this_arg.inner }.get_our_node_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Restores a single, given channel to normal operation after a
/// ChannelMonitorUpdateErr::TemporaryFailure was returned from a channel monitor update
/// operation.
///
/// All ChannelMonitor updates up to and including highest_applied_update_id must have been
/// fully committed in every copy of the given channels' ChannelMonitors.
///
/// Note that there is no effect to calling with a highest_applied_update_id other than the
/// current latest ChannelMonitorUpdate and one call to this function after multiple
/// ChannelMonitorUpdateErr::TemporaryFailures is fine. The highest_applied_update_id field
/// exists largely only to prevent races between this and concurrent update_monitor calls.
///
/// Thus, the anticipated use is, at a high level:
///  1) You register a chain::Watch with this ChannelManager,
///  2) it stores each update to disk, and begins updating any remote (eg watchtower) copies of
///     said ChannelMonitors as it can, returning ChannelMonitorUpdateErr::TemporaryFailures
///     any time it cannot do so instantly,
///  3) update(s) are applied to each remote copy of a ChannelMonitor,
///  4) once all remote copies are updated, you call this function with the update_id that
///     completed, and once it is the latest the Channel will be re-enabled.
#[no_mangle]
pub extern "C" fn ChannelManager_channel_monitor_updated(this_arg: &ChannelManager, funding_txo: &crate::lightning::chain::transaction::OutPoint, mut highest_applied_update_id: u64) {
	unsafe { &*this_arg.inner }.channel_monitor_updated(unsafe { &*funding_txo.inner }, highest_applied_update_id)
}

/// Gets a payment secret and payment hash for use in an invoice given to a third party wishing
/// to pay us.
///
/// This differs from [`create_inbound_payment_for_hash`] only in that it generates the
/// [`PaymentHash`] and [`PaymentPreimage`] for you, returning the first and storing the second.
///
/// The [`PaymentPreimage`] will ultimately be returned to you in the [`PaymentReceived`], which
/// will have the [`PaymentReceived::payment_preimage`] field filled in. That should then be
/// passed directly to [`claim_funds`].
///
/// See [`create_inbound_payment_for_hash`] for detailed documentation on behavior and requirements.
///
/// [`claim_funds`]: Self::claim_funds
/// [`PaymentReceived`]: events::Event::PaymentReceived
/// [`PaymentReceived::payment_preimage`]: events::Event::PaymentReceived::payment_preimage
/// [`create_inbound_payment_for_hash`]: Self::create_inbound_payment_for_hash
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment(this_arg: &ChannelManager, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32, mut user_payment_id: u64) -> crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*this_arg.inner }.create_inbound_payment(local_min_value_msat, invoice_expiry_delta_secs, user_payment_id);
	let (mut orig_ret_0, mut orig_ret_1) = ret; let mut local_ret = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0.0 }, crate::c_types::ThirtyTwoBytes { data: orig_ret_1.0 }).into();
	local_ret
}

/// Gets a [`PaymentSecret`] for a given [`PaymentHash`], for which the payment preimage is
/// stored external to LDK.
///
/// A [`PaymentReceived`] event will only be generated if the [`PaymentSecret`] matches a
/// payment secret fetched via this method or [`create_inbound_payment`], and which is at least
/// the `min_value_msat` provided here, if one is provided.
///
/// The [`PaymentHash`] (and corresponding [`PaymentPreimage`]) must be globally unique. This
/// method may return an Err if another payment with the same payment_hash is still pending.
///
/// `user_payment_id` will be provided back in [`PaymentReceived::user_payment_id`] events to
/// allow tracking of which events correspond with which calls to this and
/// [`create_inbound_payment`]. `user_payment_id` has no meaning inside of LDK, it is simply
/// copied to events and otherwise ignored. It may be used to correlate PaymentReceived events
/// with invoice metadata stored elsewhere.
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
/// Pending inbound payments are stored in memory and in serialized versions of this
/// [`ChannelManager`]. If potentially unbounded numbers of inbound payments may exist and
/// space is limited, you may wish to rate-limit inbound payment creation.
///
/// May panic if `invoice_expiry_delta_secs` is greater than one year.
///
/// Note that invoices generated for inbound payments should have their `min_final_cltv_expiry`
/// set to at least [`MIN_FINAL_CLTV_EXPIRY`].
///
/// [`create_inbound_payment`]: Self::create_inbound_payment
/// [`PaymentReceived`]: events::Event::PaymentReceived
/// [`PaymentReceived::user_payment_id`]: events::Event::PaymentReceived::user_payment_id
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_create_inbound_payment_for_hash(this_arg: &ChannelManager, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut min_value_msat: crate::c_types::derived::COption_u64Z, mut invoice_expiry_delta_secs: u32, mut user_payment_id: u64) -> crate::c_types::derived::CResult_PaymentSecretAPIErrorZ {
	let mut local_min_value_msat = if min_value_msat.is_some() { Some( { min_value_msat.take() }) } else { None };
	let mut ret = unsafe { &*this_arg.inner }.create_inbound_payment_for_hash(::lightning::ln::PaymentHash(payment_hash.data), local_min_value_msat, invoice_expiry_delta_secs, user_payment_id);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

impl From<nativeChannelManager> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChannelManager_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_MessageSendEventsProvider(this_arg: &ChannelManager) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
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
		let mut rust_obj = ChannelManager { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChannelManager_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new EventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_EventsProvider(this_arg: &ChannelManager) -> crate::lightning::util::events::EventsProvider {
	crate::lightning::util::events::EventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		process_pending_events: ChannelManager_EventsProvider_process_pending_events,
	}
}

extern "C" fn ChannelManager_EventsProvider_process_pending_events(this_arg: *const c_void, mut handler: crate::lightning::util::events::EventHandler) {
	<nativeChannelManager as lightning::util::events::EventsProvider<>>::process_pending_events(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, handler)
}

impl From<nativeChannelManager> for crate::lightning::chain::Listen {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChannelManager_as_Listen(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Listen which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Listen must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Listen(this_arg: &ChannelManager) -> crate::lightning::chain::Listen {
	crate::lightning::chain::Listen {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
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
		let mut rust_obj = ChannelManager { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChannelManager_as_Confirm(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Confirm which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Confirm must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Confirm(this_arg: &ChannelManager) -> crate::lightning::chain::Confirm {
	crate::lightning::chain::Confirm {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
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
/// Note that the feature `allow_wallclock_use` must be enabled to use this function.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_await_persistable_update_timeout(this_arg: &ChannelManager, mut max_wait: u64) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.await_persistable_update_timeout(std::time::Duration::from_secs(max_wait));
	ret
}

/// Blocks until ChannelManager needs to be persisted. Only one listener on
/// `await_persistable_update` or `await_persistable_update_timeout` is guaranteed to be woken
/// up.
#[no_mangle]
pub extern "C" fn ChannelManager_await_persistable_update(this_arg: &ChannelManager) {
	unsafe { &*this_arg.inner }.await_persistable_update()
}

/// Gets the latest best block which was connected either via the [`chain::Listen`] or
/// [`chain::Confirm`] interfaces.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManager_current_best_block(this_arg: &ChannelManager) -> crate::lightning::chain::BestBlock {
	let mut ret = unsafe { &*this_arg.inner }.current_best_block();
	crate::lightning::chain::BestBlock { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

impl From<nativeChannelManager> for crate::lightning::ln::msgs::ChannelMessageHandler {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ChannelManager_as_ChannelMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new ChannelMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ChannelMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_ChannelMessageHandler(this_arg: &ChannelManager) -> crate::lightning::ln::msgs::ChannelMessageHandler {
	crate::lightning::ln::msgs::ChannelMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
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
			this_arg: unsafe { (*this_arg).inner as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: ChannelManager_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

extern "C" fn ChannelManager_ChannelMessageHandler_handle_open_channel(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::OpenChannel) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_open_channel(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), *unsafe { Box::from_raw(their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_accept_channel(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::AcceptChannel) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_accept_channel(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), *unsafe { Box::from_raw(their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_created(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingCreated) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_created(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_funding_locked(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingLocked) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_locked(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_shutdown(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, their_features: &crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::Shutdown) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_shutdown(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*their_features.inner }, unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_closing_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ClosingSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_closing_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_add_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateAddHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_add_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fulfill_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFulfillHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fulfill_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fail_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fail_malformed_htlc(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailMalformedHTLC) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_malformed_htlc(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_commitment_signed(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::CommitmentSigned) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_commitment_signed(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_revoke_and_ack(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::RevokeAndACK) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_revoke_and_ack(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_update_fee(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFee) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fee(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_announcement_signatures(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::AnnouncementSignatures) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_announcement_signatures(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_channel_update(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ChannelUpdate) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_channel_reestablish(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ChannelReestablish) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_reestablish(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_peer_disconnected(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, mut no_connection_possible: bool) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), no_connection_possible)
}
extern "C" fn ChannelManager_ChannelMessageHandler_peer_connected(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, init_msg: &crate::lightning::ln::msgs::Init) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*init_msg.inner })
}
extern "C" fn ChannelManager_ChannelMessageHandler_handle_error(this_arg: *const c_void, mut counterparty_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ErrorMessage) {
	<nativeChannelManager as lightning::ln::msgs::ChannelMessageHandler<>>::handle_error(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, &counterparty_node_id.into_rust(), unsafe { &*msg.inner })
}

#[no_mangle]
/// Serialize the ChannelManager object into a byte array which can be read by ChannelManager_read
pub extern "C" fn ChannelManager_write(obj: &ChannelManager) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelManager_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelManager) })
}

use lightning::ln::channelmanager::ChannelManagerReadArgs as nativeChannelManagerReadArgsImport;
type nativeChannelManagerReadArgs = nativeChannelManagerReadArgsImport<'static, crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>;

/// Arguments for the creation of a ChannelManager that are not deserialized.
///
/// At a high-level, the process for deserializing a ChannelManager and resuming normal operation
/// is:
/// 1) Deserialize all stored ChannelMonitors.
/// 2) Deserialize the ChannelManager by filling in this struct and calling:
///    <(BlockHash, ChannelManager)>::read(reader, args)
///    This may result in closing some Channels if the ChannelMonitor is newer than the stored
///    ChannelManager state to ensure no loss of funds. Thus, transactions may be broadcasted.
/// 3) If you are not fetching full blocks, register all relevant ChannelMonitor outpoints the same
///    way you would handle a `chain::Filter` call using ChannelMonitor::get_outputs_to_watch() and
///    ChannelMonitor::get_funding_txo().
/// 4) Reconnect blocks on your ChannelMonitors.
/// 5) Disconnect/connect blocks on the ChannelManager.
/// 6) Move the ChannelMonitors into your local chain::Watch.
///
/// Note that the ordering of #4-6 is not of importance, however all three must occur before you
/// call any other methods on the newly-deserialized ChannelManager.
///
/// Note that because some channels may be closed during deserialization, it is critical that you
/// always deserialize only the latest version of a ChannelManager and ChannelMonitors available to
/// you. If you deserialize an old ChannelManager (during which force-closure transactions may be
/// broadcast), and then later deserialize a newer version of the same ChannelManager (which will
/// not force-close the same channels but consider them live), you may end up revoking a state for
/// which you've already broadcasted the transaction.
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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChannelManagerReadArgs, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_free(this_obj: ChannelManagerReadArgs) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelManagerReadArgs_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelManagerReadArgs); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelManagerReadArgs {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelManagerReadArgs {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The keys provider which will give us relevant keys. Some keys will be loaded during
/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
/// signing data.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_keys_manager(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::keysinterface::KeysInterface {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.keys_manager;
	inner_val
}
/// The keys provider which will give us relevant keys. Some keys will be loaded during
/// deserialization and KeysInterface::read_chan_signer will be used to read per-Channel
/// signing data.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_keys_manager(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::keysinterface::KeysInterface) {
	unsafe { &mut *this_ptr.inner }.keys_manager = val;
}
/// The fee_estimator for use in the ChannelManager in the future.
///
/// No calls to the FeeEstimator will be made during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_fee_estimator(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::chaininterface::FeeEstimator {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.fee_estimator;
	inner_val
}
/// The fee_estimator for use in the ChannelManager in the future.
///
/// No calls to the FeeEstimator will be made during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_fee_estimator(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::chaininterface::FeeEstimator) {
	unsafe { &mut *this_ptr.inner }.fee_estimator = val;
}
/// The chain::Watch for use in the ChannelManager in the future.
///
/// No calls to the chain::Watch will be made during deserialization. It is assumed that
/// you have deserialized ChannelMonitors separately and will add them to your
/// chain::Watch after deserializing this ChannelManager.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_chain_monitor(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::Watch {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chain_monitor;
	inner_val
}
/// The chain::Watch for use in the ChannelManager in the future.
///
/// No calls to the chain::Watch will be made during deserialization. It is assumed that
/// you have deserialized ChannelMonitors separately and will add them to your
/// chain::Watch after deserializing this ChannelManager.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_chain_monitor(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::Watch) {
	unsafe { &mut *this_ptr.inner }.chain_monitor = val;
}
/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
/// used to broadcast the latest local commitment transactions of channels which must be
/// force-closed during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_tx_broadcaster(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::chain::chaininterface::BroadcasterInterface {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.tx_broadcaster;
	inner_val
}
/// The BroadcasterInterface which will be used in the ChannelManager in the future and may be
/// used to broadcast the latest local commitment transactions of channels which must be
/// force-closed during deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_tx_broadcaster(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::chain::chaininterface::BroadcasterInterface) {
	unsafe { &mut *this_ptr.inner }.tx_broadcaster = val;
}
/// The Logger for use in the ChannelManager and which may be used to log information during
/// deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_logger(this_ptr: &ChannelManagerReadArgs) -> *const crate::lightning::util::logger::Logger {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.logger;
	inner_val
}
/// The Logger for use in the ChannelManager and which may be used to log information during
/// deserialization.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_logger(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::util::logger::Logger) {
	unsafe { &mut *this_ptr.inner }.logger = val;
}
/// Default settings used for new channels. Any existing channels will continue to use the
/// runtime settings which were stored when the ChannelManager was serialized.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_get_default_config(this_ptr: &ChannelManagerReadArgs) -> crate::lightning::util::config::UserConfig {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.default_config;
	crate::lightning::util::config::UserConfig { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// Default settings used for new channels. Any existing channels will continue to use the
/// runtime settings which were stored when the ChannelManager was serialized.
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_set_default_config(this_ptr: &mut ChannelManagerReadArgs, mut val: crate::lightning::util::config::UserConfig) {
	unsafe { &mut *this_ptr.inner }.default_config = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Simple utility function to create a ChannelManagerReadArgs which creates the monitor
/// HashMap for you. This is primarily useful for C bindings where it is not practical to
/// populate a HashMap directly from C.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelManagerReadArgs_new(mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut fee_estimator: crate::lightning::chain::chaininterface::FeeEstimator, mut chain_monitor: crate::lightning::chain::Watch, mut tx_broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut default_config: crate::lightning::util::config::UserConfig, mut channel_monitors: crate::c_types::derived::CVec_ChannelMonitorZ) -> ChannelManagerReadArgs {
	let mut local_channel_monitors = Vec::new(); for mut item in channel_monitors.into_rust().drain(..) { local_channel_monitors.push( { unsafe { &mut *item.inner } }); };
	let mut ret = lightning::ln::channelmanager::ChannelManagerReadArgs::new(keys_manager, fee_estimator, chain_monitor, tx_broadcaster, logger, *unsafe { Box::from_raw(default_config.take_inner()) }, local_channel_monitors);
	ChannelManagerReadArgs { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

#[no_mangle]
/// Read a C2Tuple_BlockHashChannelManagerZ from a byte array, created by C2Tuple_BlockHashChannelManagerZ_write
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_read(ser: crate::c_types::u8slice, arg: crate::lightning::ln::channelmanager::ChannelManagerReadArgs) -> crate::c_types::derived::CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	let arg_conv = *unsafe { Box::from_raw(arg.take_inner()) };
	let res: Result<(bitcoin::hash_types::BlockHash, lightning::ln::channelmanager::ChannelManager<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>), lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_res_0_0, mut orig_res_0_1) = o; let mut local_res_0 = (crate::c_types::ThirtyTwoBytes { data: orig_res_0_0.into_inner() }, crate::lightning::ln::channelmanager::ChannelManager { inner: Box::into_raw(Box::new(orig_res_0_1)), is_owned: true }).into(); local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
