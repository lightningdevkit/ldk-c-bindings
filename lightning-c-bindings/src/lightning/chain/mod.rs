// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod transaction;
pub mod keysinterface;
mod onchaintx {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod package {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning::chain::BestBlock as nativeBestBlockImport;
pub(crate) type nativeBestBlock = nativeBestBlockImport;

/// The best known block as identified by its hash and height.
#[must_use]
#[repr(C)]
pub struct BestBlock {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBestBlock,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BestBlock {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBestBlock>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BestBlock, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BestBlock_free(this_obj: BestBlock) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BestBlock_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBestBlock) };
}
#[allow(unused)]
impl BestBlock {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBestBlock {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBestBlock {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBestBlock {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for BestBlock {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBestBlock>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BestBlock_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBestBlock)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BestBlock
pub extern "C" fn BestBlock_clone(orig: &BestBlock) -> BestBlock {
	orig.clone()
}
/// Checks if two BestBlocks contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BestBlock_eq(a: &BestBlock, b: &BestBlock) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Constructs a `BestBlock` that represents the genesis block at height 0 of the given
/// network.
#[must_use]
#[no_mangle]
pub extern "C" fn BestBlock_from_genesis(mut network: crate::bitcoin::network::Network) -> crate::lightning::chain::BestBlock {
	let mut ret = lightning::chain::BestBlock::from_genesis(network.into_bitcoin());
	crate::lightning::chain::BestBlock { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns a `BestBlock` as identified by the given block hash and height.
#[must_use]
#[no_mangle]
pub extern "C" fn BestBlock_new(mut block_hash: crate::c_types::ThirtyTwoBytes, mut height: u32) -> crate::lightning::chain::BestBlock {
	let mut ret = lightning::chain::BestBlock::new(::bitcoin::hash_types::BlockHash::from_slice(&block_hash.data[..]).unwrap(), height);
	crate::lightning::chain::BestBlock { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the best block hash.
#[must_use]
#[no_mangle]
pub extern "C" fn BestBlock_block_hash(this_arg: &crate::lightning::chain::BestBlock) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.block_hash();
	crate::c_types::ThirtyTwoBytes { data: ret.into_inner() }
}

/// Returns the best block height.
#[must_use]
#[no_mangle]
pub extern "C" fn BestBlock_height(this_arg: &crate::lightning::chain::BestBlock) -> u32 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.height();
	ret
}

/// An error when accessing the chain via [`Access`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum AccessError {
	/// The requested chain is unknown.
	UnknownChain,
	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}
use lightning::chain::AccessError as AccessErrorImport;
pub(crate) type nativeAccessError = AccessErrorImport;

impl AccessError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAccessError {
		match self {
			AccessError::UnknownChain => nativeAccessError::UnknownChain,
			AccessError::UnknownTx => nativeAccessError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAccessError {
		match self {
			AccessError::UnknownChain => nativeAccessError::UnknownChain,
			AccessError::UnknownTx => nativeAccessError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeAccessError) -> Self {
		match native {
			nativeAccessError::UnknownChain => AccessError::UnknownChain,
			nativeAccessError::UnknownTx => AccessError::UnknownTx,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAccessError) -> Self {
		match native {
			nativeAccessError::UnknownChain => AccessError::UnknownChain,
			nativeAccessError::UnknownTx => AccessError::UnknownTx,
		}
	}
}
/// Creates a copy of the AccessError
#[no_mangle]
pub extern "C" fn AccessError_clone(orig: &AccessError) -> AccessError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new UnknownChain-variant AccessError
pub extern "C" fn AccessError_unknown_chain() -> AccessError {
	AccessError::UnknownChain}
#[no_mangle]
/// Utility method to constructs a new UnknownTx-variant AccessError
pub extern "C" fn AccessError_unknown_tx() -> AccessError {
	AccessError::UnknownTx}
/// The `Access` trait defines behavior for accessing chain data and state, such as blocks and
/// UTXOs.
#[repr(C)]
pub struct Access {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the transaction output of a funding transaction encoded by [`short_channel_id`].
	/// Returns an error if `genesis_hash` is for a different chain or if such a transaction output
	/// is unknown.
	///
	/// [`short_channel_id`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	#[must_use]
	pub get_utxo: extern "C" fn (this_arg: *const c_void, genesis_hash: *const [u8; 32], short_channel_id: u64) -> crate::c_types::derived::CResult_TxOutAccessErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Access {}
unsafe impl Sync for Access {}
#[no_mangle]
pub(crate) extern "C" fn Access_clone_fields(orig: &Access) -> Access {
	Access {
		this_arg: orig.this_arg,
		get_utxo: Clone::clone(&orig.get_utxo),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Access as rustAccess;
impl rustAccess for Access {
	fn get_utxo(&self, mut genesis_hash: &bitcoin::hash_types::BlockHash, mut short_channel_id: u64) -> Result<bitcoin::blockdata::transaction::TxOut, lightning::chain::AccessError> {
		let mut ret = (self.get_utxo)(self.this_arg, genesis_hash.as_inner(), short_channel_id);
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Access {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Access_free(this_ptr: Access) { }
impl Drop for Access {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// The `Listen` trait is used to notify when blocks have been connected or disconnected from the
/// chain.
///
/// Useful when needing to replay chain data upon startup or as new chain events occur. Clients
/// sourcing chain data using a block-oriented API should prefer this interface over [`Confirm`].
/// Such clients fetch the entire header chain whereas clients using [`Confirm`] only fetch headers
/// when needed.
///
/// By using [`Listen::filtered_block_connected`] this interface supports clients fetching the
/// entire header chain and only blocks with matching transaction data using BIP 157 filters or
/// other similar filtering.
#[repr(C)]
pub struct Listen {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Notifies the listener that a block was added at the given height, with the transaction data
	/// possibly filtered.
	pub filtered_block_connected: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, height: u32),
	/// Notifies the listener that a block was added at the given height.
	pub block_connected: extern "C" fn (this_arg: *const c_void, block: crate::c_types::u8slice, height: u32),
	/// Notifies the listener that a block was removed at the given height.
	pub block_disconnected: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], height: u32),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Listen {}
unsafe impl Sync for Listen {}
#[no_mangle]
pub(crate) extern "C" fn Listen_clone_fields(orig: &Listen) -> Listen {
	Listen {
		this_arg: orig.this_arg,
		filtered_block_connected: Clone::clone(&orig.filtered_block_connected),
		block_connected: Clone::clone(&orig.block_connected),
		block_disconnected: Clone::clone(&orig.block_disconnected),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Listen as rustListen;
impl rustListen for Listen {
	fn filtered_block_connected(&self, mut header: &bitcoin::blockdata::block::BlockHeader, mut txdata: &lightning::chain::transaction::TransactionData, mut height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		let mut local_txdata = Vec::new(); for item in txdata.iter() { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item; let mut local_txdata_0 = (orig_txdata_0_0, crate::c_types::Transaction::from_bitcoin(&orig_txdata_0_1)).into(); local_txdata_0 }); };
		(self.filtered_block_connected)(self.this_arg, &local_header, local_txdata.into(), height)
	}
	fn block_connected(&self, mut block: &bitcoin::blockdata::block::Block, mut height: u32) {
		let mut local_block = ::bitcoin::consensus::encode::serialize(block);
		(self.block_connected)(self.this_arg, crate::c_types::u8slice::from_slice(&local_block), height)
	}
	fn block_disconnected(&self, mut header: &bitcoin::blockdata::block::BlockHeader, mut height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		(self.block_disconnected)(self.this_arg, &local_header, height)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Listen {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Listen_free(this_ptr: Listen) { }
impl Drop for Listen {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// The `Confirm` trait is used to notify LDK when relevant transactions have been confirmed on
/// chain or unconfirmed during a chain reorganization.
///
/// Clients sourcing chain data using a transaction-oriented API should prefer this interface over
/// [`Listen`]. For instance, an Electrum-based transaction sync implementation may implement
/// [`Filter`] to subscribe to relevant transactions and unspent outputs it should monitor for
/// on-chain activity. Then, it needs to notify LDK via this interface upon observing any changes
/// with reference to the confirmation status of the monitored objects.
///
/// # Use
/// The intended use is as follows:
/// - Call [`transactions_confirmed`] to notify LDK whenever any of the registered transactions or
///   outputs are, respectively, confirmed or spent on chain.
/// - Call [`transaction_unconfirmed`] to notify LDK whenever any transaction returned by
///   [`get_relevant_txids`] is no longer confirmed in the block with the given block hash.
/// - Call [`best_block_updated`] to notify LDK whenever a new chain tip becomes available.
///
/// # Order
///
/// Clients must call these methods in chain order. Specifically:
/// - Transactions which are confirmed in a particular block must be given before transactions
///   confirmed in a later block.
/// - Dependent transactions within the same block must be given in topological order, possibly in
///   separate calls.
/// - All unconfirmed transactions must be given after the original confirmations and before *any*
///   reconfirmations, i.e., [`transactions_confirmed`] and [`transaction_unconfirmed`] calls should
///   never be interleaved, but always conduced *en bloc*.
/// - Any reconfirmed transactions need to be explicitly unconfirmed before they are reconfirmed
///   in regard to the new block.
///
/// See individual method documentation for further details.
///
/// [`transactions_confirmed`]: Self::transactions_confirmed
/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
/// [`best_block_updated`]: Self::best_block_updated
/// [`get_relevant_txids`]: Self::get_relevant_txids
#[repr(C)]
pub struct Confirm {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Notifies LDK of transactions confirmed in a block with a given header and height.
	///
	/// Must be called for any transactions registered by [`Filter::register_tx`] or any
	/// transactions spending an output registered by [`Filter::register_output`]. Such transactions
	/// appearing in the same block do not need to be included in the same call; instead, multiple
	/// calls with additional transactions may be made so long as they are made in [chain order].
	///
	/// May be called before or after [`best_block_updated`] for the corresponding block. However,
	/// in the event of a chain reorganization, it must not be called with a `header` that is no
	/// longer in the chain as of the last call to [`best_block_updated`].
	///
	/// [chain order]: Confirm#order
	/// [`best_block_updated`]: Self::best_block_updated
	pub transactions_confirmed: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, height: u32),
	/// Notifies LDK of a transaction that is no longer confirmed as result of a chain reorganization.
	///
	/// Must be called for any transaction returned by [`get_relevant_txids`] if it has been
	/// reorganized out of the best chain or if it is no longer confirmed in the block with the
	/// given block hash. Once called, the given transaction will not be returned
	/// by [`get_relevant_txids`], unless it has been reconfirmed via [`transactions_confirmed`].
	///
	/// [`get_relevant_txids`]: Self::get_relevant_txids
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	pub transaction_unconfirmed: extern "C" fn (this_arg: *const c_void, txid: *const [u8; 32]),
	/// Notifies LDK of an update to the best header connected at the given height.
	///
	/// Must be called whenever a new chain tip becomes available. May be skipped for intermediary
	/// blocks.
	pub best_block_updated: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], height: u32),
	/// Returns transactions that must be monitored for reorganization out of the chain along
	/// with the hash of the block as part of which it had been previously confirmed.
	///
	/// Will include any transactions passed to [`transactions_confirmed`] that have insufficient
	/// confirmations to be safe from a chain reorganization. Will not include any transactions
	/// passed to [`transaction_unconfirmed`], unless later reconfirmed.
	///
	/// Must be called to determine the subset of transactions that must be monitored for
	/// reorganization. Will be idempotent between calls but may change as a result of calls to the
	/// other interface methods. Thus, this is useful to determine which transactions must be
	/// given to [`transaction_unconfirmed`].
	///
	/// If any of the returned transactions are confirmed in a block other than the one with the
	/// given hash, they need to be unconfirmed and reconfirmed via [`transaction_unconfirmed`] and
	/// [`transactions_confirmed`], respectively.
	///
	/// [`transactions_confirmed`]: Self::transactions_confirmed
	/// [`transaction_unconfirmed`]: Self::transaction_unconfirmed
	#[must_use]
	pub get_relevant_txids: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_TxidBlockHashZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Confirm {}
unsafe impl Sync for Confirm {}
#[no_mangle]
pub(crate) extern "C" fn Confirm_clone_fields(orig: &Confirm) -> Confirm {
	Confirm {
		this_arg: orig.this_arg,
		transactions_confirmed: Clone::clone(&orig.transactions_confirmed),
		transaction_unconfirmed: Clone::clone(&orig.transaction_unconfirmed),
		best_block_updated: Clone::clone(&orig.best_block_updated),
		get_relevant_txids: Clone::clone(&orig.get_relevant_txids),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Confirm as rustConfirm;
impl rustConfirm for Confirm {
	fn transactions_confirmed(&self, mut header: &bitcoin::blockdata::block::BlockHeader, mut txdata: &lightning::chain::transaction::TransactionData, mut height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		let mut local_txdata = Vec::new(); for item in txdata.iter() { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item; let mut local_txdata_0 = (orig_txdata_0_0, crate::c_types::Transaction::from_bitcoin(&orig_txdata_0_1)).into(); local_txdata_0 }); };
		(self.transactions_confirmed)(self.this_arg, &local_header, local_txdata.into(), height)
	}
	fn transaction_unconfirmed(&self, mut txid: &bitcoin::hash_types::Txid) {
		(self.transaction_unconfirmed)(self.this_arg, txid.as_inner())
	}
	fn best_block_updated(&self, mut header: &bitcoin::blockdata::block::BlockHeader, mut height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		(self.best_block_updated)(self.this_arg, &local_header, height)
	}
	fn get_relevant_txids(&self) -> Vec<(bitcoin::hash_types::Txid, Option<bitcoin::hash_types::BlockHash>)> {
		let mut ret = (self.get_relevant_txids)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_orig_ret_0_1 = if orig_ret_0_1.data == [0; 32] { None } else { Some( { ::bitcoin::hash_types::BlockHash::from_slice(&orig_ret_0_1.data[..]).unwrap() }) }; let mut local_ret_0 = (::bitcoin::hash_types::Txid::from_slice(&orig_ret_0_0.data[..]).unwrap(), local_orig_ret_0_1); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Confirm {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Confirm_free(this_ptr: Confirm) { }
impl Drop for Confirm {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An enum representing the status of a channel monitor update persistence.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ChannelMonitorUpdateStatus {
	/// The update has been durably persisted and all copies of the relevant [`ChannelMonitor`]
	/// have been updated.
	///
	/// This includes performing any `fsync()` calls required to ensure the update is guaranteed to
	/// be available on restart even if the application crashes.
	Completed,
	/// Used to indicate a temporary failure (eg connection to a watchtower or remote backup of
	/// our state failed, but is expected to succeed at some point in the future).
	///
	/// Such a failure will \"freeze\" a channel, preventing us from revoking old states or
	/// submitting new commitment transactions to the counterparty. Once the update(s) which failed
	/// have been successfully applied, a [`MonitorEvent::Completed`] can be used to restore the
	/// channel to an operational state.
	///
	/// Note that a given [`ChannelManager`] will *never* re-generate a [`ChannelMonitorUpdate`].
	/// If you return this error you must ensure that it is written to disk safely before writing
	/// the latest [`ChannelManager`] state, or you should return [`PermanentFailure`] instead.
	///
	/// Even when a channel has been \"frozen\", updates to the [`ChannelMonitor`] can continue to
	/// occur (e.g. if an inbound HTLC which we forwarded was claimed upstream, resulting in us
	/// attempting to claim it on this channel) and those updates must still be persisted.
	///
	/// No updates to the channel will be made which could invalidate other [`ChannelMonitor`]s
	/// until a [`MonitorEvent::Completed`] is provided, even if you return no error on a later
	/// monitor update for the same channel.
	///
	/// For deployments where a copy of ChannelMonitors and other local state are backed up in a
	/// remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return [`InProgress`] until the remote copies could be updated.
	///
	/// [`PermanentFailure`]: ChannelMonitorUpdateStatus::PermanentFailure
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	InProgress,
	/// Used to indicate no further channel monitor updates will be allowed (likely a disk failure
	/// or a remote copy of this [`ChannelMonitor`] is no longer reachable and thus not updatable).
	///
	/// When this is returned, [`ChannelManager`] will force-close the channel but *not* broadcast
	/// our current commitment transaction. This avoids a dangerous case where a local disk failure
	/// (e.g. the Linux-default remounting of the disk as read-only) causes [`PermanentFailure`]s
	/// for all monitor updates. If we were to broadcast our latest commitment transaction and then
	/// restart, we could end up reading a previous [`ChannelMonitor`] and [`ChannelManager`],
	/// revoking our now-broadcasted state before seeing it confirm and losing all our funds.
	///
	/// Note that this is somewhat of a tradeoff - if the disk is really gone and we may have lost
	/// the data permanently, we really should broadcast immediately. If the data can be recovered
	/// with manual intervention, we'd rather close the channel, rejecting future updates to it,
	/// and broadcast the latest state only if we have HTLCs to claim which are timing out (which
	/// we do as long as blocks are connected).
	///
	/// In order to broadcast the latest local commitment transaction, you'll need to call
	/// [`ChannelMonitor::get_latest_holder_commitment_txn`] and broadcast the resulting
	/// transactions once you've safely ensured no further channel updates can be generated by your
	/// [`ChannelManager`].
	///
	/// Note that at least one final [`ChannelMonitorUpdate`] may still be provided, which must
	/// still be processed by a running [`ChannelMonitor`]. This final update will mark the
	/// [`ChannelMonitor`] as finalized, ensuring no further updates (e.g. revocation of the latest
	/// commitment transaction) are allowed.
	///
	/// Note that even if you return a [`PermanentFailure`] due to unavailability of secondary
	/// [`ChannelMonitor`] copies, you should still make an attempt to store the update where
	/// possible to ensure you can claim HTLC outputs on the latest commitment transaction
	/// broadcasted later.
	///
	/// In case of distributed watchtowers deployment, the new version must be written to disk, as
	/// state may have been stored but rejected due to a block forcing a commitment broadcast. This
	/// storage is used to claim outputs of rejected state confirmed onchain by another watchtower,
	/// lagging behind on block processing.
	///
	/// [`PermanentFailure`]: ChannelMonitorUpdateStatus::PermanentFailure
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	PermanentFailure,
}
use lightning::chain::ChannelMonitorUpdateStatus as ChannelMonitorUpdateStatusImport;
pub(crate) type nativeChannelMonitorUpdateStatus = ChannelMonitorUpdateStatusImport;

impl ChannelMonitorUpdateStatus {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChannelMonitorUpdateStatus {
		match self {
			ChannelMonitorUpdateStatus::Completed => nativeChannelMonitorUpdateStatus::Completed,
			ChannelMonitorUpdateStatus::InProgress => nativeChannelMonitorUpdateStatus::InProgress,
			ChannelMonitorUpdateStatus::PermanentFailure => nativeChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChannelMonitorUpdateStatus {
		match self {
			ChannelMonitorUpdateStatus::Completed => nativeChannelMonitorUpdateStatus::Completed,
			ChannelMonitorUpdateStatus::InProgress => nativeChannelMonitorUpdateStatus::InProgress,
			ChannelMonitorUpdateStatus::PermanentFailure => nativeChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeChannelMonitorUpdateStatus) -> Self {
		match native {
			nativeChannelMonitorUpdateStatus::Completed => ChannelMonitorUpdateStatus::Completed,
			nativeChannelMonitorUpdateStatus::InProgress => ChannelMonitorUpdateStatus::InProgress,
			nativeChannelMonitorUpdateStatus::PermanentFailure => ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChannelMonitorUpdateStatus) -> Self {
		match native {
			nativeChannelMonitorUpdateStatus::Completed => ChannelMonitorUpdateStatus::Completed,
			nativeChannelMonitorUpdateStatus::InProgress => ChannelMonitorUpdateStatus::InProgress,
			nativeChannelMonitorUpdateStatus::PermanentFailure => ChannelMonitorUpdateStatus::PermanentFailure,
		}
	}
}
/// Creates a copy of the ChannelMonitorUpdateStatus
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdateStatus_clone(orig: &ChannelMonitorUpdateStatus) -> ChannelMonitorUpdateStatus {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Completed-variant ChannelMonitorUpdateStatus
pub extern "C" fn ChannelMonitorUpdateStatus_completed() -> ChannelMonitorUpdateStatus {
	ChannelMonitorUpdateStatus::Completed}
#[no_mangle]
/// Utility method to constructs a new InProgress-variant ChannelMonitorUpdateStatus
pub extern "C" fn ChannelMonitorUpdateStatus_in_progress() -> ChannelMonitorUpdateStatus {
	ChannelMonitorUpdateStatus::InProgress}
#[no_mangle]
/// Utility method to constructs a new PermanentFailure-variant ChannelMonitorUpdateStatus
pub extern "C" fn ChannelMonitorUpdateStatus_permanent_failure() -> ChannelMonitorUpdateStatus {
	ChannelMonitorUpdateStatus::PermanentFailure}
/// Checks if two ChannelMonitorUpdateStatuss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdateStatus_eq(a: &ChannelMonitorUpdateStatus, b: &ChannelMonitorUpdateStatus) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// The `Watch` trait defines behavior for watching on-chain activity pertaining to channels as
/// blocks are connected and disconnected.
///
/// Each channel is associated with a [`ChannelMonitor`]. Implementations of this trait are
/// responsible for maintaining a set of monitors such that they can be updated accordingly as
/// channel state changes and HTLCs are resolved. See method documentation for specific
/// requirements.
///
/// Implementations **must** ensure that updates are successfully applied and persisted upon method
/// completion. If an update fails with a [`PermanentFailure`], then it must immediately shut down
/// without taking any further action such as persisting the current state.
///
/// If an implementation maintains multiple instances of a channel's monitor (e.g., by storing
/// backup copies), then it must ensure that updates are applied across all instances. Otherwise, it
/// could result in a revoked transaction being broadcast, allowing the counterparty to claim all
/// funds in the channel. See [`ChannelMonitorUpdateStatus`] for more details about how to handle
/// multiple instances.
///
/// [`PermanentFailure`]: ChannelMonitorUpdateStatus::PermanentFailure
#[repr(C)]
pub struct Watch {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Watches a channel identified by `funding_txo` using `monitor`.
	///
	/// Implementations are responsible for watching the chain for the funding transaction along
	/// with any spends of outputs returned by [`get_outputs_to_watch`]. In practice, this means
	/// calling [`block_connected`] and [`block_disconnected`] on the monitor.
	///
	/// Note: this interface MUST error with [`ChannelMonitorUpdateStatus::PermanentFailure`] if
	/// the given `funding_txo` has previously been registered via `watch_channel`.
	///
	/// [`get_outputs_to_watch`]: channelmonitor::ChannelMonitor::get_outputs_to_watch
	/// [`block_connected`]: channelmonitor::ChannelMonitor::block_connected
	/// [`block_disconnected`]: channelmonitor::ChannelMonitor::block_disconnected
	#[must_use]
	pub watch_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::lightning::chain::transaction::OutPoint, monitor: crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::lightning::chain::ChannelMonitorUpdateStatus,
	/// Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	///
	/// Implementations must call [`update_monitor`] with the given update. See
	/// [`ChannelMonitorUpdateStatus`] for invariants around returning an error.
	///
	/// [`update_monitor`]: channelmonitor::ChannelMonitor::update_monitor
	#[must_use]
	pub update_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::lightning::chain::transaction::OutPoint, update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> crate::lightning::chain::ChannelMonitorUpdateStatus,
	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	///
	/// Note that after any block- or transaction-connection calls to a [`ChannelMonitor`], no
	/// further events may be returned here until the [`ChannelMonitor`] has been fully persisted
	/// to disk.
	///
	/// For details on asynchronous [`ChannelMonitor`] updating and returning
	/// [`MonitorEvent::Completed`] here, see [`ChannelMonitorUpdateStatus::InProgress`].
	#[must_use]
	pub release_pending_monitor_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Watch {}
unsafe impl Sync for Watch {}
#[no_mangle]
pub(crate) extern "C" fn Watch_clone_fields(orig: &Watch) -> Watch {
	Watch {
		this_arg: orig.this_arg,
		watch_channel: Clone::clone(&orig.watch_channel),
		update_channel: Clone::clone(&orig.update_channel),
		release_pending_monitor_events: Clone::clone(&orig.release_pending_monitor_events),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Watch as rustWatch;
impl rustWatch<crate::lightning::chain::keysinterface::Sign> for Watch {
	fn watch_channel(&self, mut funding_txo: lightning::chain::transaction::OutPoint, mut monitor: lightning::chain::channelmonitor::ChannelMonitor<crate::lightning::chain::keysinterface::Sign>) -> lightning::chain::ChannelMonitorUpdateStatus {
		let mut ret = (self.watch_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(funding_txo), is_owned: true }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(monitor), is_owned: true });
		ret.into_native()
	}
	fn update_channel(&self, mut funding_txo: lightning::chain::transaction::OutPoint, mut update: lightning::chain::channelmonitor::ChannelMonitorUpdate) -> lightning::chain::ChannelMonitorUpdateStatus {
		let mut ret = (self.update_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(funding_txo), is_owned: true }, crate::lightning::chain::channelmonitor::ChannelMonitorUpdate { inner: ObjOps::heap_alloc(update), is_owned: true });
		ret.into_native()
	}
	fn release_pending_monitor_events(&self) -> Vec<(lightning::chain::transaction::OutPoint, Vec<lightning::chain::channelmonitor::MonitorEvent>, Option<bitcoin::secp256k1::PublicKey>)> {
		let mut ret = (self.release_pending_monitor_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item.to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_native() }); }; let mut local_orig_ret_0_2 = if orig_ret_0_2.is_null() { None } else { Some( { orig_ret_0_2.into_rust() }) }; let mut local_ret_0 = (*unsafe { Box::from_raw(orig_ret_0_0.take_inner()) }, local_orig_ret_0_1, local_orig_ret_0_2); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Watch {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Watch_free(this_ptr: Watch) { }
impl Drop for Watch {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// The `Filter` trait defines behavior for indicating chain activity of interest pertaining to
/// channels.
///
/// This is useful in order to have a [`Watch`] implementation convey to a chain source which
/// transactions to be notified of. Notification may take the form of pre-filtering blocks or, in
/// the case of [BIP 157]/[BIP 158], only fetching a block if the compact filter matches. If
/// receiving full blocks from a chain source, any further filtering is unnecessary.
///
/// After an output has been registered, subsequent block retrievals from the chain source must not
/// exclude any transactions matching the new criteria nor any in-block descendants of such
/// transactions.
///
/// Note that use as part of a [`Watch`] implementation involves reentrancy. Therefore, the `Filter`
/// should not block on I/O. Implementations should instead queue the newly monitored data to be
/// processed later. Then, in order to block until the data has been processed, any [`Watch`]
/// invocation that has called the `Filter` must return [`InProgress`].
///
/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
/// [BIP 157]: https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki
/// [BIP 158]: https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki
#[repr(C)]
pub struct Filter {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Registers interest in a transaction with `txid` and having an output with `script_pubkey` as
	/// a spending condition.
	pub register_tx: extern "C" fn (this_arg: *const c_void, txid: *const [u8; 32], script_pubkey: crate::c_types::u8slice),
	/// Registers interest in spends of a transaction output.
	///
	/// Note that this method might be called during processing of a new block. You therefore need
	/// to ensure that also dependent output spents within an already connected block are correctly
	/// handled, e.g., by re-scanning the block in question whenever new outputs have been
	/// registered mid-processing.
	pub register_output: extern "C" fn (this_arg: *const c_void, output: crate::lightning::chain::WatchedOutput),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Filter {}
unsafe impl Sync for Filter {}
#[no_mangle]
pub(crate) extern "C" fn Filter_clone_fields(orig: &Filter) -> Filter {
	Filter {
		this_arg: orig.this_arg,
		register_tx: Clone::clone(&orig.register_tx),
		register_output: Clone::clone(&orig.register_output),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Filter as rustFilter;
impl rustFilter for Filter {
	fn register_tx(&self, mut txid: &bitcoin::hash_types::Txid, mut script_pubkey: &bitcoin::blockdata::script::Script) {
		(self.register_tx)(self.this_arg, txid.as_inner(), crate::c_types::u8slice::from_slice(&script_pubkey[..]))
	}
	fn register_output(&self, mut output: lightning::chain::WatchedOutput) {
		(self.register_output)(self.this_arg, crate::lightning::chain::WatchedOutput { inner: ObjOps::heap_alloc(output), is_owned: true })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Filter {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Filter_free(this_ptr: Filter) { }
impl Drop for Filter {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::chain::WatchedOutput as nativeWatchedOutputImport;
pub(crate) type nativeWatchedOutput = nativeWatchedOutputImport;

/// A transaction output watched by a [`ChannelMonitor`] for spends on-chain.
///
/// Used to convey to a [`Filter`] such an output with a given spending condition. Any transaction
/// spending the output must be given to [`ChannelMonitor::block_connected`] either directly or via
/// [`Confirm::transactions_confirmed`].
///
/// If `block_hash` is `Some`, this indicates the output was created in the corresponding block and
/// may have been spent there. See [`Filter::register_output`] for details.
///
/// [`ChannelMonitor`]: channelmonitor::ChannelMonitor
/// [`ChannelMonitor::block_connected`]: channelmonitor::ChannelMonitor::block_connected
#[must_use]
#[repr(C)]
pub struct WatchedOutput {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeWatchedOutput,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for WatchedOutput {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeWatchedOutput>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the WatchedOutput, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn WatchedOutput_free(this_obj: WatchedOutput) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn WatchedOutput_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeWatchedOutput) };
}
#[allow(unused)]
impl WatchedOutput {
	pub(crate) fn get_native_ref(&self) -> &'static nativeWatchedOutput {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeWatchedOutput {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeWatchedOutput {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// First block where the transaction output may have been spent.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn WatchedOutput_get_block_hash(this_ptr: &WatchedOutput) -> crate::c_types::ThirtyTwoBytes {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().block_hash;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (inner_val.unwrap()).into_inner() } } };
	local_inner_val
}
/// First block where the transaction output may have been spent.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn WatchedOutput_set_block_hash(this_ptr: &mut WatchedOutput, mut val: crate::c_types::ThirtyTwoBytes) {
	let mut local_val = if val.data == [0; 32] { None } else { Some( { ::bitcoin::hash_types::BlockHash::from_slice(&val.data[..]).unwrap() }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.block_hash = local_val;
}
/// Outpoint identifying the transaction output.
#[no_mangle]
pub extern "C" fn WatchedOutput_get_outpoint(this_ptr: &WatchedOutput) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::lightning::chain::transaction::OutPoint { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::chain::transaction::OutPoint<>) as *mut _) }, is_owned: false }
}
/// Outpoint identifying the transaction output.
#[no_mangle]
pub extern "C" fn WatchedOutput_set_outpoint(this_ptr: &mut WatchedOutput, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Spending condition of the transaction output.
#[no_mangle]
pub extern "C" fn WatchedOutput_get_script_pubkey(this_ptr: &WatchedOutput) -> crate::c_types::u8slice {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().script_pubkey;
	crate::c_types::u8slice::from_slice(&inner_val[..])
}
/// Spending condition of the transaction output.
#[no_mangle]
pub extern "C" fn WatchedOutput_set_script_pubkey(this_ptr: &mut WatchedOutput, mut val: crate::c_types::derived::CVec_u8Z) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.script_pubkey = ::bitcoin::blockdata::script::Script::from(val.into_rust());
}
/// Constructs a new WatchedOutput given each field
#[must_use]
#[no_mangle]
pub extern "C" fn WatchedOutput_new(mut block_hash_arg: crate::c_types::ThirtyTwoBytes, mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut script_pubkey_arg: crate::c_types::derived::CVec_u8Z) -> WatchedOutput {
	let mut local_block_hash_arg = if block_hash_arg.data == [0; 32] { None } else { Some( { ::bitcoin::hash_types::BlockHash::from_slice(&block_hash_arg.data[..]).unwrap() }) };
	WatchedOutput { inner: ObjOps::heap_alloc(nativeWatchedOutput {
		block_hash: local_block_hash_arg,
		outpoint: *unsafe { Box::from_raw(outpoint_arg.take_inner()) },
		script_pubkey: ::bitcoin::blockdata::script::Script::from(script_pubkey_arg.into_rust()),
	}), is_owned: true }
}
impl Clone for WatchedOutput {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeWatchedOutput>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn WatchedOutput_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeWatchedOutput)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the WatchedOutput
pub extern "C" fn WatchedOutput_clone(orig: &WatchedOutput) -> WatchedOutput {
	orig.clone()
}
/// Checks if two WatchedOutputs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn WatchedOutput_eq(a: &WatchedOutput, b: &WatchedOutput) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two WatchedOutputs contain equal inner contents.
#[no_mangle]
pub extern "C" fn WatchedOutput_hash(o: &WatchedOutput) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
