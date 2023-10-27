// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use alloc::str::FromStr;
use alloc::string::String;
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
mod onchaintx {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod package {

use alloc::str::FromStr;
use alloc::string::String;
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBestBlock)).clone() })) as *mut c_void
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
pub extern "C" fn BestBlock_from_network(mut network: crate::bitcoin::network::Network) -> crate::lightning::chain::BestBlock {
	let mut ret = lightning::chain::BestBlock::from_network(network.into_bitcoin());
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
#[allow(unused)]
pub(crate) fn Listen_clone_fields(orig: &Listen) -> Listen {
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
impl core::ops::DerefMut for Listen {
	fn deref_mut(&mut self) -> &mut Self {
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
	/// Note that the returned `Option<BlockHash>` might be `None` for channels created with LDK
	/// 0.0.112 and prior, in which case you need to manually track previous confirmations.
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
	pub get_relevant_txids: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_ThirtyTwoBytesCOption_ThirtyTwoBytesZZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Confirm {}
unsafe impl Sync for Confirm {}
#[allow(unused)]
pub(crate) fn Confirm_clone_fields(orig: &Confirm) -> Confirm {
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
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item.to_rust(); let mut local_orig_ret_0_1 = { /*orig_ret_0_1*/ let orig_ret_0_1_opt = orig_ret_0_1; if orig_ret_0_1_opt.is_none() { None } else { Some({ { ::bitcoin::hash_types::BlockHash::from_slice(&{ orig_ret_0_1_opt.take() }.data[..]).unwrap() }})} }; let mut local_ret_0 = (::bitcoin::hash_types::Txid::from_slice(&orig_ret_0_0.data[..]).unwrap(), local_orig_ret_0_1); local_ret_0 }); };
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
impl core::ops::DerefMut for Confirm {
	fn deref_mut(&mut self) -> &mut Self {
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
///
/// These are generally used as the return value for an implementation of [`Persist`] which is used
/// as the storage layer for a [`ChainMonitor`]. See the docs on [`Persist`] for a high-level
/// explanation of how to handle different cases.
///
/// While `UnrecoverableError` is provided as a failure variant, it is not truly \"handled\" on the
/// calling side, and generally results in an immediate panic. For those who prefer to avoid
/// panics, `InProgress` can be used and you can retry the update operation in the background or
/// shut down cleanly.
///
/// Note that channels should generally *not* be force-closed after a persistence failure.
/// Force-closing with the latest [`ChannelMonitorUpdate`] applied may result in a transaction
/// being broadcast which can only be spent by the latest [`ChannelMonitor`]! Thus, if the
/// latest [`ChannelMonitor`] is not durably persisted anywhere and exists only in memory, naively
/// calling [`ChannelManager::force_close_broadcasting_latest_txn`] *may result in loss of funds*!
///
/// [`Persist`]: chainmonitor::Persist
/// [`ChainMonitor`]: chainmonitor::ChainMonitor
/// [`ChannelManager::force_close_broadcasting_latest_txn`]: crate::ln::channelmanager::ChannelManager::force_close_broadcasting_latest_txn
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
	/// Indicates that the update will happen asynchronously in the background or that a transient
	/// failure occurred which is being retried in the background and will eventually complete.
	///
	/// This will \"freeze\" a channel, preventing us from revoking old states or submitting a new
	/// commitment transaction to the counterparty. Once the update(s) which are `InProgress` have
	/// been completed, a [`MonitorEvent::Completed`] can be used to restore the channel to an
	/// operational state.
	///
	/// Even when a channel has been \"frozen\", updates to the [`ChannelMonitor`] can continue to
	/// occur (e.g. if an inbound HTLC which we forwarded was claimed upstream, resulting in us
	/// attempting to claim it on this channel) and those updates must still be persisted.
	///
	/// No updates to the channel will be made which could invalidate other [`ChannelMonitor`]s
	/// until a [`MonitorEvent::Completed`] is provided, even if you return no error on a later
	/// monitor update for the same channel.
	///
	/// For deployments where a copy of [`ChannelMonitor`]s and other local state are backed up in
	/// a remote location (with local copies persisted immediately), it is anticipated that all
	/// updates will return [`InProgress`] until the remote copies could be updated.
	///
	/// Note that while fully asynchronous persistence of [`ChannelMonitor`] data is generally
	/// reliable, this feature is considered beta, and a handful of edge-cases remain. Until the
	/// remaining cases are fixed, in rare cases, *using this feature may lead to funds loss*.
	///
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	InProgress,
	/// Indicates that an update has failed and will not complete at any point in the future.
	///
	/// Currently returning this variant will cause LDK to immediately panic to encourage immediate
	/// shutdown. In the future this may be updated to disconnect peers and refuse to continue
	/// normal operation without a panic.
	///
	/// Applications which wish to perform an orderly shutdown after failure should consider
	/// returning [`InProgress`] instead and simply shut down without ever marking the update
	/// complete.
	///
	/// [`InProgress`]: ChannelMonitorUpdateStatus::InProgress
	UnrecoverableError,
}
use lightning::chain::ChannelMonitorUpdateStatus as ChannelMonitorUpdateStatusImport;
pub(crate) type nativeChannelMonitorUpdateStatus = ChannelMonitorUpdateStatusImport;

impl ChannelMonitorUpdateStatus {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeChannelMonitorUpdateStatus {
		match self {
			ChannelMonitorUpdateStatus::Completed => nativeChannelMonitorUpdateStatus::Completed,
			ChannelMonitorUpdateStatus::InProgress => nativeChannelMonitorUpdateStatus::InProgress,
			ChannelMonitorUpdateStatus::UnrecoverableError => nativeChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeChannelMonitorUpdateStatus {
		match self {
			ChannelMonitorUpdateStatus::Completed => nativeChannelMonitorUpdateStatus::Completed,
			ChannelMonitorUpdateStatus::InProgress => nativeChannelMonitorUpdateStatus::InProgress,
			ChannelMonitorUpdateStatus::UnrecoverableError => nativeChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeChannelMonitorUpdateStatus) -> Self {
		match native {
			nativeChannelMonitorUpdateStatus::Completed => ChannelMonitorUpdateStatus::Completed,
			nativeChannelMonitorUpdateStatus::InProgress => ChannelMonitorUpdateStatus::InProgress,
			nativeChannelMonitorUpdateStatus::UnrecoverableError => ChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeChannelMonitorUpdateStatus) -> Self {
		match native {
			nativeChannelMonitorUpdateStatus::Completed => ChannelMonitorUpdateStatus::Completed,
			nativeChannelMonitorUpdateStatus::InProgress => ChannelMonitorUpdateStatus::InProgress,
			nativeChannelMonitorUpdateStatus::UnrecoverableError => ChannelMonitorUpdateStatus::UnrecoverableError,
		}
	}
}
/// Creates a copy of the ChannelMonitorUpdateStatus
#[no_mangle]
pub extern "C" fn ChannelMonitorUpdateStatus_clone(orig: &ChannelMonitorUpdateStatus) -> ChannelMonitorUpdateStatus {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelMonitorUpdateStatus_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const ChannelMonitorUpdateStatus)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelMonitorUpdateStatus_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut ChannelMonitorUpdateStatus) };
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
/// Utility method to constructs a new UnrecoverableError-variant ChannelMonitorUpdateStatus
pub extern "C" fn ChannelMonitorUpdateStatus_unrecoverable_error() -> ChannelMonitorUpdateStatus {
	ChannelMonitorUpdateStatus::UnrecoverableError}
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
/// responsible for maintaining a set of monitors such that they can be updated as channel state
/// changes. On each update, *all copies* of a [`ChannelMonitor`] must be updated and the update
/// persisted to disk to ensure that the latest [`ChannelMonitor`] state can be reloaded if the
/// application crashes.
///
/// See method documentation and [`ChannelMonitorUpdateStatus`] for specific requirements.
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
	/// A return of `Err(())` indicates that the channel should immediately be force-closed without
	/// broadcasting the funding transaction.
	///
	/// If the given `funding_txo` has previously been registered via `watch_channel`, `Err(())`
	/// must be returned.
	///
	/// [`get_outputs_to_watch`]: channelmonitor::ChannelMonitor::get_outputs_to_watch
	/// [`block_connected`]: channelmonitor::ChannelMonitor::block_connected
	/// [`block_disconnected`]: channelmonitor::ChannelMonitor::block_disconnected
	pub watch_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::lightning::chain::transaction::OutPoint, monitor: crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_ChannelMonitorUpdateStatusNoneZ,
	/// Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	///
	/// Implementations must call [`ChannelMonitor::update_monitor`] with the given update. This
	/// may fail (returning an `Err(())`), in which case this should return
	/// [`ChannelMonitorUpdateStatus::InProgress`] (and the update should never complete). This
	/// generally implies the channel has been closed (either by the funding outpoint being spent
	/// on-chain or the [`ChannelMonitor`] having decided to do so and broadcasted a transaction),
	/// and the [`ChannelManager`] state will be updated once it sees the funding spend on-chain.
	///
	/// In general, persistence failures should be retried after returning
	/// [`ChannelMonitorUpdateStatus::InProgress`] and eventually complete. If a failure truly
	/// cannot be retried, the node should shut down immediately after returning
	/// [`ChannelMonitorUpdateStatus::UnrecoverableError`], see its documentation for more info.
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	pub update_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::lightning::chain::transaction::OutPoint, update: &crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> crate::lightning::chain::ChannelMonitorUpdateStatus,
	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	///
	/// Note that after any block- or transaction-connection calls to a [`ChannelMonitor`], no
	/// further events may be returned here until the [`ChannelMonitor`] has been fully persisted
	/// to disk.
	///
	/// For details on asynchronous [`ChannelMonitor`] updating and returning
	/// [`MonitorEvent::Completed`] here, see [`ChannelMonitorUpdateStatus::InProgress`].
	pub release_pending_monitor_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Watch {}
unsafe impl Sync for Watch {}
#[allow(unused)]
pub(crate) fn Watch_clone_fields(orig: &Watch) -> Watch {
	Watch {
		this_arg: orig.this_arg,
		watch_channel: Clone::clone(&orig.watch_channel),
		update_channel: Clone::clone(&orig.update_channel),
		release_pending_monitor_events: Clone::clone(&orig.release_pending_monitor_events),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::Watch as rustWatch;
impl rustWatch<crate::lightning::sign::WriteableEcdsaChannelSigner> for Watch {
	fn watch_channel(&self, mut funding_txo: lightning::chain::transaction::OutPoint, mut monitor: lightning::chain::channelmonitor::ChannelMonitor<crate::lightning::sign::WriteableEcdsaChannelSigner>) -> Result<lightning::chain::ChannelMonitorUpdateStatus, ()> {
		let mut ret = (self.watch_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(funding_txo), is_owned: true }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(monitor), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_native() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn update_channel(&self, mut funding_txo: lightning::chain::transaction::OutPoint, mut update: &lightning::chain::channelmonitor::ChannelMonitorUpdate) -> lightning::chain::ChannelMonitorUpdateStatus {
		let mut ret = (self.update_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(funding_txo), is_owned: true }, &crate::lightning::chain::channelmonitor::ChannelMonitorUpdate { inner: unsafe { ObjOps::nonnull_ptr_to_inner((update as *const lightning::chain::channelmonitor::ChannelMonitorUpdate<>) as *mut _) }, is_owned: false });
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
impl core::ops::DerefMut for Watch {
	fn deref_mut(&mut self) -> &mut Self {
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
#[allow(unused)]
pub(crate) fn Filter_clone_fields(orig: &Filter) -> Filter {
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
impl core::ops::DerefMut for Filter {
	fn deref_mut(&mut self) -> &mut Self {
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
#[no_mangle]
pub extern "C" fn WatchedOutput_get_block_hash(this_ptr: &WatchedOutput) -> crate::c_types::derived::COption_ThirtyTwoBytesZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().block_hash;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::ThirtyTwoBytes { data: (*inner_val.as_ref().unwrap()).clone().into_inner() } }) };
	local_inner_val
}
/// First block where the transaction output may have been spent.
#[no_mangle]
pub extern "C" fn WatchedOutput_set_block_hash(this_ptr: &mut WatchedOutput, mut val: crate::c_types::derived::COption_ThirtyTwoBytesZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { ::bitcoin::hash_types::BlockHash::from_slice(&{ val_opt.take() }.data[..]).unwrap() }})} };
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
pub extern "C" fn WatchedOutput_new(mut block_hash_arg: crate::c_types::derived::COption_ThirtyTwoBytesZ, mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut script_pubkey_arg: crate::c_types::derived::CVec_u8Z) -> WatchedOutput {
	let mut local_block_hash_arg = { /*block_hash_arg*/ let block_hash_arg_opt = block_hash_arg; if block_hash_arg_opt.is_none() { None } else { Some({ { ::bitcoin::hash_types::BlockHash::from_slice(&{ block_hash_arg_opt.take() }.data[..]).unwrap() }})} };
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeWatchedOutput)).clone() })) as *mut c_void
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
/// Generates a non-cryptographic 64-bit hash of the WatchedOutput.
#[no_mangle]
pub extern "C" fn WatchedOutput_hash(o: &WatchedOutput) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
