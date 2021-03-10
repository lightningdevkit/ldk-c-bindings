//! Structs and traits which allow other parts of rust-lightning to interact with the blockchain.

use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

pub mod chaininterface;
pub mod chainmonitor;
pub mod channelmonitor;
pub mod transaction;
pub mod keysinterface;
/// An error when accessing the chain via [`Access`].
///
/// [`Access`]: trait.Access.html
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum AccessError {
	/// The requested chain is unknown.
	UnknownChain,
	/// The requested transaction doesn't exist or hasn't confirmed.
	UnknownTx,
}
use lightning::chain::AccessError as nativeAccessError;
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
	/// [`short_channel_id`]: https://github.com/lightningnetwork/lightning-rfc/blob/master/07-routing-gossip.md#definition-of-short_channel_id
	#[must_use]
	pub get_utxo: extern "C" fn (this_arg: *const c_void, genesis_hash: *const [u8; 32], short_channel_id: u64) -> crate::c_types::derived::CResult_TxOutAccessErrorZ,
/// Frees any resources associated with this object given its this_arg pointer.
/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Access {}
unsafe impl Sync for Access {}

use lightning::chain::Access as rustAccess;
impl rustAccess for Access {
	fn get_utxo(&self, genesis_hash: &bitcoin::hash_types::BlockHash, short_channel_id: u64) -> Result<bitcoin::blockdata::transaction::TxOut, lightning::chain::AccessError> {
		let mut ret = (self.get_utxo)(self.this_arg, genesis_hash.as_inner(), short_channel_id);
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Access {
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
/// The `Listen` trait is used to be notified of when blocks have been connected or disconnected
/// from the chain.
///
/// Useful when needing to replay chain data upon startup or as new chain events occur.
#[repr(C)]
pub struct Listen {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Notifies the listener that a block was added at the given height.
	pub block_connected: extern "C" fn (this_arg: *const c_void, block: crate::c_types::u8slice, height: u32),
	/// Notifies the listener that a block was removed at the given height.
	pub block_disconnected: extern "C" fn (this_arg: *const c_void, header: *const [u8; 80], height: u32),
/// Frees any resources associated with this object given its this_arg pointer.
/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}

use lightning::chain::Listen as rustListen;
impl rustListen for Listen {
	fn block_connected(&self, block: &bitcoin::blockdata::block::Block, height: u32) {
		let mut local_block = ::bitcoin::consensus::encode::serialize(block);
		(self.block_connected)(self.this_arg, crate::c_types::u8slice::from_slice(&local_block), height)
	}
	fn block_disconnected(&self, header: &bitcoin::blockdata::block::BlockHeader, height: u32) {
		let mut local_header = { let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(header)); s };
		(self.block_disconnected)(self.this_arg, &local_header, height)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Listen {
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
/// funds in the channel. See [`ChannelMonitorUpdateErr`] for more details about how to handle
/// multiple instances.
///
/// [`ChannelMonitor`]: channelmonitor/struct.ChannelMonitor.html
/// [`ChannelMonitorUpdateErr`]: channelmonitor/enum.ChannelMonitorUpdateErr.html
/// [`PermanentFailure`]: channelmonitor/enum.ChannelMonitorUpdateErr.html#variant.PermanentFailure
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
	/// [`get_outputs_to_watch`]: channelmonitor/struct.ChannelMonitor.html#method.get_outputs_to_watch
	/// [`block_connected`]: channelmonitor/struct.ChannelMonitor.html#method.block_connected
	/// [`block_disconnected`]: channelmonitor/struct.ChannelMonitor.html#method.block_disconnected
	#[must_use]
	pub watch_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::chain::transaction::OutPoint, monitor: crate::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	/// Updates a channel identified by `funding_txo` by applying `update` to its monitor.
	///
	/// Implementations must call [`update_monitor`] with the given update. See
	/// [`ChannelMonitorUpdateErr`] for invariants around returning an error.
	///
	/// [`update_monitor`]: channelmonitor/struct.ChannelMonitor.html#method.update_monitor
	/// [`ChannelMonitorUpdateErr`]: channelmonitor/enum.ChannelMonitorUpdateErr.html
	#[must_use]
	pub update_channel: extern "C" fn (this_arg: *const c_void, funding_txo: crate::chain::transaction::OutPoint, update: crate::chain::channelmonitor::ChannelMonitorUpdate) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ,
	/// Returns any monitor events since the last call. Subsequent calls must only return new
	/// events.
	#[must_use]
	pub release_pending_monitor_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_MonitorEventZ,
/// Frees any resources associated with this object given its this_arg pointer.
/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Watch {}
unsafe impl Sync for Watch {}

use lightning::chain::Watch as rustWatch;
impl rustWatch<crate::chain::keysinterface::Sign> for Watch {
	fn watch_channel(&self, funding_txo: lightning::chain::transaction::OutPoint, monitor: lightning::chain::channelmonitor::ChannelMonitor<crate::chain::keysinterface::Sign>) -> Result<(), lightning::chain::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.watch_channel)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo)), is_owned: true }, crate::chain::channelmonitor::ChannelMonitor { inner: Box::into_raw(Box::new(monitor)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn update_channel(&self, funding_txo: lightning::chain::transaction::OutPoint, update: lightning::chain::channelmonitor::ChannelMonitorUpdate) -> Result<(), lightning::chain::channelmonitor::ChannelMonitorUpdateErr> {
		let mut ret = (self.update_channel)(self.this_arg, crate::chain::transaction::OutPoint { inner: Box::into_raw(Box::new(funding_txo)), is_owned: true }, crate::chain::channelmonitor::ChannelMonitorUpdate { inner: Box::into_raw(Box::new(update)), is_owned: true });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn release_pending_monitor_events(&self) -> Vec<lightning::chain::channelmonitor::MonitorEvent> {
		let mut ret = (self.release_pending_monitor_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Watch {
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
/// processed later. Then, in order to block until the data has been processed, any `Watch`
/// invocation that has called the `Filter` must return [`TemporaryFailure`].
///
/// [`Watch`]: trait.Watch.html
/// [`TemporaryFailure`]: channelmonitor/enum.ChannelMonitorUpdateErr.html#variant.TemporaryFailure
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
	/// Registers interest in spends of a transaction output identified by `outpoint` having
	/// `script_pubkey` as the spending condition.
	pub register_output: extern "C" fn (this_arg: *const c_void, outpoint: &crate::chain::transaction::OutPoint, script_pubkey: crate::c_types::u8slice),
/// Frees any resources associated with this object given its this_arg pointer.
/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Filter {}
unsafe impl Sync for Filter {}

use lightning::chain::Filter as rustFilter;
impl rustFilter for Filter {
	fn register_tx(&self, txid: &bitcoin::hash_types::Txid, script_pubkey: &bitcoin::blockdata::script::Script) {
		(self.register_tx)(self.this_arg, txid.as_inner(), crate::c_types::u8slice::from_slice(&script_pubkey[..]))
	}
	fn register_output(&self, outpoint: &lightning::chain::transaction::OutPoint, script_pubkey: &bitcoin::blockdata::script::Script) {
		(self.register_output)(self.this_arg, &crate::chain::transaction::OutPoint { inner: unsafe { (outpoint as *const _) as *mut _ }, is_owned: false }, crate::c_types::u8slice::from_slice(&script_pubkey[..]))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Filter {
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
