// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Logic to connect off-chain channel management with on-chain transaction monitoring.
//!
//! [`ChainMonitor`] is an implementation of [`chain::Watch`] used both to process blocks and to
//! update [`ChannelMonitor`]s accordingly. If any on-chain events need further processing, it will
//! make those available as [`MonitorEvent`]s to be consumed.
//!
//! [`ChainMonitor`] is parameterized by an optional chain source, which must implement the
//! [`chain::Filter`] trait. This provides a mechanism to signal new relevant outputs back to light
//! clients, such that transactions spending those outputs are included in block data.
//!
//! [`ChainMonitor`] may be used directly to monitor channels locally or as a part of a distributed
//! setup to monitor channels remotely. In the latter case, a custom [`chain::Watch`] implementation
//! would be responsible for routing each update to a remote server and for retrieving monitor
//! events. The remote server would make use of [`ChainMonitor`] for block processing and for
//! servicing [`ChannelMonitor`] updates from the client.

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::chain::chainmonitor::ChainMonitor as nativeChainMonitorImport;
type nativeChainMonitor = nativeChainMonitorImport<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Filter, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger, crate::lightning::chain::channelmonitor::Persist>;

/// An implementation of [`chain::Watch`] for monitoring channels.
///
/// Connected and disconnected blocks must be provided to `ChainMonitor` as documented by
/// [`chain::Watch`]. May be used in conjunction with [`ChannelManager`] to monitor channels locally
/// or used independently to monitor channels remotely. See the [module-level documentation] for
/// details.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [module-level documentation]: crate::chain::chainmonitor
#[must_use]
#[repr(C)]
pub struct ChainMonitor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainMonitor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChainMonitor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChainMonitor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChainMonitor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChainMonitor_free(this_obj: ChainMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChainMonitor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChainMonitor); }
}
#[allow(unused)]
impl ChainMonitor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChainMonitor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChainMonitor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChainMonitor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Creates a new `ChainMonitor` used to watch on-chain activity pertaining to channels.
///
/// When an optional chain source implementing [`chain::Filter`] is provided, the chain monitor
/// will call back to it indicating transactions and outputs of interest. This allows clients to
/// pre-filter blocks or only fetch blocks matching a compact filter. Otherwise, clients may
/// always need to fetch full blocks absent another means for determining which blocks contain
/// transactions relevant to the watched channels.
///
/// Note that chain_source (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_new(chain_source: *mut crate::lightning::chain::Filter, mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut feeest: crate::lightning::chain::chaininterface::FeeEstimator, mut persister: crate::lightning::chain::channelmonitor::Persist) -> ChainMonitor {
	let mut local_chain_source = if chain_source == std::ptr::null_mut() { None } else { Some( { unsafe { *Box::from_raw(chain_source) } }) };
	let mut ret = lightning::chain::chainmonitor::ChainMonitor::new(local_chain_source, broadcaster, logger, feeest, persister);
	ChainMonitor { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeChainMonitor> for crate::lightning::chain::Listen {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Listen(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Listen which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Listen must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Listen(this_arg: &ChainMonitor) -> crate::lightning::chain::Listen {
	crate::lightning::chain::Listen {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		block_connected: ChainMonitor_Listen_block_connected,
		block_disconnected: ChainMonitor_Listen_block_disconnected,
	}
}

extern "C" fn ChainMonitor_Listen_block_connected(this_arg: *const c_void, mut block: crate::c_types::u8slice, mut height: u32) {
	<nativeChainMonitor as lightning::chain::Listen<>>::block_connected(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap(), height)
}
extern "C" fn ChainMonitor_Listen_block_disconnected(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChainMonitor as lightning::chain::Listen<>>::block_disconnected(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}

impl From<nativeChainMonitor> for crate::lightning::chain::Confirm {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Confirm(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Confirm which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Confirm must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Confirm(this_arg: &ChainMonitor) -> crate::lightning::chain::Confirm {
	crate::lightning::chain::Confirm {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		transactions_confirmed: ChainMonitor_Confirm_transactions_confirmed,
		transaction_unconfirmed: ChainMonitor_Confirm_transaction_unconfirmed,
		best_block_updated: ChainMonitor_Confirm_best_block_updated,
		get_relevant_txids: ChainMonitor_Confirm_get_relevant_txids,
	}
}

extern "C" fn ChainMonitor_Confirm_transactions_confirmed(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeChainMonitor as lightning::chain::Confirm<>>::transactions_confirmed(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn ChainMonitor_Confirm_transaction_unconfirmed(this_arg: *const c_void, txid: *const [u8; 32]) {
	<nativeChainMonitor as lightning::chain::Confirm<>>::transaction_unconfirmed(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap())
}
extern "C" fn ChainMonitor_Confirm_best_block_updated(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChainMonitor as lightning::chain::Confirm<>>::best_block_updated(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}
#[must_use]
extern "C" fn ChainMonitor_Confirm_get_relevant_txids(this_arg: *const c_void) -> crate::c_types::derived::CVec_TxidZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Confirm<>>::get_relevant_txids(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: item.into_inner() } }); };
	local_ret.into()
}

impl From<nativeChainMonitor> for crate::lightning::chain::Watch {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Watch(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Watch which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Watch must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Watch(this_arg: &ChainMonitor) -> crate::lightning::chain::Watch {
	crate::lightning::chain::Watch {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		watch_channel: ChainMonitor_Watch_watch_channel,
		update_channel: ChainMonitor_Watch_update_channel,
		release_pending_monitor_events: ChainMonitor_Watch_release_pending_monitor_events,
	}
}

#[must_use]
extern "C" fn ChainMonitor_Watch_watch_channel(this_arg: *const c_void, mut funding_outpoint: crate::lightning::chain::transaction::OutPoint, mut monitor: crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::watch_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_outpoint.take_inner()) }, *unsafe { Box::from_raw(monitor.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_update_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, mut update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::update_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, *unsafe { Box::from_raw(update.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_release_pending_monitor_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MonitorEventZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::release_pending_monitor_events(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::chain::channelmonitor::MonitorEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeChainMonitor> for crate::lightning::util::events::EventsProvider {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new EventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_EventsProvider(this_arg: &ChainMonitor) -> crate::lightning::util::events::EventsProvider {
	crate::lightning::util::events::EventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		process_pending_events: ChainMonitor_EventsProvider_process_pending_events,
	}
}

extern "C" fn ChainMonitor_EventsProvider_process_pending_events(this_arg: *const c_void, mut handler: crate::lightning::util::events::EventHandler) {
	<nativeChainMonitor as lightning::util::events::EventsProvider<>>::process_pending_events(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, handler)
}

