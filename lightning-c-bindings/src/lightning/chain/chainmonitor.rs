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
			let _ = unsafe { Box::from_raw(self.inner) };
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
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChainMonitor {
	pub(crate) fn take_inner(mut self) -> *mut nativeChainMonitor {
		assert!(self.is_owned);
		let ret = self.inner;
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
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_new(chain_source: *mut crate::lightning::chain::Filter, mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut feeest: crate::lightning::chain::chaininterface::FeeEstimator, mut persister: crate::lightning::chain::channelmonitor::Persist) -> ChainMonitor {
	let mut local_chain_source = if chain_source == std::ptr::null_mut() { None } else { Some( { unsafe { *Box::from_raw(chain_source) } }) };
	let mut ret = lightning::chain::chainmonitor::ChainMonitor::new(local_chain_source, broadcaster, logger, feeest, persister);
	ChainMonitor { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

impl From<nativeChainMonitor> for crate::lightning::chain::Watch {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: Box::into_raw(Box::new(obj)), is_owned: true };
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
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		watch_channel: ChainMonitor_Watch_watch_channel,
		update_channel: ChainMonitor_Watch_update_channel,
		release_pending_monitor_events: ChainMonitor_Watch_release_pending_monitor_events,
	}
}

#[must_use]
extern "C" fn ChainMonitor_Watch_watch_channel(this_arg: *const c_void, mut funding_outpoint: crate::lightning::chain::transaction::OutPoint, mut monitor: crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::watch_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_outpoint.take_inner()) }, *unsafe { Box::from_raw(monitor.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_update_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, mut update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::update_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, *unsafe { Box::from_raw(update.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { 0u8 /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::channelmonitor::ChannelMonitorUpdateErr::native_into(e) }).into() };
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
		let mut rust_obj = ChainMonitor { inner: Box::into_raw(Box::new(obj)), is_owned: true };
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
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_events: ChainMonitor_EventsProvider_get_and_clear_pending_events,
	}
}

#[must_use]
extern "C" fn ChainMonitor_EventsProvider_get_and_clear_pending_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_EventZ {
	let mut ret = <nativeChainMonitor as lightning::util::events::EventsProvider<>>::get_and_clear_pending_events(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::Event::native_into(item) }); };
	local_ret.into()
}

