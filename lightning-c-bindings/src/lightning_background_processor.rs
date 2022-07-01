// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities that take care of tasks that (1) need to happen periodically to keep Rust-Lightning
//! running properly, and (2) either can or should be run in the background. See docs for
//! [`BackgroundProcessor`] for more details on the nitty-gritty.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_background_processor::BackgroundProcessor as nativeBackgroundProcessorImport;
pub(crate) type nativeBackgroundProcessor = nativeBackgroundProcessorImport;

/// `BackgroundProcessor` takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Processing [`Event`]s with a user-provided [`EventHandler`].
/// * Monitoring whether the [`ChannelManager`] needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   [`ChannelManager`] persistence should be done in the background.
/// * Calling [`ChannelManager::timer_tick_occurred`] and [`PeerManager::timer_tick_occurred`]
///   at the appropriate intervals.
/// * Calling [`NetworkGraph::remove_stale_channels`] (if a [`GossipSync`] with a [`NetworkGraph`]
///   is provided to [`BackgroundProcessor::start`]).
///
/// It will also call [`PeerManager::process_events`] periodically though this shouldn't be relied
/// upon as doing so may result in high latency.
///
/// # Note
///
/// If [`ChannelManager`] persistence fails and the persisted manager becomes out-of-date, then
/// there is a risk of channels force-closing on startup when the manager realizes it's outdated.
/// However, as long as [`ChannelMonitor`] backups are sound, no funds besides those used for
/// unilateral chain closure fees are at risk.
///
/// [`ChannelMonitor`]: lightning::chain::channelmonitor::ChannelMonitor
/// [`Event`]: lightning::util::events::Event
///BackgroundProcessor will immediately stop on drop. It should be stored until shutdown.
#[must_use]
#[repr(C)]
pub struct BackgroundProcessor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBackgroundProcessor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BackgroundProcessor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBackgroundProcessor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BackgroundProcessor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BackgroundProcessor_free(this_obj: BackgroundProcessor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BackgroundProcessor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeBackgroundProcessor); }
}
#[allow(unused)]
impl BackgroundProcessor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBackgroundProcessor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBackgroundProcessor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBackgroundProcessor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Either [`P2PGossipSync`] or [`RapidGossipSync`].
#[must_use]
#[repr(C)]
pub enum GossipSync {
	/// Gossip sync via the lightning peer-to-peer network as defined by BOLT 7.
	P2P(
		/// Note that this field is expected to be a reference.
		crate::lightning::routing::gossip::P2PGossipSync),
	/// Rapid gossip sync from a trusted server.
	Rapid(
		/// Note that this field is expected to be a reference.
		crate::lightning_rapid_gossip_sync::RapidGossipSync),
	/// No gossip sync.
	None,
}
use lightning_background_processor::GossipSync as GossipSyncImport;
pub(crate) type nativeGossipSync = GossipSyncImport<&'static lightning::routing::gossip::P2PGossipSync<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::chain::Access, crate::lightning::util::logger::Logger>, &'static lightning_rapid_gossip_sync::RapidGossipSync<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>, &'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::chain::Access, crate::lightning::util::logger::Logger>;

impl GossipSync {
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeGossipSync {
		match self {
			GossipSync::P2P (mut a, ) => {
				nativeGossipSync::P2P (
					a.get_native_ref(),
				)
			},
			GossipSync::Rapid (mut a, ) => {
				nativeGossipSync::Rapid (
					a.get_native_ref(),
				)
			},
			GossipSync::None => nativeGossipSync::None,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeGossipSync) -> Self {
		match native {
			nativeGossipSync::P2P (mut a, ) => {
				GossipSync::P2P (
					crate::lightning::routing::gossip::P2PGossipSync { inner: unsafe { ObjOps::nonnull_ptr_to_inner((a as *const lightning::routing::gossip::P2PGossipSync<_, _, _, >) as *mut _) }, is_owned: false },
				)
			},
			nativeGossipSync::Rapid (mut a, ) => {
				GossipSync::Rapid (
					crate::lightning_rapid_gossip_sync::RapidGossipSync { inner: unsafe { ObjOps::nonnull_ptr_to_inner((a as *const lightning_rapid_gossip_sync::RapidGossipSync<_, _, >) as *mut _) }, is_owned: false },
				)
			},
			nativeGossipSync::None => GossipSync::None,
		}
	}
}
/// Frees any resources used by the GossipSync
#[no_mangle]
pub extern "C" fn GossipSync_free(this_ptr: GossipSync) { }
#[no_mangle]
/// Utility method to constructs a new P2P-variant GossipSync
pub extern "C" fn GossipSync_p2_p(a: &crate::lightning::routing::gossip::P2PGossipSync) -> GossipSync {
	GossipSync::P2P(crate::lightning::routing::gossip::P2PGossipSync { inner: a.inner, is_owned: false }, )
}
#[no_mangle]
/// Utility method to constructs a new Rapid-variant GossipSync
pub extern "C" fn GossipSync_rapid(a: &crate::lightning_rapid_gossip_sync::RapidGossipSync) -> GossipSync {
	GossipSync::Rapid(crate::lightning_rapid_gossip_sync::RapidGossipSync { inner: a.inner, is_owned: false }, )
}
#[no_mangle]
/// Utility method to constructs a new None-variant GossipSync
pub extern "C" fn GossipSync_none() -> GossipSync {
	GossipSync::None}
/// Start a background thread that takes care of responsibilities enumerated in the [top-level
/// documentation].
///
/// The thread runs indefinitely unless the object is dropped, [`stop`] is called, or
/// [`Persister::persist_manager`] returns an error. In case of an error, the error is retrieved by calling
/// either [`join`] or [`stop`].
///
/// # Data Persistence
///
/// [`Persister::persist_manager`] is responsible for writing out the [`ChannelManager`] to disk, and/or
/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
/// [`ChannelManager`]. See the `lightning-persister` crate for LDK's
/// provided implementation.
///
/// [`Persister::persist_graph`] is responsible for writing out the [`NetworkGraph`] to disk, if
/// [`GossipSync`] is supplied. See [`NetworkGraph::write`] for writing out a [`NetworkGraph`].
/// See the `lightning-persister` crate for LDK's provided implementation.
///
/// Typically, users should either implement [`Persister::persist_manager`] to never return an
/// error or call [`join`] and handle any error that may arise. For the latter case,
/// `BackgroundProcessor` must be restarted by calling `start` again after handling the error.
///
/// # Event Handling
///
/// `event_handler` is responsible for handling events that users should be notified of (e.g.,
/// payment failed). [`BackgroundProcessor`] may decorate the given [`EventHandler`] with common
/// functionality implemented by other handlers.
/// * [`P2PGossipSync`] if given will update the [`NetworkGraph`] based on payment failures.
///
/// # Rapid Gossip Sync
///
/// If rapid gossip sync is meant to run at startup, pass [`RapidGossipSync`] via `gossip_sync`
/// to indicate that the [`BackgroundProcessor`] should not prune the [`NetworkGraph`] instance
/// until the [`RapidGossipSync`] instance completes its first sync.
///
/// [top-level documentation]: BackgroundProcessor
/// [`join`]: Self::join
/// [`stop`]: Self::stop
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
/// [`Persister::persist_manager`]: lightning::util::persist::Persister::persist_manager
/// [`Persister::persist_graph`]: lightning::util::persist::Persister::persist_graph
/// [`NetworkGraph`]: lightning::routing::gossip::NetworkGraph
/// [`NetworkGraph::write`]: lightning::routing::gossip::NetworkGraph#impl-Writeable
///
/// Note that scorer (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn BackgroundProcessor_start(mut persister: crate::lightning::util::persist::Persister, mut event_handler: crate::lightning::util::events::EventHandler, chain_monitor: &crate::lightning::chain::chainmonitor::ChainMonitor, channel_manager: &crate::lightning::ln::channelmanager::ChannelManager, mut gossip_sync: crate::lightning_background_processor::GossipSync, peer_manager: &crate::lightning::ln::peer_handler::PeerManager, mut logger: crate::lightning::util::logger::Logger, mut scorer: crate::lightning::routing::scoring::MultiThreadedLockableScore) -> crate::lightning_background_processor::BackgroundProcessor {
	let mut local_scorer = if scorer.inner.is_null() { None } else { Some( { scorer.get_native_ref() }) };
	let mut ret = lightning_background_processor::BackgroundProcessor::start(persister, event_handler, chain_monitor.get_native_ref(), channel_manager.get_native_ref(), gossip_sync.into_native(), peer_manager.get_native_ref(), logger, local_scorer);
	crate::lightning_background_processor::BackgroundProcessor { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Join `BackgroundProcessor`'s thread, returning any error that occurred while persisting
/// [`ChannelManager`].
///
/// # Panics
///
/// This function panics if the background thread has panicked such as while persisting or
/// handling events.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
#[must_use]
#[no_mangle]
pub extern "C" fn BackgroundProcessor_join(mut this_arg: crate::lightning_background_processor::BackgroundProcessor) -> crate::c_types::derived::CResult_NoneErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).join();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

/// Stop `BackgroundProcessor`'s thread, returning any error that occurred while persisting
/// [`ChannelManager`].
///
/// # Panics
///
/// This function panics if the background thread has panicked such as while persisting or
/// handling events.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
#[must_use]
#[no_mangle]
pub extern "C" fn BackgroundProcessor_stop(mut this_arg: crate::lightning_background_processor::BackgroundProcessor) -> crate::c_types::derived::CResult_NoneErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).stop();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

