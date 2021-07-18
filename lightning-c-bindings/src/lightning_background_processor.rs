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

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning_background_processor::BackgroundProcessor as nativeBackgroundProcessorImport;
type nativeBackgroundProcessor = nativeBackgroundProcessorImport;

/// BackgroundProcessor takes care of tasks that (1) need to happen periodically to keep
/// Rust-Lightning running properly, and (2) either can or should be run in the background. Its
/// responsibilities are:
/// * Monitoring whether the ChannelManager needs to be re-persisted to disk, and if so,
///   writing it to disk/backups by invoking the callback given to it at startup.
///   ChannelManager persistence should be done in the background.
/// * Calling `ChannelManager::timer_tick_occurred()` and
///   `PeerManager::timer_tick_occurred()` every minute (can be done in the
///   background).
///
/// Note that if ChannelManager persistence fails and the persisted manager becomes out-of-date,
/// then there is a risk of channels force-closing on startup when the manager realizes it's
/// outdated. However, as long as `ChannelMonitor` backups are sound, no funds besides those used
/// for unilateral chain closure fees are at risk.
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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the BackgroundProcessor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BackgroundProcessor_free(this_obj: BackgroundProcessor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn BackgroundProcessor_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeBackgroundProcessor); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl BackgroundProcessor {
	pub(crate) fn take_inner(mut self) -> *mut nativeBackgroundProcessor {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Trait which handles persisting a [`ChannelManager`] to disk.
///
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
#[repr(C)]
pub struct ChannelManagerPersister {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Persist the given [`ChannelManager`] to disk, returning an error if persistence failed
	/// (which will cause the [`BackgroundProcessor`] which called this method to exit.
	///
	/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
	#[must_use]
	pub persist_manager: extern "C" fn (this_arg: *const c_void, channel_manager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NoneErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ChannelManagerPersister {}
unsafe impl Sync for ChannelManagerPersister {}
#[no_mangle]
pub(crate) extern "C" fn ChannelManagerPersister_clone_fields(orig: &ChannelManagerPersister) -> ChannelManagerPersister {
	ChannelManagerPersister {
		this_arg: orig.this_arg,
		persist_manager: Clone::clone(&orig.persist_manager),
		free: Clone::clone(&orig.free),
	}
}

use lightning_background_processor::ChannelManagerPersister as rustChannelManagerPersister;
impl rustChannelManagerPersister<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger> for ChannelManagerPersister {
	fn persist_manager(&self, mut channel_manager: &lightning::ln::channelmanager::ChannelManager<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>) -> Result<(), std::io::Error> {
		let mut ret = (self.persist_manager)(self.this_arg, &crate::lightning::ln::channelmanager::ChannelManager { inner: unsafe { (channel_manager as *const _) as *mut _ }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for ChannelManagerPersister {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ChannelManagerPersister_free(this_ptr: ChannelManagerPersister) { }
impl Drop for ChannelManagerPersister {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Start a background thread that takes care of responsibilities enumerated in the [top-level
/// documentation].
///
/// The thread runs indefinitely unless the object is dropped, [`stop`] is called, or
/// `persist_manager` returns an error. In case of an error, the error is retrieved by calling
/// either [`join`] or [`stop`].
///
/// Typically, users should either implement [`ChannelManagerPersister`] to never return an
/// error or call [`join`] and handle any error that may arise. For the latter case, the
/// `BackgroundProcessor` must be restarted by calling `start` again after handling the error.
///
/// `persist_manager` is responsible for writing out the [`ChannelManager`] to disk, and/or
/// uploading to one or more backup services. See [`ChannelManager::write`] for writing out a
/// [`ChannelManager`]. See [`FilesystemPersister::persist_manager`] for Rust-Lightning's
/// provided implementation.
///
/// [top-level documentation]: Self
/// [`join`]: Self::join
/// [`stop`]: Self::stop
/// [`ChannelManager`]: lightning::ln::channelmanager::ChannelManager
/// [`ChannelManager::write`]: lightning::ln::channelmanager::ChannelManager#impl-Writeable
/// [`FilesystemPersister::persist_manager`]: lightning_persister::FilesystemPersister::persist_manager
#[must_use]
#[no_mangle]
pub extern "C" fn BackgroundProcessor_start(mut persister: crate::lightning_background_processor::ChannelManagerPersister, mut event_handler: crate::lightning::util::events::EventHandler, chain_monitor: &crate::lightning::chain::chainmonitor::ChainMonitor, channel_manager: &crate::lightning::ln::channelmanager::ChannelManager, peer_manager: &crate::lightning::ln::peer_handler::PeerManager, mut logger: crate::lightning::util::logger::Logger) -> BackgroundProcessor {
	let mut ret = lightning_background_processor::BackgroundProcessor::start(persister, event_handler, unsafe { &*chain_monitor.inner }, unsafe { &*channel_manager.inner }, unsafe { &*peer_manager.inner }, logger);
	BackgroundProcessor { inner: Box::into_raw(Box::new(ret)), is_owned: true }
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
pub extern "C" fn BackgroundProcessor_join(mut this_arg: BackgroundProcessor) -> crate::c_types::derived::CResult_NoneErrorZ {
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
pub extern "C" fn BackgroundProcessor_stop(mut this_arg: BackgroundProcessor) -> crate::c_types::derived::CResult_NoneErrorZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).stop();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

