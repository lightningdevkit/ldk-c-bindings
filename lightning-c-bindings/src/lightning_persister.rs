// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities that handle persisting Rust-Lightning data to disk via standard filesystem APIs.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod util {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning_persister::FilesystemPersister as nativeFilesystemPersisterImport;
pub(crate) type nativeFilesystemPersister = nativeFilesystemPersisterImport;

/// FilesystemPersister persists channel data on disk, where each channel's
/// data is stored in a file named after its funding outpoint.
///
/// Warning: this module does the best it can with calls to persist data, but it
/// can only guarantee that the data is passed to the drive. It is up to the
/// drive manufacturers to do the actual persistence properly, which they often
/// don't (especially on consumer-grade hardware). Therefore, it is up to the
/// user to validate their entire storage stack, to ensure the writes are
/// persistent.
/// Corollary: especially when dealing with larger amounts of money, it is best
/// practice to have multiple channel data backups and not rely only on one
/// FilesystemPersister.
#[must_use]
#[repr(C)]
pub struct FilesystemPersister {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFilesystemPersister,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for FilesystemPersister {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFilesystemPersister>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the FilesystemPersister, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn FilesystemPersister_free(this_obj: FilesystemPersister) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FilesystemPersister_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeFilesystemPersister); }
}
#[allow(unused)]
impl FilesystemPersister {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFilesystemPersister {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFilesystemPersister {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFilesystemPersister {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Initialize a new FilesystemPersister and set the path to the individual channels'
/// files.
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemPersister_new(mut path_to_channel_data: crate::c_types::Str) -> FilesystemPersister {
	let mut ret = lightning_persister::FilesystemPersister::new(path_to_channel_data.into_string());
	FilesystemPersister { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get the directory which was provided when this persister was initialized.
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemPersister_get_data_dir(this_arg: &FilesystemPersister) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_data_dir();
	ret.into()
}

/// Writes the provided `ChannelManager` to the path provided at `FilesystemPersister`
/// initialization, within a file called \"manager\".
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemPersister_persist_manager(mut data_dir: crate::c_types::Str, manager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NoneErrorZ {
	let mut ret = lightning_persister::FilesystemPersister::persist_manager(data_dir.into_string(), manager.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

/// Read `ChannelMonitor`s from disk.
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemPersister_read_channelmonitors(this_arg: &FilesystemPersister, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface) -> crate::c_types::derived::CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_channelmonitors(keys_manager);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_0.into_inner() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

impl From<nativeFilesystemPersister> for crate::lightning::chain::chainmonitor::Persist {
	fn from(obj: nativeFilesystemPersister) -> Self {
		let mut rust_obj = FilesystemPersister { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = FilesystemPersister_as_Persist(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(FilesystemPersister_free_void);
		ret
	}
}
/// Constructs a new Persist which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Persist must be freed before this_arg is
#[no_mangle]
pub extern "C" fn FilesystemPersister_as_Persist(this_arg: &FilesystemPersister) -> crate::lightning::chain::chainmonitor::Persist {
	crate::lightning::chain::chainmonitor::Persist {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		persist_new_channel: FilesystemPersister_Persist_persist_new_channel,
		update_persisted_channel: FilesystemPersister_Persist_update_persisted_channel,
	}
}

#[must_use]
extern "C" fn FilesystemPersister_Persist_persist_new_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, monitor: &crate::lightning::chain::channelmonitor::ChannelMonitor, mut _update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut ret = <nativeFilesystemPersister as lightning::chain::chainmonitor::Persist<_>>::persist_new_channel(unsafe { &mut *(this_arg as *mut nativeFilesystemPersister) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, monitor.get_native_ref(), *unsafe { Box::from_raw(_update_id.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::ChannelMonitorUpdateErr::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn FilesystemPersister_Persist_update_persisted_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, _update: &crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, monitor: &crate::lightning::chain::channelmonitor::ChannelMonitor, mut _update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::c_types::derived::CResult_NoneChannelMonitorUpdateErrZ {
	let mut local__update = if _update.inner.is_null() { None } else { Some((* { _update.get_native_ref() }).clone()) };
	let mut ret = <nativeFilesystemPersister as lightning::chain::chainmonitor::Persist<_>>::update_persisted_channel(unsafe { &mut *(this_arg as *mut nativeFilesystemPersister) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, &local__update, monitor.get_native_ref(), *unsafe { Box::from_raw(_update_id.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::chain::ChannelMonitorUpdateErr::native_into(e) }).into() };
	local_ret
}

