// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Objects related to [`FilesystemStore`] live here.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning_persister::fs_store::FilesystemStore as nativeFilesystemStoreImport;
pub(crate) type nativeFilesystemStore = nativeFilesystemStoreImport;

/// A [`KVStore`] implementation that writes to and reads from the file system.
#[must_use]
#[repr(C)]
pub struct FilesystemStore {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFilesystemStore,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for FilesystemStore {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFilesystemStore>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the FilesystemStore, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn FilesystemStore_free(this_obj: FilesystemStore) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn FilesystemStore_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeFilesystemStore) };
}
#[allow(unused)]
impl FilesystemStore {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFilesystemStore {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFilesystemStore {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFilesystemStore {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a new [`FilesystemStore`].
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemStore_new(mut data_dir: crate::c_types::Str) -> crate::lightning_persister::fs_store::FilesystemStore {
	let mut ret = lightning_persister::fs_store::FilesystemStore::new(data_dir.into_pathbuf());
	crate::lightning_persister::fs_store::FilesystemStore { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the data directory.
#[must_use]
#[no_mangle]
pub extern "C" fn FilesystemStore_get_data_dir(this_arg: &crate::lightning_persister::fs_store::FilesystemStore) -> crate::c_types::Str {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_data_dir();
	ret.into()
}

impl From<nativeFilesystemStore> for crate::lightning::util::persist::KVStore {
	fn from(obj: nativeFilesystemStore) -> Self {
		let mut rust_obj = FilesystemStore { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = FilesystemStore_as_KVStore(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(FilesystemStore_free_void);
		ret
	}
}
/// Constructs a new KVStore which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned KVStore must be freed before this_arg is
#[no_mangle]
pub extern "C" fn FilesystemStore_as_KVStore(this_arg: &FilesystemStore) -> crate::lightning::util::persist::KVStore {
	crate::lightning::util::persist::KVStore {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		read: FilesystemStore_KVStore_read,
		write: FilesystemStore_KVStore_write,
		remove: FilesystemStore_KVStore_remove,
		list: FilesystemStore_KVStore_list,
	}
}

#[must_use]
extern "C" fn FilesystemStore_KVStore_read(this_arg: *const c_void, mut primary_namespace: crate::c_types::Str, mut secondary_namespace: crate::c_types::Str, mut key: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_u8ZIOErrorZ {
	let mut ret = <nativeFilesystemStore as lightning::util::persist::KVStore<>>::read(unsafe { &mut *(this_arg as *mut nativeFilesystemStore) }, primary_namespace.into_str(), secondary_namespace.into_str(), key.into_str());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn FilesystemStore_KVStore_write(this_arg: *const c_void, mut primary_namespace: crate::c_types::Str, mut secondary_namespace: crate::c_types::Str, mut key: crate::c_types::Str, mut buf: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NoneIOErrorZ {
	let mut ret = <nativeFilesystemStore as lightning::util::persist::KVStore<>>::write(unsafe { &mut *(this_arg as *mut nativeFilesystemStore) }, primary_namespace.into_str(), secondary_namespace.into_str(), key.into_str(), buf.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn FilesystemStore_KVStore_remove(this_arg: *const c_void, mut primary_namespace: crate::c_types::Str, mut secondary_namespace: crate::c_types::Str, mut key: crate::c_types::Str, mut lazy: bool) -> crate::c_types::derived::CResult_NoneIOErrorZ {
	let mut ret = <nativeFilesystemStore as lightning::util::persist::KVStore<>>::remove(unsafe { &mut *(this_arg as *mut nativeFilesystemStore) }, primary_namespace.into_str(), secondary_namespace.into_str(), key.into_str(), lazy);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn FilesystemStore_KVStore_list(this_arg: *const c_void, mut primary_namespace: crate::c_types::Str, mut secondary_namespace: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_StrZIOErrorZ {
	let mut ret = <nativeFilesystemStore as lightning::util::persist::KVStore<>>::list(unsafe { &mut *(this_arg as *mut nativeFilesystemStore) }, primary_namespace.into_str(), secondary_namespace.into_str());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { item.into() }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

