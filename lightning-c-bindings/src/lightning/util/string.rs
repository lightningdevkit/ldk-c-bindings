// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for strings.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::util::string::PrintableString as nativePrintableStringImport;
pub(crate) type nativePrintableString = nativePrintableStringImport<'static>;

/// A string that displays only printable characters, replacing control characters with
/// [`core::char::REPLACEMENT_CHARACTER`].
#[must_use]
#[repr(C)]
pub struct PrintableString {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePrintableString,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PrintableString {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePrintableString>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PrintableString, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PrintableString_free(this_obj: PrintableString) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrintableString_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePrintableString) };
}
#[allow(unused)]
impl PrintableString {
	pub(crate) fn get_native_ref(&self) -> &'static nativePrintableString {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePrintableString {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePrintableString {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn PrintableString_get_a(this_ptr: &PrintableString) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.into()
}
#[no_mangle]
pub extern "C" fn PrintableString_set_a(this_ptr: &mut PrintableString, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_str();
}
/// Constructs a new PrintableString given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PrintableString_new(mut a_arg: crate::c_types::Str) -> PrintableString {
	PrintableString { inner: ObjOps::heap_alloc(lightning::util::string::PrintableString (
		a_arg.into_str(),
	)), is_owned: true }
}
