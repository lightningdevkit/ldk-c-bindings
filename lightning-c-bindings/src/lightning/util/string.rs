// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for strings.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::util::string::UntrustedString as nativeUntrustedStringImport;
pub(crate) type nativeUntrustedString = nativeUntrustedStringImport;

/// Struct to `Display` fields in a safe way using `PrintableString`
#[must_use]
#[repr(C)]
pub struct UntrustedString {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUntrustedString,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for UntrustedString {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUntrustedString>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UntrustedString, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UntrustedString_free(this_obj: UntrustedString) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UntrustedString_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUntrustedString) };
}
#[allow(unused)]
impl UntrustedString {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUntrustedString {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUntrustedString {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUntrustedString {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn UntrustedString_get_a(this_ptr: &UntrustedString) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val.as_str().into()
}
#[no_mangle]
pub extern "C" fn UntrustedString_set_a(this_ptr: &mut UntrustedString, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_string();
}
/// Constructs a new UntrustedString given each field
#[must_use]
#[no_mangle]
pub extern "C" fn UntrustedString_new(mut a_arg: crate::c_types::Str) -> UntrustedString {
	UntrustedString { inner: ObjOps::heap_alloc(lightning::util::string::UntrustedString (
		a_arg.into_string(),
	)), is_owned: true }
}
impl Clone for UntrustedString {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUntrustedString>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UntrustedString_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUntrustedString)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the UntrustedString
pub extern "C" fn UntrustedString_clone(orig: &UntrustedString) -> UntrustedString {
	orig.clone()
}
/// Checks if two UntrustedStrings contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn UntrustedString_eq(a: &UntrustedString, b: &UntrustedString) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the UntrustedString object into a byte array which can be read by UntrustedString_read
pub extern "C" fn UntrustedString_write(obj: &crate::lightning::util::string::UntrustedString) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UntrustedString_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUntrustedString) })
}
#[no_mangle]
/// Read a UntrustedString from a byte array, created by UntrustedString_write
pub extern "C" fn UntrustedString_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_UntrustedStringDecodeErrorZ {
	let res: Result<lightning::util::string::UntrustedString, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::string::UntrustedString { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

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
