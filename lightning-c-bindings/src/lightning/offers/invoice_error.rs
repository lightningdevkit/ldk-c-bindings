// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `invoice_error` messages.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice_error::InvoiceError as nativeInvoiceErrorImport;
pub(crate) type nativeInvoiceError = nativeInvoiceErrorImport;

/// An error in response to an [`InvoiceRequest`] or an [`Bolt12Invoice`].
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct InvoiceError {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceError,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoiceError {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceError>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceError, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceError_free(this_obj: InvoiceError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceError) };
}
#[allow(unused)]
impl InvoiceError {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceError {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceError {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceError {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The field in the [`InvoiceRequest`] or the [`Bolt12Invoice`] that contained an error.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn InvoiceError_get_erroneous_field(this_ptr: &InvoiceError) -> crate::lightning::offers::invoice_error::ErroneousField {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().erroneous_field;
	let mut local_inner_val = crate::lightning::offers::invoice_error::ErroneousField { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::offers::invoice_error::ErroneousField<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The field in the [`InvoiceRequest`] or the [`Bolt12Invoice`] that contained an error.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn InvoiceError_set_erroneous_field(this_ptr: &mut InvoiceError, mut val: crate::lightning::offers::invoice_error::ErroneousField) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.erroneous_field = local_val;
}
/// An explanation of the error.
#[no_mangle]
pub extern "C" fn InvoiceError_get_message(this_ptr: &InvoiceError) -> crate::lightning::util::string::UntrustedString {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().message;
	crate::lightning::util::string::UntrustedString { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::util::string::UntrustedString<>) as *mut _) }, is_owned: false }
}
/// An explanation of the error.
#[no_mangle]
pub extern "C" fn InvoiceError_set_message(this_ptr: &mut InvoiceError, mut val: crate::lightning::util::string::UntrustedString) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.message = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new InvoiceError given each field
///
/// Note that erroneous_field_arg (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceError_new(mut erroneous_field_arg: crate::lightning::offers::invoice_error::ErroneousField, mut message_arg: crate::lightning::util::string::UntrustedString) -> InvoiceError {
	let mut local_erroneous_field_arg = if erroneous_field_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(erroneous_field_arg.take_inner()) } }) };
	InvoiceError { inner: ObjOps::heap_alloc(nativeInvoiceError {
		erroneous_field: local_erroneous_field_arg,
		message: *unsafe { Box::from_raw(message_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for InvoiceError {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceError>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInvoiceError)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceError
pub extern "C" fn InvoiceError_clone(orig: &InvoiceError) -> InvoiceError {
	orig.clone()
}
/// Get a string which allows debug introspection of a InvoiceError object
pub extern "C" fn InvoiceError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice_error::InvoiceError }).into()}

use lightning::offers::invoice_error::ErroneousField as nativeErroneousFieldImport;
pub(crate) type nativeErroneousField = nativeErroneousFieldImport;

/// The field in the [`InvoiceRequest`] or the [`Bolt12Invoice`] that contained an error.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct ErroneousField {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeErroneousField,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ErroneousField {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeErroneousField>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ErroneousField, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ErroneousField_free(this_obj: ErroneousField) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ErroneousField_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeErroneousField) };
}
#[allow(unused)]
impl ErroneousField {
	pub(crate) fn get_native_ref(&self) -> &'static nativeErroneousField {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeErroneousField {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeErroneousField {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The type number of the TLV field containing the error.
#[no_mangle]
pub extern "C" fn ErroneousField_get_tlv_fieldnum(this_ptr: &ErroneousField) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().tlv_fieldnum;
	*inner_val
}
/// The type number of the TLV field containing the error.
#[no_mangle]
pub extern "C" fn ErroneousField_set_tlv_fieldnum(this_ptr: &mut ErroneousField, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.tlv_fieldnum = val;
}
/// A value to use for the TLV field to avoid the error.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn ErroneousField_get_suggested_value(this_ptr: &ErroneousField) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut inner_val = this_ptr.get_native_mut_ref().suggested_value.clone();
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some( { let mut local_inner_val_0 = Vec::new(); for mut item in inner_val.unwrap().drain(..) { local_inner_val_0.push( { item }); }; local_inner_val_0.into() }) };
	local_inner_val
}
/// A value to use for the TLV field to avoid the error.
#[no_mangle]
pub extern "C" fn ErroneousField_set_suggested_value(this_ptr: &mut ErroneousField, mut val: crate::c_types::derived::COption_CVec_u8ZZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { let mut local_val_0 = Vec::new(); for mut item in { val_opt.take() }.into_rust().drain(..) { local_val_0.push( { item }); }; local_val_0 }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.suggested_value = local_val;
}
/// Constructs a new ErroneousField given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ErroneousField_new(mut tlv_fieldnum_arg: u64, mut suggested_value_arg: crate::c_types::derived::COption_CVec_u8ZZ) -> ErroneousField {
	let mut local_suggested_value_arg = { /*suggested_value_arg*/ let suggested_value_arg_opt = suggested_value_arg; if suggested_value_arg_opt.is_none() { None } else { Some({ { let mut local_suggested_value_arg_0 = Vec::new(); for mut item in { suggested_value_arg_opt.take() }.into_rust().drain(..) { local_suggested_value_arg_0.push( { item }); }; local_suggested_value_arg_0 }})} };
	ErroneousField { inner: ObjOps::heap_alloc(nativeErroneousField {
		tlv_fieldnum: tlv_fieldnum_arg,
		suggested_value: local_suggested_value_arg,
	}), is_owned: true }
}
impl Clone for ErroneousField {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeErroneousField>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ErroneousField_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeErroneousField)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ErroneousField
pub extern "C" fn ErroneousField_clone(orig: &ErroneousField) -> ErroneousField {
	orig.clone()
}
/// Get a string which allows debug introspection of a ErroneousField object
pub extern "C" fn ErroneousField_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice_error::ErroneousField }).into()}
/// Creates an [`InvoiceError`] with the given message.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceError_from_string(mut s: crate::c_types::Str) -> crate::lightning::offers::invoice_error::InvoiceError {
	let mut ret = lightning::offers::invoice_error::InvoiceError::from_string(s.into_string());
	crate::lightning::offers::invoice_error::InvoiceError { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the InvoiceError object into a byte array which can be read by InvoiceError_read
pub extern "C" fn InvoiceError_write(obj: &crate::lightning::offers::invoice_error::InvoiceError) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InvoiceError_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInvoiceError) })
}
#[no_mangle]
/// Read a InvoiceError from a byte array, created by InvoiceError_write
pub extern "C" fn InvoiceError_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InvoiceErrorDecodeErrorZ {
	let res: Result<lightning::offers::invoice_error::InvoiceError, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice_error::InvoiceError { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
