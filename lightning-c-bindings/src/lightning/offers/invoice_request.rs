// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `invoice_request` messages.
//!
//! An [`InvoiceRequest`] can be built from a parsed [`Offer`] as an \"offer to be paid\". It is
//! typically constructed by a customer and sent to the merchant who had published the corresponding
//! offer. The recipient of the request responds with a [`Bolt12Invoice`].
//!
//! For an \"offer for money\" (e.g., refund, ATM withdrawal), where an offer doesn't exist as a
//! precursor, see [`Refund`].
//!
//! [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
//! [`Refund`]: crate::offers::refund::Refund
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::Infallible;
//! use lightning::ln::features::OfferFeatures;
//! use lightning::offers::offer::Offer;
//! use lightning::util::ser::Writeable;
//!
//! # fn parse() -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let mut buffer = Vec::new();
//!
//! \"lno1qcp4256ypq\"
//!     .parse::<Offer>()?
//!     .request_invoice(vec![42; 64], pubkey)?
//!     .chain(Network::Testnet)?
//!     .amount_msats(1000)?
//!     .quantity(5)?
//!     .payer_note(\"foo\".to_string())
//!     .build()?
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//! ```

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice_request::UnsignedInvoiceRequest as nativeUnsignedInvoiceRequestImport;
pub(crate) type nativeUnsignedInvoiceRequest = nativeUnsignedInvoiceRequestImport<'static>;

/// A semantically valid [`InvoiceRequest`] that hasn't been signed.
#[must_use]
#[repr(C)]
pub struct UnsignedInvoiceRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedInvoiceRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for UnsignedInvoiceRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnsignedInvoiceRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnsignedInvoiceRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnsignedInvoiceRequest_free(this_obj: UnsignedInvoiceRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedInvoiceRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnsignedInvoiceRequest) };
}
#[allow(unused)]
impl UnsignedInvoiceRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnsignedInvoiceRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnsignedInvoiceRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedInvoiceRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::offers::invoice_request::InvoiceRequest as nativeInvoiceRequestImport;
pub(crate) type nativeInvoiceRequest = nativeInvoiceRequestImport;

/// An `InvoiceRequest` is a request for a [`Bolt12Invoice`] formulated from an [`Offer`].
///
/// An offer may provide choices such as quantity, amount, chain, features, etc. An invoice request
/// specifies these such that its recipient can send an invoice for payment.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct InvoiceRequest {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequest,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoiceRequest {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequest>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequest, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequest_free(this_obj: InvoiceRequest) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequest_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequest) };
}
#[allow(unused)]
impl InvoiceRequest {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequest {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequest {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequest {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for InvoiceRequest {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceRequest>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequest_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInvoiceRequest)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceRequest
pub extern "C" fn InvoiceRequest_clone(orig: &InvoiceRequest) -> InvoiceRequest {
	orig.clone()
}
/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_metadata(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain from [`Offer::chains`] that the offer is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_chain(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: ret.to_bytes() }
}

/// The amount to pay in msats (i.e., the minimum lightning-payable unit for [`chain`]), which
/// must be greater than or equal to [`Offer::amount`], converted if necessary.
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_amount_msats(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_features(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning::ln::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	crate::lightning::ln::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of the offer's item conforming to [`Offer::is_valid_quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_quantity(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_payer_id(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note which will be seen by the recipient and reflected back in the invoice
/// response.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_payer_note(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Verifies that the request was for an offer created using the given key. Returns the derived
/// keys need to sign an [`Bolt12Invoice`] for the request if they could be extracted from the
/// metadata.
///
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequest_verify(this_arg: &crate::lightning::offers::invoice_request::InvoiceRequest, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_COption_KeyPairZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify(key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = if o.is_none() { crate::c_types::derived::COption_KeyPairZ::None } else { crate::c_types::derived::COption_KeyPairZ::Some( { crate::c_types::SecretKey::from_rust(o.unwrap().secret_key()) }) }; local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

#[no_mangle]
/// Serialize the InvoiceRequest object into a byte array which can be read by InvoiceRequest_read
pub extern "C" fn InvoiceRequest_write(obj: &crate::lightning::offers::invoice_request::InvoiceRequest) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn InvoiceRequest_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInvoiceRequest) })
}
