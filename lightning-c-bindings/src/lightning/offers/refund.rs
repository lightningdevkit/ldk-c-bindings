// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for refunds.
//!
//! A [`Refund`] is an \"offer for money\" and is typically constructed by a merchant and presented
//! directly to the customer. The recipient responds with an [`Invoice`] to be paid.
//!
//! This is an [`InvoiceRequest`] produced *not* in response to an [`Offer`].
//!
//! [`Invoice`]: crate::offers::invoice::Invoice
//! [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
//! [`Offer`]: crate::offers::offer::Offer
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::time::Duration;
//!
//! use bitcoin::network::constants::Network;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::parse::ParseError;
//! use lightning::offers::refund::{Refund, RefundBuilder};
//! use lightning::util::ser::{Readable, Writeable};
//!
//! # use lightning::blinded_path::BlindedPath;
//! # #[cfg(feature = \"std\")]
//! # use std::time::SystemTime;
//! #
//! # fn create_blinded_path() -> BlindedPath { unimplemented!() }
//! # fn create_another_blinded_path() -> BlindedPath { unimplemented!() }
//! #
//! # #[cfg(feature = \"std\")]
//! # fn build() -> Result<(), ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let refund = RefundBuilder::new(\"coffee, large\".to_string(), vec![1; 32], pubkey, 20_000)?
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer(\"Foo Bar\".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .chain(Network::Bitcoin)
//!     .payer_note(\"refund for order #12345\".to_string())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_refund = refund.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let refund = encoded_refund.parse::<Refund>()?;
//!
//! // Encode refund as raw bytes.
//! let mut bytes = Vec::new();
//! refund.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an refund.
//! let refund = Refund::try_from(bytes)?;
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


use lightning::offers::refund::Refund as nativeRefundImport;
pub(crate) type nativeRefund = nativeRefundImport;

/// A `Refund` is a request to send an [`Invoice`] without a preceding [`Offer`].
///
/// Typically, after an invoice is paid, the recipient may publish a refund allowing the sender to
/// recoup their funds. A refund may be used more generally as an \"offer for money\", such as with a
/// bitcoin ATM.
///
/// [`Invoice`]: crate::offers::invoice::Invoice
/// [`Offer`]: crate::offers::offer::Offer
#[must_use]
#[repr(C)]
pub struct Refund {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRefund,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Refund {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRefund>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Refund, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Refund_free(this_obj: Refund) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Refund_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRefund) };
}
#[allow(unused)]
impl Refund {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRefund {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRefund {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRefund {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Refund {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRefund>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Refund_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRefund)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Refund
pub extern "C" fn Refund_clone(orig: &Refund) -> Refund {
	orig.clone()
}
/// A complete description of the purpose of the refund. Intended to be displayed to the user
/// but with the caveat that it has not been verified in any way.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_description(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning::util::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Duration since the Unix epoch when an invoice should no longer be sent.
///
/// If `None`, the refund does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_absolute_expiry(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::COption_DurationZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_DurationZ::None } else { crate::c_types::derived::COption_DurationZ::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// Whether the refund has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_is_expired(this_arg: &crate::lightning::offers::refund::Refund) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// The issuer of the refund, possibly beginning with `user@domain` or `domain`. Intended to be
/// displayed to the user but with the caveat that it has not been verified in any way.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_issuer(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the sender originating from publicly reachable nodes. Blinded paths provide sender
/// privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_paths(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::CVec_BlindedPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// An unpredictable series of bytes, typically containing information about the derivation of
/// [`payer_id`].
///
/// [`payer_id`]: Self::payer_id
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_metadata(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// A chain that the refund is valid for.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_chain(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: ret.to_bytes() }
}

/// The amount to refund in msats (i.e., the minimum lightning-payable unit for [`chain`]).
///
/// [`chain`]: Self::chain
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_amount_msats(this_arg: &crate::lightning::offers::refund::Refund) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Features pertaining to requesting an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_features(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning::ln::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	crate::lightning::ln::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of an item that refund is for.
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_quantity(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A public node id to send to in the case where there are no [`paths`]. Otherwise, a possibly
/// transient pubkey.
///
/// [`paths`]: Self::paths
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_payer_id(this_arg: &crate::lightning::offers::refund::Refund) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Payer provided note to include in the invoice.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Refund_payer_note(this_arg: &crate::lightning::offers::refund::Refund) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

#[no_mangle]
/// Serialize the Refund object into a byte array which can be read by Refund_read
pub extern "C" fn Refund_write(obj: &crate::lightning::offers::refund::Refund) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Refund_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRefund) })
}
