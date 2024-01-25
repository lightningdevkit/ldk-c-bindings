// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `invoice` messages.
//!
//! A [`Bolt12Invoice`] can be built from a parsed [`InvoiceRequest`] for the \"offer to be paid\"
//! flow or from a [`Refund`] as an \"offer for money\" flow. The expected recipient of the payment
//! then sends the invoice to the intended payer, who will then pay it.
//!
//! The payment recipient must include a [`PaymentHash`], so as to reveal the preimage upon payment
//! receipt, and one or more [`BlindedPath`]s for the payer to use when sending the payment.
//!
//! ```
//! extern crate bitcoin;
//! extern crate lightning;
//!
//! use bitcoin::hashes::Hash;
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use core::convert::{Infallible, TryFrom};
//! use lightning::offers::invoice_request::InvoiceRequest;
//! use lightning::offers::refund::Refund;
//! use lightning::util::ser::Writeable;
//!
//! # use lightning::ln::PaymentHash;
//! # use lightning::offers::invoice::BlindedPayInfo;
//! # use lightning::blinded_path::BlindedPath;
//! #
//! # fn create_payment_paths() -> Vec<(BlindedPayInfo, BlindedPath)> { unimplemented!() }
//! # fn create_payment_hash() -> PaymentHash { unimplemented!() }
//! #
//! # fn parse_invoice_request(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! let payment_paths = create_payment_paths();
//! let payment_hash = create_payment_hash();
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! let pubkey = PublicKey::from(keys);
//! let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! let mut buffer = Vec::new();
//!
//! // Invoice for the \"offer to be paid\" flow.
//! InvoiceRequest::try_from(bytes)?
//!
//!    .respond_with(payment_paths, payment_hash)?
//!
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign::<_, Infallible>(
//!         |message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! # fn parse_refund(bytes: Vec<u8>) -> Result<(), lightning::offers::parse::Bolt12ParseError> {
//! # let payment_paths = create_payment_paths();
//! # let payment_hash = create_payment_hash();
//! # let secp_ctx = Secp256k1::new();
//! # let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32])?);
//! # let pubkey = PublicKey::from(keys);
//! # let wpubkey_hash = bitcoin::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
//! # let mut buffer = Vec::new();
//!
//! // Invoice for the \"offer for money\" flow.
//! \"lnr1qcp4256ypq\"
//!     .parse::<Refund>()?
//!
//!    .respond_with(payment_paths, payment_hash, pubkey)?
//!
//!     .relative_expiry(3600)
//!     .allow_mpp()
//!     .fallback_v0_p2wpkh(&wpubkey_hash)
//!     .build()?
//!     .sign::<_, Infallible>(
//!         |message| Ok(secp_ctx.sign_schnorr_no_aux_rand(message.as_ref().as_digest(), &keys))
//!     )
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! ```

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice::UnsignedBolt12Invoice as nativeUnsignedBolt12InvoiceImport;
pub(crate) type nativeUnsignedBolt12Invoice = nativeUnsignedBolt12InvoiceImport;

/// A semantically valid [`Bolt12Invoice`] that hasn't been signed.
///
/// # Serialization
///
/// This is serialized as a TLV stream, which includes TLV records from the originating message. As
/// such, it may include unknown, odd TLV records.
#[must_use]
#[repr(C)]
pub struct UnsignedBolt12Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUnsignedBolt12Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for UnsignedBolt12Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUnsignedBolt12Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the UnsignedBolt12Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_free(this_obj: UnsignedBolt12Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn UnsignedBolt12Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUnsignedBolt12Invoice) };
}
#[allow(unused)]
impl UnsignedBolt12Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUnsignedBolt12Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUnsignedBolt12Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUnsignedBolt12Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Returns the [`TaggedHash`] of the invoice to sign.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_tagged_hash(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::offers::merkle::TaggedHash {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tagged_hash();
	crate::lightning::offers::merkle::TaggedHash { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::offers::merkle::TaggedHash<>) as *mut _) }, is_owned: false }
}


use lightning::offers::invoice::Bolt12Invoice as nativeBolt12InvoiceImport;
pub(crate) type nativeBolt12Invoice = nativeBolt12InvoiceImport;

/// A `Bolt12Invoice` is a payment request, typically corresponding to an [`Offer`] or a [`Refund`].
///
/// An invoice may be sent in response to an [`InvoiceRequest`] in the case of an offer or sent
/// directly after scanning a refund. It includes all the information needed to pay a recipient.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Refund`]: crate::offers::refund::Refund
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[repr(C)]
pub struct Bolt12Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt12Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12Invoice_free(this_obj: Bolt12Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12Invoice) };
}
#[allow(unused)]
impl Bolt12Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Bolt12Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt12Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12Invoice
pub extern "C" fn Bolt12Invoice_clone(orig: &Bolt12Invoice) -> Bolt12Invoice {
	orig.clone()
}
/// Get a string which allows debug introspection of a Bolt12Invoice object
pub extern "C" fn Bolt12Invoice_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice::Bolt12Invoice }).into()}
/// The chains that may be used when paying a requested invoice.
///
/// From [`Offer::chains`]; `None` if the invoice was created in response to a [`Refund`].
///
/// [`Offer::chains`]: crate::offers::offer::Offer::chains
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_offer_chains(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_chains();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::None } else { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); }; local_ret_0.into() }) };
	local_ret
}

/// The chain that must be used when paying the invoice; selected from [`offer_chains`] if the
/// invoice originated from an offer.
///
/// From [`InvoiceRequest::chain`] or [`Refund::chain`].
///
/// [`offer_chains`]: Self::offer_chains
/// [`InvoiceRequest::chain`]: crate::offers::invoice_request::InvoiceRequest::chain
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_chain(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer`].
///
/// From [`Offer::metadata`]; `None` if the invoice was created in response to a [`Refund`] or
/// if the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_metadata(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`]; `None` if the invoice was created in response to a [`Refund`] or if
/// the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_amount(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::offers::offer::Amount {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = crate::lightning::offers::offer::Amount { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::offers::offer::Amount<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Features pertaining to the originating [`Offer`].
///
/// From [`Offer::offer_features`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_offer_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::ln::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	let mut local_ret = crate::lightning::ln::features::OfferFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::ln::features::OfferFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

/// A complete description of the purpose of the originating offer or refund.
///
/// From [`Offer::description`] or [`Refund::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_description(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning::util::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// From [`Offer::absolute_expiry`] or [`Refund::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_absolute_expiry(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer or refund.
///
/// From [`Offer::issuer`] or [`Refund::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_issuer(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes.
///
/// From [`Offer::paths`] or [`Refund::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_message_paths(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_BlindedPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
///
/// From [`Offer::supported_quantity`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_supported_quantity(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	let mut local_ret = crate::lightning::offers::offer::Quantity { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// An unpredictable series of bytes from the payer.
///
/// From [`InvoiceRequest::payer_metadata`] or [`Refund::payer_metadata`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_metadata(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Features pertaining to requesting an invoice.
///
/// From [`InvoiceRequest::invoice_request_features`] or [`Refund::features`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_invoice_request_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::ln::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning::ln::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of items requested or refunded for.
///
/// From [`InvoiceRequest::quantity`] or [`Refund::quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_quantity(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request or to send an invoice for a
/// refund in case there are no [`message_paths`].
///
/// [`message_paths`]: Self::message_paths
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_id(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note reflected back in the invoice.
///
/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payer_note(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_created_at(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since [`Bolt12Invoice::created_at`] when the invoice has expired and therefore
/// should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_relative_expiry(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_is_expired(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_payment_hash(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}

/// The minimum amount required for a successful payment of the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_amount_msats(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_invoice_features(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::lightning::ln::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// The public key corresponding to the key used to sign the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// The chains that may be used when paying a requested invoice.
///
/// From [`Offer::chains`]; `None` if the invoice was created in response to a [`Refund`].
///
/// [`Offer::chains`]: crate::offers::offer::Offer::chains
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_offer_chains(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_chains();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::None } else { crate::c_types::derived::COption_CVec_ThirtyTwoBytesZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::c_types::ThirtyTwoBytes { data: *item.as_ref() } }); }; local_ret_0.into() }) };
	local_ret
}

/// The chain that must be used when paying the invoice; selected from [`offer_chains`] if the
/// invoice originated from an offer.
///
/// From [`InvoiceRequest::chain`] or [`Refund::chain`].
///
/// [`offer_chains`]: Self::offer_chains
/// [`InvoiceRequest::chain`]: crate::offers::invoice_request::InvoiceRequest::chain
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_chain(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chain();
	crate::c_types::ThirtyTwoBytes { data: *ret.as_ref() }
}

/// Opaque bytes set by the originating [`Offer`].
///
/// From [`Offer::metadata`]; `None` if the invoice was created in response to a [`Refund`] or
/// if the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::metadata`]: crate::offers::offer::Offer::metadata
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_metadata(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// From [`Offer::amount`]; `None` if the invoice was created in response to a [`Refund`] or if
/// the [`Offer`] did not set it.
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::amount`]: crate::offers::offer::Offer::amount
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_amount(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::offers::offer::Amount {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = crate::lightning::offers::offer::Amount { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::offers::offer::Amount<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Features pertaining to the originating [`Offer`].
///
/// From [`Offer::offer_features`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer`]: crate::offers::offer::Offer
/// [`Offer::offer_features`]: crate::offers::offer::Offer::offer_features
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_offer_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::ln::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.offer_features();
	let mut local_ret = crate::lightning::ln::features::OfferFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::ln::features::OfferFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

/// A complete description of the purpose of the originating offer or refund.
///
/// From [`Offer::description`] or [`Refund::description`].
///
/// [`Offer::description`]: crate::offers::offer::Offer::description
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_description(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning::util::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// From [`Offer::absolute_expiry`] or [`Refund::absolute_expiry`].
///
/// [`Offer::absolute_expiry`]: crate::offers::offer::Offer::absolute_expiry
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_absolute_expiry(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// The issuer of the offer or refund.
///
/// From [`Offer::issuer`] or [`Refund::issuer`].
///
/// [`Offer::issuer`]: crate::offers::offer::Offer::issuer
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_issuer(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes.
///
/// From [`Offer::paths`] or [`Refund::paths`].
///
/// [`Offer::paths`]: crate::offers::offer::Offer::paths
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_message_paths(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_BlindedPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.message_paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
///
/// From [`Offer::supported_quantity`]; `None` if the invoice was created in response to a
/// [`Refund`].
///
/// [`Offer::supported_quantity`]: crate::offers::offer::Offer::supported_quantity
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_supported_quantity(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	let mut local_ret = crate::lightning::offers::offer::Quantity { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// An unpredictable series of bytes from the payer.
///
/// From [`InvoiceRequest::payer_metadata`] or [`Refund::payer_metadata`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_metadata(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_metadata();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Features pertaining to requesting an invoice.
///
/// From [`InvoiceRequest::invoice_request_features`] or [`Refund::features`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_invoice_request_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::ln::features::InvoiceRequestFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_request_features();
	crate::lightning::ln::features::InvoiceRequestFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::InvoiceRequestFeatures<>) as *mut _) }, is_owned: false }
}

/// The quantity of items requested or refunded for.
///
/// From [`InvoiceRequest::quantity`] or [`Refund::quantity`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_quantity(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.quantity();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// A possibly transient pubkey used to sign the invoice request or to send an invoice for a
/// refund in case there are no [`message_paths`].
///
/// [`message_paths`]: Self::message_paths
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_id(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_id();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// A payer-provided note reflected back in the invoice.
///
/// From [`InvoiceRequest::payer_note`] or [`Refund::payer_note`].
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payer_note(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payer_note();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Duration since the Unix epoch when the invoice was created.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_created_at(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.created_at();
	ret.as_secs()
}

/// Duration since [`Bolt12Invoice::created_at`] when the invoice has expired and therefore
/// should no longer be paid.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_relative_expiry(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.relative_expiry();
	ret.as_secs()
}

/// Whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_is_expired(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// SHA256 hash of the payment preimage that will be given in return for paying the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_payment_hash(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}

/// The minimum amount required for a successful payment of the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_amount_msats(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_msats();
	ret
}

/// Features pertaining to paying an invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_invoice_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::ln::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.invoice_features();
	crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// The public key corresponding to the key used to sign the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Signature of the invoice verified using [`Bolt12Invoice::signing_pubkey`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signature(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::SchnorrSignature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signature();
	crate::c_types::SchnorrSignature::from_rust(&ret)
}

/// Hash that was used for signing the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signable_hash(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Verifies that the invoice was for a request or refund created using the given key. Returns
/// the associated [`PaymentId`] to use when sending the payment.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_verify(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> crate::c_types::derived::CResult_ThirtyTwoBytesNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify(key.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.0 } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

#[no_mangle]
/// Serialize the UnsignedBolt12Invoice object into a byte array which can be read by UnsignedBolt12Invoice_read
pub extern "C" fn UnsignedBolt12Invoice_write(obj: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn UnsignedBolt12Invoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeUnsignedBolt12Invoice) })
}
#[no_mangle]
/// Serialize the Bolt12Invoice object into a byte array which can be read by Bolt12Invoice_read
pub extern "C" fn Bolt12Invoice_write(obj: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12Invoice_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBolt12Invoice) })
}

use lightning::offers::invoice::BlindedPayInfo as nativeBlindedPayInfoImport;
pub(crate) type nativeBlindedPayInfo = nativeBlindedPayInfoImport;

/// Information needed to route a payment across a [`BlindedPath`].
#[must_use]
#[repr(C)]
pub struct BlindedPayInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedPayInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedPayInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedPayInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedPayInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_free(this_obj: BlindedPayInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPayInfo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedPayInfo) };
}
#[allow(unused)]
impl BlindedPayInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedPayInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedPayInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedPayInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Base fee charged (in millisatoshi) for the entire blinded path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_fee_base_msat(this_ptr: &BlindedPayInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_base_msat;
	*inner_val
}
/// Base fee charged (in millisatoshi) for the entire blinded path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_fee_base_msat(this_ptr: &mut BlindedPayInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_base_msat = val;
}
/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
/// (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_fee_proportional_millionths(this_ptr: &BlindedPayInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_proportional_millionths;
	*inner_val
}
/// Liquidity fee charged (in millionths of the amount transferred) for the entire blinded path
/// (i.e., 10,000 is 1%).
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_fee_proportional_millionths(this_ptr: &mut BlindedPayInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_proportional_millionths = val;
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
/// path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_cltv_expiry_delta(this_ptr: &BlindedPayInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// Number of blocks subtracted from an incoming HTLC's `cltv_expiry` for the entire blinded
/// path.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_cltv_expiry_delta(this_ptr: &mut BlindedPayInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_htlc_minimum_msat(this_ptr: &BlindedPayInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_htlc_minimum_msat(this_ptr: &mut BlindedPayInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_htlc_maximum_msat(this_ptr: &BlindedPayInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	*inner_val
}
/// The maximum HTLC value (in millisatoshi) that is acceptable to all channel peers on the
/// blinded path from the introduction node to the recipient, accounting for any fees, i.e., as
/// seen by the recipient.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_htlc_maximum_msat(this_ptr: &mut BlindedPayInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = val;
}
/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
/// onion payload.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_get_features(this_ptr: &BlindedPayInfo) -> crate::lightning::ln::features::BlindedHopFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning::ln::features::BlindedHopFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::BlindedHopFeatures<>) as *mut _) }, is_owned: false }
}
/// Features set in `encrypted_data_tlv` for the `encrypted_recipient_data` TLV record in an
/// onion payload.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_set_features(this_ptr: &mut BlindedPayInfo, mut val: crate::lightning::ln::features::BlindedHopFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new BlindedPayInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedPayInfo_new(mut fee_base_msat_arg: u32, mut fee_proportional_millionths_arg: u32, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: u64, mut htlc_maximum_msat_arg: u64, mut features_arg: crate::lightning::ln::features::BlindedHopFeatures) -> BlindedPayInfo {
	BlindedPayInfo { inner: ObjOps::heap_alloc(nativeBlindedPayInfo {
		fee_base_msat: fee_base_msat_arg,
		fee_proportional_millionths: fee_proportional_millionths_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
		htlc_maximum_msat: htlc_maximum_msat_arg,
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for BlindedPayInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedPayInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedPayInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedPayInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPayInfo
pub extern "C" fn BlindedPayInfo_clone(orig: &BlindedPayInfo) -> BlindedPayInfo {
	orig.clone()
}
/// Get a string which allows debug introspection of a BlindedPayInfo object
pub extern "C" fn BlindedPayInfo_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::offers::invoice::BlindedPayInfo }).into()}
/// Generates a non-cryptographic 64-bit hash of the BlindedPayInfo.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_hash(o: &BlindedPayInfo) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BlindedPayInfos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedPayInfo_eq(a: &BlindedPayInfo, b: &BlindedPayInfo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BlindedPayInfo object into a byte array which can be read by BlindedPayInfo_read
pub extern "C" fn BlindedPayInfo_write(obj: &crate::lightning::offers::invoice::BlindedPayInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedPayInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedPayInfo) })
}
#[no_mangle]
/// Read a BlindedPayInfo from a byte array, created by BlindedPayInfo_write
pub extern "C" fn BlindedPayInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedPayInfoDecodeErrorZ {
	let res: Result<lightning::offers::invoice::BlindedPayInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::offers::invoice::BlindedPayInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
