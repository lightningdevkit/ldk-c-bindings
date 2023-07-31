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
//! let wpubkey_hash = bitcoin::util::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
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
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
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
//! # let wpubkey_hash = bitcoin::util::key::PublicKey::new(pubkey).wpubkey_hash().unwrap();
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
//!     .sign::<_, Infallible>(|digest| Ok(secp_ctx.sign_schnorr_no_aux_rand(digest, &keys)))
//!     .expect(\"failed verifying signature\")
//!     .write(&mut buffer)
//!     .unwrap();
//! # Ok(())
//! # }
//!
//! ```

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::offers::invoice::UnsignedBolt12Invoice as nativeUnsignedBolt12InvoiceImport;
pub(crate) type nativeUnsignedBolt12Invoice = nativeUnsignedBolt12InvoiceImport<'static>;

/// A semantically valid [`Bolt12Invoice`] that hasn't been signed.
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
/// The public key corresponding to the key needed to sign the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn UnsignedBolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::UnsignedBolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBolt12Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12Invoice
pub extern "C" fn Bolt12Invoice_clone(orig: &Bolt12Invoice) -> Bolt12Invoice {
	orig.clone()
}
/// A complete description of the purpose of the originating offer or refund. Intended to be
/// displayed to the user but with the caveat that it has not been verified in any way.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_description(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning::util::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
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
pub extern "C" fn Bolt12Invoice_features(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::lightning::ln::features::Bolt12InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::Bolt12InvoiceFeatures<>) as *mut _) }, is_owned: false }
}

/// The public key corresponding to the key used to sign the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signing_pubkey(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Hash that was used for signing the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_signable_hash(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Verifies that the invoice was for a request or refund created using the given key.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12Invoice_verify(this_arg: &crate::lightning::offers::invoice::Bolt12Invoice, key: &crate::lightning::ln::inbound_payment::ExpandedKey) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify(key.get_native_ref(), secp256k1::global::SECP256K1);
	ret
}

#[no_mangle]
/// Serialize the Bolt12Invoice object into a byte array which can be read by Bolt12Invoice_read
pub extern "C" fn Bolt12Invoice_write(obj: &crate::lightning::offers::invoice::Bolt12Invoice) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
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
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBlindedPayInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedPayInfo
pub extern "C" fn BlindedPayInfo_clone(orig: &BlindedPayInfo) -> BlindedPayInfo {
	orig.clone()
}
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
#[no_mangle]
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
