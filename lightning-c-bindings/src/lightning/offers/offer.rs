// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Data structures and encoding for `offer` messages.
//!
//! An [`Offer`] represents an \"offer to be paid.\" It is typically constructed by a merchant and
//! published as a QR code to be scanned by a customer. The customer uses the offer to request an
//! invoice from the merchant to be paid.
//!
//! ```
//! extern crate bitcoin;
//! extern crate core;
//! extern crate lightning;
//!
//! use core::convert::TryFrom;
//! use core::num::NonZeroU64;
//! use core::time::Duration;
//!
//! use bitcoin::secp256k1::{KeyPair, PublicKey, Secp256k1, SecretKey};
//! use lightning::offers::offer::{Offer, OfferBuilder, Quantity};
//! use lightning::offers::parse::Bolt12ParseError;
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
//! # fn build() -> Result<(), Bolt12ParseError> {
//! let secp_ctx = Secp256k1::new();
//! let keys = KeyPair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
//! let pubkey = PublicKey::from(keys);
//!
//! let expiration = SystemTime::now() + Duration::from_secs(24 * 60 * 60);
//! let offer = OfferBuilder::new(\"coffee, large\".to_string(), pubkey)
//!     .amount_msats(20_000)
//!     .supported_quantity(Quantity::Unbounded)
//!     .absolute_expiry(expiration.duration_since(SystemTime::UNIX_EPOCH).unwrap())
//!     .issuer(\"Foo Bar\".to_string())
//!     .path(create_blinded_path())
//!     .path(create_another_blinded_path())
//!     .build()?;
//!
//! // Encode as a bech32 string for use in a QR code.
//! let encoded_offer = offer.to_string();
//!
//! // Parse from a bech32 string after scanning from a QR code.
//! let offer = encoded_offer.parse::<Offer>()?;
//!
//! // Encode offer as raw bytes.
//! let mut bytes = Vec::new();
//! offer.write(&mut bytes).unwrap();
//!
//! // Decode raw bytes into an offer.
//! let offer = Offer::try_from(bytes)?;
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


use lightning::offers::offer::Offer as nativeOfferImport;
pub(crate) type nativeOffer = nativeOfferImport;

/// An `Offer` is a potentially long-lived proposal for payment of a good or service.
///
/// An offer is a precursor to an [`InvoiceRequest`]. A merchant publishes an offer from which a
/// customer may request an [`Bolt12Invoice`] for a specific quantity and using an amount sufficient
/// to cover that quantity (i.e., at least `quantity * amount`). See [`Offer::amount`].
///
/// Offers may be denominated in currency other than bitcoin but are ultimately paid using the
/// latter.
///
/// Through the use of [`BlindedPath`]s, offers provide recipient privacy.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
#[must_use]
#[repr(C)]
pub struct Offer {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOffer,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Offer {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOffer>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Offer, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Offer_free(this_obj: Offer) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Offer_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOffer) };
}
#[allow(unused)]
impl Offer {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOffer {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOffer {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOffer {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Offer {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOffer>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Offer_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeOffer)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Offer
pub extern "C" fn Offer_clone(orig: &Offer) -> Offer {
	orig.clone()
}
/// The chains that may be used when paying a requested invoice (e.g., bitcoin mainnet).
/// Payments must be denominated in units of the minimal lightning-payable unit (e.g., msats)
/// for the selected chain.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_chains(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_ChainHashZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.chains();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::ThirtyTwoBytes { data: item.to_bytes() } }); };
	local_ret.into()
}

/// Returns whether the given chain is supported by the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_supports_chain(this_arg: &crate::lightning::offers::offer::Offer, mut chain: crate::c_types::ThirtyTwoBytes) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_chain(::bitcoin::blockdata::constants::ChainHash::from(&chain.data[..]));
	ret
}

/// Opaque bytes set by the originator. Useful for authentication and validating fields since it
/// is reflected in `invoice_request` messages along with all the other fields from the `offer`.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_metadata(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// The minimum amount required for a successful payment of a single item.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_amount(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::offers::offer::Amount {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount();
	let mut local_ret = crate::lightning::offers::offer::Amount { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::offers::offer::Amount<>) as *mut _ }, is_owned: false };
	local_ret
}

/// A complete description of the purpose of the payment. Intended to be displayed to the user
/// but with the caveat that it has not been verified in any way.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_description(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	crate::lightning::util::string::PrintableString { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Features pertaining to the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_features(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::ln::features::OfferFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	crate::lightning::ln::features::OfferFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::OfferFeatures<>) as *mut _) }, is_owned: false }
}

/// Duration since the Unix epoch when an invoice should no longer be requested.
///
/// If `None`, the offer does not expire.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_absolute_expiry(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::COption_DurationZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.absolute_expiry();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_DurationZ::None } else { crate::c_types::derived::COption_DurationZ::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// Whether the offer has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_is_expired(this_arg: &crate::lightning::offers::offer::Offer) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// The issuer of the offer, possibly beginning with `user@domain` or `domain`. Intended to be
/// displayed to the user but with the caveat that it has not been verified in any way.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_issuer(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::util::string::PrintableString {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.issuer();
	let mut local_ret = crate::lightning::util::string::PrintableString { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

/// Paths to the recipient originating from publicly reachable nodes. Blinded paths provide
/// recipient privacy by obfuscating its node id.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_paths(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_BlindedPathZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.paths();
	let mut local_ret_clone = Vec::new(); local_ret_clone.extend_from_slice(ret); let mut ret = local_ret_clone; let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// The quantity of items supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_supported_quantity(this_arg: &crate::lightning::offers::offer::Offer) -> crate::lightning::offers::offer::Quantity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supported_quantity();
	crate::lightning::offers::offer::Quantity { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns whether the given quantity is valid for the offer.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_is_valid_quantity(this_arg: &crate::lightning::offers::offer::Offer, mut quantity: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_valid_quantity(quantity);
	ret
}

/// Returns whether a quantity is expected in an [`InvoiceRequest`] for the offer.
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_expects_quantity(this_arg: &crate::lightning::offers::offer::Offer) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expects_quantity();
	ret
}

/// The public key used by the recipient to sign invoices.
#[must_use]
#[no_mangle]
pub extern "C" fn Offer_signing_pubkey(this_arg: &crate::lightning::offers::offer::Offer) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signing_pubkey();
	crate::c_types::PublicKey::from_rust(&ret)
}

#[no_mangle]
/// Serialize the Offer object into a byte array which can be read by Offer_read
pub extern "C" fn Offer_write(obj: &crate::lightning::offers::offer::Offer) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Offer_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeOffer) })
}

use lightning::offers::offer::Amount as nativeAmountImport;
pub(crate) type nativeAmount = nativeAmountImport;

/// The minimum amount required for an item in an [`Offer`], denominated in either bitcoin or
/// another currency.
#[must_use]
#[repr(C)]
pub struct Amount {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAmount,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Amount {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAmount>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Amount, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Amount_free(this_obj: Amount) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Amount_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAmount) };
}
#[allow(unused)]
impl Amount {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAmount {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAmount {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAmount {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Amount {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeAmount>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Amount_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeAmount)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Amount
pub extern "C" fn Amount_clone(orig: &Amount) -> Amount {
	orig.clone()
}

use lightning::offers::offer::Quantity as nativeQuantityImport;
pub(crate) type nativeQuantity = nativeQuantityImport;

/// Quantity of items supported by an [`Offer`].
#[must_use]
#[repr(C)]
pub struct Quantity {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeQuantity,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Quantity {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeQuantity>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Quantity, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Quantity_free(this_obj: Quantity) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Quantity_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeQuantity) };
}
#[allow(unused)]
impl Quantity {
	pub(crate) fn get_native_ref(&self) -> &'static nativeQuantity {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeQuantity {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeQuantity {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Quantity {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeQuantity>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Quantity_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeQuantity)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Quantity
pub extern "C" fn Quantity_clone(orig: &Quantity) -> Quantity {
	orig.clone()
}
#[no_mangle]
/// Read a Offer object from a string
pub extern "C" fn Offer_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_OfferBolt12ParseErrorZ {
	match lightning::offers::offer::Offer::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning::offers::offer::Offer { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning::offers::parse::Bolt12ParseError { inner: ObjOps::heap_alloc(e), is_owned: true }
			)
		},
	}.into()
}
