// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Parsing and formatting for bech32 message encoding.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod sealed {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning::offers::parse::Bolt12ParseError as nativeBolt12ParseErrorImport;
pub(crate) type nativeBolt12ParseError = nativeBolt12ParseErrorImport;

/// Error when parsing a bech32 encoded message using [`str::parse`].
#[must_use]
#[repr(C)]
pub struct Bolt12ParseError {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12ParseError,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt12ParseError {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12ParseError>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12ParseError, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12ParseError_free(this_obj: Bolt12ParseError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12ParseError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12ParseError) };
}
#[allow(unused)]
impl Bolt12ParseError {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12ParseError {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12ParseError {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12ParseError {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Bolt12ParseError {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12ParseError>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12ParseError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBolt12ParseError)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12ParseError
pub extern "C" fn Bolt12ParseError_clone(orig: &Bolt12ParseError) -> Bolt12ParseError {
	orig.clone()
}
/// Error when interpreting a TLV stream as a specific type.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Bolt12SemanticError {
	/// The current [`std::time::SystemTime`] is past the offer or invoice's expiration.
	AlreadyExpired,
	/// The provided chain hash does not correspond to a supported chain.
	UnsupportedChain,
	/// A chain was provided but was not expected.
	UnexpectedChain,
	/// An amount was expected but was missing.
	MissingAmount,
	/// The amount exceeded the total bitcoin supply.
	InvalidAmount,
	/// An amount was provided but was not sufficient in value.
	InsufficientAmount,
	/// An amount was provided but was not expected.
	UnexpectedAmount,
	/// A currency was provided that is not supported.
	UnsupportedCurrency,
	/// A feature was required but is unknown.
	UnknownRequiredFeatures,
	/// Features were provided but were not expected.
	UnexpectedFeatures,
	/// A required description was not provided.
	MissingDescription,
	/// A signing pubkey was not provided.
	MissingSigningPubkey,
	/// A signing pubkey was provided but a different one was expected.
	InvalidSigningPubkey,
	/// A signing pubkey was provided but was not expected.
	UnexpectedSigningPubkey,
	/// A quantity was expected but was missing.
	MissingQuantity,
	/// An unsupported quantity was provided.
	InvalidQuantity,
	/// A quantity or quantity bounds was provided but was not expected.
	UnexpectedQuantity,
	/// Metadata could not be used to verify the offers message.
	InvalidMetadata,
	/// Metadata was provided but was not expected.
	UnexpectedMetadata,
	/// Payer metadata was expected but was missing.
	MissingPayerMetadata,
	/// A payer id was expected but was missing.
	MissingPayerId,
	/// Blinded paths were expected but were missing.
	MissingPaths,
	/// The blinded payinfo given does not match the number of blinded path hops.
	InvalidPayInfo,
	/// An invoice creation time was expected but was missing.
	MissingCreationTime,
	/// An invoice payment hash was expected but was missing.
	MissingPaymentHash,
	/// A signature was expected but was missing.
	MissingSignature,
}
use lightning::offers::parse::Bolt12SemanticError as Bolt12SemanticErrorImport;
pub(crate) type nativeBolt12SemanticError = Bolt12SemanticErrorImport;

impl Bolt12SemanticError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeBolt12SemanticError {
		match self {
			Bolt12SemanticError::AlreadyExpired => nativeBolt12SemanticError::AlreadyExpired,
			Bolt12SemanticError::UnsupportedChain => nativeBolt12SemanticError::UnsupportedChain,
			Bolt12SemanticError::UnexpectedChain => nativeBolt12SemanticError::UnexpectedChain,
			Bolt12SemanticError::MissingAmount => nativeBolt12SemanticError::MissingAmount,
			Bolt12SemanticError::InvalidAmount => nativeBolt12SemanticError::InvalidAmount,
			Bolt12SemanticError::InsufficientAmount => nativeBolt12SemanticError::InsufficientAmount,
			Bolt12SemanticError::UnexpectedAmount => nativeBolt12SemanticError::UnexpectedAmount,
			Bolt12SemanticError::UnsupportedCurrency => nativeBolt12SemanticError::UnsupportedCurrency,
			Bolt12SemanticError::UnknownRequiredFeatures => nativeBolt12SemanticError::UnknownRequiredFeatures,
			Bolt12SemanticError::UnexpectedFeatures => nativeBolt12SemanticError::UnexpectedFeatures,
			Bolt12SemanticError::MissingDescription => nativeBolt12SemanticError::MissingDescription,
			Bolt12SemanticError::MissingSigningPubkey => nativeBolt12SemanticError::MissingSigningPubkey,
			Bolt12SemanticError::InvalidSigningPubkey => nativeBolt12SemanticError::InvalidSigningPubkey,
			Bolt12SemanticError::UnexpectedSigningPubkey => nativeBolt12SemanticError::UnexpectedSigningPubkey,
			Bolt12SemanticError::MissingQuantity => nativeBolt12SemanticError::MissingQuantity,
			Bolt12SemanticError::InvalidQuantity => nativeBolt12SemanticError::InvalidQuantity,
			Bolt12SemanticError::UnexpectedQuantity => nativeBolt12SemanticError::UnexpectedQuantity,
			Bolt12SemanticError::InvalidMetadata => nativeBolt12SemanticError::InvalidMetadata,
			Bolt12SemanticError::UnexpectedMetadata => nativeBolt12SemanticError::UnexpectedMetadata,
			Bolt12SemanticError::MissingPayerMetadata => nativeBolt12SemanticError::MissingPayerMetadata,
			Bolt12SemanticError::MissingPayerId => nativeBolt12SemanticError::MissingPayerId,
			Bolt12SemanticError::MissingPaths => nativeBolt12SemanticError::MissingPaths,
			Bolt12SemanticError::InvalidPayInfo => nativeBolt12SemanticError::InvalidPayInfo,
			Bolt12SemanticError::MissingCreationTime => nativeBolt12SemanticError::MissingCreationTime,
			Bolt12SemanticError::MissingPaymentHash => nativeBolt12SemanticError::MissingPaymentHash,
			Bolt12SemanticError::MissingSignature => nativeBolt12SemanticError::MissingSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeBolt12SemanticError {
		match self {
			Bolt12SemanticError::AlreadyExpired => nativeBolt12SemanticError::AlreadyExpired,
			Bolt12SemanticError::UnsupportedChain => nativeBolt12SemanticError::UnsupportedChain,
			Bolt12SemanticError::UnexpectedChain => nativeBolt12SemanticError::UnexpectedChain,
			Bolt12SemanticError::MissingAmount => nativeBolt12SemanticError::MissingAmount,
			Bolt12SemanticError::InvalidAmount => nativeBolt12SemanticError::InvalidAmount,
			Bolt12SemanticError::InsufficientAmount => nativeBolt12SemanticError::InsufficientAmount,
			Bolt12SemanticError::UnexpectedAmount => nativeBolt12SemanticError::UnexpectedAmount,
			Bolt12SemanticError::UnsupportedCurrency => nativeBolt12SemanticError::UnsupportedCurrency,
			Bolt12SemanticError::UnknownRequiredFeatures => nativeBolt12SemanticError::UnknownRequiredFeatures,
			Bolt12SemanticError::UnexpectedFeatures => nativeBolt12SemanticError::UnexpectedFeatures,
			Bolt12SemanticError::MissingDescription => nativeBolt12SemanticError::MissingDescription,
			Bolt12SemanticError::MissingSigningPubkey => nativeBolt12SemanticError::MissingSigningPubkey,
			Bolt12SemanticError::InvalidSigningPubkey => nativeBolt12SemanticError::InvalidSigningPubkey,
			Bolt12SemanticError::UnexpectedSigningPubkey => nativeBolt12SemanticError::UnexpectedSigningPubkey,
			Bolt12SemanticError::MissingQuantity => nativeBolt12SemanticError::MissingQuantity,
			Bolt12SemanticError::InvalidQuantity => nativeBolt12SemanticError::InvalidQuantity,
			Bolt12SemanticError::UnexpectedQuantity => nativeBolt12SemanticError::UnexpectedQuantity,
			Bolt12SemanticError::InvalidMetadata => nativeBolt12SemanticError::InvalidMetadata,
			Bolt12SemanticError::UnexpectedMetadata => nativeBolt12SemanticError::UnexpectedMetadata,
			Bolt12SemanticError::MissingPayerMetadata => nativeBolt12SemanticError::MissingPayerMetadata,
			Bolt12SemanticError::MissingPayerId => nativeBolt12SemanticError::MissingPayerId,
			Bolt12SemanticError::MissingPaths => nativeBolt12SemanticError::MissingPaths,
			Bolt12SemanticError::InvalidPayInfo => nativeBolt12SemanticError::InvalidPayInfo,
			Bolt12SemanticError::MissingCreationTime => nativeBolt12SemanticError::MissingCreationTime,
			Bolt12SemanticError::MissingPaymentHash => nativeBolt12SemanticError::MissingPaymentHash,
			Bolt12SemanticError::MissingSignature => nativeBolt12SemanticError::MissingSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeBolt12SemanticError) -> Self {
		match native {
			nativeBolt12SemanticError::AlreadyExpired => Bolt12SemanticError::AlreadyExpired,
			nativeBolt12SemanticError::UnsupportedChain => Bolt12SemanticError::UnsupportedChain,
			nativeBolt12SemanticError::UnexpectedChain => Bolt12SemanticError::UnexpectedChain,
			nativeBolt12SemanticError::MissingAmount => Bolt12SemanticError::MissingAmount,
			nativeBolt12SemanticError::InvalidAmount => Bolt12SemanticError::InvalidAmount,
			nativeBolt12SemanticError::InsufficientAmount => Bolt12SemanticError::InsufficientAmount,
			nativeBolt12SemanticError::UnexpectedAmount => Bolt12SemanticError::UnexpectedAmount,
			nativeBolt12SemanticError::UnsupportedCurrency => Bolt12SemanticError::UnsupportedCurrency,
			nativeBolt12SemanticError::UnknownRequiredFeatures => Bolt12SemanticError::UnknownRequiredFeatures,
			nativeBolt12SemanticError::UnexpectedFeatures => Bolt12SemanticError::UnexpectedFeatures,
			nativeBolt12SemanticError::MissingDescription => Bolt12SemanticError::MissingDescription,
			nativeBolt12SemanticError::MissingSigningPubkey => Bolt12SemanticError::MissingSigningPubkey,
			nativeBolt12SemanticError::InvalidSigningPubkey => Bolt12SemanticError::InvalidSigningPubkey,
			nativeBolt12SemanticError::UnexpectedSigningPubkey => Bolt12SemanticError::UnexpectedSigningPubkey,
			nativeBolt12SemanticError::MissingQuantity => Bolt12SemanticError::MissingQuantity,
			nativeBolt12SemanticError::InvalidQuantity => Bolt12SemanticError::InvalidQuantity,
			nativeBolt12SemanticError::UnexpectedQuantity => Bolt12SemanticError::UnexpectedQuantity,
			nativeBolt12SemanticError::InvalidMetadata => Bolt12SemanticError::InvalidMetadata,
			nativeBolt12SemanticError::UnexpectedMetadata => Bolt12SemanticError::UnexpectedMetadata,
			nativeBolt12SemanticError::MissingPayerMetadata => Bolt12SemanticError::MissingPayerMetadata,
			nativeBolt12SemanticError::MissingPayerId => Bolt12SemanticError::MissingPayerId,
			nativeBolt12SemanticError::MissingPaths => Bolt12SemanticError::MissingPaths,
			nativeBolt12SemanticError::InvalidPayInfo => Bolt12SemanticError::InvalidPayInfo,
			nativeBolt12SemanticError::MissingCreationTime => Bolt12SemanticError::MissingCreationTime,
			nativeBolt12SemanticError::MissingPaymentHash => Bolt12SemanticError::MissingPaymentHash,
			nativeBolt12SemanticError::MissingSignature => Bolt12SemanticError::MissingSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeBolt12SemanticError) -> Self {
		match native {
			nativeBolt12SemanticError::AlreadyExpired => Bolt12SemanticError::AlreadyExpired,
			nativeBolt12SemanticError::UnsupportedChain => Bolt12SemanticError::UnsupportedChain,
			nativeBolt12SemanticError::UnexpectedChain => Bolt12SemanticError::UnexpectedChain,
			nativeBolt12SemanticError::MissingAmount => Bolt12SemanticError::MissingAmount,
			nativeBolt12SemanticError::InvalidAmount => Bolt12SemanticError::InvalidAmount,
			nativeBolt12SemanticError::InsufficientAmount => Bolt12SemanticError::InsufficientAmount,
			nativeBolt12SemanticError::UnexpectedAmount => Bolt12SemanticError::UnexpectedAmount,
			nativeBolt12SemanticError::UnsupportedCurrency => Bolt12SemanticError::UnsupportedCurrency,
			nativeBolt12SemanticError::UnknownRequiredFeatures => Bolt12SemanticError::UnknownRequiredFeatures,
			nativeBolt12SemanticError::UnexpectedFeatures => Bolt12SemanticError::UnexpectedFeatures,
			nativeBolt12SemanticError::MissingDescription => Bolt12SemanticError::MissingDescription,
			nativeBolt12SemanticError::MissingSigningPubkey => Bolt12SemanticError::MissingSigningPubkey,
			nativeBolt12SemanticError::InvalidSigningPubkey => Bolt12SemanticError::InvalidSigningPubkey,
			nativeBolt12SemanticError::UnexpectedSigningPubkey => Bolt12SemanticError::UnexpectedSigningPubkey,
			nativeBolt12SemanticError::MissingQuantity => Bolt12SemanticError::MissingQuantity,
			nativeBolt12SemanticError::InvalidQuantity => Bolt12SemanticError::InvalidQuantity,
			nativeBolt12SemanticError::UnexpectedQuantity => Bolt12SemanticError::UnexpectedQuantity,
			nativeBolt12SemanticError::InvalidMetadata => Bolt12SemanticError::InvalidMetadata,
			nativeBolt12SemanticError::UnexpectedMetadata => Bolt12SemanticError::UnexpectedMetadata,
			nativeBolt12SemanticError::MissingPayerMetadata => Bolt12SemanticError::MissingPayerMetadata,
			nativeBolt12SemanticError::MissingPayerId => Bolt12SemanticError::MissingPayerId,
			nativeBolt12SemanticError::MissingPaths => Bolt12SemanticError::MissingPaths,
			nativeBolt12SemanticError::InvalidPayInfo => Bolt12SemanticError::InvalidPayInfo,
			nativeBolt12SemanticError::MissingCreationTime => Bolt12SemanticError::MissingCreationTime,
			nativeBolt12SemanticError::MissingPaymentHash => Bolt12SemanticError::MissingPaymentHash,
			nativeBolt12SemanticError::MissingSignature => Bolt12SemanticError::MissingSignature,
		}
	}
}
/// Creates a copy of the Bolt12SemanticError
#[no_mangle]
pub extern "C" fn Bolt12SemanticError_clone(orig: &Bolt12SemanticError) -> Bolt12SemanticError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new AlreadyExpired-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_already_expired() -> Bolt12SemanticError {
	Bolt12SemanticError::AlreadyExpired}
#[no_mangle]
/// Utility method to constructs a new UnsupportedChain-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unsupported_chain() -> Bolt12SemanticError {
	Bolt12SemanticError::UnsupportedChain}
#[no_mangle]
/// Utility method to constructs a new UnexpectedChain-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_chain() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedChain}
#[no_mangle]
/// Utility method to constructs a new MissingAmount-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_amount() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingAmount}
#[no_mangle]
/// Utility method to constructs a new InvalidAmount-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_invalid_amount() -> Bolt12SemanticError {
	Bolt12SemanticError::InvalidAmount}
#[no_mangle]
/// Utility method to constructs a new InsufficientAmount-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_insufficient_amount() -> Bolt12SemanticError {
	Bolt12SemanticError::InsufficientAmount}
#[no_mangle]
/// Utility method to constructs a new UnexpectedAmount-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_amount() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedAmount}
#[no_mangle]
/// Utility method to constructs a new UnsupportedCurrency-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unsupported_currency() -> Bolt12SemanticError {
	Bolt12SemanticError::UnsupportedCurrency}
#[no_mangle]
/// Utility method to constructs a new UnknownRequiredFeatures-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unknown_required_features() -> Bolt12SemanticError {
	Bolt12SemanticError::UnknownRequiredFeatures}
#[no_mangle]
/// Utility method to constructs a new UnexpectedFeatures-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_features() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedFeatures}
#[no_mangle]
/// Utility method to constructs a new MissingDescription-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_description() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingDescription}
#[no_mangle]
/// Utility method to constructs a new MissingSigningPubkey-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_signing_pubkey() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingSigningPubkey}
#[no_mangle]
/// Utility method to constructs a new InvalidSigningPubkey-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_invalid_signing_pubkey() -> Bolt12SemanticError {
	Bolt12SemanticError::InvalidSigningPubkey}
#[no_mangle]
/// Utility method to constructs a new UnexpectedSigningPubkey-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_signing_pubkey() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedSigningPubkey}
#[no_mangle]
/// Utility method to constructs a new MissingQuantity-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_quantity() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingQuantity}
#[no_mangle]
/// Utility method to constructs a new InvalidQuantity-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_invalid_quantity() -> Bolt12SemanticError {
	Bolt12SemanticError::InvalidQuantity}
#[no_mangle]
/// Utility method to constructs a new UnexpectedQuantity-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_quantity() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedQuantity}
#[no_mangle]
/// Utility method to constructs a new InvalidMetadata-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_invalid_metadata() -> Bolt12SemanticError {
	Bolt12SemanticError::InvalidMetadata}
#[no_mangle]
/// Utility method to constructs a new UnexpectedMetadata-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_unexpected_metadata() -> Bolt12SemanticError {
	Bolt12SemanticError::UnexpectedMetadata}
#[no_mangle]
/// Utility method to constructs a new MissingPayerMetadata-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_payer_metadata() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingPayerMetadata}
#[no_mangle]
/// Utility method to constructs a new MissingPayerId-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_payer_id() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingPayerId}
#[no_mangle]
/// Utility method to constructs a new MissingPaths-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_paths() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingPaths}
#[no_mangle]
/// Utility method to constructs a new InvalidPayInfo-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_invalid_pay_info() -> Bolt12SemanticError {
	Bolt12SemanticError::InvalidPayInfo}
#[no_mangle]
/// Utility method to constructs a new MissingCreationTime-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_creation_time() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingCreationTime}
#[no_mangle]
/// Utility method to constructs a new MissingPaymentHash-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_payment_hash() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingPaymentHash}
#[no_mangle]
/// Utility method to constructs a new MissingSignature-variant Bolt12SemanticError
pub extern "C" fn Bolt12SemanticError_missing_signature() -> Bolt12SemanticError {
	Bolt12SemanticError::MissingSignature}
