// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This crate provides data structures to represent
//! [lightning BOLT11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
//! invoices and functions to create, encode and decode these. If you just want to use the standard
//! en-/decoding functionality this should get you started:
//!
//!   * For parsing use `str::parse::<Bolt11Invoice>(&self)` (see [`Bolt11Invoice::from_str`])
//!   * For constructing invoices use the [`InvoiceBuilder`]
//!   * For serializing invoices use the [`Display`]/[`ToString`] traits
//!
//! [`Bolt11Invoice::from_str`]: crate::Bolt11Invoice#impl-FromStr

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod payment;
pub mod utils;
pub mod constants;
mod time_utils {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod de {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod hrp_sm {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
#[no_mangle]
/// Read a SiPrefix object from a string
pub extern "C" fn SiPrefix_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_SiPrefixBolt11ParseErrorZ {
	match lightning_invoice::SiPrefix::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::SiPrefix::native_into(r)
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning_invoice::Bolt11ParseError::native_into(e)
			)
		},
	}.into()
}
#[no_mangle]
/// Read a Bolt11Invoice object from a string
pub extern "C" fn Bolt11Invoice_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_Bolt11InvoiceParseOrSemanticErrorZ {
	match lightning_invoice::Bolt11Invoice::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning_invoice::ParseOrSemanticError::native_into(e)
			)
		},
	}.into()
}
#[no_mangle]
/// Read a SignedRawBolt11Invoice object from a string
pub extern "C" fn SignedRawBolt11Invoice_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_SignedRawBolt11InvoiceBolt11ParseErrorZ {
	match lightning_invoice::SignedRawBolt11Invoice::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::SignedRawBolt11Invoice { inner: ObjOps::heap_alloc(r), is_owned: true }
			)
		},
		Err(e) => {
			crate::c_types::CResultTempl::err(
				crate::lightning_invoice::Bolt11ParseError::native_into(e)
			)
		},
	}.into()
}
#[no_mangle]
/// Get the string representation of a Bolt11ParseError object
pub extern "C" fn Bolt11ParseError_to_str(o: &crate::lightning_invoice::Bolt11ParseError) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
#[no_mangle]
/// Get the string representation of a ParseOrSemanticError object
pub extern "C" fn ParseOrSemanticError_to_str(o: &crate::lightning_invoice::ParseOrSemanticError) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
}
mod ser {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

#[no_mangle]
/// Get the string representation of a Bolt11Invoice object
pub extern "C" fn Bolt11Invoice_to_str(o: &crate::lightning_invoice::Bolt11Invoice) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
#[no_mangle]
/// Get the string representation of a SignedRawBolt11Invoice object
pub extern "C" fn SignedRawBolt11Invoice_to_str(o: &crate::lightning_invoice::SignedRawBolt11Invoice) -> Str {
	alloc::format!("{}", o.get_native_ref()).into()
}
#[no_mangle]
/// Get the string representation of a Currency object
pub extern "C" fn Currency_to_str(o: &crate::lightning_invoice::Currency) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
#[no_mangle]
/// Get the string representation of a SiPrefix object
pub extern "C" fn SiPrefix_to_str(o: &crate::lightning_invoice::SiPrefix) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
}
mod tb {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod prelude {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod sync {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
/// Errors that indicate what is wrong with the invoice. They have some granularity for debug
/// reasons, but should generally result in an \"invalid BOLT11 invoice\" message for the user.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Bolt11ParseError {
	Bech32Error(
		crate::c_types::Bech32Error),
	ParseAmountError(
		crate::c_types::Error),
	MalformedSignature(
		crate::c_types::Secp256k1Error),
	BadPrefix,
	UnknownCurrency,
	UnknownSiPrefix,
	MalformedHRP,
	TooShortDataPart,
	UnexpectedEndOfTaggedFields,
	DescriptionDecodeError(
		crate::c_types::Error),
	PaddingError,
	IntegerOverflowError,
	InvalidSegWitProgramLength,
	InvalidPubKeyHashLength,
	InvalidScriptHashLength,
	InvalidRecoveryId,
	InvalidSliceLength(
		crate::c_types::Str),
	/// Not an error, but used internally to signal that a part of the invoice should be ignored
	/// according to BOLT11
	Skip,
}
use lightning_invoice::Bolt11ParseError as Bolt11ParseErrorImport;
pub(crate) type nativeBolt11ParseError = Bolt11ParseErrorImport;

impl Bolt11ParseError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeBolt11ParseError {
		match self {
			Bolt11ParseError::Bech32Error (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeBolt11ParseError::Bech32Error (
					a_nonref.into_rust(),
				)
			},
			Bolt11ParseError::ParseAmountError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeBolt11ParseError::ParseAmountError (
					u8::from_str_radix(" a", 10).unwrap_err() /*a_nonref*/,
				)
			},
			Bolt11ParseError::MalformedSignature (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeBolt11ParseError::MalformedSignature (
					a_nonref.into_rust(),
				)
			},
			Bolt11ParseError::BadPrefix => nativeBolt11ParseError::BadPrefix,
			Bolt11ParseError::UnknownCurrency => nativeBolt11ParseError::UnknownCurrency,
			Bolt11ParseError::UnknownSiPrefix => nativeBolt11ParseError::UnknownSiPrefix,
			Bolt11ParseError::MalformedHRP => nativeBolt11ParseError::MalformedHRP,
			Bolt11ParseError::TooShortDataPart => nativeBolt11ParseError::TooShortDataPart,
			Bolt11ParseError::UnexpectedEndOfTaggedFields => nativeBolt11ParseError::UnexpectedEndOfTaggedFields,
			Bolt11ParseError::DescriptionDecodeError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeBolt11ParseError::DescriptionDecodeError (
					core::str::from_utf8(&[0xff]).unwrap_err() /*a_nonref*/,
				)
			},
			Bolt11ParseError::PaddingError => nativeBolt11ParseError::PaddingError,
			Bolt11ParseError::IntegerOverflowError => nativeBolt11ParseError::IntegerOverflowError,
			Bolt11ParseError::InvalidSegWitProgramLength => nativeBolt11ParseError::InvalidSegWitProgramLength,
			Bolt11ParseError::InvalidPubKeyHashLength => nativeBolt11ParseError::InvalidPubKeyHashLength,
			Bolt11ParseError::InvalidScriptHashLength => nativeBolt11ParseError::InvalidScriptHashLength,
			Bolt11ParseError::InvalidRecoveryId => nativeBolt11ParseError::InvalidRecoveryId,
			Bolt11ParseError::InvalidSliceLength (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeBolt11ParseError::InvalidSliceLength (
					a_nonref.into_string(),
				)
			},
			Bolt11ParseError::Skip => nativeBolt11ParseError::Skip,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeBolt11ParseError {
		match self {
			Bolt11ParseError::Bech32Error (mut a, ) => {
				nativeBolt11ParseError::Bech32Error (
					a.into_rust(),
				)
			},
			Bolt11ParseError::ParseAmountError (mut a, ) => {
				nativeBolt11ParseError::ParseAmountError (
					u8::from_str_radix(" a", 10).unwrap_err() /*a*/,
				)
			},
			Bolt11ParseError::MalformedSignature (mut a, ) => {
				nativeBolt11ParseError::MalformedSignature (
					a.into_rust(),
				)
			},
			Bolt11ParseError::BadPrefix => nativeBolt11ParseError::BadPrefix,
			Bolt11ParseError::UnknownCurrency => nativeBolt11ParseError::UnknownCurrency,
			Bolt11ParseError::UnknownSiPrefix => nativeBolt11ParseError::UnknownSiPrefix,
			Bolt11ParseError::MalformedHRP => nativeBolt11ParseError::MalformedHRP,
			Bolt11ParseError::TooShortDataPart => nativeBolt11ParseError::TooShortDataPart,
			Bolt11ParseError::UnexpectedEndOfTaggedFields => nativeBolt11ParseError::UnexpectedEndOfTaggedFields,
			Bolt11ParseError::DescriptionDecodeError (mut a, ) => {
				nativeBolt11ParseError::DescriptionDecodeError (
					core::str::from_utf8(&[0xff]).unwrap_err() /*a*/,
				)
			},
			Bolt11ParseError::PaddingError => nativeBolt11ParseError::PaddingError,
			Bolt11ParseError::IntegerOverflowError => nativeBolt11ParseError::IntegerOverflowError,
			Bolt11ParseError::InvalidSegWitProgramLength => nativeBolt11ParseError::InvalidSegWitProgramLength,
			Bolt11ParseError::InvalidPubKeyHashLength => nativeBolt11ParseError::InvalidPubKeyHashLength,
			Bolt11ParseError::InvalidScriptHashLength => nativeBolt11ParseError::InvalidScriptHashLength,
			Bolt11ParseError::InvalidRecoveryId => nativeBolt11ParseError::InvalidRecoveryId,
			Bolt11ParseError::InvalidSliceLength (mut a, ) => {
				nativeBolt11ParseError::InvalidSliceLength (
					a.into_string(),
				)
			},
			Bolt11ParseError::Skip => nativeBolt11ParseError::Skip,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeBolt11ParseError) -> Self {
		match native {
			nativeBolt11ParseError::Bech32Error (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Bolt11ParseError::Bech32Error (
					crate::c_types::Bech32Error::from_rust(a_nonref),
				)
			},
			nativeBolt11ParseError::ParseAmountError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Bolt11ParseError::ParseAmountError (
					crate::c_types::Error { _dummy: 0 } /*a_nonref*/,
				)
			},
			nativeBolt11ParseError::MalformedSignature (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Bolt11ParseError::MalformedSignature (
					crate::c_types::Secp256k1Error::from_rust(a_nonref),
				)
			},
			nativeBolt11ParseError::BadPrefix => Bolt11ParseError::BadPrefix,
			nativeBolt11ParseError::UnknownCurrency => Bolt11ParseError::UnknownCurrency,
			nativeBolt11ParseError::UnknownSiPrefix => Bolt11ParseError::UnknownSiPrefix,
			nativeBolt11ParseError::MalformedHRP => Bolt11ParseError::MalformedHRP,
			nativeBolt11ParseError::TooShortDataPart => Bolt11ParseError::TooShortDataPart,
			nativeBolt11ParseError::UnexpectedEndOfTaggedFields => Bolt11ParseError::UnexpectedEndOfTaggedFields,
			nativeBolt11ParseError::DescriptionDecodeError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Bolt11ParseError::DescriptionDecodeError (
					crate::c_types::Error { _dummy: 0 } /*a_nonref*/,
				)
			},
			nativeBolt11ParseError::PaddingError => Bolt11ParseError::PaddingError,
			nativeBolt11ParseError::IntegerOverflowError => Bolt11ParseError::IntegerOverflowError,
			nativeBolt11ParseError::InvalidSegWitProgramLength => Bolt11ParseError::InvalidSegWitProgramLength,
			nativeBolt11ParseError::InvalidPubKeyHashLength => Bolt11ParseError::InvalidPubKeyHashLength,
			nativeBolt11ParseError::InvalidScriptHashLength => Bolt11ParseError::InvalidScriptHashLength,
			nativeBolt11ParseError::InvalidRecoveryId => Bolt11ParseError::InvalidRecoveryId,
			nativeBolt11ParseError::InvalidSliceLength (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Bolt11ParseError::InvalidSliceLength (
					a_nonref.into(),
				)
			},
			nativeBolt11ParseError::Skip => Bolt11ParseError::Skip,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeBolt11ParseError) -> Self {
		match native {
			nativeBolt11ParseError::Bech32Error (mut a, ) => {
				Bolt11ParseError::Bech32Error (
					crate::c_types::Bech32Error::from_rust(a),
				)
			},
			nativeBolt11ParseError::ParseAmountError (mut a, ) => {
				Bolt11ParseError::ParseAmountError (
					crate::c_types::Error { _dummy: 0 } /*a*/,
				)
			},
			nativeBolt11ParseError::MalformedSignature (mut a, ) => {
				Bolt11ParseError::MalformedSignature (
					crate::c_types::Secp256k1Error::from_rust(a),
				)
			},
			nativeBolt11ParseError::BadPrefix => Bolt11ParseError::BadPrefix,
			nativeBolt11ParseError::UnknownCurrency => Bolt11ParseError::UnknownCurrency,
			nativeBolt11ParseError::UnknownSiPrefix => Bolt11ParseError::UnknownSiPrefix,
			nativeBolt11ParseError::MalformedHRP => Bolt11ParseError::MalformedHRP,
			nativeBolt11ParseError::TooShortDataPart => Bolt11ParseError::TooShortDataPart,
			nativeBolt11ParseError::UnexpectedEndOfTaggedFields => Bolt11ParseError::UnexpectedEndOfTaggedFields,
			nativeBolt11ParseError::DescriptionDecodeError (mut a, ) => {
				Bolt11ParseError::DescriptionDecodeError (
					crate::c_types::Error { _dummy: 0 } /*a*/,
				)
			},
			nativeBolt11ParseError::PaddingError => Bolt11ParseError::PaddingError,
			nativeBolt11ParseError::IntegerOverflowError => Bolt11ParseError::IntegerOverflowError,
			nativeBolt11ParseError::InvalidSegWitProgramLength => Bolt11ParseError::InvalidSegWitProgramLength,
			nativeBolt11ParseError::InvalidPubKeyHashLength => Bolt11ParseError::InvalidPubKeyHashLength,
			nativeBolt11ParseError::InvalidScriptHashLength => Bolt11ParseError::InvalidScriptHashLength,
			nativeBolt11ParseError::InvalidRecoveryId => Bolt11ParseError::InvalidRecoveryId,
			nativeBolt11ParseError::InvalidSliceLength (mut a, ) => {
				Bolt11ParseError::InvalidSliceLength (
					a.into(),
				)
			},
			nativeBolt11ParseError::Skip => Bolt11ParseError::Skip,
		}
	}
}
/// Frees any resources used by the Bolt11ParseError
#[no_mangle]
pub extern "C" fn Bolt11ParseError_free(this_ptr: Bolt11ParseError) { }
/// Creates a copy of the Bolt11ParseError
#[no_mangle]
pub extern "C" fn Bolt11ParseError_clone(orig: &Bolt11ParseError) -> Bolt11ParseError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Bech32Error-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_bech32_error(a: crate::c_types::Bech32Error) -> Bolt11ParseError {
	Bolt11ParseError::Bech32Error(a, )
}
#[no_mangle]
/// Utility method to constructs a new ParseAmountError-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_parse_amount_error(a: crate::c_types::Error) -> Bolt11ParseError {
	Bolt11ParseError::ParseAmountError(a, )
}
#[no_mangle]
/// Utility method to constructs a new MalformedSignature-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_malformed_signature(a: crate::c_types::Secp256k1Error) -> Bolt11ParseError {
	Bolt11ParseError::MalformedSignature(a, )
}
#[no_mangle]
/// Utility method to constructs a new BadPrefix-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_bad_prefix() -> Bolt11ParseError {
	Bolt11ParseError::BadPrefix}
#[no_mangle]
/// Utility method to constructs a new UnknownCurrency-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_unknown_currency() -> Bolt11ParseError {
	Bolt11ParseError::UnknownCurrency}
#[no_mangle]
/// Utility method to constructs a new UnknownSiPrefix-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_unknown_si_prefix() -> Bolt11ParseError {
	Bolt11ParseError::UnknownSiPrefix}
#[no_mangle]
/// Utility method to constructs a new MalformedHRP-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_malformed_hrp() -> Bolt11ParseError {
	Bolt11ParseError::MalformedHRP}
#[no_mangle]
/// Utility method to constructs a new TooShortDataPart-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_too_short_data_part() -> Bolt11ParseError {
	Bolt11ParseError::TooShortDataPart}
#[no_mangle]
/// Utility method to constructs a new UnexpectedEndOfTaggedFields-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_unexpected_end_of_tagged_fields() -> Bolt11ParseError {
	Bolt11ParseError::UnexpectedEndOfTaggedFields}
#[no_mangle]
/// Utility method to constructs a new DescriptionDecodeError-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_description_decode_error(a: crate::c_types::Error) -> Bolt11ParseError {
	Bolt11ParseError::DescriptionDecodeError(a, )
}
#[no_mangle]
/// Utility method to constructs a new PaddingError-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_padding_error() -> Bolt11ParseError {
	Bolt11ParseError::PaddingError}
#[no_mangle]
/// Utility method to constructs a new IntegerOverflowError-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_integer_overflow_error() -> Bolt11ParseError {
	Bolt11ParseError::IntegerOverflowError}
#[no_mangle]
/// Utility method to constructs a new InvalidSegWitProgramLength-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_invalid_seg_wit_program_length() -> Bolt11ParseError {
	Bolt11ParseError::InvalidSegWitProgramLength}
#[no_mangle]
/// Utility method to constructs a new InvalidPubKeyHashLength-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_invalid_pub_key_hash_length() -> Bolt11ParseError {
	Bolt11ParseError::InvalidPubKeyHashLength}
#[no_mangle]
/// Utility method to constructs a new InvalidScriptHashLength-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_invalid_script_hash_length() -> Bolt11ParseError {
	Bolt11ParseError::InvalidScriptHashLength}
#[no_mangle]
/// Utility method to constructs a new InvalidRecoveryId-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_invalid_recovery_id() -> Bolt11ParseError {
	Bolt11ParseError::InvalidRecoveryId}
#[no_mangle]
/// Utility method to constructs a new InvalidSliceLength-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_invalid_slice_length(a: crate::c_types::Str) -> Bolt11ParseError {
	Bolt11ParseError::InvalidSliceLength(a, )
}
#[no_mangle]
/// Utility method to constructs a new Skip-variant Bolt11ParseError
pub extern "C" fn Bolt11ParseError_skip() -> Bolt11ParseError {
	Bolt11ParseError::Skip}
/// Checks if two Bolt11ParseErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Bolt11ParseError_eq(a: &Bolt11ParseError, b: &Bolt11ParseError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Indicates that something went wrong while parsing or validating the invoice. Parsing errors
/// should be mostly seen as opaque and are only there for debugging reasons. Semantic errors
/// like wrong signatures, missing fields etc. could mean that someone tampered with the invoice.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ParseOrSemanticError {
	/// The invoice couldn't be decoded
	ParseError(
		crate::lightning_invoice::Bolt11ParseError),
	/// The invoice could be decoded but violates the BOLT11 standard
	SemanticError(
		crate::lightning_invoice::Bolt11SemanticError),
}
use lightning_invoice::ParseOrSemanticError as ParseOrSemanticErrorImport;
pub(crate) type nativeParseOrSemanticError = ParseOrSemanticErrorImport;

impl ParseOrSemanticError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeParseOrSemanticError {
		match self {
			ParseOrSemanticError::ParseError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeParseOrSemanticError::ParseError (
					a_nonref.into_native(),
				)
			},
			ParseOrSemanticError::SemanticError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeParseOrSemanticError::SemanticError (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeParseOrSemanticError {
		match self {
			ParseOrSemanticError::ParseError (mut a, ) => {
				nativeParseOrSemanticError::ParseError (
					a.into_native(),
				)
			},
			ParseOrSemanticError::SemanticError (mut a, ) => {
				nativeParseOrSemanticError::SemanticError (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeParseOrSemanticError) -> Self {
		match native {
			nativeParseOrSemanticError::ParseError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				ParseOrSemanticError::ParseError (
					crate::lightning_invoice::Bolt11ParseError::native_into(a_nonref),
				)
			},
			nativeParseOrSemanticError::SemanticError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				ParseOrSemanticError::SemanticError (
					crate::lightning_invoice::Bolt11SemanticError::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeParseOrSemanticError) -> Self {
		match native {
			nativeParseOrSemanticError::ParseError (mut a, ) => {
				ParseOrSemanticError::ParseError (
					crate::lightning_invoice::Bolt11ParseError::native_into(a),
				)
			},
			nativeParseOrSemanticError::SemanticError (mut a, ) => {
				ParseOrSemanticError::SemanticError (
					crate::lightning_invoice::Bolt11SemanticError::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the ParseOrSemanticError
#[no_mangle]
pub extern "C" fn ParseOrSemanticError_free(this_ptr: ParseOrSemanticError) { }
/// Creates a copy of the ParseOrSemanticError
#[no_mangle]
pub extern "C" fn ParseOrSemanticError_clone(orig: &ParseOrSemanticError) -> ParseOrSemanticError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new ParseError-variant ParseOrSemanticError
pub extern "C" fn ParseOrSemanticError_parse_error(a: crate::lightning_invoice::Bolt11ParseError) -> ParseOrSemanticError {
	ParseOrSemanticError::ParseError(a, )
}
#[no_mangle]
/// Utility method to constructs a new SemanticError-variant ParseOrSemanticError
pub extern "C" fn ParseOrSemanticError_semantic_error(a: crate::lightning_invoice::Bolt11SemanticError) -> ParseOrSemanticError {
	ParseOrSemanticError::SemanticError(a, )
}
/// Checks if two ParseOrSemanticErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ParseOrSemanticError_eq(a: &ParseOrSemanticError, b: &ParseOrSemanticError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// The maximum timestamp as [`Duration::as_secs`] since the Unix epoch allowed by [`BOLT 11`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

#[no_mangle]
pub static MAX_TIMESTAMP: u64 = lightning_invoice::MAX_TIMESTAMP;
/// Default expiry time as defined by [BOLT 11].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

#[no_mangle]
pub static DEFAULT_EXPIRY_TIME: u64 = lightning_invoice::DEFAULT_EXPIRY_TIME;
/// Default minimum final CLTV expiry as defined by [BOLT 11].
///
/// Note that this is *not* the same value as rust-lightning's minimum CLTV expiry, which is
/// provided in [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
///
/// [BOLT 11]: https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA

#[no_mangle]
pub static DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA: u64 = lightning_invoice::DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA;

use lightning_invoice::Bolt11Invoice as nativeBolt11InvoiceImport;
pub(crate) type nativeBolt11Invoice = nativeBolt11InvoiceImport;

/// Represents a syntactically and semantically correct lightning BOLT11 invoice.
///
/// There are three ways to construct a `Bolt11Invoice`:
///  1. using [`InvoiceBuilder`]
///  2. using [`Bolt11Invoice::from_signed`]
///  3. using `str::parse::<Bolt11Invoice>(&str)` (see [`Bolt11Invoice::from_str`])
///
/// [`Bolt11Invoice::from_str`]: crate::Bolt11Invoice#impl-FromStr
#[must_use]
#[repr(C)]
pub struct Bolt11Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt11Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt11Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt11Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt11Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt11Invoice_free(this_obj: Bolt11Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt11Invoice) };
}
#[allow(unused)]
impl Bolt11Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt11Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt11Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt11Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Checks if two Bolt11Invoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt11Invoice_eq(a: &Bolt11Invoice, b: &Bolt11Invoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for Bolt11Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt11Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBolt11Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt11Invoice
pub extern "C" fn Bolt11Invoice_clone(orig: &Bolt11Invoice) -> Bolt11Invoice {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Bolt11Invoice.
#[no_mangle]
pub extern "C" fn Bolt11Invoice_hash(o: &Bolt11Invoice) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_invoice::SignedRawBolt11Invoice as nativeSignedRawBolt11InvoiceImport;
pub(crate) type nativeSignedRawBolt11Invoice = nativeSignedRawBolt11InvoiceImport;

/// Represents a signed [`RawBolt11Invoice`] with cached hash. The signature is not checked and may be
/// invalid.
///
/// # Invariants
/// The hash has to be either from the deserialized invoice or from the serialized [`RawBolt11Invoice`].
#[must_use]
#[repr(C)]
pub struct SignedRawBolt11Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeSignedRawBolt11Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for SignedRawBolt11Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeSignedRawBolt11Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the SignedRawBolt11Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_free(this_obj: SignedRawBolt11Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SignedRawBolt11Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeSignedRawBolt11Invoice) };
}
#[allow(unused)]
impl SignedRawBolt11Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeSignedRawBolt11Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeSignedRawBolt11Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeSignedRawBolt11Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Checks if two SignedRawBolt11Invoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_eq(a: &SignedRawBolt11Invoice, b: &SignedRawBolt11Invoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for SignedRawBolt11Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeSignedRawBolt11Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SignedRawBolt11Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeSignedRawBolt11Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the SignedRawBolt11Invoice
pub extern "C" fn SignedRawBolt11Invoice_clone(orig: &SignedRawBolt11Invoice) -> SignedRawBolt11Invoice {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the SignedRawBolt11Invoice.
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_hash(o: &SignedRawBolt11Invoice) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_invoice::RawBolt11Invoice as nativeRawBolt11InvoiceImport;
pub(crate) type nativeRawBolt11Invoice = nativeRawBolt11InvoiceImport;

/// Represents an syntactically correct [`Bolt11Invoice`] for a payment on the lightning network,
/// but without the signature information.
/// Decoding and encoding should not lead to information loss but may lead to different hashes.
///
/// For methods without docs see the corresponding methods in [`Bolt11Invoice`].
#[must_use]
#[repr(C)]
pub struct RawBolt11Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRawBolt11Invoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RawBolt11Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRawBolt11Invoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RawBolt11Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_free(this_obj: RawBolt11Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawBolt11Invoice_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRawBolt11Invoice) };
}
#[allow(unused)]
impl RawBolt11Invoice {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRawBolt11Invoice {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRawBolt11Invoice {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRawBolt11Invoice {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// data part
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_get_data(this_ptr: &RawBolt11Invoice) -> crate::lightning_invoice::RawDataPart {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().data;
	crate::lightning_invoice::RawDataPart { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_invoice::RawDataPart<>) as *mut _) }, is_owned: false }
}
/// data part
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_set_data(this_ptr: &mut RawBolt11Invoice, mut val: crate::lightning_invoice::RawDataPart) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.data = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Checks if two RawBolt11Invoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_eq(a: &RawBolt11Invoice, b: &RawBolt11Invoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RawBolt11Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRawBolt11Invoice>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawBolt11Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRawBolt11Invoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RawBolt11Invoice
pub extern "C" fn RawBolt11Invoice_clone(orig: &RawBolt11Invoice) -> RawBolt11Invoice {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the RawBolt11Invoice.
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_hash(o: &RawBolt11Invoice) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_invoice::RawDataPart as nativeRawDataPartImport;
pub(crate) type nativeRawDataPart = nativeRawDataPartImport;

/// Data of the [`RawBolt11Invoice`] that is encoded in the data part
#[must_use]
#[repr(C)]
pub struct RawDataPart {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRawDataPart,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RawDataPart {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRawDataPart>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RawDataPart, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RawDataPart_free(this_obj: RawDataPart) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawDataPart_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRawDataPart) };
}
#[allow(unused)]
impl RawDataPart {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRawDataPart {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRawDataPart {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRawDataPart {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// generation time of the invoice
#[no_mangle]
pub extern "C" fn RawDataPart_get_timestamp(this_ptr: &RawDataPart) -> crate::lightning_invoice::PositiveTimestamp {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().timestamp;
	crate::lightning_invoice::PositiveTimestamp { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning_invoice::PositiveTimestamp<>) as *mut _) }, is_owned: false }
}
/// generation time of the invoice
#[no_mangle]
pub extern "C" fn RawDataPart_set_timestamp(this_ptr: &mut RawDataPart, mut val: crate::lightning_invoice::PositiveTimestamp) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.timestamp = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Checks if two RawDataParts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RawDataPart_eq(a: &RawDataPart, b: &RawDataPart) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RawDataPart {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRawDataPart>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawDataPart_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRawDataPart)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RawDataPart
pub extern "C" fn RawDataPart_clone(orig: &RawDataPart) -> RawDataPart {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the RawDataPart.
#[no_mangle]
pub extern "C" fn RawDataPart_hash(o: &RawDataPart) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}

use lightning_invoice::PositiveTimestamp as nativePositiveTimestampImport;
pub(crate) type nativePositiveTimestamp = nativePositiveTimestampImport;

/// A timestamp that refers to a date after 1 January 1970.
///
/// # Invariants
///
/// The Unix timestamp representing the stored time has to be positive and no greater than
/// [`MAX_TIMESTAMP`].
#[must_use]
#[repr(C)]
pub struct PositiveTimestamp {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePositiveTimestamp,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PositiveTimestamp {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePositiveTimestamp>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PositiveTimestamp, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PositiveTimestamp_free(this_obj: PositiveTimestamp) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PositiveTimestamp_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePositiveTimestamp) };
}
#[allow(unused)]
impl PositiveTimestamp {
	pub(crate) fn get_native_ref(&self) -> &'static nativePositiveTimestamp {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePositiveTimestamp {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePositiveTimestamp {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Checks if two PositiveTimestamps contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn PositiveTimestamp_eq(a: &PositiveTimestamp, b: &PositiveTimestamp) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for PositiveTimestamp {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePositiveTimestamp>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PositiveTimestamp_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePositiveTimestamp)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PositiveTimestamp
pub extern "C" fn PositiveTimestamp_clone(orig: &PositiveTimestamp) -> PositiveTimestamp {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the PositiveTimestamp.
#[no_mangle]
pub extern "C" fn PositiveTimestamp_hash(o: &PositiveTimestamp) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// SI prefixes for the human readable part
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SiPrefix {
	/// 10^-3
	Milli,
	/// 10^-6
	Micro,
	/// 10^-9
	Nano,
	/// 10^-12
	Pico,
}
use lightning_invoice::SiPrefix as SiPrefixImport;
pub(crate) type nativeSiPrefix = SiPrefixImport;

impl SiPrefix {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSiPrefix {
		match self {
			SiPrefix::Milli => nativeSiPrefix::Milli,
			SiPrefix::Micro => nativeSiPrefix::Micro,
			SiPrefix::Nano => nativeSiPrefix::Nano,
			SiPrefix::Pico => nativeSiPrefix::Pico,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSiPrefix {
		match self {
			SiPrefix::Milli => nativeSiPrefix::Milli,
			SiPrefix::Micro => nativeSiPrefix::Micro,
			SiPrefix::Nano => nativeSiPrefix::Nano,
			SiPrefix::Pico => nativeSiPrefix::Pico,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeSiPrefix) -> Self {
		match native {
			nativeSiPrefix::Milli => SiPrefix::Milli,
			nativeSiPrefix::Micro => SiPrefix::Micro,
			nativeSiPrefix::Nano => SiPrefix::Nano,
			nativeSiPrefix::Pico => SiPrefix::Pico,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSiPrefix) -> Self {
		match native {
			nativeSiPrefix::Milli => SiPrefix::Milli,
			nativeSiPrefix::Micro => SiPrefix::Micro,
			nativeSiPrefix::Nano => SiPrefix::Nano,
			nativeSiPrefix::Pico => SiPrefix::Pico,
		}
	}
}
/// Creates a copy of the SiPrefix
#[no_mangle]
pub extern "C" fn SiPrefix_clone(orig: &SiPrefix) -> SiPrefix {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Milli-variant SiPrefix
pub extern "C" fn SiPrefix_milli() -> SiPrefix {
	SiPrefix::Milli}
#[no_mangle]
/// Utility method to constructs a new Micro-variant SiPrefix
pub extern "C" fn SiPrefix_micro() -> SiPrefix {
	SiPrefix::Micro}
#[no_mangle]
/// Utility method to constructs a new Nano-variant SiPrefix
pub extern "C" fn SiPrefix_nano() -> SiPrefix {
	SiPrefix::Nano}
#[no_mangle]
/// Utility method to constructs a new Pico-variant SiPrefix
pub extern "C" fn SiPrefix_pico() -> SiPrefix {
	SiPrefix::Pico}
/// Checks if two SiPrefixs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SiPrefix_eq(a: &SiPrefix, b: &SiPrefix) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Generates a non-cryptographic 64-bit hash of the SiPrefix.
#[no_mangle]
pub extern "C" fn SiPrefix_hash(o: &SiPrefix) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Returns the multiplier to go from a BTC value to picoBTC implied by this SiPrefix.
/// This is effectively 10^12 * the prefix multiplier
#[must_use]
#[no_mangle]
pub extern "C" fn SiPrefix_multiplier(this_arg: &crate::lightning_invoice::SiPrefix) -> u64 {
	let mut ret = this_arg.to_native().multiplier();
	ret
}

/// Enum representing the crypto currencies (or networks) supported by this library
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Currency {
	/// Bitcoin mainnet
	Bitcoin,
	/// Bitcoin testnet
	BitcoinTestnet,
	/// Bitcoin regtest
	Regtest,
	/// Bitcoin simnet
	Simnet,
	/// Bitcoin signet
	Signet,
}
use lightning_invoice::Currency as CurrencyImport;
pub(crate) type nativeCurrency = CurrencyImport;

impl Currency {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeCurrency {
		match self {
			Currency::Bitcoin => nativeCurrency::Bitcoin,
			Currency::BitcoinTestnet => nativeCurrency::BitcoinTestnet,
			Currency::Regtest => nativeCurrency::Regtest,
			Currency::Simnet => nativeCurrency::Simnet,
			Currency::Signet => nativeCurrency::Signet,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeCurrency {
		match self {
			Currency::Bitcoin => nativeCurrency::Bitcoin,
			Currency::BitcoinTestnet => nativeCurrency::BitcoinTestnet,
			Currency::Regtest => nativeCurrency::Regtest,
			Currency::Simnet => nativeCurrency::Simnet,
			Currency::Signet => nativeCurrency::Signet,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeCurrency) -> Self {
		match native {
			nativeCurrency::Bitcoin => Currency::Bitcoin,
			nativeCurrency::BitcoinTestnet => Currency::BitcoinTestnet,
			nativeCurrency::Regtest => Currency::Regtest,
			nativeCurrency::Simnet => Currency::Simnet,
			nativeCurrency::Signet => Currency::Signet,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeCurrency) -> Self {
		match native {
			nativeCurrency::Bitcoin => Currency::Bitcoin,
			nativeCurrency::BitcoinTestnet => Currency::BitcoinTestnet,
			nativeCurrency::Regtest => Currency::Regtest,
			nativeCurrency::Simnet => Currency::Simnet,
			nativeCurrency::Signet => Currency::Signet,
		}
	}
}
/// Creates a copy of the Currency
#[no_mangle]
pub extern "C" fn Currency_clone(orig: &Currency) -> Currency {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Bitcoin-variant Currency
pub extern "C" fn Currency_bitcoin() -> Currency {
	Currency::Bitcoin}
#[no_mangle]
/// Utility method to constructs a new BitcoinTestnet-variant Currency
pub extern "C" fn Currency_bitcoin_testnet() -> Currency {
	Currency::BitcoinTestnet}
#[no_mangle]
/// Utility method to constructs a new Regtest-variant Currency
pub extern "C" fn Currency_regtest() -> Currency {
	Currency::Regtest}
#[no_mangle]
/// Utility method to constructs a new Simnet-variant Currency
pub extern "C" fn Currency_simnet() -> Currency {
	Currency::Simnet}
#[no_mangle]
/// Utility method to constructs a new Signet-variant Currency
pub extern "C" fn Currency_signet() -> Currency {
	Currency::Signet}
/// Generates a non-cryptographic 64-bit hash of the Currency.
#[no_mangle]
pub extern "C" fn Currency_hash(o: &Currency) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Currencys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Currency_eq(a: &Currency, b: &Currency) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_invoice::Sha256 as nativeSha256Import;
pub(crate) type nativeSha256 = nativeSha256Import;

/// SHA-256 hash
#[must_use]
#[repr(C)]
pub struct Sha256 {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeSha256,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Sha256 {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeSha256>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Sha256, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Sha256_free(this_obj: Sha256) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Sha256_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeSha256) };
}
#[allow(unused)]
impl Sha256 {
	pub(crate) fn get_native_ref(&self) -> &'static nativeSha256 {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeSha256 {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeSha256 {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Sha256 {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeSha256>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Sha256_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeSha256)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Sha256
pub extern "C" fn Sha256_clone(orig: &Sha256) -> Sha256 {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Sha256.
#[no_mangle]
pub extern "C" fn Sha256_hash(o: &Sha256) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Sha256s contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Sha256_eq(a: &Sha256, b: &Sha256) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Constructs a new [`Sha256`] from the given bytes, which are assumed to be the output of a
/// single sha256 hash.
#[must_use]
#[no_mangle]
pub extern "C" fn Sha256_from_bytes(bytes: *const [u8; 32]) -> crate::lightning_invoice::Sha256 {
	let mut ret = lightning_invoice::Sha256::from_bytes(unsafe { &*bytes});
	crate::lightning_invoice::Sha256 { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning_invoice::Description as nativeDescriptionImport;
pub(crate) type nativeDescription = nativeDescriptionImport;

/// Description string
///
/// # Invariants
/// The description can be at most 639 __bytes__ long
#[must_use]
#[repr(C)]
pub struct Description {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDescription,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Description {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDescription>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Description, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Description_free(this_obj: Description) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Description_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDescription) };
}
#[allow(unused)]
impl Description {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDescription {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDescription {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDescription {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Description {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDescription>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Description_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDescription)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Description
pub extern "C" fn Description_clone(orig: &Description) -> Description {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Description.
#[no_mangle]
pub extern "C" fn Description_hash(o: &Description) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Descriptions contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Description_eq(a: &Description, b: &Description) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_invoice::PayeePubKey as nativePayeePubKeyImport;
pub(crate) type nativePayeePubKey = nativePayeePubKeyImport;

/// Payee public key
#[must_use]
#[repr(C)]
pub struct PayeePubKey {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePayeePubKey,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PayeePubKey {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePayeePubKey>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PayeePubKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PayeePubKey_free(this_obj: PayeePubKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PayeePubKey_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePayeePubKey) };
}
#[allow(unused)]
impl PayeePubKey {
	pub(crate) fn get_native_ref(&self) -> &'static nativePayeePubKey {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePayeePubKey {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePayeePubKey {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn PayeePubKey_get_a(this_ptr: &PayeePubKey) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
#[no_mangle]
pub extern "C" fn PayeePubKey_set_a(this_ptr: &mut PayeePubKey, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.into_rust();
}
/// Constructs a new PayeePubKey given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PayeePubKey_new(mut a_arg: crate::c_types::PublicKey) -> PayeePubKey {
	PayeePubKey { inner: ObjOps::heap_alloc(lightning_invoice::PayeePubKey (
		a_arg.into_rust(),
	)), is_owned: true }
}
impl Clone for PayeePubKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePayeePubKey>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PayeePubKey_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePayeePubKey)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PayeePubKey
pub extern "C" fn PayeePubKey_clone(orig: &PayeePubKey) -> PayeePubKey {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the PayeePubKey.
#[no_mangle]
pub extern "C" fn PayeePubKey_hash(o: &PayeePubKey) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two PayeePubKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn PayeePubKey_eq(a: &PayeePubKey, b: &PayeePubKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_invoice::ExpiryTime as nativeExpiryTimeImport;
pub(crate) type nativeExpiryTime = nativeExpiryTimeImport;

/// Positive duration that defines when (relatively to the timestamp) in the future the invoice
/// expires
#[must_use]
#[repr(C)]
pub struct ExpiryTime {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeExpiryTime,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ExpiryTime {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeExpiryTime>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ExpiryTime, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ExpiryTime_free(this_obj: ExpiryTime) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ExpiryTime_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeExpiryTime) };
}
#[allow(unused)]
impl ExpiryTime {
	pub(crate) fn get_native_ref(&self) -> &'static nativeExpiryTime {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeExpiryTime {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeExpiryTime {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for ExpiryTime {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeExpiryTime>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ExpiryTime_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeExpiryTime)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ExpiryTime
pub extern "C" fn ExpiryTime_clone(orig: &ExpiryTime) -> ExpiryTime {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the ExpiryTime.
#[no_mangle]
pub extern "C" fn ExpiryTime_hash(o: &ExpiryTime) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two ExpiryTimes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ExpiryTime_eq(a: &ExpiryTime, b: &ExpiryTime) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_invoice::MinFinalCltvExpiryDelta as nativeMinFinalCltvExpiryDeltaImport;
pub(crate) type nativeMinFinalCltvExpiryDelta = nativeMinFinalCltvExpiryDeltaImport;

/// `min_final_cltv_expiry_delta` to use for the last HTLC in the route
#[must_use]
#[repr(C)]
pub struct MinFinalCltvExpiryDelta {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMinFinalCltvExpiryDelta,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MinFinalCltvExpiryDelta {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMinFinalCltvExpiryDelta>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MinFinalCltvExpiryDelta, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_free(this_obj: MinFinalCltvExpiryDelta) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MinFinalCltvExpiryDelta_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMinFinalCltvExpiryDelta) };
}
#[allow(unused)]
impl MinFinalCltvExpiryDelta {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMinFinalCltvExpiryDelta {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMinFinalCltvExpiryDelta {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMinFinalCltvExpiryDelta {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_get_a(this_ptr: &MinFinalCltvExpiryDelta) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_set_a(this_ptr: &mut MinFinalCltvExpiryDelta, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new MinFinalCltvExpiryDelta given each field
#[must_use]
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_new(mut a_arg: u64) -> MinFinalCltvExpiryDelta {
	MinFinalCltvExpiryDelta { inner: ObjOps::heap_alloc(lightning_invoice::MinFinalCltvExpiryDelta (
		a_arg,
	)), is_owned: true }
}
impl Clone for MinFinalCltvExpiryDelta {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeMinFinalCltvExpiryDelta>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MinFinalCltvExpiryDelta_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeMinFinalCltvExpiryDelta)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the MinFinalCltvExpiryDelta
pub extern "C" fn MinFinalCltvExpiryDelta_clone(orig: &MinFinalCltvExpiryDelta) -> MinFinalCltvExpiryDelta {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the MinFinalCltvExpiryDelta.
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_hash(o: &MinFinalCltvExpiryDelta) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two MinFinalCltvExpiryDeltas contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiryDelta_eq(a: &MinFinalCltvExpiryDelta, b: &MinFinalCltvExpiryDelta) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Fallback address in case no LN payment is possible
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Fallback {
	SegWitProgram {
		version: crate::c_types::WitnessVersion,
		program: crate::c_types::derived::CVec_u8Z,
	},
	PubKeyHash(
		crate::c_types::TwentyBytes),
	ScriptHash(
		crate::c_types::TwentyBytes),
}
use lightning_invoice::Fallback as FallbackImport;
pub(crate) type nativeFallback = FallbackImport;

impl Fallback {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeFallback {
		match self {
			Fallback::SegWitProgram {ref version, ref program, } => {
				let mut version_nonref = Clone::clone(version);
				let mut program_nonref = Clone::clone(program);
				let mut local_program_nonref = Vec::new(); for mut item in program_nonref.into_rust().drain(..) { local_program_nonref.push( { item }); };
				nativeFallback::SegWitProgram {
					version: version_nonref.into(),
					program: local_program_nonref,
				}
			},
			Fallback::PubKeyHash (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeFallback::PubKeyHash (
					bitcoin::hash_types::PubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner(a_nonref.data)),
				)
			},
			Fallback::ScriptHash (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeFallback::ScriptHash (
					bitcoin::hash_types::ScriptHash::from_hash(bitcoin::hashes::Hash::from_inner(a_nonref.data)),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeFallback {
		match self {
			Fallback::SegWitProgram {mut version, mut program, } => {
				let mut local_program = Vec::new(); for mut item in program.into_rust().drain(..) { local_program.push( { item }); };
				nativeFallback::SegWitProgram {
					version: version.into(),
					program: local_program,
				}
			},
			Fallback::PubKeyHash (mut a, ) => {
				nativeFallback::PubKeyHash (
					bitcoin::hash_types::PubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner(a.data)),
				)
			},
			Fallback::ScriptHash (mut a, ) => {
				nativeFallback::ScriptHash (
					bitcoin::hash_types::ScriptHash::from_hash(bitcoin::hashes::Hash::from_inner(a.data)),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeFallback) -> Self {
		match native {
			nativeFallback::SegWitProgram {ref version, ref program, } => {
				let mut version_nonref = Clone::clone(version);
				let mut program_nonref = Clone::clone(program);
				let mut local_program_nonref = Vec::new(); for mut item in program_nonref.drain(..) { local_program_nonref.push( { item }); };
				Fallback::SegWitProgram {
					version: version_nonref.into(),
					program: local_program_nonref.into(),
				}
			},
			nativeFallback::PubKeyHash (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Fallback::PubKeyHash (
					crate::c_types::TwentyBytes { data: a_nonref.as_hash().into_inner() },
				)
			},
			nativeFallback::ScriptHash (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Fallback::ScriptHash (
					crate::c_types::TwentyBytes { data: a_nonref.as_hash().into_inner() },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeFallback) -> Self {
		match native {
			nativeFallback::SegWitProgram {mut version, mut program, } => {
				let mut local_program = Vec::new(); for mut item in program.drain(..) { local_program.push( { item }); };
				Fallback::SegWitProgram {
					version: version.into(),
					program: local_program.into(),
				}
			},
			nativeFallback::PubKeyHash (mut a, ) => {
				Fallback::PubKeyHash (
					crate::c_types::TwentyBytes { data: a.as_hash().into_inner() },
				)
			},
			nativeFallback::ScriptHash (mut a, ) => {
				Fallback::ScriptHash (
					crate::c_types::TwentyBytes { data: a.as_hash().into_inner() },
				)
			},
		}
	}
}
/// Frees any resources used by the Fallback
#[no_mangle]
pub extern "C" fn Fallback_free(this_ptr: Fallback) { }
/// Creates a copy of the Fallback
#[no_mangle]
pub extern "C" fn Fallback_clone(orig: &Fallback) -> Fallback {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new SegWitProgram-variant Fallback
pub extern "C" fn Fallback_seg_wit_program(version: crate::c_types::WitnessVersion, program: crate::c_types::derived::CVec_u8Z) -> Fallback {
	Fallback::SegWitProgram {
		version,
		program,
	}
}
#[no_mangle]
/// Utility method to constructs a new PubKeyHash-variant Fallback
pub extern "C" fn Fallback_pub_key_hash(a: crate::c_types::TwentyBytes) -> Fallback {
	Fallback::PubKeyHash(a, )
}
#[no_mangle]
/// Utility method to constructs a new ScriptHash-variant Fallback
pub extern "C" fn Fallback_script_hash(a: crate::c_types::TwentyBytes) -> Fallback {
	Fallback::ScriptHash(a, )
}
/// Generates a non-cryptographic 64-bit hash of the Fallback.
#[no_mangle]
pub extern "C" fn Fallback_hash(o: &Fallback) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Fallbacks contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Fallback_eq(a: &Fallback, b: &Fallback) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_invoice::Bolt11InvoiceSignature as nativeBolt11InvoiceSignatureImport;
pub(crate) type nativeBolt11InvoiceSignature = nativeBolt11InvoiceSignatureImport;

/// Recoverable signature
#[must_use]
#[repr(C)]
pub struct Bolt11InvoiceSignature {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt11InvoiceSignature,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt11InvoiceSignature {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt11InvoiceSignature>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt11InvoiceSignature, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceSignature_free(this_obj: Bolt11InvoiceSignature) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11InvoiceSignature_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt11InvoiceSignature) };
}
#[allow(unused)]
impl Bolt11InvoiceSignature {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt11InvoiceSignature {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt11InvoiceSignature {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt11InvoiceSignature {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Bolt11InvoiceSignature {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt11InvoiceSignature>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11InvoiceSignature_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBolt11InvoiceSignature)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt11InvoiceSignature
pub extern "C" fn Bolt11InvoiceSignature_clone(orig: &Bolt11InvoiceSignature) -> Bolt11InvoiceSignature {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Bolt11InvoiceSignature.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceSignature_hash(o: &Bolt11InvoiceSignature) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Bolt11InvoiceSignatures contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceSignature_eq(a: &Bolt11InvoiceSignature, b: &Bolt11InvoiceSignature) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning_invoice::PrivateRoute as nativePrivateRouteImport;
pub(crate) type nativePrivateRoute = nativePrivateRouteImport;

/// Private routing information
///
/// # Invariants
/// The encoded route has to be <1024 5bit characters long (<=639 bytes or <=12 hops)
///
#[must_use]
#[repr(C)]
pub struct PrivateRoute {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePrivateRoute,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PrivateRoute {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePrivateRoute>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PrivateRoute, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PrivateRoute_free(this_obj: PrivateRoute) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrivateRoute_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePrivateRoute) };
}
#[allow(unused)]
impl PrivateRoute {
	pub(crate) fn get_native_ref(&self) -> &'static nativePrivateRoute {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePrivateRoute {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePrivateRoute {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for PrivateRoute {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePrivateRoute>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PrivateRoute_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePrivateRoute)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PrivateRoute
pub extern "C" fn PrivateRoute_clone(orig: &PrivateRoute) -> PrivateRoute {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the PrivateRoute.
#[no_mangle]
pub extern "C" fn PrivateRoute_hash(o: &PrivateRoute) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two PrivateRoutes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn PrivateRoute_eq(a: &PrivateRoute, b: &PrivateRoute) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Disassembles the `SignedRawBolt11Invoice` into its three parts:
///  1. raw invoice
///  2. hash of the raw invoice
///  3. signature
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_into_parts(mut this_arg: crate::lightning_invoice::SignedRawBolt11Invoice) -> crate::c_types::derived::C3Tuple_RawBolt11Invoice_u832Bolt11InvoiceSignatureZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_parts();
	let (mut orig_ret_0, mut orig_ret_1, mut orig_ret_2) = ret; let mut local_ret = (crate::lightning_invoice::RawBolt11Invoice { inner: ObjOps::heap_alloc(orig_ret_0), is_owned: true }, crate::c_types::ThirtyTwoBytes { data: orig_ret_1 }, crate::lightning_invoice::Bolt11InvoiceSignature { inner: ObjOps::heap_alloc(orig_ret_2), is_owned: true }).into();
	local_ret
}

/// The [`RawBolt11Invoice`] which was signed.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_raw_invoice(this_arg: &crate::lightning_invoice::SignedRawBolt11Invoice) -> crate::lightning_invoice::RawBolt11Invoice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.raw_invoice();
	crate::lightning_invoice::RawBolt11Invoice { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_invoice::RawBolt11Invoice<>) as *mut _) }, is_owned: false }
}

/// The hash of the [`RawBolt11Invoice`] that was signed.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_signable_hash(this_arg: &crate::lightning_invoice::SignedRawBolt11Invoice) -> *const [u8; 32] {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	ret
}

/// Signature for the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_signature(this_arg: &crate::lightning_invoice::SignedRawBolt11Invoice) -> crate::lightning_invoice::Bolt11InvoiceSignature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signature();
	crate::lightning_invoice::Bolt11InvoiceSignature { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning_invoice::Bolt11InvoiceSignature<>) as *mut _) }, is_owned: false }
}

/// Recovers the public key used for signing the invoice from the recoverable signature.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_recover_payee_pub_key(this_arg: &crate::lightning_invoice::SignedRawBolt11Invoice) -> crate::c_types::derived::CResult_PayeePubKeyErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.recover_payee_pub_key();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PayeePubKey { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }).into() };
	local_ret
}

/// Checks if the signature is valid for the included payee public key or if none exists if it's
/// valid for the recovered signature (which should always be true?).
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawBolt11Invoice_check_signature(this_arg: &crate::lightning_invoice::SignedRawBolt11Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.check_signature();
	ret
}

/// Calculate the hash of the encoded `RawBolt11Invoice` which should be signed.
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_signable_hash(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_payment_hash(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::Sha256 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	let mut local_ret = crate::lightning_invoice::Sha256 { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::Sha256<>) as *mut _ }, is_owned: false };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_description(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::Description {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description();
	let mut local_ret = crate::lightning_invoice::Description { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::Description<>) as *mut _ }, is_owned: false };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_payee_pub_key(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::PayeePubKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payee_pub_key();
	let mut local_ret = crate::lightning_invoice::PayeePubKey { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::PayeePubKey<>) as *mut _ }, is_owned: false };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_description_hash(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::Sha256 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.description_hash();
	let mut local_ret = crate::lightning_invoice::Sha256 { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::Sha256<>) as *mut _ }, is_owned: false };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_expiry_time(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::ExpiryTime {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expiry_time();
	let mut local_ret = crate::lightning_invoice::ExpiryTime { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::ExpiryTime<>) as *mut _ }, is_owned: false };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_min_final_cltv_expiry_delta(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::MinFinalCltvExpiryDelta {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.min_final_cltv_expiry_delta();
	let mut local_ret = crate::lightning_invoice::MinFinalCltvExpiryDelta { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning_invoice::MinFinalCltvExpiryDelta<>) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_payment_secret(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::c_types::derived::COption_PaymentSecretZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_secret();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_PaymentSecretZ::None } else { crate::c_types::derived::COption_PaymentSecretZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::ThirtyTwoBytes { data: (*ret.as_ref().unwrap()).clone().0 } }) };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_payment_metadata(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_features(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning::ln::features::Bolt11InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	let mut local_ret = crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::ln::features::Bolt11InvoiceFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_private_routes(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::c_types::derived::CVec_PrivateRouteZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.private_routes();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning_invoice::PrivateRoute { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning_invoice::PrivateRoute<>) as *mut _) }, is_owned: false } }); };
	local_ret.into()
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_amount_pico_btc(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_pico_btc();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawBolt11Invoice_currency(this_arg: &crate::lightning_invoice::RawBolt11Invoice) -> crate::lightning_invoice::Currency {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.currency();
	crate::lightning_invoice::Currency::native_into(ret)
}

/// Creates a `PositiveTimestamp` from a Unix timestamp in the range `0..=MAX_TIMESTAMP`.
///
/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_from_unix_timestamp(mut unix_seconds: u64) -> crate::c_types::derived::CResult_PositiveTimestampCreationErrorZ {
	let mut ret = lightning_invoice::PositiveTimestamp::from_unix_timestamp(unix_seconds);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PositiveTimestamp { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Creates a `PositiveTimestamp` from a [`SystemTime`] with a corresponding Unix timestamp in
/// the range `0..=MAX_TIMESTAMP`.
///
/// Note that the subsecond part is dropped as it is not representable in BOLT 11 invoices.
///
/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_from_system_time(mut time: u64) -> crate::c_types::derived::CResult_PositiveTimestampCreationErrorZ {
	let mut ret = lightning_invoice::PositiveTimestamp::from_system_time((::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(time)));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PositiveTimestamp { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Creates a `PositiveTimestamp` from a [`Duration`] since the Unix epoch in the range
/// `0..=MAX_TIMESTAMP`.
///
/// Note that the subsecond part is dropped as it is not representable in BOLT 11 invoices.
///
/// Otherwise, returns a [`CreationError::TimestampOutOfBounds`].
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_from_duration_since_epoch(mut duration: u64) -> crate::c_types::derived::CResult_PositiveTimestampCreationErrorZ {
	let mut ret = lightning_invoice::PositiveTimestamp::from_duration_since_epoch(core::time::Duration::from_secs(duration));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PositiveTimestamp { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the Unix timestamp representing the stored time
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_as_unix_timestamp(this_arg: &crate::lightning_invoice::PositiveTimestamp) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_unix_timestamp();
	ret
}

/// Returns the duration of the stored time since the Unix epoch
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_as_duration_since_epoch(this_arg: &crate::lightning_invoice::PositiveTimestamp) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_duration_since_epoch();
	ret.as_secs()
}

/// Returns the [`SystemTime`] representing the stored time
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_as_time(this_arg: &crate::lightning_invoice::PositiveTimestamp) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_time();
	ret.duration_since(::std::time::SystemTime::UNIX_EPOCH).expect("Times must be post-1970").as_secs()
}

/// The hash of the [`RawBolt11Invoice`] that was signed.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_signable_hash(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.signable_hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Transform the `Bolt11Invoice` into its unchecked version.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_into_signed_raw(mut this_arg: crate::lightning_invoice::Bolt11Invoice) -> crate::lightning_invoice::SignedRawBolt11Invoice {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_signed_raw();
	crate::lightning_invoice::SignedRawBolt11Invoice { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Check that the invoice is signed correctly and that key recovery works
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_check_signature(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::CResult_NoneBolt11SemanticErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.check_signature();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::Bolt11SemanticError::native_into(e) }).into() };
	local_ret
}

/// Constructs a `Bolt11Invoice` from a [`SignedRawBolt11Invoice`] by checking all its invariants.
/// ```
/// use lightning_invoice::*;
///
/// let invoice = \"lnbc100p1psj9jhxdqud3jxktt5w46x7unfv9kz6mn0v3jsnp4q0d3p2sfluzdx45tqcs\\
/// h2pu5qc7lgq0xs578ngs6s0s68ua4h7cvspp5q6rmq35js88zp5dvwrv9m459tnk2zunwj5jalqtyxqulh0l\\
/// 5gflssp5nf55ny5gcrfl30xuhzj3nphgj27rstekmr9fw3ny5989s300gyus9qyysgqcqpcrzjqw2sxwe993\\
/// h5pcm4dxzpvttgza8zhkqxpgffcrf5v25nwpr3cmfg7z54kuqq8rgqqqqqqqq2qqqqq9qq9qrzjqd0ylaqcl\\
/// j9424x9m8h2vcukcgnm6s56xfgu3j78zyqzhgs4hlpzvznlugqq9vsqqqqqqqlgqqqqqeqq9qrzjqwldmj9d\\
/// ha74df76zhx6l9we0vjdquygcdt3kssupehe64g6yyp5yz5rhuqqwccqqyqqqqlgqqqqjcqq9qrzjqf9e58a\\
/// guqr0rcun0ajlvmzq3ek63cw2w282gv3z5uupmuwvgjtq2z55qsqqg6qqqyqqqrtnqqqzq3cqygrzjqvphms\\
/// ywntrrhqjcraumvc4y6r8v4z5v593trte429v4hredj7ms5z52usqq9ngqqqqqqqlgqqqqqqgq9qrzjq2v0v\\
/// p62g49p7569ev48cmulecsxe59lvaw3wlxm7r982zxa9zzj7z5l0cqqxusqqyqqqqlgqqqqqzsqygarl9fh3\\
/// 8s0gyuxjjgux34w75dnc6xp2l35j7es3jd4ugt3lu0xzre26yg5m7ke54n2d5sym4xcmxtl8238xxvw5h5h5\\
/// j5r6drg6k6zcqj0fcwg\";
///
/// let signed = invoice.parse::<SignedRawBolt11Invoice>().unwrap();
///
/// assert!(Bolt11Invoice::from_signed(signed).is_ok());
/// ```
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_from_signed(mut signed_invoice: crate::lightning_invoice::SignedRawBolt11Invoice) -> crate::c_types::derived::CResult_Bolt11InvoiceBolt11SemanticErrorZ {
	let mut ret = lightning_invoice::Bolt11Invoice::from_signed(*unsafe { Box::from_raw(signed_invoice.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::Bolt11SemanticError::native_into(e) }).into() };
	local_ret
}

/// Returns the `Bolt11Invoice`'s timestamp (should equal its creation time)
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_timestamp(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.timestamp();
	ret.duration_since(::std::time::SystemTime::UNIX_EPOCH).expect("Times must be post-1970").as_secs()
}

/// Returns the `Bolt11Invoice`'s timestamp as a duration since the Unix epoch
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_duration_since_epoch(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.duration_since_epoch();
	ret.as_secs()
}

/// Returns the hash to which we will receive the preimage on completion of the payment
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_payment_hash(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> *const [u8; 32] {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_hash();
	ret.as_inner()
}

/// Get the payee's public key if one was included in the invoice
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_payee_pub_key(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payee_pub_key();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// Get the payment secret if one was included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_payment_secret(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> *const [u8; 32] {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_secret();
	&ret.0
}

/// Get the payment metadata blob if one was included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_payment_metadata(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::COption_CVec_u8ZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.payment_metadata();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_u8ZZ::None } else { crate::c_types::derived::COption_CVec_u8ZZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { let mut local_ret_0 = Vec::new(); for mut item in (*ret.as_ref().unwrap()).clone().drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }) };
	local_ret
}

/// Get the invoice features if they were included in the invoice
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_features(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::lightning::ln::features::Bolt11InvoiceFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.features();
	let mut local_ret = crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::ln::features::Bolt11InvoiceFeatures<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Recover the payee's public key (only to be used if none was included in the invoice)
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_recover_payee_pub_key(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.recover_payee_pub_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Returns the Duration since the Unix epoch at which the invoice expires.
/// Returning None if overflow occurred.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_expires_at(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::COption_DurationZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expires_at();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_DurationZ::None } else { crate::c_types::derived::COption_DurationZ::Some( { ret.unwrap().as_secs() }) };
	local_ret
}

/// Returns the invoice's expiry time, if present, otherwise [`DEFAULT_EXPIRY_TIME`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_expiry_time(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expiry_time();
	ret.as_secs()
}

/// Returns whether the invoice has expired.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_is_expired(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_expired();
	ret
}

/// Returns the Duration remaining until the invoice expires.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_duration_until_expiry(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.duration_until_expiry();
	ret.as_secs()
}

/// Returns the Duration remaining until the invoice expires given the current time.
/// `time` is the timestamp as a duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_expiration_remaining_from_epoch(this_arg: &crate::lightning_invoice::Bolt11Invoice, mut time: u64) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.expiration_remaining_from_epoch(core::time::Duration::from_secs(time));
	ret.as_secs()
}

/// Returns whether the expiry time would pass at the given point in time.
/// `at_time` is the timestamp as a duration since the Unix epoch.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_would_expire(this_arg: &crate::lightning_invoice::Bolt11Invoice, mut at_time: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.would_expire(core::time::Duration::from_secs(at_time));
	ret
}

/// Returns the invoice's `min_final_cltv_expiry_delta` time, if present, otherwise
/// [`DEFAULT_MIN_FINAL_CLTV_EXPIRY_DELTA`].
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_min_final_cltv_expiry_delta(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.min_final_cltv_expiry_delta();
	ret
}

/// Returns a list of all fallback addresses as [`Address`]es
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_fallback_addresses(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::CVec_AddressZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fallback_addresses();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { alloc::string::ToString::to_string(&item).into() }); };
	local_ret.into()
}

/// Returns a list of all routes included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_private_routes(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::CVec_PrivateRouteZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.private_routes();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning_invoice::PrivateRoute { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning_invoice::PrivateRoute<>) as *mut _) }, is_owned: false } }); };
	local_ret.into()
}

/// Returns a list of all routes included in the invoice as the underlying hints
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_route_hints(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::CVec_RouteHintZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.route_hints();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::routing::router::RouteHint { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Returns the currency for which the invoice was issued
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_currency(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::lightning_invoice::Currency {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.currency();
	crate::lightning_invoice::Currency::native_into(ret)
}

/// Returns the amount if specified in the invoice as millisatoshis.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11Invoice_amount_milli_satoshis(this_arg: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.amount_milli_satoshis();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Creates a new `Description` if `description` is at most 1023 __bytes__ long,
/// returns [`CreationError::DescriptionTooLong`] otherwise
///
/// Please note that single characters may use more than one byte due to UTF8 encoding.
#[must_use]
#[no_mangle]
pub extern "C" fn Description_new(mut description: crate::c_types::Str) -> crate::c_types::derived::CResult_DescriptionCreationErrorZ {
	let mut ret = lightning_invoice::Description::new(description.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Description { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the underlying description [`String`]
#[must_use]
#[no_mangle]
pub extern "C" fn Description_into_inner(mut this_arg: crate::lightning_invoice::Description) -> crate::c_types::Str {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_inner();
	ret.into()
}

/// Construct an `ExpiryTime` from seconds.
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_from_seconds(mut seconds: u64) -> crate::lightning_invoice::ExpiryTime {
	let mut ret = lightning_invoice::ExpiryTime::from_seconds(seconds);
	crate::lightning_invoice::ExpiryTime { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Construct an `ExpiryTime` from a [`Duration`], dropping the sub-second part.
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_from_duration(mut duration: u64) -> crate::lightning_invoice::ExpiryTime {
	let mut ret = lightning_invoice::ExpiryTime::from_duration(core::time::Duration::from_secs(duration));
	crate::lightning_invoice::ExpiryTime { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the expiry time in seconds
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_as_seconds(this_arg: &crate::lightning_invoice::ExpiryTime) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_seconds();
	ret
}

/// Returns a reference to the underlying [`Duration`] (=expiry time)
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_as_duration(this_arg: &crate::lightning_invoice::ExpiryTime) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_duration();
	ret.as_secs()
}

/// Creates a new (partial) route from a list of hops
#[must_use]
#[no_mangle]
pub extern "C" fn PrivateRoute_new(mut hops: crate::lightning::routing::router::RouteHint) -> crate::c_types::derived::CResult_PrivateRouteCreationErrorZ {
	let mut ret = lightning_invoice::PrivateRoute::new(*unsafe { Box::from_raw(hops.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PrivateRoute { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the underlying list of hops
#[must_use]
#[no_mangle]
pub extern "C" fn PrivateRoute_into_inner(mut this_arg: crate::lightning_invoice::PrivateRoute) -> crate::lightning::routing::router::RouteHint {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_inner();
	crate::lightning::routing::router::RouteHint { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Errors that may occur when constructing a new [`RawBolt11Invoice`] or [`Bolt11Invoice`]
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum CreationError {
	/// The supplied description string was longer than 639 __bytes__ (see [`Description::new`])
	DescriptionTooLong,
	/// The specified route has too many hops and can't be encoded
	RouteTooLong,
	/// The Unix timestamp of the supplied date is less than zero or greater than 35-bits
	TimestampOutOfBounds,
	/// The supplied millisatoshi amount was greater than the total bitcoin supply.
	InvalidAmount,
	/// Route hints were required for this invoice and were missing. Applies to
	/// [phantom invoices].
	///
	/// [phantom invoices]: crate::utils::create_phantom_invoice
	MissingRouteHints,
	/// The provided `min_final_cltv_expiry_delta` was less than [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
	///
	/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
	MinFinalCltvExpiryDeltaTooShort,
}
use lightning_invoice::CreationError as CreationErrorImport;
pub(crate) type nativeCreationError = CreationErrorImport;

impl CreationError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeCreationError {
		match self {
			CreationError::DescriptionTooLong => nativeCreationError::DescriptionTooLong,
			CreationError::RouteTooLong => nativeCreationError::RouteTooLong,
			CreationError::TimestampOutOfBounds => nativeCreationError::TimestampOutOfBounds,
			CreationError::InvalidAmount => nativeCreationError::InvalidAmount,
			CreationError::MissingRouteHints => nativeCreationError::MissingRouteHints,
			CreationError::MinFinalCltvExpiryDeltaTooShort => nativeCreationError::MinFinalCltvExpiryDeltaTooShort,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeCreationError {
		match self {
			CreationError::DescriptionTooLong => nativeCreationError::DescriptionTooLong,
			CreationError::RouteTooLong => nativeCreationError::RouteTooLong,
			CreationError::TimestampOutOfBounds => nativeCreationError::TimestampOutOfBounds,
			CreationError::InvalidAmount => nativeCreationError::InvalidAmount,
			CreationError::MissingRouteHints => nativeCreationError::MissingRouteHints,
			CreationError::MinFinalCltvExpiryDeltaTooShort => nativeCreationError::MinFinalCltvExpiryDeltaTooShort,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeCreationError) -> Self {
		match native {
			nativeCreationError::DescriptionTooLong => CreationError::DescriptionTooLong,
			nativeCreationError::RouteTooLong => CreationError::RouteTooLong,
			nativeCreationError::TimestampOutOfBounds => CreationError::TimestampOutOfBounds,
			nativeCreationError::InvalidAmount => CreationError::InvalidAmount,
			nativeCreationError::MissingRouteHints => CreationError::MissingRouteHints,
			nativeCreationError::MinFinalCltvExpiryDeltaTooShort => CreationError::MinFinalCltvExpiryDeltaTooShort,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeCreationError) -> Self {
		match native {
			nativeCreationError::DescriptionTooLong => CreationError::DescriptionTooLong,
			nativeCreationError::RouteTooLong => CreationError::RouteTooLong,
			nativeCreationError::TimestampOutOfBounds => CreationError::TimestampOutOfBounds,
			nativeCreationError::InvalidAmount => CreationError::InvalidAmount,
			nativeCreationError::MissingRouteHints => CreationError::MissingRouteHints,
			nativeCreationError::MinFinalCltvExpiryDeltaTooShort => CreationError::MinFinalCltvExpiryDeltaTooShort,
		}
	}
}
/// Creates a copy of the CreationError
#[no_mangle]
pub extern "C" fn CreationError_clone(orig: &CreationError) -> CreationError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new DescriptionTooLong-variant CreationError
pub extern "C" fn CreationError_description_too_long() -> CreationError {
	CreationError::DescriptionTooLong}
#[no_mangle]
/// Utility method to constructs a new RouteTooLong-variant CreationError
pub extern "C" fn CreationError_route_too_long() -> CreationError {
	CreationError::RouteTooLong}
#[no_mangle]
/// Utility method to constructs a new TimestampOutOfBounds-variant CreationError
pub extern "C" fn CreationError_timestamp_out_of_bounds() -> CreationError {
	CreationError::TimestampOutOfBounds}
#[no_mangle]
/// Utility method to constructs a new InvalidAmount-variant CreationError
pub extern "C" fn CreationError_invalid_amount() -> CreationError {
	CreationError::InvalidAmount}
#[no_mangle]
/// Utility method to constructs a new MissingRouteHints-variant CreationError
pub extern "C" fn CreationError_missing_route_hints() -> CreationError {
	CreationError::MissingRouteHints}
#[no_mangle]
/// Utility method to constructs a new MinFinalCltvExpiryDeltaTooShort-variant CreationError
pub extern "C" fn CreationError_min_final_cltv_expiry_delta_too_short() -> CreationError {
	CreationError::MinFinalCltvExpiryDeltaTooShort}
/// Checks if two CreationErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn CreationError_eq(a: &CreationError, b: &CreationError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a CreationError object
pub extern "C" fn CreationError_to_str(o: &crate::lightning_invoice::CreationError) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
/// Errors that may occur when converting a [`RawBolt11Invoice`] to a [`Bolt11Invoice`]. They relate to
/// the requirements sections in BOLT #11
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Bolt11SemanticError {
	/// The invoice is missing the mandatory payment hash
	NoPaymentHash,
	/// The invoice has multiple payment hashes which isn't allowed
	MultiplePaymentHashes,
	/// No description or description hash are part of the invoice
	NoDescription,
	/// The invoice contains multiple descriptions and/or description hashes which isn't allowed
	MultipleDescriptions,
	/// The invoice is missing the mandatory payment secret, which all modern lightning nodes
	/// should provide.
	NoPaymentSecret,
	/// The invoice contains multiple payment secrets
	MultiplePaymentSecrets,
	/// The invoice's features are invalid
	InvalidFeatures,
	/// The recovery id doesn't fit the signature/pub key
	InvalidRecoveryId,
	/// The invoice's signature is invalid
	InvalidSignature,
	/// The invoice's amount was not a whole number of millisatoshis
	ImpreciseAmount,
}
use lightning_invoice::Bolt11SemanticError as Bolt11SemanticErrorImport;
pub(crate) type nativeBolt11SemanticError = Bolt11SemanticErrorImport;

impl Bolt11SemanticError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeBolt11SemanticError {
		match self {
			Bolt11SemanticError::NoPaymentHash => nativeBolt11SemanticError::NoPaymentHash,
			Bolt11SemanticError::MultiplePaymentHashes => nativeBolt11SemanticError::MultiplePaymentHashes,
			Bolt11SemanticError::NoDescription => nativeBolt11SemanticError::NoDescription,
			Bolt11SemanticError::MultipleDescriptions => nativeBolt11SemanticError::MultipleDescriptions,
			Bolt11SemanticError::NoPaymentSecret => nativeBolt11SemanticError::NoPaymentSecret,
			Bolt11SemanticError::MultiplePaymentSecrets => nativeBolt11SemanticError::MultiplePaymentSecrets,
			Bolt11SemanticError::InvalidFeatures => nativeBolt11SemanticError::InvalidFeatures,
			Bolt11SemanticError::InvalidRecoveryId => nativeBolt11SemanticError::InvalidRecoveryId,
			Bolt11SemanticError::InvalidSignature => nativeBolt11SemanticError::InvalidSignature,
			Bolt11SemanticError::ImpreciseAmount => nativeBolt11SemanticError::ImpreciseAmount,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeBolt11SemanticError {
		match self {
			Bolt11SemanticError::NoPaymentHash => nativeBolt11SemanticError::NoPaymentHash,
			Bolt11SemanticError::MultiplePaymentHashes => nativeBolt11SemanticError::MultiplePaymentHashes,
			Bolt11SemanticError::NoDescription => nativeBolt11SemanticError::NoDescription,
			Bolt11SemanticError::MultipleDescriptions => nativeBolt11SemanticError::MultipleDescriptions,
			Bolt11SemanticError::NoPaymentSecret => nativeBolt11SemanticError::NoPaymentSecret,
			Bolt11SemanticError::MultiplePaymentSecrets => nativeBolt11SemanticError::MultiplePaymentSecrets,
			Bolt11SemanticError::InvalidFeatures => nativeBolt11SemanticError::InvalidFeatures,
			Bolt11SemanticError::InvalidRecoveryId => nativeBolt11SemanticError::InvalidRecoveryId,
			Bolt11SemanticError::InvalidSignature => nativeBolt11SemanticError::InvalidSignature,
			Bolt11SemanticError::ImpreciseAmount => nativeBolt11SemanticError::ImpreciseAmount,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeBolt11SemanticError) -> Self {
		match native {
			nativeBolt11SemanticError::NoPaymentHash => Bolt11SemanticError::NoPaymentHash,
			nativeBolt11SemanticError::MultiplePaymentHashes => Bolt11SemanticError::MultiplePaymentHashes,
			nativeBolt11SemanticError::NoDescription => Bolt11SemanticError::NoDescription,
			nativeBolt11SemanticError::MultipleDescriptions => Bolt11SemanticError::MultipleDescriptions,
			nativeBolt11SemanticError::NoPaymentSecret => Bolt11SemanticError::NoPaymentSecret,
			nativeBolt11SemanticError::MultiplePaymentSecrets => Bolt11SemanticError::MultiplePaymentSecrets,
			nativeBolt11SemanticError::InvalidFeatures => Bolt11SemanticError::InvalidFeatures,
			nativeBolt11SemanticError::InvalidRecoveryId => Bolt11SemanticError::InvalidRecoveryId,
			nativeBolt11SemanticError::InvalidSignature => Bolt11SemanticError::InvalidSignature,
			nativeBolt11SemanticError::ImpreciseAmount => Bolt11SemanticError::ImpreciseAmount,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeBolt11SemanticError) -> Self {
		match native {
			nativeBolt11SemanticError::NoPaymentHash => Bolt11SemanticError::NoPaymentHash,
			nativeBolt11SemanticError::MultiplePaymentHashes => Bolt11SemanticError::MultiplePaymentHashes,
			nativeBolt11SemanticError::NoDescription => Bolt11SemanticError::NoDescription,
			nativeBolt11SemanticError::MultipleDescriptions => Bolt11SemanticError::MultipleDescriptions,
			nativeBolt11SemanticError::NoPaymentSecret => Bolt11SemanticError::NoPaymentSecret,
			nativeBolt11SemanticError::MultiplePaymentSecrets => Bolt11SemanticError::MultiplePaymentSecrets,
			nativeBolt11SemanticError::InvalidFeatures => Bolt11SemanticError::InvalidFeatures,
			nativeBolt11SemanticError::InvalidRecoveryId => Bolt11SemanticError::InvalidRecoveryId,
			nativeBolt11SemanticError::InvalidSignature => Bolt11SemanticError::InvalidSignature,
			nativeBolt11SemanticError::ImpreciseAmount => Bolt11SemanticError::ImpreciseAmount,
		}
	}
}
/// Creates a copy of the Bolt11SemanticError
#[no_mangle]
pub extern "C" fn Bolt11SemanticError_clone(orig: &Bolt11SemanticError) -> Bolt11SemanticError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new NoPaymentHash-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_no_payment_hash() -> Bolt11SemanticError {
	Bolt11SemanticError::NoPaymentHash}
#[no_mangle]
/// Utility method to constructs a new MultiplePaymentHashes-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_multiple_payment_hashes() -> Bolt11SemanticError {
	Bolt11SemanticError::MultiplePaymentHashes}
#[no_mangle]
/// Utility method to constructs a new NoDescription-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_no_description() -> Bolt11SemanticError {
	Bolt11SemanticError::NoDescription}
#[no_mangle]
/// Utility method to constructs a new MultipleDescriptions-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_multiple_descriptions() -> Bolt11SemanticError {
	Bolt11SemanticError::MultipleDescriptions}
#[no_mangle]
/// Utility method to constructs a new NoPaymentSecret-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_no_payment_secret() -> Bolt11SemanticError {
	Bolt11SemanticError::NoPaymentSecret}
#[no_mangle]
/// Utility method to constructs a new MultiplePaymentSecrets-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_multiple_payment_secrets() -> Bolt11SemanticError {
	Bolt11SemanticError::MultiplePaymentSecrets}
#[no_mangle]
/// Utility method to constructs a new InvalidFeatures-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_invalid_features() -> Bolt11SemanticError {
	Bolt11SemanticError::InvalidFeatures}
#[no_mangle]
/// Utility method to constructs a new InvalidRecoveryId-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_invalid_recovery_id() -> Bolt11SemanticError {
	Bolt11SemanticError::InvalidRecoveryId}
#[no_mangle]
/// Utility method to constructs a new InvalidSignature-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_invalid_signature() -> Bolt11SemanticError {
	Bolt11SemanticError::InvalidSignature}
#[no_mangle]
/// Utility method to constructs a new ImpreciseAmount-variant Bolt11SemanticError
pub extern "C" fn Bolt11SemanticError_imprecise_amount() -> Bolt11SemanticError {
	Bolt11SemanticError::ImpreciseAmount}
/// Checks if two Bolt11SemanticErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Bolt11SemanticError_eq(a: &Bolt11SemanticError, b: &Bolt11SemanticError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a Bolt11SemanticError object
pub extern "C" fn Bolt11SemanticError_to_str(o: &crate::lightning_invoice::Bolt11SemanticError) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
/// When signing using a fallible method either an user-supplied `SignError` or a [`CreationError`]
/// may occur.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SignOrCreationError {
	/// An error occurred during signing
	SignError,
	/// An error occurred while building the transaction
	CreationError(
		crate::lightning_invoice::CreationError),
}
use lightning_invoice::SignOrCreationError as SignOrCreationErrorImport;
pub(crate) type nativeSignOrCreationError = SignOrCreationErrorImport<>;

impl SignOrCreationError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSignOrCreationError {
		match self {
			SignOrCreationError::SignError => {
				nativeSignOrCreationError::SignError (
					() /*a_nonref*/,
				)
			},
			SignOrCreationError::CreationError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSignOrCreationError::CreationError (
					a_nonref.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSignOrCreationError {
		match self {
			SignOrCreationError::SignError => {
				nativeSignOrCreationError::SignError (
					() /*a*/,
				)
			},
			SignOrCreationError::CreationError (mut a, ) => {
				nativeSignOrCreationError::CreationError (
					a.into_native(),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeSignOrCreationError) -> Self {
		match native {
			nativeSignOrCreationError::SignError (ref a, ) => {
				SignOrCreationError::SignError			},
			nativeSignOrCreationError::CreationError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SignOrCreationError::CreationError (
					crate::lightning_invoice::CreationError::native_into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSignOrCreationError) -> Self {
		match native {
			nativeSignOrCreationError::SignError (mut a, ) => {
				SignOrCreationError::SignError			},
			nativeSignOrCreationError::CreationError (mut a, ) => {
				SignOrCreationError::CreationError (
					crate::lightning_invoice::CreationError::native_into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the SignOrCreationError
#[no_mangle]
pub extern "C" fn SignOrCreationError_free(this_ptr: SignOrCreationError) { }
/// Creates a copy of the SignOrCreationError
#[no_mangle]
pub extern "C" fn SignOrCreationError_clone(orig: &SignOrCreationError) -> SignOrCreationError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new SignError-variant SignOrCreationError
pub extern "C" fn SignOrCreationError_sign_error() -> SignOrCreationError {
	SignOrCreationError::SignError
}
#[no_mangle]
/// Utility method to constructs a new CreationError-variant SignOrCreationError
pub extern "C" fn SignOrCreationError_creation_error(a: crate::lightning_invoice::CreationError) -> SignOrCreationError {
	SignOrCreationError::CreationError(a, )
}
/// Checks if two SignOrCreationErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SignOrCreationError_eq(a: &SignOrCreationError, b: &SignOrCreationError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a SignOrCreationError object
pub extern "C" fn SignOrCreationError_to_str(o: &crate::lightning_invoice::SignOrCreationError) -> Str {
	alloc::format!("{}", &o.to_native()).into()
}
