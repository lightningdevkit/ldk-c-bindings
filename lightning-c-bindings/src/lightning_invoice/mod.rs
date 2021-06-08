// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This crate provides data structures to represent
//! [lightning BOLT11](https://github.com/lightningnetwork/lightning-rfc/blob/master/11-payment-encoding.md)
//! invoices and functions to create, encode and decode these. If you just want to use the standard
//! en-/decoding functionality this should get you started:
//!
//!   * For parsing use `str::parse::<Invoice>(&self)` (see the docs of `impl FromStr for Invoice`)
//!   * For constructing invoices use the `InvoiceBuilder`
//!   * For serializing invoices use the `Display`/`ToString` traits

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

pub mod utils;
pub mod constants;
mod de {

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

mod hrp_sm {

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

}
#[no_mangle]
/// Read a SiPrefix object from a string
pub extern "C" fn SiPrefix_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_SiPrefixNoneZ {
	match lightning_invoice::SiPrefix::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::SiPrefix::native_into(r)
			)
		},
		Err(e) => crate::c_types::CResultTempl::err(()),
	}.into()
}
#[no_mangle]
/// Read a Invoice object from a string
pub extern "C" fn Invoice_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_InvoiceNoneZ {
	match lightning_invoice::Invoice::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::Invoice { inner: Box::into_raw(Box::new(r)), is_owned: true }
			)
		},
		Err(e) => crate::c_types::CResultTempl::err(()),
	}.into()
}
#[no_mangle]
/// Read a SignedRawInvoice object from a string
pub extern "C" fn SignedRawInvoice_from_str(s: crate::c_types::Str) -> crate::c_types::derived::CResult_SignedRawInvoiceNoneZ {
	match lightning_invoice::SignedRawInvoice::from_str(s.into_str()) {
		Ok(r) => {
			crate::c_types::CResultTempl::ok(
				crate::lightning_invoice::SignedRawInvoice { inner: Box::into_raw(Box::new(r)), is_owned: true }
			)
		},
		Err(e) => crate::c_types::CResultTempl::err(()),
	}.into()
}
}
mod ser {

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

#[no_mangle]
/// Get the string representation of a Invoice object
pub extern "C" fn Invoice_to_str(o: &crate::lightning_invoice::Invoice) -> Str {
	format!("{}", unsafe { &*o.inner }).into()
}
#[no_mangle]
/// Get the string representation of a SignedRawInvoice object
pub extern "C" fn SignedRawInvoice_to_str(o: &crate::lightning_invoice::SignedRawInvoice) -> Str {
	format!("{}", unsafe { &*o.inner }).into()
}
#[no_mangle]
/// Get the string representation of a Currency object
pub extern "C" fn Currency_to_str(o: &crate::lightning_invoice::Currency) -> Str {
	format!("{}", &o.to_native()).into()
}
#[no_mangle]
/// Get the string representation of a SiPrefix object
pub extern "C" fn SiPrefix_to_str(o: &crate::lightning_invoice::SiPrefix) -> Str {
	format!("{}", &o.to_native()).into()
}
}
mod tb {

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

}
/// **Call this function on startup to ensure that all assumptions about the platform are valid.**
///
/// Unfortunately we have to make assumptions about the upper bounds of the `SystemTime` type on
/// your platform which we can't fully verify at compile time and which isn't part of it's contract.
/// To our best knowledge our assumptions hold for all platforms officially supported by rust, but
/// since this check is fast we recommend to do it anyway.
///
/// If this function fails this is considered a bug. Please open an issue describing your
/// platform and stating your current system time.
///
/// # Panics
/// If the check fails this function panics. By calling this function on startup you ensure that
/// this wont happen at an arbitrary later point in time.
#[no_mangle]
pub extern "C" fn check_platform() {
	lightning_invoice::check_platform()
}


use lightning_invoice::Invoice as nativeInvoiceImport;
type nativeInvoice = nativeInvoiceImport;

/// Represents a syntactically and semantically correct lightning BOLT11 invoice.
///
/// There are three ways to construct an `Invoice`:
///  1. using `InvoiceBuilder`
///  2. using `Invoice::from_signed(SignedRawInvoice)`
///  3. using `str::parse::<Invoice>(&str)`
#[must_use]
#[repr(C)]
pub struct Invoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Invoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the Invoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Invoice_free(this_obj: Invoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Invoice_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInvoice); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Invoice {
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoice {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two Invoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Invoice_eq(a: &Invoice, b: &Invoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for Invoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoice>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Invoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInvoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Invoice
pub extern "C" fn Invoice_clone(orig: &Invoice) -> Invoice {
	orig.clone()
}

use lightning_invoice::SignedRawInvoice as nativeSignedRawInvoiceImport;
type nativeSignedRawInvoice = nativeSignedRawInvoiceImport;

/// Represents a signed `RawInvoice` with cached hash. The signature is not checked and may be
/// invalid.
///
/// # Invariants
/// The hash has to be either from the deserialized invoice or from the serialized `raw_invoice`.
#[must_use]
#[repr(C)]
pub struct SignedRawInvoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeSignedRawInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for SignedRawInvoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeSignedRawInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the SignedRawInvoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn SignedRawInvoice_free(this_obj: SignedRawInvoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn SignedRawInvoice_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeSignedRawInvoice); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl SignedRawInvoice {
	pub(crate) fn take_inner(mut self) -> *mut nativeSignedRawInvoice {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two SignedRawInvoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn SignedRawInvoice_eq(a: &SignedRawInvoice, b: &SignedRawInvoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for SignedRawInvoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeSignedRawInvoice>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SignedRawInvoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeSignedRawInvoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the SignedRawInvoice
pub extern "C" fn SignedRawInvoice_clone(orig: &SignedRawInvoice) -> SignedRawInvoice {
	orig.clone()
}

use lightning_invoice::RawInvoice as nativeRawInvoiceImport;
type nativeRawInvoice = nativeRawInvoiceImport;

/// Represents an syntactically correct Invoice for a payment on the lightning network,
/// but without the signature information.
/// De- and encoding should not lead to information loss but may lead to different hashes.
///
/// For methods without docs see the corresponding methods in `Invoice`.
#[must_use]
#[repr(C)]
pub struct RawInvoice {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRawInvoice,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RawInvoice {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRawInvoice>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the RawInvoice, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RawInvoice_free(this_obj: RawInvoice) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RawInvoice_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRawInvoice); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RawInvoice {
	pub(crate) fn take_inner(mut self) -> *mut nativeRawInvoice {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// data part
#[no_mangle]
pub extern "C" fn RawInvoice_get_data(this_ptr: &RawInvoice) -> crate::lightning_invoice::RawDataPart {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.data;
	crate::lightning_invoice::RawDataPart { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// data part
#[no_mangle]
pub extern "C" fn RawInvoice_set_data(this_ptr: &mut RawInvoice, mut val: crate::lightning_invoice::RawDataPart) {
	unsafe { &mut *this_ptr.inner }.data = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Checks if two RawInvoices contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RawInvoice_eq(a: &RawInvoice, b: &RawInvoice) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for RawInvoice {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRawInvoice>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RawInvoice_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRawInvoice)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RawInvoice
pub extern "C" fn RawInvoice_clone(orig: &RawInvoice) -> RawInvoice {
	orig.clone()
}

use lightning_invoice::RawDataPart as nativeRawDataPartImport;
type nativeRawDataPart = nativeRawDataPartImport;

/// Data of the `RawInvoice` that is encoded in the data part
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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the RawDataPart, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RawDataPart_free(this_obj: RawDataPart) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RawDataPart_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRawDataPart); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RawDataPart {
	pub(crate) fn take_inner(mut self) -> *mut nativeRawDataPart {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// generation time of the invoice
#[no_mangle]
pub extern "C" fn RawDataPart_get_timestamp(this_ptr: &RawDataPart) -> crate::lightning_invoice::PositiveTimestamp {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.timestamp;
	crate::lightning_invoice::PositiveTimestamp { inner: unsafe { ( (&(*inner_val) as *const _) as *mut _) }, is_owned: false }
}
/// generation time of the invoice
#[no_mangle]
pub extern "C" fn RawDataPart_set_timestamp(this_ptr: &mut RawDataPart, mut val: crate::lightning_invoice::PositiveTimestamp) {
	unsafe { &mut *this_ptr.inner }.timestamp = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Checks if two RawDataParts contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RawDataPart_eq(a: &RawDataPart, b: &RawDataPart) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for RawDataPart {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRawDataPart>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning_invoice::PositiveTimestamp as nativePositiveTimestampImport;
type nativePositiveTimestamp = nativePositiveTimestampImport;

/// A timestamp that refers to a date after 1 January 1970 which means its representation as UNIX
/// timestamp is positive.
///
/// # Invariants
/// The UNIX timestamp representing the stored time has to be positive and small enough so that
/// a `EpiryTime` can be added to it without an overflow.
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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the PositiveTimestamp, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PositiveTimestamp_free(this_obj: PositiveTimestamp) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PositiveTimestamp_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePositiveTimestamp); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PositiveTimestamp {
	pub(crate) fn take_inner(mut self) -> *mut nativePositiveTimestamp {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
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
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for PositiveTimestamp {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePositiveTimestamp>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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
/// SI prefixes for the human readable part
#[must_use]
#[derive(Clone)]
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
use lightning_invoice::SiPrefix as nativeSiPrefix;
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
/// Checks if two SiPrefixs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SiPrefix_eq(a: &SiPrefix, b: &SiPrefix) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Returns the multiplier to go from a BTC value to picoBTC implied by this SiPrefix.
/// This is effectively 10^12 * the prefix multiplier
#[must_use]
#[no_mangle]
pub extern "C" fn SiPrefix_multiplier(this_arg: &SiPrefix) -> u64 {
	let mut ret = this_arg.to_native().multiplier();
	ret
}

/// Enum representing the crypto currencies (or networks) supported by this library
#[must_use]
#[derive(Clone)]
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
use lightning_invoice::Currency as nativeCurrency;
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
/// Checks if two Currencys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Currency_eq(a: &Currency, b: &Currency) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_invoice::Sha256 as nativeSha256Import;
type nativeSha256 = nativeSha256Import;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the Sha256, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Sha256_free(this_obj: Sha256) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Sha256_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeSha256); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Sha256 {
	pub(crate) fn take_inner(mut self) -> *mut nativeSha256 {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two Sha256s contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Sha256_eq(a: &Sha256, b: &Sha256) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for Sha256 {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeSha256>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning_invoice::Description as nativeDescriptionImport;
type nativeDescription = nativeDescriptionImport;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the Description, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Description_free(this_obj: Description) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Description_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDescription); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl Description {
	pub(crate) fn take_inner(mut self) -> *mut nativeDescription {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two Descriptions contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Description_eq(a: &Description, b: &Description) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for Description {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDescription>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning_invoice::PayeePubKey as nativePayeePubKeyImport;
type nativePayeePubKey = nativePayeePubKeyImport;

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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the PayeePubKey, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PayeePubKey_free(this_obj: PayeePubKey) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PayeePubKey_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePayeePubKey); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PayeePubKey {
	pub(crate) fn take_inner(mut self) -> *mut nativePayeePubKey {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two PayeePubKeys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn PayeePubKey_eq(a: &PayeePubKey, b: &PayeePubKey) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for PayeePubKey {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePayeePubKey>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning_invoice::ExpiryTime as nativeExpiryTimeImport;
type nativeExpiryTime = nativeExpiryTimeImport;

/// Positive duration that defines when (relatively to the timestamp) in the future the invoice
/// expires
///
/// # Invariants
/// The number of seconds this expiry time represents has to be in the range
/// `0...(SYSTEM_TIME_MAX_UNIX_TIMESTAMP - MAX_EXPIRY_TIME)` to avoid overflows when adding it to a
/// timestamp
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
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ExpiryTime, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ExpiryTime_free(this_obj: ExpiryTime) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ExpiryTime_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeExpiryTime); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ExpiryTime {
	pub(crate) fn take_inner(mut self) -> *mut nativeExpiryTime {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two ExpiryTimes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ExpiryTime_eq(a: &ExpiryTime, b: &ExpiryTime) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for ExpiryTime {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeExpiryTime>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
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

use lightning_invoice::MinFinalCltvExpiry as nativeMinFinalCltvExpiryImport;
type nativeMinFinalCltvExpiry = nativeMinFinalCltvExpiryImport;

/// `min_final_cltv_expiry` to use for the last HTLC in the route
#[must_use]
#[repr(C)]
pub struct MinFinalCltvExpiry {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMinFinalCltvExpiry,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MinFinalCltvExpiry {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMinFinalCltvExpiry>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the MinFinalCltvExpiry, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiry_free(this_obj: MinFinalCltvExpiry) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MinFinalCltvExpiry_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMinFinalCltvExpiry); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MinFinalCltvExpiry {
	pub(crate) fn take_inner(mut self) -> *mut nativeMinFinalCltvExpiry {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two MinFinalCltvExpirys contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn MinFinalCltvExpiry_eq(a: &MinFinalCltvExpiry, b: &MinFinalCltvExpiry) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for MinFinalCltvExpiry {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeMinFinalCltvExpiry>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MinFinalCltvExpiry_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeMinFinalCltvExpiry)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the MinFinalCltvExpiry
pub extern "C" fn MinFinalCltvExpiry_clone(orig: &MinFinalCltvExpiry) -> MinFinalCltvExpiry {
	orig.clone()
}
/// Fallback address in case no LN payment is possible
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum Fallback {
	SegWitProgram {
		version: crate::c_types::u5,
		program: crate::c_types::derived::CVec_u8Z,
	},
	PubKeyHash(crate::c_types::TwentyBytes),
	ScriptHash(crate::c_types::TwentyBytes),
}
use lightning_invoice::Fallback as nativeFallback;
impl Fallback {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeFallback {
		match self {
			Fallback::SegWitProgram {ref version, ref program, } => {
				let mut version_nonref = (*version).clone();
				let mut program_nonref = (*program).clone();
				let mut local_program_nonref = Vec::new(); for mut item in program_nonref.into_rust().drain(..) { local_program_nonref.push( { item }); };
				nativeFallback::SegWitProgram {
					version: version_nonref.into(),
					program: local_program_nonref,
				}
			},
			Fallback::PubKeyHash (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativeFallback::PubKeyHash (
					a_nonref.data,
				)
			},
			Fallback::ScriptHash (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativeFallback::ScriptHash (
					a_nonref.data,
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
					a.data,
				)
			},
			Fallback::ScriptHash (mut a, ) => {
				nativeFallback::ScriptHash (
					a.data,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeFallback) -> Self {
		match native {
			nativeFallback::SegWitProgram {ref version, ref program, } => {
				let mut version_nonref = (*version).clone();
				let mut program_nonref = (*program).clone();
				let mut local_program_nonref = Vec::new(); for mut item in program_nonref.drain(..) { local_program_nonref.push( { item }); };
				Fallback::SegWitProgram {
					version: version_nonref.into(),
					program: local_program_nonref.into(),
				}
			},
			nativeFallback::PubKeyHash (ref a, ) => {
				let mut a_nonref = (*a).clone();
				Fallback::PubKeyHash (
					crate::c_types::TwentyBytes { data: a_nonref },
				)
			},
			nativeFallback::ScriptHash (ref a, ) => {
				let mut a_nonref = (*a).clone();
				Fallback::ScriptHash (
					crate::c_types::TwentyBytes { data: a_nonref },
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
					crate::c_types::TwentyBytes { data: a },
				)
			},
			nativeFallback::ScriptHash (mut a, ) => {
				Fallback::ScriptHash (
					crate::c_types::TwentyBytes { data: a },
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
/// Checks if two Fallbacks contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Fallback_eq(a: &Fallback, b: &Fallback) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning_invoice::InvoiceSignature as nativeInvoiceSignatureImport;
type nativeInvoiceSignature = nativeInvoiceSignatureImport;

/// Recoverable signature
#[must_use]
#[repr(C)]
pub struct InvoiceSignature {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceSignature,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoiceSignature {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceSignature>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the InvoiceSignature, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceSignature_free(this_obj: InvoiceSignature) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn InvoiceSignature_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInvoiceSignature); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl InvoiceSignature {
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceSignature {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two InvoiceSignatures contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InvoiceSignature_eq(a: &InvoiceSignature, b: &InvoiceSignature) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for InvoiceSignature {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceSignature>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceSignature_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInvoiceSignature)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceSignature
pub extern "C" fn InvoiceSignature_clone(orig: &InvoiceSignature) -> InvoiceSignature {
	orig.clone()
}

use lightning_invoice::RouteHint as nativeRouteHintImport;
type nativeRouteHint = nativeRouteHintImport;

/// Private routing information
///
/// # Invariants
/// The encoded route has to be <1024 5bit characters long (<=639 bytes or <=12 hops)
///
#[must_use]
#[repr(C)]
pub struct RouteHint {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHint,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHint {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHint>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the RouteHint, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHint_free(this_obj: RouteHint) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RouteHint_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRouteHint); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl RouteHint {
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHint {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Checks if two RouteHints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHint_eq(a: &RouteHint, b: &RouteHint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for RouteHint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHint>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHint_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRouteHint)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHint
pub extern "C" fn RouteHint_clone(orig: &RouteHint) -> RouteHint {
	orig.clone()
}
/// Disassembles the `SignedRawInvoice` into its three parts:
///  1. raw invoice
///  2. hash of the raw invoice
///  3. signature
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_into_parts(mut this_arg: SignedRawInvoice) -> crate::c_types::derived::C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_parts();
	let (mut orig_ret_0, mut orig_ret_1, mut orig_ret_2) = ret; let mut local_ret = (crate::lightning_invoice::RawInvoice { inner: Box::into_raw(Box::new(orig_ret_0)), is_owned: true }, crate::c_types::ThirtyTwoBytes { data: orig_ret_1 }, crate::lightning_invoice::InvoiceSignature { inner: Box::into_raw(Box::new(orig_ret_2)), is_owned: true }).into();
	local_ret
}

/// The `RawInvoice` which was signed.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_raw_invoice(this_arg: &SignedRawInvoice) -> crate::lightning_invoice::RawInvoice {
	let mut ret = unsafe { &*this_arg.inner }.raw_invoice();
	crate::lightning_invoice::RawInvoice { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// The hash of the `RawInvoice` that was signed.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_hash(this_arg: &SignedRawInvoice) -> *const [u8; 32] {
	let mut ret = unsafe { &*this_arg.inner }.hash();
	ret
}

/// InvoiceSignature for the invoice.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_signature(this_arg: &SignedRawInvoice) -> crate::lightning_invoice::InvoiceSignature {
	let mut ret = unsafe { &*this_arg.inner }.signature();
	crate::lightning_invoice::InvoiceSignature { inner: unsafe { ( (&(*ret) as *const _) as *mut _) }, is_owned: false }
}

/// Recovers the public key used for signing the invoice from the recoverable signature.
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_recover_payee_pub_key(this_arg: &SignedRawInvoice) -> crate::c_types::derived::CResult_PayeePubKeyErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.recover_payee_pub_key();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PayeePubKey { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::Secp256k1Error::from_rust(e) }).into() };
	local_ret
}

/// Checks if the signature is valid for the included payee public key or if none exists if it's
/// valid for the recovered signature (which should always be true?).
#[must_use]
#[no_mangle]
pub extern "C" fn SignedRawInvoice_check_signature(this_arg: &SignedRawInvoice) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.check_signature();
	ret
}

/// Calculate the hash of the encoded `RawInvoice`
#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_hash(this_arg: &RawInvoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.hash();
	crate::c_types::ThirtyTwoBytes { data: ret }
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_payment_hash(this_arg: &RawInvoice) -> crate::lightning_invoice::Sha256 {
	let mut ret = unsafe { &*this_arg.inner }.payment_hash();
	let mut local_ret = crate::lightning_invoice::Sha256 { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_description(this_arg: &RawInvoice) -> crate::lightning_invoice::Description {
	let mut ret = unsafe { &*this_arg.inner }.description();
	let mut local_ret = crate::lightning_invoice::Description { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_payee_pub_key(this_arg: &RawInvoice) -> crate::lightning_invoice::PayeePubKey {
	let mut ret = unsafe { &*this_arg.inner }.payee_pub_key();
	let mut local_ret = crate::lightning_invoice::PayeePubKey { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_description_hash(this_arg: &RawInvoice) -> crate::lightning_invoice::Sha256 {
	let mut ret = unsafe { &*this_arg.inner }.description_hash();
	let mut local_ret = crate::lightning_invoice::Sha256 { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_expiry_time(this_arg: &RawInvoice) -> crate::lightning_invoice::ExpiryTime {
	let mut ret = unsafe { &*this_arg.inner }.expiry_time();
	let mut local_ret = crate::lightning_invoice::ExpiryTime { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_min_final_cltv_expiry(this_arg: &RawInvoice) -> crate::lightning_invoice::MinFinalCltvExpiry {
	let mut ret = unsafe { &*this_arg.inner }.min_final_cltv_expiry();
	let mut local_ret = crate::lightning_invoice::MinFinalCltvExpiry { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_payment_secret(this_arg: &RawInvoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.payment_secret();
	let mut local_ret = if ret.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (ret.unwrap()).0 } } };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_features(this_arg: &RawInvoice) -> crate::lightning::ln::features::InvoiceFeatures {
	let mut ret = unsafe { &*this_arg.inner }.features();
	let mut local_ret = crate::lightning::ln::features::InvoiceFeatures { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_routes(this_arg: &RawInvoice) -> crate::c_types::derived::CVec_RouteHintZ {
	let mut ret = unsafe { &*this_arg.inner }.routes();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning_invoice::RouteHint { inner: unsafe { ( (&(**item) as *const _) as *mut _) }, is_owned: false } }); };
	local_ret.into()
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_amount_pico_btc(this_arg: &RawInvoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*this_arg.inner }.amount_pico_btc();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else {  { crate::c_types::derived::COption_u64Z::Some(ret.unwrap()) } };
	local_ret
}

#[must_use]
#[no_mangle]
pub extern "C" fn RawInvoice_currency(this_arg: &RawInvoice) -> crate::lightning_invoice::Currency {
	let mut ret = unsafe { &*this_arg.inner }.currency();
	crate::lightning_invoice::Currency::native_into(ret)
}

/// Create a new `PositiveTimestamp` from a unix timestamp in the Range
/// `0...SYSTEM_TIME_MAX_UNIX_TIMESTAMP - MAX_EXPIRY_TIME`, otherwise return a
/// `CreationError::TimestampOutOfBounds`.
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_from_unix_timestamp(mut unix_seconds: u64) -> crate::c_types::derived::CResult_PositiveTimestampCreationErrorZ {
	let mut ret = lightning_invoice::PositiveTimestamp::from_unix_timestamp(unix_seconds);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PositiveTimestamp { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Create a new `PositiveTimestamp` from a `SystemTime` with a corresponding unix timestamp in
/// the Range `0...SYSTEM_TIME_MAX_UNIX_TIMESTAMP - MAX_EXPIRY_TIME`, otherwise return a
/// `CreationError::TimestampOutOfBounds`.
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_from_system_time(mut time: u64) -> crate::c_types::derived::CResult_PositiveTimestampCreationErrorZ {
	let mut ret = lightning_invoice::PositiveTimestamp::from_system_time((::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(time)));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::PositiveTimestamp { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the UNIX timestamp representing the stored time
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_as_unix_timestamp(this_arg: &PositiveTimestamp) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.as_unix_timestamp();
	ret
}

/// Returns a reference to the internal `SystemTime` time representation
#[must_use]
#[no_mangle]
pub extern "C" fn PositiveTimestamp_as_time(this_arg: &PositiveTimestamp) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.as_time();
	ret.duration_since(::std::time::SystemTime::UNIX_EPOCH).expect("Times must be post-1970").as_secs()
}

/// Transform the `Invoice` into it's unchecked version
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_into_signed_raw(mut this_arg: Invoice) -> crate::lightning_invoice::SignedRawInvoice {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_signed_raw();
	crate::lightning_invoice::SignedRawInvoice { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Check that the invoice is signed correctly and that key recovery works
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_check_signature(this_arg: &Invoice) -> crate::c_types::derived::CResult_NoneSemanticErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.check_signature();
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SemanticError::native_into(e) }).into() };
	local_ret
}

/// Constructs an `Invoice` from a `SignedInvoice` by checking all its invariants.
/// ```
/// use lightning_invoice::*;
///
/// let invoice = \"lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp\\
/// \tl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d7\\
/// \t3gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ec\\
/// \tky03ylcqca784w\";
///
/// let signed = invoice.parse::<SignedRawInvoice>().unwrap();
///
/// assert!(Invoice::from_signed(signed).is_ok());
/// ```
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_from_signed(mut signed_invoice: crate::lightning_invoice::SignedRawInvoice) -> crate::c_types::derived::CResult_InvoiceSemanticErrorZ {
	let mut ret = lightning_invoice::Invoice::from_signed(*unsafe { Box::from_raw(signed_invoice.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SemanticError::native_into(e) }).into() };
	local_ret
}

/// Returns the `Invoice`'s timestamp (should equal it's creation time)
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_timestamp(this_arg: &Invoice) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.timestamp();
	ret.duration_since(::std::time::SystemTime::UNIX_EPOCH).expect("Times must be post-1970").as_secs()
}

/// Returns the hash to which we will receive the preimage on completion of the payment
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_payment_hash(this_arg: &Invoice) -> *const [u8; 32] {
	let mut ret = unsafe { &*this_arg.inner }.payment_hash();
	ret.as_inner()
}

/// Get the payee's public key if one was included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_payee_pub_key(this_arg: &Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*this_arg.inner }.payee_pub_key();
	let mut local_ret = if ret.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(ret.unwrap())) } };
	local_ret
}

/// Get the payment secret if one was included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_payment_secret(this_arg: &Invoice) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*this_arg.inner }.payment_secret();
	let mut local_ret = if ret.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (ret.unwrap()).0 } } };
	local_ret
}

/// Get the invoice features if they were included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_features(this_arg: &Invoice) -> crate::lightning::ln::features::InvoiceFeatures {
	let mut ret = unsafe { &*this_arg.inner }.features();
	let mut local_ret = crate::lightning::ln::features::InvoiceFeatures { inner: unsafe { (if ret.is_none() { std::ptr::null() } else {  { (ret.unwrap()) } } as *const _) as *mut _ }, is_owned: false };
	local_ret
}

/// Recover the payee's public key (only to be used if none was included in the invoice)
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_recover_payee_pub_key(this_arg: &Invoice) -> crate::c_types::PublicKey {
	let mut ret = unsafe { &*this_arg.inner }.recover_payee_pub_key();
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Returns the invoice's expiry time, if present, otherwise [`DEFAULT_EXPIRY_TIME`].
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_expiry_time(this_arg: &Invoice) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.expiry_time();
	ret.as_secs()
}

/// Returns the invoice's `min_final_cltv_expiry` time, if present, otherwise
/// [`DEFAULT_MIN_FINAL_CLTV_EXPIRY`].
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_min_final_cltv_expiry(this_arg: &Invoice) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.min_final_cltv_expiry();
	ret
}

/// Returns a list of all routes included in the invoice
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_routes(this_arg: &Invoice) -> crate::c_types::derived::CVec_RouteHintZ {
	let mut ret = unsafe { &*this_arg.inner }.routes();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning_invoice::RouteHint { inner: unsafe { ( (&(**item) as *const _) as *mut _) }, is_owned: false } }); };
	local_ret.into()
}

/// Returns the currency for which the invoice was issued
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_currency(this_arg: &Invoice) -> crate::lightning_invoice::Currency {
	let mut ret = unsafe { &*this_arg.inner }.currency();
	crate::lightning_invoice::Currency::native_into(ret)
}

/// Returns the amount if specified in the invoice as pico <currency>.
#[must_use]
#[no_mangle]
pub extern "C" fn Invoice_amount_pico_btc(this_arg: &Invoice) -> crate::c_types::derived::COption_u64Z {
	let mut ret = unsafe { &*this_arg.inner }.amount_pico_btc();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u64Z::None } else {  { crate::c_types::derived::COption_u64Z::Some(ret.unwrap()) } };
	local_ret
}

/// Creates a new `Description` if `description` is at most 1023 __bytes__ long,
/// returns `CreationError::DescriptionTooLong` otherwise
///
/// Please note that single characters may use more than one byte due to UTF8 encoding.
#[must_use]
#[no_mangle]
pub extern "C" fn Description_new(mut description: crate::c_types::Str) -> crate::c_types::derived::CResult_DescriptionCreationErrorZ {
	let mut ret = lightning_invoice::Description::new(description.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Description { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the underlying description `String`
#[must_use]
#[no_mangle]
pub extern "C" fn Description_into_inner(mut this_arg: Description) -> crate::c_types::Str {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_inner();
	ret.into()
}

/// Construct an `ExpiryTime` from seconds. If there exists a `PositiveTimestamp` which would
/// overflow on adding the `EpiryTime` to it then this function will return a
/// `CreationError::ExpiryTimeOutOfBounds`.
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_from_seconds(mut seconds: u64) -> crate::c_types::derived::CResult_ExpiryTimeCreationErrorZ {
	let mut ret = lightning_invoice::ExpiryTime::from_seconds(seconds);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::ExpiryTime { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Construct an `ExpiryTime` from a `Duration`. If there exists a `PositiveTimestamp` which
/// would overflow on adding the `EpiryTime` to it then this function will return a
/// `CreationError::ExpiryTimeOutOfBounds`.
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_from_duration(mut duration: u64) -> crate::c_types::derived::CResult_ExpiryTimeCreationErrorZ {
	let mut ret = lightning_invoice::ExpiryTime::from_duration(std::time::Duration::from_secs(duration));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::ExpiryTime { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returns the expiry time in seconds
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_as_seconds(this_arg: &ExpiryTime) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.as_seconds();
	ret
}

/// Returns a reference to the underlying `Duration` (=expiry time)
#[must_use]
#[no_mangle]
pub extern "C" fn ExpiryTime_as_duration(this_arg: &ExpiryTime) -> u64 {
	let mut ret = unsafe { &*this_arg.inner }.as_duration();
	ret.as_secs()
}

/// Create a new (partial) route from a list of hops
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHint_new(mut hops: crate::c_types::derived::CVec_RouteHintHopZ) -> crate::c_types::derived::CResult_RouteHintCreationErrorZ {
	let mut local_hops = Vec::new(); for mut item in hops.into_rust().drain(..) { local_hops.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning_invoice::RouteHint::new(local_hops);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::RouteHint { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::CreationError::native_into(e) }).into() };
	local_ret
}

/// Returrn the underlying vector of hops
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHint_into_inner(mut this_arg: RouteHint) -> crate::c_types::derived::CVec_RouteHintHopZ {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_inner();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::routing::router::RouteHintHop { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}

/// Errors that may occur when constructing a new `RawInvoice` or `Invoice`
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum CreationError {
	/// The supplied description string was longer than 639 __bytes__ (see [`Description::new(…)`](./struct.Description.html#method.new))
	DescriptionTooLong,
	/// The specified route has too many hops and can't be encoded
	RouteTooLong,
	/// The unix timestamp of the supplied date is <0 or can't be represented as `SystemTime`
	TimestampOutOfBounds,
	/// The supplied expiry time could cause an overflow if added to a `PositiveTimestamp`
	ExpiryTimeOutOfBounds,
}
use lightning_invoice::CreationError as nativeCreationError;
impl CreationError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeCreationError {
		match self {
			CreationError::DescriptionTooLong => nativeCreationError::DescriptionTooLong,
			CreationError::RouteTooLong => nativeCreationError::RouteTooLong,
			CreationError::TimestampOutOfBounds => nativeCreationError::TimestampOutOfBounds,
			CreationError::ExpiryTimeOutOfBounds => nativeCreationError::ExpiryTimeOutOfBounds,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeCreationError {
		match self {
			CreationError::DescriptionTooLong => nativeCreationError::DescriptionTooLong,
			CreationError::RouteTooLong => nativeCreationError::RouteTooLong,
			CreationError::TimestampOutOfBounds => nativeCreationError::TimestampOutOfBounds,
			CreationError::ExpiryTimeOutOfBounds => nativeCreationError::ExpiryTimeOutOfBounds,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeCreationError) -> Self {
		match native {
			nativeCreationError::DescriptionTooLong => CreationError::DescriptionTooLong,
			nativeCreationError::RouteTooLong => CreationError::RouteTooLong,
			nativeCreationError::TimestampOutOfBounds => CreationError::TimestampOutOfBounds,
			nativeCreationError::ExpiryTimeOutOfBounds => CreationError::ExpiryTimeOutOfBounds,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeCreationError) -> Self {
		match native {
			nativeCreationError::DescriptionTooLong => CreationError::DescriptionTooLong,
			nativeCreationError::RouteTooLong => CreationError::RouteTooLong,
			nativeCreationError::TimestampOutOfBounds => CreationError::TimestampOutOfBounds,
			nativeCreationError::ExpiryTimeOutOfBounds => CreationError::ExpiryTimeOutOfBounds,
		}
	}
}
/// Creates a copy of the CreationError
#[no_mangle]
pub extern "C" fn CreationError_clone(orig: &CreationError) -> CreationError {
	orig.clone()
}
/// Checks if two CreationErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn CreationError_eq(a: &CreationError, b: &CreationError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a CreationError object
pub extern "C" fn CreationError_to_str(o: &crate::lightning_invoice::CreationError) -> Str {
	format!("{}", &o.to_native()).into()
}
/// Errors that may occur when converting a `RawInvoice` to an `Invoice`. They relate to the
/// requirements sections in BOLT #11
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum SemanticError {
	/// The invoice is missing the mandatory payment hash
	NoPaymentHash,
	/// The invoice has multiple payment hashes which isn't allowed
	MultiplePaymentHashes,
	/// No description or description hash are part of the invoice
	NoDescription,
	/// The invoice contains multiple descriptions and/or description hashes which isn't allowed
	MultipleDescriptions,
	/// The invoice contains multiple payment secrets
	MultiplePaymentSecrets,
	/// The invoice's features are invalid
	InvalidFeatures,
	/// The recovery id doesn't fit the signature/pub key
	InvalidRecoveryId,
	/// The invoice's signature is invalid
	InvalidSignature,
}
use lightning_invoice::SemanticError as nativeSemanticError;
impl SemanticError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSemanticError {
		match self {
			SemanticError::NoPaymentHash => nativeSemanticError::NoPaymentHash,
			SemanticError::MultiplePaymentHashes => nativeSemanticError::MultiplePaymentHashes,
			SemanticError::NoDescription => nativeSemanticError::NoDescription,
			SemanticError::MultipleDescriptions => nativeSemanticError::MultipleDescriptions,
			SemanticError::MultiplePaymentSecrets => nativeSemanticError::MultiplePaymentSecrets,
			SemanticError::InvalidFeatures => nativeSemanticError::InvalidFeatures,
			SemanticError::InvalidRecoveryId => nativeSemanticError::InvalidRecoveryId,
			SemanticError::InvalidSignature => nativeSemanticError::InvalidSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSemanticError {
		match self {
			SemanticError::NoPaymentHash => nativeSemanticError::NoPaymentHash,
			SemanticError::MultiplePaymentHashes => nativeSemanticError::MultiplePaymentHashes,
			SemanticError::NoDescription => nativeSemanticError::NoDescription,
			SemanticError::MultipleDescriptions => nativeSemanticError::MultipleDescriptions,
			SemanticError::MultiplePaymentSecrets => nativeSemanticError::MultiplePaymentSecrets,
			SemanticError::InvalidFeatures => nativeSemanticError::InvalidFeatures,
			SemanticError::InvalidRecoveryId => nativeSemanticError::InvalidRecoveryId,
			SemanticError::InvalidSignature => nativeSemanticError::InvalidSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeSemanticError) -> Self {
		match native {
			nativeSemanticError::NoPaymentHash => SemanticError::NoPaymentHash,
			nativeSemanticError::MultiplePaymentHashes => SemanticError::MultiplePaymentHashes,
			nativeSemanticError::NoDescription => SemanticError::NoDescription,
			nativeSemanticError::MultipleDescriptions => SemanticError::MultipleDescriptions,
			nativeSemanticError::MultiplePaymentSecrets => SemanticError::MultiplePaymentSecrets,
			nativeSemanticError::InvalidFeatures => SemanticError::InvalidFeatures,
			nativeSemanticError::InvalidRecoveryId => SemanticError::InvalidRecoveryId,
			nativeSemanticError::InvalidSignature => SemanticError::InvalidSignature,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSemanticError) -> Self {
		match native {
			nativeSemanticError::NoPaymentHash => SemanticError::NoPaymentHash,
			nativeSemanticError::MultiplePaymentHashes => SemanticError::MultiplePaymentHashes,
			nativeSemanticError::NoDescription => SemanticError::NoDescription,
			nativeSemanticError::MultipleDescriptions => SemanticError::MultipleDescriptions,
			nativeSemanticError::MultiplePaymentSecrets => SemanticError::MultiplePaymentSecrets,
			nativeSemanticError::InvalidFeatures => SemanticError::InvalidFeatures,
			nativeSemanticError::InvalidRecoveryId => SemanticError::InvalidRecoveryId,
			nativeSemanticError::InvalidSignature => SemanticError::InvalidSignature,
		}
	}
}
/// Creates a copy of the SemanticError
#[no_mangle]
pub extern "C" fn SemanticError_clone(orig: &SemanticError) -> SemanticError {
	orig.clone()
}
/// Checks if two SemanticErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SemanticError_eq(a: &SemanticError, b: &SemanticError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a SemanticError object
pub extern "C" fn SemanticError_to_str(o: &crate::lightning_invoice::SemanticError) -> Str {
	format!("{}", &o.to_native()).into()
}
/// When signing using a fallible method either an user-supplied `SignError` or a `CreationError`
/// may occur.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum SignOrCreationError {
	/// An error occurred during signing
	SignError,
	/// An error occurred while building the transaction
	CreationError(crate::lightning_invoice::CreationError),
}
use lightning_invoice::SignOrCreationError as nativeSignOrCreationError;
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
				let mut a_nonref = (*a).clone();
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
				let mut a_nonref = (*a).clone();
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
/// Checks if two SignOrCreationErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SignOrCreationError_eq(a: &SignOrCreationError, b: &SignOrCreationError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Get the string representation of a SignOrCreationError object
pub extern "C" fn SignOrCreationError_to_str(o: &crate::lightning_invoice::SignOrCreationError) -> Str {
	format!("{}", &o.to_native()).into()
}
