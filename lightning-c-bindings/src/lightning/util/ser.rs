// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as [`ChannelManager`]s and [`ChannelMonitor`]s.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
//! [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// serialization buffer size

#[no_mangle]
pub static MAX_BUF_SIZE: usize = lightning::util::ser::MAX_BUF_SIZE;

use lightning::util::ser::BigSize as nativeBigSizeImport;
pub(crate) type nativeBigSize = nativeBigSizeImport;

/// Lightning TLV uses a custom variable-length integer called `BigSize`. It is similar to Bitcoin's
/// variable-length integers except that it is serialized in big-endian instead of little-endian.
///
/// Like Bitcoin's variable-length integer, it exhibits ambiguity in that certain values can be
/// encoded in several different ways, which we must check for at deserialization-time. Thus, if
/// you're looking for an example of a variable-length integer to use for your own project, move
/// along, this is a rather poor design.
#[must_use]
#[repr(C)]
pub struct BigSize {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBigSize,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BigSize {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBigSize>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BigSize, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BigSize_free(this_obj: BigSize) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BigSize_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBigSize) };
}
#[allow(unused)]
impl BigSize {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBigSize {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBigSize {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBigSize {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn BigSize_get_a(this_ptr: &BigSize) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	*inner_val
}
#[no_mangle]
pub extern "C" fn BigSize_set_a(this_ptr: &mut BigSize, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val;
}
/// Constructs a new BigSize given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BigSize_new(mut a_arg: u64) -> BigSize {
	BigSize { inner: ObjOps::heap_alloc(lightning::util::ser::BigSize (
		a_arg,
	)), is_owned: true }
}
impl Clone for BigSize {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBigSize>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BigSize_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBigSize)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BigSize
pub extern "C" fn BigSize_clone(orig: &BigSize) -> BigSize {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the BigSize.
#[no_mangle]
pub extern "C" fn BigSize_hash(o: &BigSize) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two BigSizes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BigSize_eq(a: &BigSize, b: &BigSize) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the BigSize object into a byte array which can be read by BigSize_read
pub extern "C" fn BigSize_write(obj: &crate::lightning::util::ser::BigSize) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn BigSize_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBigSize) })
}
#[no_mangle]
/// Read a BigSize from a byte array, created by BigSize_write
pub extern "C" fn BigSize_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BigSizeDecodeErrorZ {
	let res: Result<lightning::util::ser::BigSize, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::BigSize { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::ser::Hostname as nativeHostnameImport;
pub(crate) type nativeHostname = nativeHostnameImport;

/// Represents a hostname for serialization purposes.
/// Only the character set and length will be validated.
/// The character set consists of ASCII alphanumeric characters, hyphens, and periods.
/// Its length is guaranteed to be representable by a single byte.
/// This serialization is used by [`BOLT 7`] hostnames.
///
/// [`BOLT 7`]: https://github.com/lightning/bolts/blob/master/07-routing-gossip.md
#[must_use]
#[repr(C)]
pub struct Hostname {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHostname,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Hostname {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHostname>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Hostname, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Hostname_free(this_obj: Hostname) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Hostname_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHostname) };
}
#[allow(unused)]
impl Hostname {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHostname {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHostname {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHostname {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Hostname {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHostname>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Hostname_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHostname)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Hostname
pub extern "C" fn Hostname_clone(orig: &Hostname) -> Hostname {
	orig.clone()
}
/// Checks if two Hostnames contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Hostname_eq(a: &Hostname, b: &Hostname) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the length of the hostname.
#[must_use]
#[no_mangle]
pub extern "C" fn Hostname_len(this_arg: &crate::lightning::util::ser::Hostname) -> u8 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.len();
	ret
}

#[no_mangle]
/// Serialize the Hostname object into a byte array which can be read by Hostname_read
pub extern "C" fn Hostname_write(obj: &crate::lightning::util::ser::Hostname) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Hostname_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHostname) })
}
#[no_mangle]
/// Read a Hostname from a byte array, created by Hostname_write
pub extern "C" fn Hostname_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HostnameDecodeErrorZ {
	let res: Result<lightning::util::ser::Hostname, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::Hostname { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::util::ser::TransactionU16LenLimited as nativeTransactionU16LenLimitedImport;
pub(crate) type nativeTransactionU16LenLimited = nativeTransactionU16LenLimitedImport;

/// A wrapper for a `Transaction` which can only be constructed with [`TransactionU16LenLimited::new`]
/// if the `Transaction`'s consensus-serialized length is <= u16::MAX.
///
/// Use [`TransactionU16LenLimited::into_transaction`] to convert into the contained `Transaction`.
#[must_use]
#[repr(C)]
pub struct TransactionU16LenLimited {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTransactionU16LenLimited,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for TransactionU16LenLimited {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTransactionU16LenLimited>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TransactionU16LenLimited, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TransactionU16LenLimited_free(this_obj: TransactionU16LenLimited) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TransactionU16LenLimited_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTransactionU16LenLimited) };
}
#[allow(unused)]
impl TransactionU16LenLimited {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTransactionU16LenLimited {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTransactionU16LenLimited {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTransactionU16LenLimited {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for TransactionU16LenLimited {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeTransactionU16LenLimited>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TransactionU16LenLimited_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeTransactionU16LenLimited)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the TransactionU16LenLimited
pub extern "C" fn TransactionU16LenLimited_clone(orig: &TransactionU16LenLimited) -> TransactionU16LenLimited {
	orig.clone()
}
/// Checks if two TransactionU16LenLimiteds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn TransactionU16LenLimited_eq(a: &TransactionU16LenLimited, b: &TransactionU16LenLimited) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Constructs a new `TransactionU16LenLimited` from a `Transaction` only if it's consensus-
/// serialized length is <= u16::MAX.
#[must_use]
#[no_mangle]
pub extern "C" fn TransactionU16LenLimited_new(mut transaction: crate::c_types::Transaction) -> crate::c_types::derived::CResult_TransactionU16LenLimitedNoneZ {
	let mut ret = lightning::util::ser::TransactionU16LenLimited::new(transaction.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::TransactionU16LenLimited { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Consumes this `TransactionU16LenLimited` and returns its contained `Transaction`.
#[must_use]
#[no_mangle]
pub extern "C" fn TransactionU16LenLimited_into_transaction(mut this_arg: crate::lightning::util::ser::TransactionU16LenLimited) -> crate::c_types::Transaction {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).into_transaction();
	crate::c_types::Transaction::from_bitcoin(&ret)
}

#[no_mangle]
/// Serialize the TransactionU16LenLimited object into a byte array which can be read by TransactionU16LenLimited_read
pub extern "C" fn TransactionU16LenLimited_write(obj: &crate::lightning::util::ser::TransactionU16LenLimited) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn TransactionU16LenLimited_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeTransactionU16LenLimited) })
}
#[no_mangle]
/// Read a TransactionU16LenLimited from a byte array, created by TransactionU16LenLimited_write
pub extern "C" fn TransactionU16LenLimited_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_TransactionU16LenLimitedDecodeErrorZ {
	let res: Result<lightning::util::ser::TransactionU16LenLimited, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::ser::TransactionU16LenLimited { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
