// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Feature flag definitions for the Lightning protocol according to [BOLT #9].
//!
//! Lightning nodes advertise a supported set of operation through feature flags. Features are
//! applicable for a specific context as indicated in some [messages]. [`Features`] encapsulates
//! behavior for specifying and checking feature flags for a particular context. Each feature is
//! defined internally by a trait specifying the corresponding flags (i.e., even and odd bits).
//!
//! Whether a feature is considered \"known\" or \"unknown\" is relative to the implementation, whereas
//! the term \"supports\" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! [BOLT #9]: https://github.com/lightningnetwork/lightning-rfc/blob/master/09-features.md
//! [messages]: crate::ln::msgs

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

mod sealed {

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

}
/// Checks if two InitFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InitFeatures_eq(a: &InitFeatures, b: &InitFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
/// Checks if two NodeFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn NodeFeatures_eq(a: &NodeFeatures, b: &NodeFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
/// Checks if two ChannelFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelFeatures_eq(a: &ChannelFeatures, b: &ChannelFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
/// Checks if two InvoiceFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InvoiceFeatures_eq(a: &InvoiceFeatures, b: &InvoiceFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if unsafe { &*a.inner } == unsafe { &*b.inner } { true } else { false }
}
impl Clone for InitFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInitFeatures>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InitFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInitFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InitFeatures
pub extern "C" fn InitFeatures_clone(orig: &InitFeatures) -> InitFeatures {
	orig.clone()
}
impl Clone for NodeFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeFeatures>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeFeatures
pub extern "C" fn NodeFeatures_clone(orig: &NodeFeatures) -> NodeFeatures {
	orig.clone()
}
impl Clone for ChannelFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelFeatures>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelFeatures
pub extern "C" fn ChannelFeatures_clone(orig: &ChannelFeatures) -> ChannelFeatures {
	orig.clone()
}
impl Clone for InvoiceFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceFeatures>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInvoiceFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceFeatures
pub extern "C" fn InvoiceFeatures_clone(orig: &InvoiceFeatures) -> InvoiceFeatures {
	orig.clone()
}

use lightning::ln::features::InitFeatures as nativeInitFeaturesImport;
type nativeInitFeatures = nativeInitFeaturesImport;

/// Features used within an `init` message.
#[must_use]
#[repr(C)]
pub struct InitFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInitFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InitFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInitFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the InitFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InitFeatures_free(this_obj: InitFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn InitFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInitFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl InitFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeInitFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::NodeFeatures as nativeNodeFeaturesImport;
type nativeNodeFeatures = nativeNodeFeaturesImport;

/// Features used within a `node_announcement` message.
#[must_use]
#[repr(C)]
pub struct NodeFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the NodeFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeFeatures_free(this_obj: NodeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn NodeFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl NodeFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelFeatures as nativeChannelFeaturesImport;
type nativeChannelFeatures = nativeChannelFeaturesImport;

/// Features used within a `channel_announcement` message.
#[must_use]
#[repr(C)]
pub struct ChannelFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ChannelFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelFeatures_free(this_obj: ChannelFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ChannelFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ChannelFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::InvoiceFeatures as nativeInvoiceFeaturesImport;
type nativeInvoiceFeatures = nativeInvoiceFeaturesImport;

/// Features used within an invoice.
#[must_use]
#[repr(C)]
pub struct InvoiceFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoiceFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the InvoiceFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceFeatures_free(this_obj: InvoiceFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn InvoiceFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInvoiceFeatures); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl InvoiceFeatures {
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceFeatures {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_empty() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::empty();
	InitFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_known() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::known();
	InitFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_empty() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::empty();
	NodeFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_known() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::known();
	NodeFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_empty() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::empty();
	ChannelFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_known() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::known();
	ChannelFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_empty() -> InvoiceFeatures {
	let mut ret = lightning::ln::features::InvoiceFeatures::empty();
	InvoiceFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_known() -> InvoiceFeatures {
	let mut ret = lightning::ln::features::InvoiceFeatures::known();
	InvoiceFeatures { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Returns whether the `payment_secret` feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_payment_secret(this_arg: &InitFeatures) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.supports_payment_secret();
	ret
}

/// Returns whether the `payment_secret` feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_payment_secret(this_arg: &NodeFeatures) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.supports_payment_secret();
	ret
}

/// Returns whether the `payment_secret` feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_supports_payment_secret(this_arg: &InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*this_arg.inner }.supports_payment_secret();
	ret
}

#[no_mangle]
/// Serialize the InitFeatures object into a byte array which can be read by InitFeatures_read
pub extern "C" fn InitFeatures_write(obj: &InitFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn InitFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInitFeatures) })
}
#[no_mangle]
/// Serialize the NodeFeatures object into a byte array which can be read by NodeFeatures_read
pub extern "C" fn NodeFeatures_write(obj: &NodeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn NodeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeFeatures) })
}
#[no_mangle]
/// Serialize the ChannelFeatures object into a byte array which can be read by ChannelFeatures_read
pub extern "C" fn ChannelFeatures_write(obj: &ChannelFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn ChannelFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelFeatures) })
}
#[no_mangle]
/// Serialize the InvoiceFeatures object into a byte array which can be read by InvoiceFeatures_read
pub extern "C" fn InvoiceFeatures_write(obj: &InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*unsafe { &*obj }.inner })
}
#[no_mangle]
pub(crate) extern "C" fn InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInvoiceFeatures) })
}
#[no_mangle]
/// Read a InitFeatures from a byte array, created by InitFeatures_write
pub extern "C" fn InitFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::InitFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Read a NodeFeatures from a byte array, created by NodeFeatures_write
pub extern "C" fn NodeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::NodeFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Read a ChannelFeatures from a byte array, created by ChannelFeatures_write
pub extern "C" fn ChannelFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::ChannelFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Read a InvoiceFeatures from a byte array, created by InvoiceFeatures_write
pub extern "C" fn InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InvoiceFeaturesDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::InvoiceFeatures { inner: Box::into_raw(Box::new(o)), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_res
}
