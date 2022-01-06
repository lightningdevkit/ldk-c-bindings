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

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod sealed {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
/// Checks if two InitFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InitFeatures_eq(a: &InitFeatures, b: &InitFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two NodeFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn NodeFeatures_eq(a: &NodeFeatures, b: &NodeFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two ChannelFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelFeatures_eq(a: &ChannelFeatures, b: &ChannelFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two InvoiceFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InvoiceFeatures_eq(a: &InvoiceFeatures, b: &InvoiceFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two ChannelTypeFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_eq(a: &ChannelTypeFeatures, b: &ChannelTypeFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for InitFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInitFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
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
			inner: if <*mut nativeNodeFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
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
			inner: if <*mut nativeChannelFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
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
			inner: if <*mut nativeInvoiceFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
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
impl Clone for ChannelTypeFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelTypeFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTypeFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelTypeFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelTypeFeatures
pub extern "C" fn ChannelTypeFeatures_clone(orig: &ChannelTypeFeatures) -> ChannelTypeFeatures {
	orig.clone()
}

use lightning::ln::features::InitFeatures as nativeInitFeaturesImport;
pub(crate) type nativeInitFeatures = nativeInitFeaturesImport;

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
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InitFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InitFeatures_free(this_obj: InitFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InitFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInitFeatures); }
}
#[allow(unused)]
impl InitFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInitFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInitFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInitFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::NodeFeatures as nativeNodeFeaturesImport;
pub(crate) type nativeNodeFeatures = nativeNodeFeaturesImport;

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
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeFeatures_free(this_obj: NodeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeFeatures); }
}
#[allow(unused)]
impl NodeFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelFeatures as nativeChannelFeaturesImport;
pub(crate) type nativeChannelFeatures = nativeChannelFeaturesImport;

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
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelFeatures_free(this_obj: ChannelFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelFeatures); }
}
#[allow(unused)]
impl ChannelFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::InvoiceFeatures as nativeInvoiceFeaturesImport;
pub(crate) type nativeInvoiceFeatures = nativeInvoiceFeaturesImport;

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
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceFeatures_free(this_obj: InvoiceFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeInvoiceFeatures); }
}
#[allow(unused)]
impl InvoiceFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelTypeFeatures as nativeChannelTypeFeaturesImport;
pub(crate) type nativeChannelTypeFeatures = nativeChannelTypeFeaturesImport;

/// Features used within the channel_type field in an OpenChannel message.
///
/// A channel is always of some known \"type\", describing the transaction formats used and the exact
/// semantics of our interaction with our peer.
///
/// Note that because a channel is a specific type which is proposed by the opener and accepted by
/// the counterparty, only required features are allowed here.
///
/// This is serialized differently from other feature types - it is not prefixed by a length, and
/// thus must only appear inside a TLV where its length is known in advance.
#[must_use]
#[repr(C)]
pub struct ChannelTypeFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelTypeFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelTypeFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelTypeFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelTypeFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_free(this_obj: ChannelTypeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTypeFeatures_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelTypeFeatures); }
}
#[allow(unused)]
impl ChannelTypeFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelTypeFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelTypeFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelTypeFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_empty() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::empty();
	InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_known() -> InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::known();
	InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_unknown_bits(this_arg: &InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_empty() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::empty();
	NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_known() -> NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::known();
	NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_unknown_bits(this_arg: &NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_empty() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::empty();
	ChannelFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_known() -> ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::known();
	ChannelFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_requires_unknown_bits(this_arg: &ChannelFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_empty() -> InvoiceFeatures {
	let mut ret = lightning::ln::features::InvoiceFeatures::empty();
	InvoiceFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_known() -> InvoiceFeatures {
	let mut ret = lightning::ln::features::InvoiceFeatures::known();
	InvoiceFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceFeatures_requires_unknown_bits(this_arg: &InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_empty() -> ChannelTypeFeatures {
	let mut ret = lightning::ln::features::ChannelTypeFeatures::empty();
	ChannelTypeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Creates a Features with the bits set which are known by the implementation
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_known() -> ChannelTypeFeatures {
	let mut ret = lightning::ln::features::ChannelTypeFeatures::known();
	ChannelTypeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_unknown_bits(this_arg: &ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

#[no_mangle]
/// Serialize the InitFeatures object into a byte array which can be read by InitFeatures_read
pub extern "C" fn InitFeatures_write(obj: &InitFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn InitFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInitFeatures) })
}
#[no_mangle]
/// Read a InitFeatures from a byte array, created by InitFeatures_write
pub extern "C" fn InitFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::InitFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::InitFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelFeatures object into a byte array which can be read by ChannelFeatures_read
pub extern "C" fn ChannelFeatures_write(obj: &ChannelFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelFeatures) })
}
#[no_mangle]
/// Read a ChannelFeatures from a byte array, created by ChannelFeatures_write
pub extern "C" fn ChannelFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::ChannelFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::ChannelFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the NodeFeatures object into a byte array which can be read by NodeFeatures_read
pub extern "C" fn NodeFeatures_write(obj: &NodeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeFeatures) })
}
#[no_mangle]
/// Read a NodeFeatures from a byte array, created by NodeFeatures_write
pub extern "C" fn NodeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::NodeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::NodeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the InvoiceFeatures object into a byte array which can be read by InvoiceFeatures_read
pub extern "C" fn InvoiceFeatures_write(obj: &InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInvoiceFeatures) })
}
#[no_mangle]
/// Read a InvoiceFeatures from a byte array, created by InvoiceFeatures_write
pub extern "C" fn InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InvoiceFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::InvoiceFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::InvoiceFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelTypeFeatures object into a byte array which can be read by ChannelTypeFeatures_read
pub extern "C" fn ChannelTypeFeatures_write(obj: &ChannelTypeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelTypeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelTypeFeatures) })
}
#[no_mangle]
/// Read a ChannelTypeFeatures from a byte array, created by ChannelTypeFeatures_write
pub extern "C" fn ChannelTypeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelTypeFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::ChannelTypeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
