// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! The top-level routing/network map tracking logic lives here.
//!
//! You probably want to create a NetGraphMsgHandler and use that as your RoutingMessageHandler and then
//! interrogate it to get routes for your own payments.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::routing::router::RouteHop as nativeRouteHopImport;
type nativeRouteHop = nativeRouteHopImport;

/// A hop in a route
#[must_use]
#[repr(C)]
pub struct RouteHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHop_free(this_obj: RouteHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RouteHop_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRouteHop); }
}
#[allow(unused)]
impl RouteHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_get_pubkey(this_ptr: &RouteHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().pubkey;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of the node at this hop.
#[no_mangle]
pub extern "C" fn RouteHop_set_pubkey(this_ptr: &mut RouteHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.pubkey = val.into_rust();
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_get_node_features(this_ptr: &RouteHop) -> crate::lightning::ln::features::NodeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_features;
	crate::lightning::ln::features::NodeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const _) as *mut _) }, is_owned: false }
}
/// The node_announcement features of the node at this hop. For the last hop, these may be
/// amended to match the features present in the invoice this node generated.
#[no_mangle]
pub extern "C" fn RouteHop_set_node_features(this_ptr: &mut RouteHop, mut val: crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_short_channel_id(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The channel that should be used from the previous hop to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_short_channel_id(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_get_channel_features(this_ptr: &RouteHop) -> crate::lightning::ln::features::ChannelFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_features;
	crate::lightning::ln::features::ChannelFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const _) as *mut _) }, is_owned: false }
}
/// The channel_announcement features of the channel that should be used from the previous hop
/// to reach this node.
#[no_mangle]
pub extern "C" fn RouteHop_set_channel_features(this_ptr: &mut RouteHop, mut val: crate::lightning::ln::features::ChannelFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
/// For the last hop, this should be the full value of the payment (might be more than
/// requested if we had to match htlc_minimum_msat).
#[no_mangle]
pub extern "C" fn RouteHop_get_fee_msat(this_ptr: &RouteHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fee_msat;
	*inner_val
}
/// The fee taken on this hop (for paying for the use of the *next* channel in the path).
/// For the last hop, this should be the full value of the payment (might be more than
/// requested if we had to match htlc_minimum_msat).
#[no_mangle]
pub extern "C" fn RouteHop_set_fee_msat(this_ptr: &mut RouteHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fee_msat = val;
}
/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
/// expected at the destination, in excess of the current block height.
#[no_mangle]
pub extern "C" fn RouteHop_get_cltv_expiry_delta(this_ptr: &RouteHop) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The CLTV delta added for this hop. For the last hop, this should be the full CLTV value
/// expected at the destination, in excess of the current block height.
#[no_mangle]
pub extern "C" fn RouteHop_set_cltv_expiry_delta(this_ptr: &mut RouteHop, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// Constructs a new RouteHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHop_new(mut pubkey_arg: crate::c_types::PublicKey, mut node_features_arg: crate::lightning::ln::features::NodeFeatures, mut short_channel_id_arg: u64, mut channel_features_arg: crate::lightning::ln::features::ChannelFeatures, mut fee_msat_arg: u64, mut cltv_expiry_delta_arg: u32) -> RouteHop {
	RouteHop { inner: ObjOps::heap_alloc(nativeRouteHop {
		pubkey: pubkey_arg.into_rust(),
		node_features: *unsafe { Box::from_raw(node_features_arg.take_inner()) },
		short_channel_id: short_channel_id_arg,
		channel_features: *unsafe { Box::from_raw(channel_features_arg.take_inner()) },
		fee_msat: fee_msat_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
	}), is_owned: true }
}
impl Clone for RouteHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHop>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRouteHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHop
pub extern "C" fn RouteHop_clone(orig: &RouteHop) -> RouteHop {
	orig.clone()
}
/// Checks if two RouteHops contain equal inner contents.
#[no_mangle]
pub extern "C" fn RouteHop_hash(o: &RouteHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHop_eq(a: &RouteHop, b: &RouteHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the RouteHop object into a byte array which can be read by RouteHop_read
pub extern "C" fn RouteHop_write(obj: &RouteHop) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn RouteHop_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRouteHop) })
}
#[no_mangle]
/// Read a RouteHop from a byte array, created by RouteHop_write
pub extern "C" fn RouteHop_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteHopDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::router::Route as nativeRouteImport;
type nativeRoute = nativeRouteImport;

/// A route directs a payment from the sender (us) to the recipient. If the recipient supports MPP,
/// it can take multiple paths. Each path is composed of one or more hops through the network.
#[must_use]
#[repr(C)]
pub struct Route {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoute,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Route {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRoute>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Route, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Route_free(this_obj: Route) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn Route_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRoute); }
}
#[allow(unused)]
impl Route {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRoute {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRoute {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRoute {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The list of routes taken for a single (potentially-)multi-part payment. The pubkey of the
/// last RouteHop in each path must be the same.
/// Each entry represents a list of hops, NOT INCLUDING our own, where the last hop is the
/// destination. Thus, this must always be at least length one. While the maximum length of any
/// given path is variable, keeping the length of any path to less than 20 should currently
/// ensure it is viable.
#[no_mangle]
pub extern "C" fn Route_get_paths(this_ptr: &Route) -> crate::c_types::derived::CVec_CVec_RouteHopZZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().paths;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { let mut local_inner_val_0 = Vec::new(); for item in item.iter() { local_inner_val_0.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const _) as *mut _) }, is_owned: false } }); }; local_inner_val_0.into() }); };
	local_inner_val.into()
}
/// The list of routes taken for a single (potentially-)multi-part payment. The pubkey of the
/// last RouteHop in each path must be the same.
/// Each entry represents a list of hops, NOT INCLUDING our own, where the last hop is the
/// destination. Thus, this must always be at least length one. While the maximum length of any
/// given path is variable, keeping the length of any path to less than 20 should currently
/// ensure it is viable.
#[no_mangle]
pub extern "C" fn Route_set_paths(this_ptr: &mut Route, mut val: crate::c_types::derived::CVec_CVec_RouteHopZZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { let mut local_val_0 = Vec::new(); for mut item in item.into_rust().drain(..) { local_val_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_val_0 }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.paths = local_val;
}
/// Constructs a new Route given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Route_new(mut paths_arg: crate::c_types::derived::CVec_CVec_RouteHopZZ) -> Route {
	let mut local_paths_arg = Vec::new(); for mut item in paths_arg.into_rust().drain(..) { local_paths_arg.push( { let mut local_paths_arg_0 = Vec::new(); for mut item in item.into_rust().drain(..) { local_paths_arg_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_paths_arg_0 }); };
	Route { inner: ObjOps::heap_alloc(nativeRoute {
		paths: local_paths_arg,
	}), is_owned: true }
}
impl Clone for Route {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRoute>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Route_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRoute)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Route
pub extern "C" fn Route_clone(orig: &Route) -> Route {
	orig.clone()
}
/// Checks if two Routes contain equal inner contents.
#[no_mangle]
pub extern "C" fn Route_hash(o: &Route) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// Checks if two Routes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Route_eq(a: &Route, b: &Route) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the total amount of fees paid on this [`Route`].
///
/// This doesn't include any extra payment made to the recipient, which can happen in excess of
/// the amount passed to [`get_route`]'s `final_value_msat`.
#[must_use]
#[no_mangle]
pub extern "C" fn Route_get_total_fees(this_arg: &Route) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_total_fees();
	ret
}

/// Returns the total amount paid on this [`Route`], excluding the fees.
#[must_use]
#[no_mangle]
pub extern "C" fn Route_get_total_amount(this_arg: &Route) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_total_amount();
	ret
}

#[no_mangle]
/// Serialize the Route object into a byte array which can be read by Route_read
pub extern "C" fn Route_write(obj: &Route) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Route_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRoute) })
}
#[no_mangle]
/// Read a Route from a byte array, created by Route_write
pub extern "C" fn Route_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RouteDecodeErrorZ {
	let res = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::router::RouteHint as nativeRouteHintImport;
type nativeRouteHint = nativeRouteHintImport;

/// A list of hops along a payment path terminating with a channel to the recipient.
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
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
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
impl RouteHint {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHint {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHint {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHint {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for RouteHint {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHint>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
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
/// Checks if two RouteHints contain equal inner contents.
#[no_mangle]
pub extern "C" fn RouteHint_hash(o: &RouteHint) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHints contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHint_eq(a: &RouteHint, b: &RouteHint) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::routing::router::RouteHintHop as nativeRouteHintHopImport;
type nativeRouteHintHop = nativeRouteHintHopImport;

/// A channel descriptor for a hop along a payment path.
#[must_use]
#[repr(C)]
pub struct RouteHintHop {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRouteHintHop,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RouteHintHop {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRouteHintHop>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RouteHintHop, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RouteHintHop_free(this_obj: RouteHintHop) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn RouteHintHop_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRouteHintHop); }
}
#[allow(unused)]
impl RouteHintHop {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRouteHintHop {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRouteHintHop {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRouteHintHop {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_get_src_node_id(this_ptr: &RouteHintHop) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().src_node_id;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The node_id of the non-target end of the route
#[no_mangle]
pub extern "C" fn RouteHintHop_set_src_node_id(this_ptr: &mut RouteHintHop, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.src_node_id = val.into_rust();
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_short_channel_id(this_ptr: &RouteHintHop) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().short_channel_id;
	*inner_val
}
/// The short_channel_id of this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_short_channel_id(this_ptr: &mut RouteHintHop, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.short_channel_id = val;
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_get_fees(this_ptr: &RouteHintHop) -> crate::lightning::routing::network_graph::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fees;
	crate::lightning::routing::network_graph::RoutingFees { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const _) as *mut _) }, is_owned: false }
}
/// The fees which must be paid to use this channel
#[no_mangle]
pub extern "C" fn RouteHintHop_set_fees(this_ptr: &mut RouteHintHop, mut val: crate::lightning::routing::network_graph::RoutingFees) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_cltv_expiry_delta(this_ptr: &RouteHintHop) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in CLTV values between this node and the next node.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_cltv_expiry_delta(this_ptr: &mut RouteHintHop, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_minimum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The minimum value, in msat, which must be relayed to the next hop.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_minimum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = local_val;
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_get_htlc_maximum_msat(this_ptr: &RouteHintHop) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximum value in msat available for routing with a single HTLC.
#[no_mangle]
pub extern "C" fn RouteHintHop_set_htlc_maximum_msat(this_ptr: &mut RouteHintHop, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = local_val;
}
/// Constructs a new RouteHintHop given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RouteHintHop_new(mut src_node_id_arg: crate::c_types::PublicKey, mut short_channel_id_arg: u64, mut fees_arg: crate::lightning::routing::network_graph::RoutingFees, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: crate::c_types::derived::COption_u64Z, mut htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z) -> RouteHintHop {
	let mut local_htlc_minimum_msat_arg = if htlc_minimum_msat_arg.is_some() { Some( { htlc_minimum_msat_arg.take() }) } else { None };
	let mut local_htlc_maximum_msat_arg = if htlc_maximum_msat_arg.is_some() { Some( { htlc_maximum_msat_arg.take() }) } else { None };
	RouteHintHop { inner: ObjOps::heap_alloc(nativeRouteHintHop {
		src_node_id: src_node_id_arg.into_rust(),
		short_channel_id: short_channel_id_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: local_htlc_minimum_msat_arg,
		htlc_maximum_msat: local_htlc_maximum_msat_arg,
	}), is_owned: true }
}
impl Clone for RouteHintHop {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRouteHintHop>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RouteHintHop_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRouteHintHop)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RouteHintHop
pub extern "C" fn RouteHintHop_clone(orig: &RouteHintHop) -> RouteHintHop {
	orig.clone()
}
/// Checks if two RouteHintHops contain equal inner contents.
#[no_mangle]
pub extern "C" fn RouteHintHop_hash(o: &RouteHintHop) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// Checks if two RouteHintHops contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RouteHintHop_eq(a: &RouteHintHop, b: &RouteHintHop) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Gets a keysend route from us (payer) to the given target node (payee). This is needed because
/// keysend payments do not have an invoice from which to pull the payee's supported features, which
/// makes it tricky to otherwise supply the `payee_features` parameter of `get_route`.
///
/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn get_keysend_route(mut our_node_pubkey: crate::c_types::PublicKey, network: &crate::lightning::routing::network_graph::NetworkGraph, mut payee: crate::c_types::PublicKey, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut last_hops: crate::c_types::derived::CVec_RouteHintZ, mut final_value_msat: u64, mut final_cltv: u32, mut logger: crate::lightning::util::logger::Logger, scorer: &crate::lightning::routing::Score) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_first_hops_base = if first_hops == std::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut local_last_hops = Vec::new(); for mut item in last_hops.as_slice().iter() { local_last_hops.push( { item.get_native_ref() }); };
	let mut ret = lightning::routing::router::get_keysend_route(&our_node_pubkey.into_rust(), network.get_native_ref(), &payee.into_rust(), local_first_hops, &local_last_hops[..], final_value_msat, final_cltv, logger, scorer);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Gets a route from us (payer) to the given target node (payee).
///
/// If the payee provided features in their invoice, they should be provided via payee_features.
/// Without this, MPP will only be used if the payee's features are available in the network graph.
///
/// Private routing paths between a public node and the target may be included in `last_hops`.
/// Currently, only the last hop in each path is considered.
///
/// If some channels aren't announced, it may be useful to fill in a first_hops with the
/// results from a local ChannelManager::list_usable_channels() call. If it is filled in, our
/// view of our local channels (from net_graph_msg_handler) will be ignored, and only those
/// in first_hops will be used.
///
/// Panics if first_hops contains channels without short_channel_ids
/// (ChannelManager::list_usable_channels will never include such channels).
///
/// The fees on channels from us to next-hops are ignored (as they are assumed to all be
/// equal), however the enabled/disabled bit on such channels as well as the
/// htlc_minimum_msat/htlc_maximum_msat *are* checked as they may change based on the receiving node.
///
/// Note that payee_features (or a relevant inner pointer) may be NULL or all-0s to represent None
/// Note that first_hops (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn get_route(mut our_node_pubkey: crate::c_types::PublicKey, network: &crate::lightning::routing::network_graph::NetworkGraph, mut payee: crate::c_types::PublicKey, mut payee_features: crate::lightning::ln::features::InvoiceFeatures, first_hops: *mut crate::c_types::derived::CVec_ChannelDetailsZ, mut last_hops: crate::c_types::derived::CVec_RouteHintZ, mut final_value_msat: u64, mut final_cltv: u32, mut logger: crate::lightning::util::logger::Logger, scorer: &crate::lightning::routing::Score) -> crate::c_types::derived::CResult_RouteLightningErrorZ {
	let mut local_payee_features = if payee_features.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(payee_features.take_inner()) } }) };
	let mut local_first_hops_base = if first_hops == std::ptr::null_mut() { None } else { Some( { let mut local_first_hops_0 = Vec::new(); for mut item in unsafe { &mut *first_hops }.as_slice().iter() { local_first_hops_0.push( { item.get_native_ref() }); }; local_first_hops_0 }) }; let mut local_first_hops = local_first_hops_base.as_ref().map(|a| &a[..]);
	let mut local_last_hops = Vec::new(); for mut item in last_hops.as_slice().iter() { local_last_hops.push( { item.get_native_ref() }); };
	let mut ret = lightning::routing::router::get_route(&our_node_pubkey.into_rust(), network.get_native_ref(), &payee.into_rust(), local_payee_features, local_first_hops, &local_last_hops[..], final_value_msat, final_cltv, logger, scorer);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::router::Route { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

