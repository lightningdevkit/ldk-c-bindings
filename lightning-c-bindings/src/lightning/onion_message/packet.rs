// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Structs and enums useful for constructing and reading an onion message packet.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::onion_message::packet::Packet as nativePacketImport;
pub(crate) type nativePacket = nativePacketImport;

/// Packet of hop data for next peer
#[must_use]
#[repr(C)]
pub struct Packet {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePacket,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Packet {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePacket>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Packet, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Packet_free(this_obj: Packet) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Packet_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePacket) };
}
#[allow(unused)]
impl Packet {
	pub(crate) fn get_native_ref(&self) -> &'static nativePacket {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePacket {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePacket {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Bolt 04 version number
#[no_mangle]
pub extern "C" fn Packet_get_version(this_ptr: &Packet) -> u8 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().version;
	*inner_val
}
/// Bolt 04 version number
#[no_mangle]
pub extern "C" fn Packet_set_version(this_ptr: &mut Packet, mut val: u8) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.version = val;
}
/// A random sepc256k1 point, used to build the ECDH shared secret to decrypt hop_data
#[no_mangle]
pub extern "C" fn Packet_get_public_key(this_ptr: &Packet) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().public_key;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// A random sepc256k1 point, used to build the ECDH shared secret to decrypt hop_data
#[no_mangle]
pub extern "C" fn Packet_set_public_key(this_ptr: &mut Packet, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.public_key = val.into_rust();
}
/// Encrypted payload for the next hop
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn Packet_get_hop_data(this_ptr: &Packet) -> crate::c_types::derived::CVec_u8Z {
	let mut inner_val = this_ptr.get_native_mut_ref().hop_data.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
}
/// Encrypted payload for the next hop
#[no_mangle]
pub extern "C" fn Packet_set_hop_data(this_ptr: &mut Packet, mut val: crate::c_types::derived::CVec_u8Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.hop_data = local_val;
}
/// HMAC to verify the integrity of hop_data
#[no_mangle]
pub extern "C" fn Packet_get_hmac(this_ptr: &Packet) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().hmac;
	inner_val
}
/// HMAC to verify the integrity of hop_data
#[no_mangle]
pub extern "C" fn Packet_set_hmac(this_ptr: &mut Packet, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.hmac = val.data;
}
/// Constructs a new Packet given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Packet_new(mut version_arg: u8, mut public_key_arg: crate::c_types::PublicKey, mut hop_data_arg: crate::c_types::derived::CVec_u8Z, mut hmac_arg: crate::c_types::ThirtyTwoBytes) -> Packet {
	let mut local_hop_data_arg = Vec::new(); for mut item in hop_data_arg.into_rust().drain(..) { local_hop_data_arg.push( { item }); };
	Packet { inner: ObjOps::heap_alloc(nativePacket {
		version: version_arg,
		public_key: public_key_arg.into_rust(),
		hop_data: local_hop_data_arg,
		hmac: hmac_arg.data,
	}), is_owned: true }
}
impl Clone for Packet {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePacket>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Packet_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePacket)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Packet
pub extern "C" fn Packet_clone(orig: &Packet) -> Packet {
	orig.clone()
}
/// Checks if two Packets contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Packet_eq(a: &Packet, b: &Packet) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the Packet object into a byte array which can be read by Packet_read
pub extern "C" fn Packet_write(obj: &crate::lightning::onion_message::packet::Packet) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn Packet_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativePacket) })
}
/// The contents of an onion message. In the context of offers, this would be the invoice, invoice
/// request, or invoice error.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum OnionMessageContents {
	/// A message related to BOLT 12 Offers.
	Offers(
		crate::lightning::onion_message::offers::OffersMessage),
	/// A custom onion message specified by the user.
	Custom(
		crate::lightning::onion_message::packet::CustomOnionMessageContents),
}
use lightning::onion_message::packet::OnionMessageContents as OnionMessageContentsImport;
pub(crate) type nativeOnionMessageContents = OnionMessageContentsImport<crate::lightning::onion_message::packet::CustomOnionMessageContents>;

impl OnionMessageContents {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeOnionMessageContents {
		match self {
			OnionMessageContents::Offers (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeOnionMessageContents::Offers (
					a_nonref.into_native(),
				)
			},
			OnionMessageContents::Custom (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeOnionMessageContents::Custom (
					a_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeOnionMessageContents {
		match self {
			OnionMessageContents::Offers (mut a, ) => {
				nativeOnionMessageContents::Offers (
					a.into_native(),
				)
			},
			OnionMessageContents::Custom (mut a, ) => {
				nativeOnionMessageContents::Custom (
					a,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeOnionMessageContents) -> Self {
		match native {
			nativeOnionMessageContents::Offers (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				OnionMessageContents::Offers (
					crate::lightning::onion_message::offers::OffersMessage::native_into(a_nonref),
				)
			},
			nativeOnionMessageContents::Custom (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				OnionMessageContents::Custom (
					Into::into(a_nonref),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeOnionMessageContents) -> Self {
		match native {
			nativeOnionMessageContents::Offers (mut a, ) => {
				OnionMessageContents::Offers (
					crate::lightning::onion_message::offers::OffersMessage::native_into(a),
				)
			},
			nativeOnionMessageContents::Custom (mut a, ) => {
				OnionMessageContents::Custom (
					Into::into(a),
				)
			},
		}
	}
}
/// Frees any resources used by the OnionMessageContents
#[no_mangle]
pub extern "C" fn OnionMessageContents_free(this_ptr: OnionMessageContents) { }
/// Creates a copy of the OnionMessageContents
#[no_mangle]
pub extern "C" fn OnionMessageContents_clone(orig: &OnionMessageContents) -> OnionMessageContents {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Offers-variant OnionMessageContents
pub extern "C" fn OnionMessageContents_offers(a: crate::lightning::onion_message::offers::OffersMessage) -> OnionMessageContents {
	OnionMessageContents::Offers(a, )
}
#[no_mangle]
/// Utility method to constructs a new Custom-variant OnionMessageContents
pub extern "C" fn OnionMessageContents_custom(a: crate::lightning::onion_message::packet::CustomOnionMessageContents) -> OnionMessageContents {
	OnionMessageContents::Custom(a, )
}
/// The contents of a custom onion message.
#[repr(C)]
pub struct CustomOnionMessageContents {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the TLV type identifying the message contents. MUST be >= 64.
	pub tlv_type: extern "C" fn (this_arg: *const c_void) -> u64,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Called, if set, after this CustomOnionMessageContents has been cloned into a duplicate object.
	/// The new CustomOnionMessageContents is provided, and should be mutated as needed to perform a
	/// deep copy of the object pointed to by this_arg or avoid any double-freeing.
	pub cloned: Option<extern "C" fn (new_CustomOnionMessageContents: &mut CustomOnionMessageContents)>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomOnionMessageContents {}
unsafe impl Sync for CustomOnionMessageContents {}
pub(crate) fn CustomOnionMessageContents_clone_fields(orig: &CustomOnionMessageContents) -> CustomOnionMessageContents {
	CustomOnionMessageContents {
		this_arg: orig.this_arg,
		tlv_type: Clone::clone(&orig.tlv_type),
		write: Clone::clone(&orig.write),
		cloned: Clone::clone(&orig.cloned),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::util::ser::Writeable for CustomOnionMessageContents {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}
#[no_mangle]
/// Creates a copy of a CustomOnionMessageContents
pub extern "C" fn CustomOnionMessageContents_clone(orig: &CustomOnionMessageContents) -> CustomOnionMessageContents {
	let mut res = CustomOnionMessageContents_clone_fields(orig);
	if let Some(f) = orig.cloned { (f)(&mut res) };
	res
}
impl Clone for CustomOnionMessageContents {
	fn clone(&self) -> Self {
		CustomOnionMessageContents_clone(self)
	}
}

use lightning::onion_message::packet::CustomOnionMessageContents as rustCustomOnionMessageContents;
impl rustCustomOnionMessageContents for CustomOnionMessageContents {
	fn tlv_type(&self) -> u64 {
		let mut ret = (self.tlv_type)(self.this_arg);
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CustomOnionMessageContents {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for CustomOnionMessageContents {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CustomOnionMessageContents_free(this_ptr: CustomOnionMessageContents) { }
impl Drop for CustomOnionMessageContents {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
