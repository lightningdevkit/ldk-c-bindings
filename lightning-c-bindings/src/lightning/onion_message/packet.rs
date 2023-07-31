// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Structs and enums useful for constructing and reading an onion message packet.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The contents of an onion message. In the context of offers, this would be the invoice, invoice
/// request, or invoice error.
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
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomOnionMessageContents {}
unsafe impl Sync for CustomOnionMessageContents {}
#[no_mangle]
pub(crate) extern "C" fn CustomOnionMessageContents_clone_fields(orig: &CustomOnionMessageContents) -> CustomOnionMessageContents {
	CustomOnionMessageContents {
		this_arg: orig.this_arg,
		tlv_type: Clone::clone(&orig.tlv_type),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::util::ser::Writeable for CustomOnionMessageContents {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
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
