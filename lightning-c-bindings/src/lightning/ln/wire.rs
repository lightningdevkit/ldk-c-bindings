// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Wire encoding/decoding for Lightning messages according to [BOLT #1], and for
//! custom message through the [`CustomMessageReader`] trait.
//!
//! [BOLT #1]: https://github.com/lightning/bolts/blob/master/01-messaging.md

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Trait to be implemented by custom message (unrelated to the channel/gossip LN layers)
/// decoders.
#[repr(C)]
pub struct CustomMessageReader {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Decodes a custom message to `CustomMessageType`. If the given message type is known to the
	/// implementation and the message could be decoded, must return `Ok(Some(message))`. If the
	/// message type is unknown to the implementation, must return `Ok(None)`. If a decoding error
	/// occur, must return `Err(DecodeError::X)` where `X` details the encountered error.
	pub read: extern "C" fn (this_arg: *const c_void, message_type: u16, buffer: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_TypeZDecodeErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomMessageReader {}
unsafe impl Sync for CustomMessageReader {}
pub(crate) fn CustomMessageReader_clone_fields(orig: &CustomMessageReader) -> CustomMessageReader {
	CustomMessageReader {
		this_arg: orig.this_arg,
		read: Clone::clone(&orig.read),
		free: Clone::clone(&orig.free),
	}
}

use lightning::ln::wire::CustomMessageReader as rustCustomMessageReader;
impl rustCustomMessageReader for CustomMessageReader {
	type CustomMessage = crate::lightning::ln::wire::Type;
	fn read<R:crate::c_types::io::Read>(&self, mut message_type: u16, mut buffer: &mut R) -> Result<Option<crate::lightning::ln::wire::Type>, lightning::ln::msgs::DecodeError> {
		let mut ret = (self.read)(self.this_arg, message_type, crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec(buffer)));
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = { /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ let ret_0_opt = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }); if ret_0_opt.is_none() { None } else { Some({ { { ret_0_opt.take() } }})} }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CustomMessageReader {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for CustomMessageReader {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CustomMessageReader_free(this_ptr: CustomMessageReader) { }
impl Drop for CustomMessageReader {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
mod encode {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
/// Defines a type identifier for sending messages over the wire.
///
/// Messages implementing this trait specify a type and must be [`Writeable`].
#[repr(C)]
pub struct Type {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the type identifying the message payload.
	pub type_id: extern "C" fn (this_arg: *const c_void) -> u16,
	/// Return a human-readable "debug" string describing this object
	pub debug_str: extern "C" fn (this_arg: *const c_void) -> crate::c_types::Str,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Called, if set, after this Type has been cloned into a duplicate object.
	/// The new Type is provided, and should be mutated as needed to perform a
	/// deep copy of the object pointed to by this_arg or avoid any double-freeing.
	pub cloned: Option<extern "C" fn (new_Type: &mut Type)>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Type {}
unsafe impl Sync for Type {}
pub(crate) fn Type_clone_fields(orig: &Type) -> Type {
	Type {
		this_arg: orig.this_arg,
		type_id: Clone::clone(&orig.type_id),
		debug_str: Clone::clone(&orig.debug_str),
		write: Clone::clone(&orig.write),
		cloned: Clone::clone(&orig.cloned),
		free: Clone::clone(&orig.free),
	}
}
impl core::fmt::Debug for Type {
	fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
		f.write_str((self.debug_str)(self.this_arg).into_str())
	}
}
impl lightning::util::ser::Writeable for Type {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}
#[no_mangle]
/// Creates a copy of a Type
pub extern "C" fn Type_clone(orig: &Type) -> Type {
	let mut res = Type_clone_fields(orig);
	if let Some(f) = orig.cloned { (f)(&mut res) };
	res
}
impl Clone for Type {
	fn clone(&self) -> Self {
		Type_clone(self)
	}
}

use lightning::ln::wire::Type as rustType;
impl rustType for Type {
	fn type_id(&self) -> u16 {
		let mut ret = (self.type_id)(self.this_arg);
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Type {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for Type {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Type_free(this_ptr: Type) { }
impl Drop for Type {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
