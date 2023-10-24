// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Message handling for BOLT 12 Offers.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// A handler for an [`OnionMessage`] containing a BOLT 12 Offers message as its payload.
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[repr(C)]
pub struct OffersMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handles the given message by either responding with an [`Bolt12Invoice`], sending a payment,
	/// or replying with an error.
	///
	/// The returned [`OffersMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	///
	/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
	pub handle_message: extern "C" fn (this_arg: *const c_void, message: crate::lightning::onion_message::offers::OffersMessage) -> crate::c_types::derived::COption_OffersMessageZ,
	/// Releases any [`OffersMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a payment flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_message`].
	pub release_pending_messages: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_OffersMessageDestinationBlindedPathZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for OffersMessageHandler {}
unsafe impl Sync for OffersMessageHandler {}
#[allow(unused)]
pub(crate) fn OffersMessageHandler_clone_fields(orig: &OffersMessageHandler) -> OffersMessageHandler {
	OffersMessageHandler {
		this_arg: orig.this_arg,
		handle_message: Clone::clone(&orig.handle_message),
		release_pending_messages: Clone::clone(&orig.release_pending_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::offers::OffersMessageHandler as rustOffersMessageHandler;
impl rustOffersMessageHandler for OffersMessageHandler {
	fn handle_message(&self, mut message: lightning::onion_message::offers::OffersMessage) -> Option<lightning::onion_message::offers::OffersMessage> {
		let mut ret = (self.handle_message)(self.this_arg, crate::lightning::onion_message::offers::OffersMessage::native_into(message));
		let mut local_ret = { /*ret*/ let ret_opt = ret; if ret_opt.is_none() { None } else { Some({ { { ret_opt.take() }.into_native() }})} };
		local_ret
	}
	fn release_pending_messages(&self) -> Vec<(lightning::onion_message::offers::OffersMessage, lightning::onion_message::messenger::Destination, Option<lightning::blinded_path::BlindedPath>)> {
		let mut ret = (self.release_pending_messages)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item.to_rust(); let mut local_orig_ret_0_2 = if orig_ret_0_2.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(orig_ret_0_2.take_inner()) } }) }; let mut local_ret_0 = (orig_ret_0_0.into_native(), orig_ret_0_1.into_native(), local_orig_ret_0_2); local_ret_0 }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for OffersMessageHandler {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for OffersMessageHandler {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn OffersMessageHandler_free(this_ptr: OffersMessageHandler) { }
impl Drop for OffersMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Possible BOLT 12 Offers messages sent and received via an [`OnionMessage`].
///
/// [`OnionMessage`]: crate::ln::msgs::OnionMessage
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum OffersMessage {
	/// A request for a [`Bolt12Invoice`] for a particular [`Offer`].
	///
	/// [`Offer`]: crate::offers::offer::Offer
	InvoiceRequest(
		crate::lightning::offers::invoice_request::InvoiceRequest),
	/// A [`Bolt12Invoice`] sent in response to an [`InvoiceRequest`] or a [`Refund`].
	///
	/// [`Refund`]: crate::offers::refund::Refund
	Invoice(
		crate::lightning::offers::invoice::Bolt12Invoice),
	/// An error from handling an [`OffersMessage`].
	InvoiceError(
		crate::lightning::offers::invoice_error::InvoiceError),
}
use lightning::onion_message::offers::OffersMessage as OffersMessageImport;
pub(crate) type nativeOffersMessage = OffersMessageImport;

impl OffersMessage {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeOffersMessage {
		match self {
			OffersMessage::InvoiceRequest (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeOffersMessage::InvoiceRequest (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			OffersMessage::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeOffersMessage::Invoice (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			OffersMessage::InvoiceError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeOffersMessage::InvoiceError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeOffersMessage {
		match self {
			OffersMessage::InvoiceRequest (mut a, ) => {
				nativeOffersMessage::InvoiceRequest (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			OffersMessage::Invoice (mut a, ) => {
				nativeOffersMessage::Invoice (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			OffersMessage::InvoiceError (mut a, ) => {
				nativeOffersMessage::InvoiceError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeOffersMessage) -> Self {
		match native {
			nativeOffersMessage::InvoiceRequest (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				OffersMessage::InvoiceRequest (
					crate::lightning::offers::invoice_request::InvoiceRequest { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeOffersMessage::Invoice (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				OffersMessage::Invoice (
					crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeOffersMessage::InvoiceError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				OffersMessage::InvoiceError (
					crate::lightning::offers::invoice_error::InvoiceError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeOffersMessage) -> Self {
		match native {
			nativeOffersMessage::InvoiceRequest (mut a, ) => {
				OffersMessage::InvoiceRequest (
					crate::lightning::offers::invoice_request::InvoiceRequest { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeOffersMessage::Invoice (mut a, ) => {
				OffersMessage::Invoice (
					crate::lightning::offers::invoice::Bolt12Invoice { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeOffersMessage::InvoiceError (mut a, ) => {
				OffersMessage::InvoiceError (
					crate::lightning::offers::invoice_error::InvoiceError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the OffersMessage
#[no_mangle]
pub extern "C" fn OffersMessage_free(this_ptr: OffersMessage) { }
/// Creates a copy of the OffersMessage
#[no_mangle]
pub extern "C" fn OffersMessage_clone(orig: &OffersMessage) -> OffersMessage {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OffersMessage_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const OffersMessage)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OffersMessage_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut OffersMessage) };
}
#[no_mangle]
/// Utility method to constructs a new InvoiceRequest-variant OffersMessage
pub extern "C" fn OffersMessage_invoice_request(a: crate::lightning::offers::invoice_request::InvoiceRequest) -> OffersMessage {
	OffersMessage::InvoiceRequest(a, )
}
#[no_mangle]
/// Utility method to constructs a new Invoice-variant OffersMessage
pub extern "C" fn OffersMessage_invoice(a: crate::lightning::offers::invoice::Bolt12Invoice) -> OffersMessage {
	OffersMessage::Invoice(a, )
}
#[no_mangle]
/// Utility method to constructs a new InvoiceError-variant OffersMessage
pub extern "C" fn OffersMessage_invoice_error(a: crate::lightning::offers::invoice_error::InvoiceError) -> OffersMessage {
	OffersMessage::InvoiceError(a, )
}
/// Returns whether `tlv_type` corresponds to a TLV record for Offers.
#[must_use]
#[no_mangle]
pub extern "C" fn OffersMessage_is_known_type(mut tlv_type: u64) -> bool {
	let mut ret = lightning::onion_message::offers::OffersMessage::is_known_type(tlv_type);
	ret
}

#[no_mangle]
/// Serialize the OffersMessage object into a byte array which can be read by OffersMessage_read
pub extern "C" fn OffersMessage_write(obj: &crate::lightning::onion_message::offers::OffersMessage) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[allow(unused)]
pub(crate) extern "C" fn OffersMessage_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	OffersMessage_write(unsafe { &*(obj as *const OffersMessage) })
}
#[no_mangle]
/// Read a OffersMessage from a byte array, created by OffersMessage_write
pub extern "C" fn OffersMessage_read(ser: crate::c_types::u8slice, arg_a: u64, arg_b: &crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_OffersMessageDecodeErrorZ {
	let arg_a_conv = arg_a;
	let arg_b_conv = arg_b;
	let arg_conv = (arg_a_conv, arg_b_conv);
	let res: Result<lightning::onion_message::offers::OffersMessage, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::offers::OffersMessage::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
