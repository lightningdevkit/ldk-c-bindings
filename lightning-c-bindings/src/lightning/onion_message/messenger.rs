// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! LDK sends, receives, and forwards onion messages via the [`OnionMessenger`]. See its docs for
//! more information.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::onion_message::messenger::OnionMessenger as nativeOnionMessengerImport;
pub(crate) type nativeOnionMessenger = nativeOnionMessengerImport<crate::lightning::chain::keysinterface::EntropySource, crate::lightning::chain::keysinterface::NodeSigner, crate::lightning::util::logger::Logger, crate::lightning::onion_message::messenger::CustomOnionMessageHandler>;

/// A sender, receiver and forwarder of onion messages. In upcoming releases, this object will be
/// used to retrieve invoices and fulfill invoice requests from [offers]. Currently, only sending
/// and receiving custom onion messages is supported.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::blinded_path::BlindedPath;
/// # use lightning::chain::keysinterface::KeysManager;
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::messenger::{Destination, OnionMessenger};
/// # use lightning::onion_message::packet::{CustomOnionMessageContents, OnionMessageContents};
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
/// # }
/// # let seed = [42u8; 32];
/// # let time = Duration::from_secs(123456);
/// # let keys_manager = KeysManager::new(&seed, time.as_secs(), time.subsec_nanos());
/// # let logger = Arc::new(FakeLogger {});
/// # let node_secret = SecretKey::from_slice(&hex::decode(\"0101010101010101010101010101010101010101010101010101010101010101\").unwrap()[..]).unwrap();
/// # let secp_ctx = Secp256k1::new();
/// # let hop_node_id1 = PublicKey::from_secret_key(&secp_ctx, &node_secret);
/// # let (hop_node_id2, hop_node_id3, hop_node_id4) = (hop_node_id1, hop_node_id1, hop_node_id1);
/// # let destination_node_id = hop_node_id1;
/// # let your_custom_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(&keys_manager, &keys_manager, logger, &your_custom_message_handler);
///
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// \tfn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// \t\t# Ok(())
/// \t\t// Write your custom onion message to `w`
/// \t}
/// }
/// impl CustomOnionMessageContents for YourCustomMessage {
/// \tfn tlv_type(&self) -> u64 {
/// \t\t# let your_custom_message_type = 42;
/// \t\tyour_custom_message_type
/// \t}
/// }
/// // Send a custom onion message to a node id.
/// let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::Node(destination_node_id), message, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_path = BlindedPath::new_for_message(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// # let intermediate_hops = [hop_node_id1, hop_node_id2];
/// let reply_path = None;
/// # let your_custom_message = YourCustomMessage {};
/// let message = OnionMessageContents::Custom(your_custom_message);
/// onion_messenger.send_onion_message(&intermediate_hops, Destination::BlindedPath(blinded_path), message, reply_path);
/// ```
///
/// [offers]: <https://github.com/lightning/bolts/pull/798>
/// [`OnionMessenger`]: crate::onion_message::OnionMessenger
#[must_use]
#[repr(C)]
pub struct OnionMessenger {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOnionMessenger,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OnionMessenger {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOnionMessenger>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OnionMessenger, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OnionMessenger_free(this_obj: OnionMessenger) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessenger_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOnionMessenger) };
}
#[allow(unused)]
impl OnionMessenger {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOnionMessenger {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOnionMessenger {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOnionMessenger {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The destination of an onion message.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Destination {
	/// We're sending this onion message to a node.
	Node(
		crate::c_types::PublicKey),
	/// We're sending this onion message to a blinded path.
	BlindedPath(
		crate::lightning::blinded_path::BlindedPath),
}
use lightning::onion_message::messenger::Destination as DestinationImport;
pub(crate) type nativeDestination = DestinationImport;

impl Destination {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeDestination {
		match self {
			Destination::Node (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDestination::Node (
					a_nonref.into_rust(),
				)
			},
			Destination::BlindedPath (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeDestination::BlindedPath (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeDestination {
		match self {
			Destination::Node (mut a, ) => {
				nativeDestination::Node (
					a.into_rust(),
				)
			},
			Destination::BlindedPath (mut a, ) => {
				nativeDestination::BlindedPath (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeDestination) -> Self {
		match native {
			nativeDestination::Node (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Destination::Node (
					crate::c_types::PublicKey::from_rust(&a_nonref),
				)
			},
			nativeDestination::BlindedPath (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				Destination::BlindedPath (
					crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeDestination) -> Self {
		match native {
			nativeDestination::Node (mut a, ) => {
				Destination::Node (
					crate::c_types::PublicKey::from_rust(&a),
				)
			},
			nativeDestination::BlindedPath (mut a, ) => {
				Destination::BlindedPath (
					crate::lightning::blinded_path::BlindedPath { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the Destination
#[no_mangle]
pub extern "C" fn Destination_free(this_ptr: Destination) { }
/// Creates a copy of the Destination
#[no_mangle]
pub extern "C" fn Destination_clone(orig: &Destination) -> Destination {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Node-variant Destination
pub extern "C" fn Destination_node(a: crate::c_types::PublicKey) -> Destination {
	Destination::Node(a, )
}
#[no_mangle]
/// Utility method to constructs a new BlindedPath-variant Destination
pub extern "C" fn Destination_blinded_path(a: crate::lightning::blinded_path::BlindedPath) -> Destination {
	Destination::BlindedPath(a, )
}
/// Errors that may occur when [sending an onion message].
///
/// [sending an onion message]: OnionMessenger::send_onion_message
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SendError {
	/// Errored computing onion message packet keys.
	Secp256k1(
		crate::c_types::Secp256k1Error),
	/// Because implementations such as Eclair will drop onion messages where the message packet
	/// exceeds 32834 bytes, we refuse to send messages where the packet exceeds this size.
	TooBigPacket,
	/// The provided [`Destination`] was an invalid [`BlindedPath`], due to having fewer than two
	/// blinded hops.
	TooFewBlindedHops,
	/// Our next-hop peer was offline or does not support onion message forwarding.
	InvalidFirstHop,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::chain::keysinterface::NodeSigner
	GetNodeIdFailed,
	/// We attempted to send to a blinded path where we are the introduction node, and failed to
	/// advance the blinded path to make the second hop the new introduction node. Either
	/// [`NodeSigner::ecdh`] failed, we failed to tweak the current blinding point to get the
	/// new blinding point, or we were attempting to send to ourselves.
	BlindedPathAdvanceFailed,
}
use lightning::onion_message::messenger::SendError as SendErrorImport;
pub(crate) type nativeSendError = SendErrorImport;

impl SendError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSendError {
		match self {
			SendError::Secp256k1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSendError::Secp256k1 (
					a_nonref.into_rust(),
				)
			},
			SendError::TooBigPacket => nativeSendError::TooBigPacket,
			SendError::TooFewBlindedHops => nativeSendError::TooFewBlindedHops,
			SendError::InvalidFirstHop => nativeSendError::InvalidFirstHop,
			SendError::InvalidMessage => nativeSendError::InvalidMessage,
			SendError::BufferFull => nativeSendError::BufferFull,
			SendError::GetNodeIdFailed => nativeSendError::GetNodeIdFailed,
			SendError::BlindedPathAdvanceFailed => nativeSendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSendError {
		match self {
			SendError::Secp256k1 (mut a, ) => {
				nativeSendError::Secp256k1 (
					a.into_rust(),
				)
			},
			SendError::TooBigPacket => nativeSendError::TooBigPacket,
			SendError::TooFewBlindedHops => nativeSendError::TooFewBlindedHops,
			SendError::InvalidFirstHop => nativeSendError::InvalidFirstHop,
			SendError::InvalidMessage => nativeSendError::InvalidMessage,
			SendError::BufferFull => nativeSendError::BufferFull,
			SendError::GetNodeIdFailed => nativeSendError::GetNodeIdFailed,
			SendError::BlindedPathAdvanceFailed => nativeSendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeSendError) -> Self {
		match native {
			nativeSendError::Secp256k1 (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SendError::Secp256k1 (
					crate::c_types::Secp256k1Error::from_rust(a_nonref),
				)
			},
			nativeSendError::TooBigPacket => SendError::TooBigPacket,
			nativeSendError::TooFewBlindedHops => SendError::TooFewBlindedHops,
			nativeSendError::InvalidFirstHop => SendError::InvalidFirstHop,
			nativeSendError::InvalidMessage => SendError::InvalidMessage,
			nativeSendError::BufferFull => SendError::BufferFull,
			nativeSendError::GetNodeIdFailed => SendError::GetNodeIdFailed,
			nativeSendError::BlindedPathAdvanceFailed => SendError::BlindedPathAdvanceFailed,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSendError) -> Self {
		match native {
			nativeSendError::Secp256k1 (mut a, ) => {
				SendError::Secp256k1 (
					crate::c_types::Secp256k1Error::from_rust(a),
				)
			},
			nativeSendError::TooBigPacket => SendError::TooBigPacket,
			nativeSendError::TooFewBlindedHops => SendError::TooFewBlindedHops,
			nativeSendError::InvalidFirstHop => SendError::InvalidFirstHop,
			nativeSendError::InvalidMessage => SendError::InvalidMessage,
			nativeSendError::BufferFull => SendError::BufferFull,
			nativeSendError::GetNodeIdFailed => SendError::GetNodeIdFailed,
			nativeSendError::BlindedPathAdvanceFailed => SendError::BlindedPathAdvanceFailed,
		}
	}
}
/// Frees any resources used by the SendError
#[no_mangle]
pub extern "C" fn SendError_free(this_ptr: SendError) { }
/// Creates a copy of the SendError
#[no_mangle]
pub extern "C" fn SendError_clone(orig: &SendError) -> SendError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Secp256k1-variant SendError
pub extern "C" fn SendError_secp256k1(a: crate::c_types::Secp256k1Error) -> SendError {
	SendError::Secp256k1(a, )
}
#[no_mangle]
/// Utility method to constructs a new TooBigPacket-variant SendError
pub extern "C" fn SendError_too_big_packet() -> SendError {
	SendError::TooBigPacket}
#[no_mangle]
/// Utility method to constructs a new TooFewBlindedHops-variant SendError
pub extern "C" fn SendError_too_few_blinded_hops() -> SendError {
	SendError::TooFewBlindedHops}
#[no_mangle]
/// Utility method to constructs a new InvalidFirstHop-variant SendError
pub extern "C" fn SendError_invalid_first_hop() -> SendError {
	SendError::InvalidFirstHop}
#[no_mangle]
/// Utility method to constructs a new InvalidMessage-variant SendError
pub extern "C" fn SendError_invalid_message() -> SendError {
	SendError::InvalidMessage}
#[no_mangle]
/// Utility method to constructs a new BufferFull-variant SendError
pub extern "C" fn SendError_buffer_full() -> SendError {
	SendError::BufferFull}
#[no_mangle]
/// Utility method to constructs a new GetNodeIdFailed-variant SendError
pub extern "C" fn SendError_get_node_id_failed() -> SendError {
	SendError::GetNodeIdFailed}
#[no_mangle]
/// Utility method to constructs a new BlindedPathAdvanceFailed-variant SendError
pub extern "C" fn SendError_blinded_path_advance_failed() -> SendError {
	SendError::BlindedPathAdvanceFailed}
/// Checks if two SendErrors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SendError_eq(a: &SendError, b: &SendError) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Handler for custom onion messages. If you are using [`SimpleArcOnionMessenger`],
/// [`SimpleRefOnionMessenger`], or prefer to ignore inbound custom onion messages,
/// [`IgnoringMessageHandler`] must be provided to [`OnionMessenger::new`]. Otherwise, a custom
/// implementation of this trait must be provided, with [`CustomMessage`] specifying the supported
/// message types.
///
/// See [`OnionMessenger`] for example usage.
///
/// [`IgnoringMessageHandler`]: crate::ln::peer_handler::IgnoringMessageHandler
/// [`CustomMessage`]: Self::CustomMessage
#[repr(C)]
pub struct CustomOnionMessageHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Called with the custom message that was received.
	pub handle_custom_message: extern "C" fn (this_arg: *const c_void, msg: crate::lightning::onion_message::packet::CustomOnionMessageContents),
	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	#[must_use]
	pub read_custom_message: extern "C" fn (this_arg: *const c_void, message_type: u64, buffer: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_CustomOnionMessageContentsZDecodeErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomOnionMessageHandler {}
unsafe impl Sync for CustomOnionMessageHandler {}
#[no_mangle]
pub(crate) extern "C" fn CustomOnionMessageHandler_clone_fields(orig: &CustomOnionMessageHandler) -> CustomOnionMessageHandler {
	CustomOnionMessageHandler {
		this_arg: orig.this_arg,
		handle_custom_message: Clone::clone(&orig.handle_custom_message),
		read_custom_message: Clone::clone(&orig.read_custom_message),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::messenger::CustomOnionMessageHandler as rustCustomOnionMessageHandler;
impl rustCustomOnionMessageHandler for CustomOnionMessageHandler {
	type CustomMessage = crate::lightning::onion_message::packet::CustomOnionMessageContents;
	fn handle_custom_message(&self, mut msg: crate::lightning::onion_message::packet::CustomOnionMessageContents) {
		(self.handle_custom_message)(self.this_arg, Into::into(msg))
	}
	fn read_custom_message<R:crate::c_types::io::Read>(&self, mut message_type: u64, mut buffer: &mut R) -> Result<Option<crate::lightning::onion_message::packet::CustomOnionMessageContents>, lightning::ln::msgs::DecodeError> {
		let mut ret = (self.read_custom_message)(self.this_arg, message_type, crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec(buffer)));
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = { /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ let ret_0_opt = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }); if ret_0_opt.is_none() { None } else { Some({ { { ret_0_opt.take() } }})} }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CustomOnionMessageHandler {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CustomOnionMessageHandler_free(this_ptr: CustomOnionMessageHandler) { }
impl Drop for CustomOnionMessageHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
/// their respective handlers.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_new(mut entropy_source: crate::lightning::chain::keysinterface::EntropySource, mut node_signer: crate::lightning::chain::keysinterface::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::lightning::onion_message::messenger::OnionMessenger {
	let mut ret = lightning::onion_message::messenger::OnionMessenger::new(entropy_source, node_signer, logger, custom_handler);
	crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Send an onion message with contents `message` to `destination`, routing it through `intermediate_nodes`.
/// See [`OnionMessenger`] for example usage.
///
/// Note that reply_path (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_send_onion_message(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger, mut intermediate_nodes: crate::c_types::derived::CVec_PublicKeyZ, mut destination: crate::lightning::onion_message::messenger::Destination, mut message: crate::lightning::onion_message::packet::OnionMessageContents, mut reply_path: crate::lightning::blinded_path::BlindedPath) -> crate::c_types::derived::CResult_NoneSendErrorZ {
	let mut local_intermediate_nodes = Vec::new(); for mut item in intermediate_nodes.into_rust().drain(..) { local_intermediate_nodes.push( { item.into_rust() }); };
	let mut local_reply_path = if reply_path.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(reply_path.take_inner()) } }) };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.send_onion_message(&local_intermediate_nodes[..], destination.into_native(), message.into_native(), local_reply_path);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

impl From<nativeOnionMessenger> for crate::lightning::ln::msgs::OnionMessageHandler {
	fn from(obj: nativeOnionMessenger) -> Self {
		let mut rust_obj = OnionMessenger { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OnionMessenger_as_OnionMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(OnionMessenger_free_void);
		ret
	}
}
/// Constructs a new OnionMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OnionMessenger_as_OnionMessageHandler(this_arg: &OnionMessenger) -> crate::lightning::ln::msgs::OnionMessageHandler {
	crate::lightning::ln::msgs::OnionMessageHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_onion_message: OnionMessenger_OnionMessageHandler_handle_onion_message,
		peer_connected: OnionMessenger_OnionMessageHandler_peer_connected,
		peer_disconnected: OnionMessenger_OnionMessageHandler_peer_disconnected,
		provided_node_features: OnionMessenger_OnionMessageHandler_provided_node_features,
		provided_init_features: OnionMessenger_OnionMessageHandler_provided_init_features,
		OnionMessageProvider: crate::lightning::events::OnionMessageProvider {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			next_onion_message_for_peer: OnionMessenger_OnionMessageProvider_next_onion_message_for_peer,
		},
	}
}

extern "C" fn OnionMessenger_OnionMessageHandler_handle_onion_message(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::OnionMessage) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::handle_onion_message(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, &peer_node_id.into_rust(), msg.get_native_ref())
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_peer_connected(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, init: &crate::lightning::ln::msgs::Init, mut inbound: bool) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, &their_node_id.into_rust(), init.get_native_ref(), inbound);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
extern "C" fn OnionMessenger_OnionMessageHandler_peer_disconnected(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, &their_node_id.into_rust())
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_provided_node_features(this_arg: *const c_void) -> crate::lightning::ln::features::NodeFeatures {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::provided_node_features(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, );
	crate::lightning::ln::features::NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_provided_init_features(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::features::InitFeatures {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::provided_init_features(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, &their_node_id.into_rust());
	crate::lightning::ln::features::InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeOnionMessenger> for crate::lightning::events::OnionMessageProvider {
	fn from(obj: nativeOnionMessenger) -> Self {
		let mut rust_obj = OnionMessenger { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OnionMessenger_as_OnionMessageProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(OnionMessenger_free_void);
		ret
	}
}
/// Constructs a new OnionMessageProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned OnionMessageProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn OnionMessenger_as_OnionMessageProvider(this_arg: &OnionMessenger) -> crate::lightning::events::OnionMessageProvider {
	crate::lightning::events::OnionMessageProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		next_onion_message_for_peer: OnionMessenger_OnionMessageProvider_next_onion_message_for_peer,
	}
}

#[must_use]
extern "C" fn OnionMessenger_OnionMessageProvider_next_onion_message_for_peer(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::msgs::OnionMessage {
	let mut ret = <nativeOnionMessenger as lightning::events::OnionMessageProvider<>>::next_onion_message_for_peer(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, peer_node_id.into_rust());
	let mut local_ret = crate::lightning::ln::msgs::OnionMessage { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}

