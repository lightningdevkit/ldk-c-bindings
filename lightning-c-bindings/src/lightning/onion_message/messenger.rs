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
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::onion_message::messenger::OnionMessenger as nativeOnionMessengerImport;
pub(crate) type nativeOnionMessenger = nativeOnionMessengerImport<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger, crate::lightning::onion_message::messenger::MessageRouter, crate::lightning::onion_message::offers::OffersMessageHandler, crate::lightning::onion_message::messenger::CustomOnionMessageHandler>;

/// A sender, receiver and forwarder of [`OnionMessage`]s.
///
/// # Handling Messages
///
/// `OnionMessenger` implements [`OnionMessageHandler`], making it responsible for either forwarding
/// messages to peers or delegating to the appropriate handler for the message type. Currently, the
/// available handlers are:
/// * [`OffersMessageHandler`], for responding to [`InvoiceRequest`]s and paying [`Bolt12Invoice`]s
/// * [`CustomOnionMessageHandler`], for handling user-defined message types
///
/// # Sending Messages
///
/// [`OnionMessage`]s are sent initially using [`OnionMessenger::send_onion_message`]. When handling
/// a message, the matched handler may return a response message which `OnionMessenger` will send
/// on its behalf.
///
/// # Example
///
/// ```
/// # extern crate bitcoin;
/// # use bitcoin::hashes::_export::_core::time::Duration;
/// # use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
/// # use lightning::blinded_path::BlindedPath;
/// # use lightning::sign::KeysManager;
/// # use lightning::ln::peer_handler::IgnoringMessageHandler;
/// # use lightning::onion_message::messenger::{Destination, MessageRouter, OnionMessenger, OnionMessagePath};
/// # use lightning::onion_message::packet::OnionMessageContents;
/// # use lightning::util::logger::{Logger, Record};
/// # use lightning::util::ser::{Writeable, Writer};
/// # use lightning::io;
/// # use std::sync::Arc;
/// # struct FakeLogger;
/// # impl Logger for FakeLogger {
/// #     fn log(&self, record: &Record) { unimplemented!() }
/// # }
/// # struct FakeMessageRouter {}
/// # impl MessageRouter for FakeMessageRouter {
/// #     fn find_path(&self, sender: PublicKey, peers: Vec<PublicKey>, destination: Destination) -> Result<OnionMessagePath, ()> {
/// #         unimplemented!()
/// #     }
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
/// # let message_router = Arc::new(FakeMessageRouter {});
/// # let custom_message_handler = IgnoringMessageHandler {};
/// # let offers_message_handler = IgnoringMessageHandler {};
/// // Create the onion messenger. This must use the same `keys_manager` as is passed to your
/// // ChannelManager.
/// let onion_messenger = OnionMessenger::new(
///     &keys_manager, &keys_manager, logger, message_router, &offers_message_handler,
///     &custom_message_handler
/// );
///
/// # #[derive(Clone)]
/// # struct YourCustomMessage {}
/// impl Writeable for YourCustomMessage {
/// \tfn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
/// \t\t# Ok(())
/// \t\t// Write your custom onion message to `w`
/// \t}
/// }
/// impl OnionMessageContents for YourCustomMessage {
/// \tfn tlv_type(&self) -> u64 {
/// \t\t# let your_custom_message_type = 42;
/// \t\tyour_custom_message_type
/// \t}
/// }
/// // Send a custom onion message to a node id.
/// let path = OnionMessagePath {
/// \tintermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// \tdestination: Destination::Node(destination_node_id),
/// };
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(path, message, reply_path);
///
/// // Create a blinded path to yourself, for someone to send an onion message to.
/// # let your_node_id = hop_node_id1;
/// let hops = [hop_node_id3, hop_node_id4, your_node_id];
/// let blinded_path = BlindedPath::new_for_message(&hops, &keys_manager, &secp_ctx).unwrap();
///
/// // Send a custom onion message to a blinded path.
/// let path = OnionMessagePath {
/// \tintermediate_nodes: vec![hop_node_id1, hop_node_id2],
/// \tdestination: Destination::BlindedPath(blinded_path),
/// };
/// let reply_path = None;
/// # let message = YourCustomMessage {};
/// onion_messenger.send_onion_message(path, message, reply_path);
/// ```
///
/// [`InvoiceRequest`]: crate::offers::invoice_request::InvoiceRequest
/// [`Bolt12Invoice`]: crate::offers::invoice::Bolt12Invoice
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
/// A trait defining behavior for routing an [`OnionMessage`].
#[repr(C)]
pub struct MessageRouter {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns a route for sending an [`OnionMessage`] to the given [`Destination`].
	pub find_path: extern "C" fn (this_arg: *const c_void, sender: crate::c_types::PublicKey, peers: crate::c_types::derived::CVec_PublicKeyZ, destination: crate::lightning::onion_message::messenger::Destination) -> crate::c_types::derived::CResult_OnionMessagePathNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for MessageRouter {}
unsafe impl Sync for MessageRouter {}
#[allow(unused)]
pub(crate) fn MessageRouter_clone_fields(orig: &MessageRouter) -> MessageRouter {
	MessageRouter {
		this_arg: orig.this_arg,
		find_path: Clone::clone(&orig.find_path),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::messenger::MessageRouter as rustMessageRouter;
impl rustMessageRouter for MessageRouter {
	fn find_path(&self, mut sender: bitcoin::secp256k1::PublicKey, mut peers: Vec<bitcoin::secp256k1::PublicKey>, mut destination: lightning::onion_message::messenger::Destination) -> Result<lightning::onion_message::messenger::OnionMessagePath, ()> {
		let mut local_peers = Vec::new(); for mut item in peers.drain(..) { local_peers.push( { crate::c_types::PublicKey::from_rust(&item) }); };
		let mut ret = (self.find_path)(self.this_arg, crate::c_types::PublicKey::from_rust(&sender), local_peers.into(), crate::lightning::onion_message::messenger::Destination::native_into(destination));
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for MessageRouter {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for MessageRouter {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MessageRouter_free(this_ptr: MessageRouter) { }
impl Drop for MessageRouter {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::onion_message::messenger::DefaultMessageRouter as nativeDefaultMessageRouterImport;
pub(crate) type nativeDefaultMessageRouter = nativeDefaultMessageRouterImport;

/// A [`MessageRouter`] that can only route to a directly connected [`Destination`].
#[must_use]
#[repr(C)]
pub struct DefaultMessageRouter {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDefaultMessageRouter,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DefaultMessageRouter {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDefaultMessageRouter>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DefaultMessageRouter, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_free(this_obj: DefaultMessageRouter) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DefaultMessageRouter_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDefaultMessageRouter) };
}
#[allow(unused)]
impl DefaultMessageRouter {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDefaultMessageRouter {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDefaultMessageRouter {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDefaultMessageRouter {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a new DefaultMessageRouter given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_new() -> DefaultMessageRouter {
	DefaultMessageRouter { inner: ObjOps::heap_alloc(lightning::onion_message::messenger::DefaultMessageRouter {}), is_owned: true }
}
impl From<nativeDefaultMessageRouter> for crate::lightning::onion_message::messenger::MessageRouter {
	fn from(obj: nativeDefaultMessageRouter) -> Self {
		let rust_obj = crate::lightning::onion_message::messenger::DefaultMessageRouter { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = DefaultMessageRouter_as_MessageRouter(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(DefaultMessageRouter_free_void);
		ret
	}
}
/// Constructs a new MessageRouter which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageRouter must be freed before this_arg is
#[no_mangle]
pub extern "C" fn DefaultMessageRouter_as_MessageRouter(this_arg: &DefaultMessageRouter) -> crate::lightning::onion_message::messenger::MessageRouter {
	crate::lightning::onion_message::messenger::MessageRouter {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		find_path: DefaultMessageRouter_MessageRouter_find_path,
	}
}

#[must_use]
extern "C" fn DefaultMessageRouter_MessageRouter_find_path(this_arg: *const c_void, mut sender: crate::c_types::PublicKey, mut peers: crate::c_types::derived::CVec_PublicKeyZ, mut destination: crate::lightning::onion_message::messenger::Destination) -> crate::c_types::derived::CResult_OnionMessagePathNoneZ {
	let mut local_peers = Vec::new(); for mut item in peers.into_rust().drain(..) { local_peers.push( { item.into_rust() }); };
	let mut ret = <nativeDefaultMessageRouter as lightning::onion_message::messenger::MessageRouter<>>::find_path(unsafe { &mut *(this_arg as *mut nativeDefaultMessageRouter) }, sender.into_rust(), local_peers, destination.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::OnionMessagePath { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::onion_message::messenger::OnionMessagePath as nativeOnionMessagePathImport;
pub(crate) type nativeOnionMessagePath = nativeOnionMessagePathImport;

/// A path for sending an [`OnionMessage`].
#[must_use]
#[repr(C)]
pub struct OnionMessagePath {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOnionMessagePath,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OnionMessagePath {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOnionMessagePath>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OnionMessagePath, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OnionMessagePath_free(this_obj: OnionMessagePath) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessagePath_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOnionMessagePath) };
}
#[allow(unused)]
impl OnionMessagePath {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOnionMessagePath {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOnionMessagePath {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOnionMessagePath {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Nodes on the path between the sender and the destination.
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn OnionMessagePath_get_intermediate_nodes(this_ptr: &OnionMessagePath) -> crate::c_types::derived::CVec_PublicKeyZ {
	let mut inner_val = this_ptr.get_native_mut_ref().intermediate_nodes.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { crate::c_types::PublicKey::from_rust(&item) }); };
	local_inner_val.into()
}
/// Nodes on the path between the sender and the destination.
#[no_mangle]
pub extern "C" fn OnionMessagePath_set_intermediate_nodes(this_ptr: &mut OnionMessagePath, mut val: crate::c_types::derived::CVec_PublicKeyZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_rust() }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.intermediate_nodes = local_val;
}
/// The recipient of the message.
#[no_mangle]
pub extern "C" fn OnionMessagePath_get_destination(this_ptr: &OnionMessagePath) -> crate::lightning::onion_message::messenger::Destination {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().destination;
	crate::lightning::onion_message::messenger::Destination::from_native(inner_val)
}
/// The recipient of the message.
#[no_mangle]
pub extern "C" fn OnionMessagePath_set_destination(this_ptr: &mut OnionMessagePath, mut val: crate::lightning::onion_message::messenger::Destination) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.destination = val.into_native();
}
/// Constructs a new OnionMessagePath given each field
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessagePath_new(mut intermediate_nodes_arg: crate::c_types::derived::CVec_PublicKeyZ, mut destination_arg: crate::lightning::onion_message::messenger::Destination) -> OnionMessagePath {
	let mut local_intermediate_nodes_arg = Vec::new(); for mut item in intermediate_nodes_arg.into_rust().drain(..) { local_intermediate_nodes_arg.push( { item.into_rust() }); };
	OnionMessagePath { inner: ObjOps::heap_alloc(nativeOnionMessagePath {
		intermediate_nodes: local_intermediate_nodes_arg,
		destination: destination_arg.into_native(),
	}), is_owned: true }
}
impl Clone for OnionMessagePath {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOnionMessagePath>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OnionMessagePath_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOnionMessagePath)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OnionMessagePath
pub extern "C" fn OnionMessagePath_clone(orig: &OnionMessagePath) -> OnionMessagePath {
	orig.clone()
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
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Destination_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const Destination)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Destination_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut Destination) };
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
	/// The provided [`Destination`] was an invalid [`BlindedPath`] due to not having any blinded
	/// hops.
	TooFewBlindedHops,
	/// Our next-hop peer was offline or does not support onion message forwarding.
	InvalidFirstHop,
	/// Onion message contents must have a TLV type >= 64.
	InvalidMessage,
	/// Our next-hop peer's buffer was full or our total outbound buffer was full.
	BufferFull,
	/// Failed to retrieve our node id from the provided [`NodeSigner`].
	///
	/// [`NodeSigner`]: crate::sign::NodeSigner
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
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const SendError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn SendError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut SendError) };
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
	/// Called with the custom message that was received, returning a response to send, if any.
	///
	/// The returned [`Self::CustomMessage`], if any, is enqueued to be sent by [`OnionMessenger`].
	pub handle_custom_message: extern "C" fn (this_arg: *const c_void, msg: crate::lightning::onion_message::packet::OnionMessageContents) -> crate::c_types::derived::COption_OnionMessageContentsZ,
	/// Read a custom message of type `message_type` from `buffer`, returning `Ok(None)` if the
	/// message type is unknown.
	pub read_custom_message: extern "C" fn (this_arg: *const c_void, message_type: u64, buffer: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_OnionMessageContentsZDecodeErrorZ,
	/// Releases any [`Self::CustomMessage`]s that need to be sent.
	///
	/// Typically, this is used for messages initiating a message flow rather than in response to
	/// another message. The latter should use the return value of [`Self::handle_custom_message`].
	pub release_pending_custom_messages: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_OnionMessageContentsDestinationBlindedPathZZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CustomOnionMessageHandler {}
unsafe impl Sync for CustomOnionMessageHandler {}
#[allow(unused)]
pub(crate) fn CustomOnionMessageHandler_clone_fields(orig: &CustomOnionMessageHandler) -> CustomOnionMessageHandler {
	CustomOnionMessageHandler {
		this_arg: orig.this_arg,
		handle_custom_message: Clone::clone(&orig.handle_custom_message),
		read_custom_message: Clone::clone(&orig.read_custom_message),
		release_pending_custom_messages: Clone::clone(&orig.release_pending_custom_messages),
		free: Clone::clone(&orig.free),
	}
}

use lightning::onion_message::messenger::CustomOnionMessageHandler as rustCustomOnionMessageHandler;
impl rustCustomOnionMessageHandler for CustomOnionMessageHandler {
	type CustomMessage = crate::lightning::onion_message::packet::OnionMessageContents;
	fn handle_custom_message(&self, mut msg: crate::lightning::onion_message::packet::OnionMessageContents) -> Option<crate::lightning::onion_message::packet::OnionMessageContents> {
		let mut ret = (self.handle_custom_message)(self.this_arg, Into::into(msg));
		let mut local_ret = { /*ret*/ let ret_opt = ret; if ret_opt.is_none() { None } else { Some({ { { ret_opt.take() } }})} };
		local_ret
	}
	fn read_custom_message<R:crate::c_types::io::Read>(&self, mut message_type: u64, mut buffer: &mut R) -> Result<Option<crate::lightning::onion_message::packet::OnionMessageContents>, lightning::ln::msgs::DecodeError> {
		let mut ret = (self.read_custom_message)(self.this_arg, message_type, crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec(buffer)));
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = { /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ let ret_0_opt = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }); if ret_0_opt.is_none() { None } else { Some({ { { ret_0_opt.take() } }})} }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn release_pending_custom_messages(&self) -> Vec<(crate::lightning::onion_message::packet::OnionMessageContents, lightning::onion_message::messenger::Destination, Option<lightning::blinded_path::BlindedPath>)> {
		let mut ret = (self.release_pending_custom_messages)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item.to_rust(); let mut local_orig_ret_0_2 = if orig_ret_0_2.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(orig_ret_0_2.take_inner()) } }) }; let mut local_ret_0 = (orig_ret_0_0, orig_ret_0_1.into_native(), local_orig_ret_0_2); local_ret_0 }); };
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
impl core::ops::DerefMut for CustomOnionMessageHandler {
	fn deref_mut(&mut self) -> &mut Self {
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
/// A processed incoming onion message, containing either a Forward (another onion message)
/// or a Receive payload with decrypted contents.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PeeledOnion {
	/// Forwarded onion, with the next node id and a new onion
	Forward(
		crate::c_types::PublicKey,
		crate::lightning::ln::msgs::OnionMessage),
	/// Received onion message, with decrypted contents, path_id, and reply path
	Receive(
		crate::lightning::onion_message::packet::ParsedOnionMessageContents,
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		crate::c_types::ThirtyTwoBytes,
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		crate::lightning::blinded_path::BlindedPath),
}
use lightning::onion_message::messenger::PeeledOnion as PeeledOnionImport;
pub(crate) type nativePeeledOnion = PeeledOnionImport<crate::lightning::onion_message::packet::OnionMessageContents>;

impl PeeledOnion {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePeeledOnion {
		match self {
			PeeledOnion::Forward (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				nativePeeledOnion::Forward (
					a_nonref.into_rust(),
					*unsafe { Box::from_raw(b_nonref.take_inner()) },
				)
			},
			PeeledOnion::Receive (ref a, ref b, ref c, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				let mut local_b_nonref = if b_nonref.data == [0; 32] { None } else { Some( { b_nonref.data }) };
				let mut c_nonref = Clone::clone(c);
				let mut local_c_nonref = if c_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(c_nonref.take_inner()) } }) };
				nativePeeledOnion::Receive (
					a_nonref.into_native(),
					local_b_nonref,
					local_c_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePeeledOnion {
		match self {
			PeeledOnion::Forward (mut a, mut b, ) => {
				nativePeeledOnion::Forward (
					a.into_rust(),
					*unsafe { Box::from_raw(b.take_inner()) },
				)
			},
			PeeledOnion::Receive (mut a, mut b, mut c, ) => {
				let mut local_b = if b.data == [0; 32] { None } else { Some( { b.data }) };
				let mut local_c = if c.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(c.take_inner()) } }) };
				nativePeeledOnion::Receive (
					a.into_native(),
					local_b,
					local_c,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePeeledOnion) -> Self {
		match native {
			nativePeeledOnion::Forward (ref a, ref b, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				PeeledOnion::Forward (
					crate::c_types::PublicKey::from_rust(&a_nonref),
					crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(b_nonref), is_owned: true },
				)
			},
			nativePeeledOnion::Receive (ref a, ref b, ref c, ) => {
				let mut a_nonref = Clone::clone(a);
				let mut b_nonref = Clone::clone(b);
				let mut local_b_nonref = if b_nonref.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (b_nonref.unwrap()) } } };
				let mut c_nonref = Clone::clone(c);
				let mut local_c_nonref = crate::lightning::blinded_path::BlindedPath { inner: if c_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((c_nonref.unwrap())) } }, is_owned: true };
				PeeledOnion::Receive (
					crate::lightning::onion_message::packet::ParsedOnionMessageContents::native_into(a_nonref),
					local_b_nonref,
					local_c_nonref,
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePeeledOnion) -> Self {
		match native {
			nativePeeledOnion::Forward (mut a, mut b, ) => {
				PeeledOnion::Forward (
					crate::c_types::PublicKey::from_rust(&a),
					crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(b), is_owned: true },
				)
			},
			nativePeeledOnion::Receive (mut a, mut b, mut c, ) => {
				let mut local_b = if b.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (b.unwrap()) } } };
				let mut local_c = crate::lightning::blinded_path::BlindedPath { inner: if c.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((c.unwrap())) } }, is_owned: true };
				PeeledOnion::Receive (
					crate::lightning::onion_message::packet::ParsedOnionMessageContents::native_into(a),
					local_b,
					local_c,
				)
			},
		}
	}
}
/// Frees any resources used by the PeeledOnion
#[no_mangle]
pub extern "C" fn PeeledOnion_free(this_ptr: PeeledOnion) { }
/// Creates a copy of the PeeledOnion
#[no_mangle]
pub extern "C" fn PeeledOnion_clone(orig: &PeeledOnion) -> PeeledOnion {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeeledOnion_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const PeeledOnion)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeeledOnion_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut PeeledOnion) };
}
#[no_mangle]
/// Utility method to constructs a new Forward-variant PeeledOnion
pub extern "C" fn PeeledOnion_forward(a: crate::c_types::PublicKey,b: crate::lightning::ln::msgs::OnionMessage) -> PeeledOnion {
	PeeledOnion::Forward(a, b, )
}
#[no_mangle]
/// Utility method to constructs a new Receive-variant PeeledOnion
pub extern "C" fn PeeledOnion_receive(a: crate::lightning::onion_message::packet::ParsedOnionMessageContents,b: crate::c_types::ThirtyTwoBytes,c: crate::lightning::blinded_path::BlindedPath) -> PeeledOnion {
	PeeledOnion::Receive(a, b, c, )
}
/// Creates an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`.
///
/// Returns both the node id of the peer to send the message to and the message itself.
///
/// Note that reply_path (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_onion_message(entropy_source: &crate::lightning::sign::EntropySource, node_signer: &crate::lightning::sign::NodeSigner, mut path: crate::lightning::onion_message::messenger::OnionMessagePath, mut contents: crate::lightning::onion_message::packet::OnionMessageContents, mut reply_path: crate::lightning::blinded_path::BlindedPath) -> crate::c_types::derived::CResult_C2Tuple_PublicKeyOnionMessageZSendErrorZ {
	let mut local_reply_path = if reply_path.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(reply_path.take_inner()) } }) };
	let mut ret = lightning::onion_message::messenger::create_onion_message::<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::onion_message::packet::OnionMessageContents>(entropy_source, node_signer, secp256k1::global::SECP256K1, *unsafe { Box::from_raw(path.take_inner()) }, contents, local_reply_path);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::PublicKey::from_rust(&orig_ret_0_0), crate::lightning::ln::msgs::OnionMessage { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

/// Decode one layer of an incoming [`OnionMessage`].
///
/// Returns either the next layer of the onion for forwarding or the decrypted content for the
/// receiver.
#[no_mangle]
pub extern "C" fn peel_onion_message(msg: &crate::lightning::ln::msgs::OnionMessage, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::c_types::derived::CResult_PeeledOnionNoneZ {
	let mut ret = lightning::onion_message::messenger::peel_onion_message::<crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger, crate::lightning::onion_message::messenger::CustomOnionMessageHandler>(msg.get_native_ref(), secp256k1::global::SECP256K1, node_signer, logger, custom_handler);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::onion_message::messenger::PeeledOnion::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Constructs a new `OnionMessenger` to send, forward, and delegate received onion messages to
/// their respective handlers.
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_new(mut entropy_source: crate::lightning::sign::EntropySource, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut message_router: crate::lightning::onion_message::messenger::MessageRouter, mut offers_handler: crate::lightning::onion_message::offers::OffersMessageHandler, mut custom_handler: crate::lightning::onion_message::messenger::CustomOnionMessageHandler) -> crate::lightning::onion_message::messenger::OnionMessenger {
	let mut ret = lightning::onion_message::messenger::OnionMessenger::new(entropy_source, node_signer, logger, message_router, offers_handler, custom_handler);
	crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Sends an [`OnionMessage`] with the given `contents` for sending to the destination of
/// `path`.
///
/// See [`OnionMessenger`] for example usage.
///
/// Note that reply_path (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn OnionMessenger_send_onion_message(this_arg: &crate::lightning::onion_message::messenger::OnionMessenger, mut path: crate::lightning::onion_message::messenger::OnionMessagePath, mut contents: crate::lightning::onion_message::packet::OnionMessageContents, mut reply_path: crate::lightning::blinded_path::BlindedPath) -> crate::c_types::derived::CResult_NoneSendErrorZ {
	let mut local_reply_path = if reply_path.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(reply_path.take_inner()) } }) };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.send_onion_message(*unsafe { Box::from_raw(path.take_inner()) }, contents, local_reply_path);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::onion_message::messenger::SendError::native_into(e) }).into() };
	local_ret
}

impl From<nativeOnionMessenger> for crate::lightning::ln::msgs::OnionMessageHandler {
	fn from(obj: nativeOnionMessenger) -> Self {
		let rust_obj = crate::lightning::onion_message::messenger::OnionMessenger { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = OnionMessenger_as_OnionMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
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
		next_onion_message_for_peer: OnionMessenger_OnionMessageHandler_next_onion_message_for_peer,
		peer_connected: OnionMessenger_OnionMessageHandler_peer_connected,
		peer_disconnected: OnionMessenger_OnionMessageHandler_peer_disconnected,
		provided_node_features: OnionMessenger_OnionMessageHandler_provided_node_features,
		provided_init_features: OnionMessenger_OnionMessageHandler_provided_init_features,
	}
}

extern "C" fn OnionMessenger_OnionMessageHandler_handle_onion_message(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::OnionMessage) {
	<nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::handle_onion_message(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, &peer_node_id.into_rust(), msg.get_native_ref())
}
#[must_use]
extern "C" fn OnionMessenger_OnionMessageHandler_next_onion_message_for_peer(this_arg: *const c_void, mut peer_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::msgs::OnionMessage {
	let mut ret = <nativeOnionMessenger as lightning::ln::msgs::OnionMessageHandler<>>::next_onion_message_for_peer(unsafe { &mut *(this_arg as *mut nativeOnionMessenger) }, peer_node_id.into_rust());
	let mut local_ret = crate::lightning::ln::msgs::OnionMessage { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
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

