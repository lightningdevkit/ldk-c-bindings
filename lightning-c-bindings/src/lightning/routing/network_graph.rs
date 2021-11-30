// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! The top-level network map tracking logic lives here.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::routing::network_graph::NodeId as nativeNodeIdImport;
pub(crate) type nativeNodeId = nativeNodeIdImport;

/// Represents the compressed public key of a node
#[must_use]
#[repr(C)]
pub struct NodeId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeId_free(this_obj: NodeId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeId_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeId); }
}
#[allow(unused)]
impl NodeId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeId {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for NodeId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeId>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeId
pub extern "C" fn NodeId_clone(orig: &NodeId) -> NodeId {
	orig.clone()
}
/// Create a new NodeId from a public key
#[must_use]
#[no_mangle]
pub extern "C" fn NodeId_from_pubkey(mut pubkey: crate::c_types::PublicKey) -> NodeId {
	let mut ret = lightning::routing::network_graph::NodeId::from_pubkey(&pubkey.into_rust());
	NodeId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get the public key slice from this NodeId
#[must_use]
#[no_mangle]
pub extern "C" fn NodeId_as_slice(this_arg: &NodeId) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_slice();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Checks if two NodeIds contain equal inner contents.
#[no_mangle]
pub extern "C" fn NodeId_hash(o: &NodeId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the NodeId object into a byte array which can be read by NodeId_read
pub extern "C" fn NodeId_write(obj: &NodeId) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeId_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeId) })
}
#[no_mangle]
/// Read a NodeId from a byte array, created by NodeId_write
pub extern "C" fn NodeId_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeIdDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::NodeId, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::NodeId { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::network_graph::NetworkGraph as nativeNetworkGraphImport;
pub(crate) type nativeNetworkGraph = nativeNetworkGraphImport;

/// Represents the network as nodes and channels between them
#[must_use]
#[repr(C)]
pub struct NetworkGraph {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNetworkGraph,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NetworkGraph {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNetworkGraph>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NetworkGraph, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NetworkGraph_free(this_obj: NetworkGraph) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NetworkGraph_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNetworkGraph); }
}
#[allow(unused)]
impl NetworkGraph {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNetworkGraph {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNetworkGraph {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNetworkGraph {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
impl Clone for NetworkGraph {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNetworkGraph>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NetworkGraph_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNetworkGraph)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NetworkGraph
pub extern "C" fn NetworkGraph_clone(orig: &NetworkGraph) -> NetworkGraph {
	orig.clone()
}

use lightning::routing::network_graph::ReadOnlyNetworkGraph as nativeReadOnlyNetworkGraphImport;
pub(crate) type nativeReadOnlyNetworkGraph = nativeReadOnlyNetworkGraphImport<'static>;

/// A read-only view of [`NetworkGraph`].
#[must_use]
#[repr(C)]
pub struct ReadOnlyNetworkGraph {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeReadOnlyNetworkGraph,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ReadOnlyNetworkGraph {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeReadOnlyNetworkGraph>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ReadOnlyNetworkGraph, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_free(this_obj: ReadOnlyNetworkGraph) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ReadOnlyNetworkGraph_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeReadOnlyNetworkGraph); }
}
#[allow(unused)]
impl ReadOnlyNetworkGraph {
	pub(crate) fn get_native_ref(&self) -> &'static nativeReadOnlyNetworkGraph {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeReadOnlyNetworkGraph {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeReadOnlyNetworkGraph {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Update to the [`NetworkGraph`] based on payment failure information conveyed via the Onion
/// return packet by a node along the route. See [BOLT #4] for details.
///
/// [BOLT #4]: https://github.com/lightningnetwork/lightning-rfc/blob/master/04-onion-routing.md
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum NetworkUpdate {
	/// An error indicating a `channel_update` messages should be applied via
	/// [`NetworkGraph::update_channel`].
	ChannelUpdateMessage {
		/// The update to apply via [`NetworkGraph::update_channel`].
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// An error indicating only that a channel has been closed, which should be applied via
	/// [`NetworkGraph::close_channel_from_update`].
	ChannelClosed {
		/// The short channel id of the closed channel.
		short_channel_id: u64,
		/// Whether the channel should be permanently removed or temporarily disabled until a new
		/// `channel_update` message is received.
		is_permanent: bool,
	},
	/// An error indicating only that a node has failed, which should be applied via
	/// [`NetworkGraph::fail_node`].
	NodeFailure {
		/// The node id of the failed node.
		node_id: crate::c_types::PublicKey,
		/// Whether the node should be permanently removed from consideration or can be restored
		/// when a new `channel_update` message is received.
		is_permanent: bool,
	},
}
use lightning::routing::network_graph::NetworkUpdate as nativeNetworkUpdate;
impl NetworkUpdate {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeNetworkUpdate {
		match self {
			NetworkUpdate::ChannelUpdateMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeNetworkUpdate::ChannelUpdateMessage {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			NetworkUpdate::ChannelClosed {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				nativeNetworkUpdate::ChannelClosed {
					short_channel_id: short_channel_id_nonref,
					is_permanent: is_permanent_nonref,
				}
			},
			NetworkUpdate::NodeFailure {ref node_id, ref is_permanent, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				nativeNetworkUpdate::NodeFailure {
					node_id: node_id_nonref.into_rust(),
					is_permanent: is_permanent_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeNetworkUpdate {
		match self {
			NetworkUpdate::ChannelUpdateMessage {mut msg, } => {
				nativeNetworkUpdate::ChannelUpdateMessage {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			NetworkUpdate::ChannelClosed {mut short_channel_id, mut is_permanent, } => {
				nativeNetworkUpdate::ChannelClosed {
					short_channel_id: short_channel_id,
					is_permanent: is_permanent,
				}
			},
			NetworkUpdate::NodeFailure {mut node_id, mut is_permanent, } => {
				nativeNetworkUpdate::NodeFailure {
					node_id: node_id.into_rust(),
					is_permanent: is_permanent,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeNetworkUpdate) -> Self {
		match native {
			nativeNetworkUpdate::ChannelUpdateMessage {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				NetworkUpdate::ChannelUpdateMessage {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeNetworkUpdate::ChannelClosed {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				NetworkUpdate::ChannelClosed {
					short_channel_id: short_channel_id_nonref,
					is_permanent: is_permanent_nonref,
				}
			},
			nativeNetworkUpdate::NodeFailure {ref node_id, ref is_permanent, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				NetworkUpdate::NodeFailure {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					is_permanent: is_permanent_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeNetworkUpdate) -> Self {
		match native {
			nativeNetworkUpdate::ChannelUpdateMessage {mut msg, } => {
				NetworkUpdate::ChannelUpdateMessage {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeNetworkUpdate::ChannelClosed {mut short_channel_id, mut is_permanent, } => {
				NetworkUpdate::ChannelClosed {
					short_channel_id: short_channel_id,
					is_permanent: is_permanent,
				}
			},
			nativeNetworkUpdate::NodeFailure {mut node_id, mut is_permanent, } => {
				NetworkUpdate::NodeFailure {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					is_permanent: is_permanent,
				}
			},
		}
	}
}
/// Frees any resources used by the NetworkUpdate
#[no_mangle]
pub extern "C" fn NetworkUpdate_free(this_ptr: NetworkUpdate) { }
/// Creates a copy of the NetworkUpdate
#[no_mangle]
pub extern "C" fn NetworkUpdate_clone(orig: &NetworkUpdate) -> NetworkUpdate {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new ChannelUpdateMessage-variant NetworkUpdate
pub extern "C" fn NetworkUpdate_channel_update_message(msg: crate::lightning::ln::msgs::ChannelUpdate) -> NetworkUpdate {
	NetworkUpdate::ChannelUpdateMessage {
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelClosed-variant NetworkUpdate
pub extern "C" fn NetworkUpdate_channel_closed(short_channel_id: u64, is_permanent: bool) -> NetworkUpdate {
	NetworkUpdate::ChannelClosed {
		short_channel_id,
		is_permanent,
	}
}
#[no_mangle]
/// Utility method to constructs a new NodeFailure-variant NetworkUpdate
pub extern "C" fn NetworkUpdate_node_failure(node_id: crate::c_types::PublicKey, is_permanent: bool) -> NetworkUpdate {
	NetworkUpdate::NodeFailure {
		node_id,
		is_permanent,
	}
}
#[no_mangle]
/// Serialize the NetworkUpdate object into a byte array which can be read by NetworkUpdate_read
pub extern "C" fn NetworkUpdate_write(obj: &NetworkUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a NetworkUpdate from a byte array, created by NetworkUpdate_write
pub extern "C" fn NetworkUpdate_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_NetworkUpdateZDecodeErrorZ {
	let res: Result<Option<lightning::routing::network_graph::NetworkUpdate>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::network_graph::NetworkUpdate::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
impl From<nativeNetGraphMsgHandler> for crate::lightning::util::events::EventHandler {
	fn from(obj: nativeNetGraphMsgHandler) -> Self {
		let mut rust_obj = NetGraphMsgHandler { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = NetGraphMsgHandler_as_EventHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(NetGraphMsgHandler_free_void);
		ret
	}
}
/// Constructs a new EventHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_as_EventHandler(this_arg: &NetGraphMsgHandler) -> crate::lightning::util::events::EventHandler {
	crate::lightning::util::events::EventHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_event: NetGraphMsgHandler_EventHandler_handle_event,
	}
}

extern "C" fn NetGraphMsgHandler_EventHandler_handle_event(this_arg: *const c_void, event: &crate::lightning::util::events::Event) {
	<nativeNetGraphMsgHandler as lightning::util::events::EventHandler<>>::handle_event(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &event.to_native())
}


use lightning::routing::network_graph::NetGraphMsgHandler as nativeNetGraphMsgHandlerImport;
pub(crate) type nativeNetGraphMsgHandler = nativeNetGraphMsgHandlerImport<&'static lightning::routing::network_graph::NetworkGraph, crate::lightning::chain::Access, crate::lightning::util::logger::Logger>;

/// Receives and validates network updates from peers,
/// stores authentic and relevant data as a network graph.
/// This network graph is then used for routing payments.
/// Provides interface to help with initial routing sync by
/// serving historical announcements.
///
/// Serves as an [`EventHandler`] for applying updates from [`Event::PaymentPathFailed`] to the
/// [`NetworkGraph`].
#[must_use]
#[repr(C)]
pub struct NetGraphMsgHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNetGraphMsgHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NetGraphMsgHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNetGraphMsgHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NetGraphMsgHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_free(this_obj: NetGraphMsgHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NetGraphMsgHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNetGraphMsgHandler); }
}
#[allow(unused)]
impl NetGraphMsgHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNetGraphMsgHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNetGraphMsgHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNetGraphMsgHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Creates a new tracker of the actual state of the network of channels and nodes,
/// assuming an existing Network Graph.
/// Chain monitor is used to make sure announced channels exist on-chain,
/// channel data is correct, and that the announcement is signed with
/// channel owners' keys.
#[must_use]
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_new(network_graph: &crate::lightning::routing::network_graph::NetworkGraph, mut chain_access: crate::c_types::derived::COption_AccessZ, mut logger: crate::lightning::util::logger::Logger) -> NetGraphMsgHandler {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = lightning::routing::network_graph::NetGraphMsgHandler::new(network_graph.get_native_ref(), local_chain_access, logger);
	NetGraphMsgHandler { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Adds a provider used to check new announcements. Does not affect
/// existing announcements unless they are updated.
/// Add, update or remove the provider would replace the current one.
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_add_chain_access(this_arg: &mut NetGraphMsgHandler, mut chain_access: crate::c_types::derived::COption_AccessZ) {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut nativeNetGraphMsgHandler)) }.add_chain_access(local_chain_access)
}

impl From<nativeNetGraphMsgHandler> for crate::lightning::ln::msgs::RoutingMessageHandler {
	fn from(obj: nativeNetGraphMsgHandler) -> Self {
		let mut rust_obj = NetGraphMsgHandler { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = NetGraphMsgHandler_as_RoutingMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(NetGraphMsgHandler_free_void);
		ret
	}
}
/// Constructs a new RoutingMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned RoutingMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_as_RoutingMessageHandler(this_arg: &NetGraphMsgHandler) -> crate::lightning::ln::msgs::RoutingMessageHandler {
	crate::lightning::ln::msgs::RoutingMessageHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_node_announcement: NetGraphMsgHandler_RoutingMessageHandler_handle_node_announcement,
		handle_channel_announcement: NetGraphMsgHandler_RoutingMessageHandler_handle_channel_announcement,
		handle_channel_update: NetGraphMsgHandler_RoutingMessageHandler_handle_channel_update,
		get_next_channel_announcements: NetGraphMsgHandler_RoutingMessageHandler_get_next_channel_announcements,
		get_next_node_announcements: NetGraphMsgHandler_RoutingMessageHandler_get_next_node_announcements,
		sync_routing_table: NetGraphMsgHandler_RoutingMessageHandler_sync_routing_table,
		handle_reply_channel_range: NetGraphMsgHandler_RoutingMessageHandler_handle_reply_channel_range,
		handle_reply_short_channel_ids_end: NetGraphMsgHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end,
		handle_query_channel_range: NetGraphMsgHandler_RoutingMessageHandler_handle_query_channel_range,
		handle_query_short_channel_ids: NetGraphMsgHandler_RoutingMessageHandler_handle_query_short_channel_ids,
		MessageSendEventsProvider: crate::lightning::util::events::MessageSendEventsProvider {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: NetGraphMsgHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_node_announcement(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_node_announcement(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_channel_announcement(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_announcement(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_channel_update(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_get_next_channel_announcements(this_arg: *const c_void, mut starting_point: u64, mut batch_amount: u8) -> crate::c_types::derived::CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_channel_announcements(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, starting_point, batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_1 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_1.is_none() { std::ptr::null_mut() } else {  { ObjOps::heap_alloc((orig_ret_0_1.unwrap())) } }, is_owned: true }; let mut local_orig_ret_0_2 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_2.is_none() { std::ptr::null_mut() } else {  { ObjOps::heap_alloc((orig_ret_0_2.unwrap())) } }, is_owned: true }; let mut local_ret_0 = (crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, local_orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_get_next_node_announcements(this_arg: *const c_void, mut starting_point: crate::c_types::PublicKey, mut batch_amount: u8) -> crate::c_types::derived::CVec_NodeAnnouncementZ {
	let mut local_starting_point_base = if starting_point.is_null() { None } else { Some( { starting_point.into_rust() }) }; let mut local_starting_point = local_starting_point_base.as_ref();
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_node_announcements(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, local_starting_point, batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::msgs::NodeAnnouncement { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_sync_routing_table(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, init_msg: &crate::lightning::ln::msgs::Init) {
	<nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::sync_routing_table(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &their_node_id.into_rust(), init_msg.get_native_ref())
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_reply_channel_range(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::ReplyChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_channel_range(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::ReplyShortChannelIdsEnd) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_short_channel_ids_end(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_query_channel_range(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::QueryChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_channel_range(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn NetGraphMsgHandler_RoutingMessageHandler_handle_query_short_channel_ids(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::lightning::ln::msgs::QueryShortChannelIds) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_short_channel_ids(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

impl From<nativeNetGraphMsgHandler> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeNetGraphMsgHandler) -> Self {
		let mut rust_obj = NetGraphMsgHandler { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = NetGraphMsgHandler_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(NetGraphMsgHandler_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn NetGraphMsgHandler_as_MessageSendEventsProvider(this_arg: &NetGraphMsgHandler) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: NetGraphMsgHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn NetGraphMsgHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeNetGraphMsgHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeNetGraphMsgHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}


use lightning::routing::network_graph::DirectionalChannelInfo as nativeDirectionalChannelInfoImport;
pub(crate) type nativeDirectionalChannelInfo = nativeDirectionalChannelInfoImport;

/// Details about one direction of a channel. Received
/// within a channel update.
#[must_use]
#[repr(C)]
pub struct DirectionalChannelInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDirectionalChannelInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DirectionalChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDirectionalChannelInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DirectionalChannelInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_free(this_obj: DirectionalChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DirectionalChannelInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDirectionalChannelInfo); }
}
#[allow(unused)]
impl DirectionalChannelInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDirectionalChannelInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDirectionalChannelInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDirectionalChannelInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_last_update(this_ptr: &DirectionalChannelInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().last_update;
	*inner_val
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_last_update(this_ptr: &mut DirectionalChannelInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.last_update = val;
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_enabled(this_ptr: &DirectionalChannelInfo) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().enabled;
	*inner_val
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_enabled(this_ptr: &mut DirectionalChannelInfo, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.enabled = val;
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_cltv_expiry_delta(this_ptr: &DirectionalChannelInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_cltv_expiry_delta(this_ptr: &mut DirectionalChannelInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_htlc_minimum_msat(this_ptr: &DirectionalChannelInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_htlc_minimum_msat(this_ptr: &mut DirectionalChannelInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// The maximum value which may be relayed to the next hop via the channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_htlc_maximum_msat(this_ptr: &DirectionalChannelInfo) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The maximum value which may be relayed to the next hop via the channel.
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_htlc_maximum_msat(this_ptr: &mut DirectionalChannelInfo, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = local_val;
}
/// Fees charged when the channel is used for routing
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_fees(this_ptr: &DirectionalChannelInfo) -> crate::lightning::routing::network_graph::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fees;
	crate::lightning::routing::network_graph::RoutingFees { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::network_graph::RoutingFees<>) as *mut _) }, is_owned: false }
}
/// Fees charged when the channel is used for routing
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_fees(this_ptr: &mut DirectionalChannelInfo, mut val: crate::lightning::routing::network_graph::RoutingFees) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_get_last_update_message(this_ptr: &DirectionalChannelInfo) -> crate::lightning::ln::msgs::ChannelUpdate {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().last_update_message;
	let mut local_inner_val = crate::lightning::ln::msgs::ChannelUpdate { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::ChannelUpdate<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_set_last_update_message(this_ptr: &mut DirectionalChannelInfo, mut val: crate::lightning::ln::msgs::ChannelUpdate) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.last_update_message = local_val;
}
/// Constructs a new DirectionalChannelInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DirectionalChannelInfo_new(mut last_update_arg: u32, mut enabled_arg: bool, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: u64, mut htlc_maximum_msat_arg: crate::c_types::derived::COption_u64Z, mut fees_arg: crate::lightning::routing::network_graph::RoutingFees, mut last_update_message_arg: crate::lightning::ln::msgs::ChannelUpdate) -> DirectionalChannelInfo {
	let mut local_htlc_maximum_msat_arg = if htlc_maximum_msat_arg.is_some() { Some( { htlc_maximum_msat_arg.take() }) } else { None };
	let mut local_last_update_message_arg = if last_update_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(last_update_message_arg.take_inner()) } }) };
	DirectionalChannelInfo { inner: ObjOps::heap_alloc(nativeDirectionalChannelInfo {
		last_update: last_update_arg,
		enabled: enabled_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
		htlc_maximum_msat: local_htlc_maximum_msat_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		last_update_message: local_last_update_message_arg,
	}), is_owned: true }
}
impl Clone for DirectionalChannelInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDirectionalChannelInfo>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DirectionalChannelInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDirectionalChannelInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DirectionalChannelInfo
pub extern "C" fn DirectionalChannelInfo_clone(orig: &DirectionalChannelInfo) -> DirectionalChannelInfo {
	orig.clone()
}
#[no_mangle]
/// Serialize the DirectionalChannelInfo object into a byte array which can be read by DirectionalChannelInfo_read
pub extern "C" fn DirectionalChannelInfo_write(obj: &DirectionalChannelInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn DirectionalChannelInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeDirectionalChannelInfo) })
}
#[no_mangle]
/// Read a DirectionalChannelInfo from a byte array, created by DirectionalChannelInfo_write
pub extern "C" fn DirectionalChannelInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_DirectionalChannelInfoDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::DirectionalChannelInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::DirectionalChannelInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::network_graph::ChannelInfo as nativeChannelInfoImport;
pub(crate) type nativeChannelInfo = nativeChannelInfoImport;

/// Details about a channel (both directions).
/// Received within a channel announcement.
#[must_use]
#[repr(C)]
pub struct ChannelInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelInfo_free(this_obj: ChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelInfo); }
}
#[allow(unused)]
impl ChannelInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Protocol features of a channel communicated during its announcement
#[no_mangle]
pub extern "C" fn ChannelInfo_get_features(this_ptr: &ChannelInfo) -> crate::lightning::ln::features::ChannelFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning::ln::features::ChannelFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::ChannelFeatures<>) as *mut _) }, is_owned: false }
}
/// Protocol features of a channel communicated during its announcement
#[no_mangle]
pub extern "C" fn ChannelInfo_set_features(this_ptr: &mut ChannelInfo, mut val: crate::lightning::ln::features::ChannelFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Source node of the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_node_one(this_ptr: &ChannelInfo) -> crate::lightning::routing::network_graph::NodeId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_one;
	crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false }
}
/// Source node of the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_one(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::network_graph::NodeId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_one = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Details about the first direction of a channel
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_get_one_to_two(this_ptr: &ChannelInfo) -> crate::lightning::routing::network_graph::DirectionalChannelInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().one_to_two;
	let mut local_inner_val = crate::lightning::routing::network_graph::DirectionalChannelInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::network_graph::DirectionalChannelInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the first direction of a channel
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_set_one_to_two(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::network_graph::DirectionalChannelInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.one_to_two = local_val;
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_node_two(this_ptr: &ChannelInfo) -> crate::lightning::routing::network_graph::NodeId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_two;
	crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false }
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_two(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::network_graph::NodeId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_two = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Details about the second direction of a channel
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_get_two_to_one(this_ptr: &ChannelInfo) -> crate::lightning::routing::network_graph::DirectionalChannelInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().two_to_one;
	let mut local_inner_val = crate::lightning::routing::network_graph::DirectionalChannelInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::network_graph::DirectionalChannelInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the second direction of a channel
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_set_two_to_one(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::network_graph::DirectionalChannelInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.two_to_one = local_val;
}
/// The channel capacity as seen on-chain, if chain lookup is available.
#[no_mangle]
pub extern "C" fn ChannelInfo_get_capacity_sats(this_ptr: &ChannelInfo) -> crate::c_types::derived::COption_u64Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().capacity_sats;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The channel capacity as seen on-chain, if chain lookup is available.
#[no_mangle]
pub extern "C" fn ChannelInfo_set_capacity_sats(this_ptr: &mut ChannelInfo, mut val: crate::c_types::derived::COption_u64Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.capacity_sats = local_val;
}
/// An initial announcement of the channel
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_get_announcement_message(this_ptr: &ChannelInfo) -> crate::lightning::ln::msgs::ChannelAnnouncement {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announcement_message;
	let mut local_inner_val = crate::lightning::ln::msgs::ChannelAnnouncement { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::ChannelAnnouncement<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An initial announcement of the channel
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_set_announcement_message(this_ptr: &mut ChannelInfo, mut val: crate::lightning::ln::msgs::ChannelAnnouncement) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announcement_message = local_val;
}
/// Constructs a new ChannelInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelInfo_new(mut features_arg: crate::lightning::ln::features::ChannelFeatures, mut node_one_arg: crate::lightning::routing::network_graph::NodeId, mut one_to_two_arg: crate::lightning::routing::network_graph::DirectionalChannelInfo, mut node_two_arg: crate::lightning::routing::network_graph::NodeId, mut two_to_one_arg: crate::lightning::routing::network_graph::DirectionalChannelInfo, mut capacity_sats_arg: crate::c_types::derived::COption_u64Z, mut announcement_message_arg: crate::lightning::ln::msgs::ChannelAnnouncement) -> ChannelInfo {
	let mut local_one_to_two_arg = if one_to_two_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(one_to_two_arg.take_inner()) } }) };
	let mut local_two_to_one_arg = if two_to_one_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(two_to_one_arg.take_inner()) } }) };
	let mut local_capacity_sats_arg = if capacity_sats_arg.is_some() { Some( { capacity_sats_arg.take() }) } else { None };
	let mut local_announcement_message_arg = if announcement_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_message_arg.take_inner()) } }) };
	ChannelInfo { inner: ObjOps::heap_alloc(nativeChannelInfo {
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		node_one: *unsafe { Box::from_raw(node_one_arg.take_inner()) },
		one_to_two: local_one_to_two_arg,
		node_two: *unsafe { Box::from_raw(node_two_arg.take_inner()) },
		two_to_one: local_two_to_one_arg,
		capacity_sats: local_capacity_sats_arg,
		announcement_message: local_announcement_message_arg,
	}), is_owned: true }
}
impl Clone for ChannelInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelInfo>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelInfo
pub extern "C" fn ChannelInfo_clone(orig: &ChannelInfo) -> ChannelInfo {
	orig.clone()
}
#[no_mangle]
/// Serialize the ChannelInfo object into a byte array which can be read by ChannelInfo_read
pub extern "C" fn ChannelInfo_write(obj: &ChannelInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelInfo) })
}
#[no_mangle]
/// Read a ChannelInfo from a byte array, created by ChannelInfo_write
pub extern "C" fn ChannelInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelInfoDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::ChannelInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::ChannelInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::network_graph::RoutingFees as nativeRoutingFeesImport;
pub(crate) type nativeRoutingFees = nativeRoutingFeesImport;

/// Fees for routing via a given channel or a node
#[must_use]
#[repr(C)]
pub struct RoutingFees {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRoutingFees,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RoutingFees {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRoutingFees>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RoutingFees, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RoutingFees_free(this_obj: RoutingFees) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RoutingFees_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRoutingFees); }
}
#[allow(unused)]
impl RoutingFees {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRoutingFees {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRoutingFees {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRoutingFees {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Flat routing fee in satoshis
#[no_mangle]
pub extern "C" fn RoutingFees_get_base_msat(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().base_msat;
	*inner_val
}
/// Flat routing fee in satoshis
#[no_mangle]
pub extern "C" fn RoutingFees_set_base_msat(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.base_msat = val;
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_get_proportional_millionths(this_ptr: &RoutingFees) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().proportional_millionths;
	*inner_val
}
/// Liquidity-based routing fee in millionths of a routed amount.
/// In other words, 10000 is 1%.
#[no_mangle]
pub extern "C" fn RoutingFees_set_proportional_millionths(this_ptr: &mut RoutingFees, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.proportional_millionths = val;
}
/// Constructs a new RoutingFees given each field
#[must_use]
#[no_mangle]
pub extern "C" fn RoutingFees_new(mut base_msat_arg: u32, mut proportional_millionths_arg: u32) -> RoutingFees {
	RoutingFees { inner: ObjOps::heap_alloc(nativeRoutingFees {
		base_msat: base_msat_arg,
		proportional_millionths: proportional_millionths_arg,
	}), is_owned: true }
}
/// Checks if two RoutingFeess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn RoutingFees_eq(a: &RoutingFees, b: &RoutingFees) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for RoutingFees {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRoutingFees>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RoutingFees_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRoutingFees)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the RoutingFees
pub extern "C" fn RoutingFees_clone(orig: &RoutingFees) -> RoutingFees {
	orig.clone()
}
/// Checks if two RoutingFeess contain equal inner contents.
#[no_mangle]
pub extern "C" fn RoutingFees_hash(o: &RoutingFees) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the RoutingFees object into a byte array which can be read by RoutingFees_read
pub extern "C" fn RoutingFees_write(obj: &RoutingFees) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn RoutingFees_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRoutingFees) })
}
#[no_mangle]
/// Read a RoutingFees from a byte array, created by RoutingFees_write
pub extern "C" fn RoutingFees_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RoutingFeesDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::RoutingFees, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::RoutingFees { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::network_graph::NodeAnnouncementInfo as nativeNodeAnnouncementInfoImport;
pub(crate) type nativeNodeAnnouncementInfo = nativeNodeAnnouncementInfoImport;

/// Information received in the latest node_announcement from this node.
#[must_use]
#[repr(C)]
pub struct NodeAnnouncementInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeAnnouncementInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeAnnouncementInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeAnnouncementInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeAnnouncementInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_free(this_obj: NodeAnnouncementInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeAnnouncementInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeAnnouncementInfo); }
}
#[allow(unused)]
impl NodeAnnouncementInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeAnnouncementInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeAnnouncementInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeAnnouncementInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Protocol features the node announced support for
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_features(this_ptr: &NodeAnnouncementInfo) -> crate::lightning::ln::features::NodeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().features;
	crate::lightning::ln::features::NodeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::NodeFeatures<>) as *mut _) }, is_owned: false }
}
/// Protocol features the node announced support for
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_features(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// When the last known update to the node state was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_last_update(this_ptr: &NodeAnnouncementInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().last_update;
	*inner_val
}
/// When the last known update to the node state was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_last_update(this_ptr: &mut NodeAnnouncementInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.last_update = val;
}
/// Color assigned to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_rgb(this_ptr: &NodeAnnouncementInfo) -> *const [u8; 3] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().rgb;
	inner_val
}
/// Color assigned to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_rgb(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::ThreeBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.rgb = val.data;
}
/// Moniker assigned to the node.
/// May be invalid or malicious (eg control chars),
/// should not be exposed to the user.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_alias(this_ptr: &NodeAnnouncementInfo) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().alias;
	inner_val
}
/// Moniker assigned to the node.
/// May be invalid or malicious (eg control chars),
/// should not be exposed to the user.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_alias(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.alias = val.data;
}
/// Internet-level addresses via which one can connect to the node
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_addresses(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::c_types::derived::CVec_NetAddressZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_native() }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.addresses = local_val;
}
/// An initial announcement of the node
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_announcement_message(this_ptr: &NodeAnnouncementInfo) -> crate::lightning::ln::msgs::NodeAnnouncement {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announcement_message;
	let mut local_inner_val = crate::lightning::ln::msgs::NodeAnnouncement { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::NodeAnnouncement<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// An initial announcement of the node
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_announcement_message(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::lightning::ln::msgs::NodeAnnouncement) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announcement_message = local_val;
}
/// Constructs a new NodeAnnouncementInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_new(mut features_arg: crate::lightning::ln::features::NodeFeatures, mut last_update_arg: u32, mut rgb_arg: crate::c_types::ThreeBytes, mut alias_arg: crate::c_types::ThirtyTwoBytes, mut addresses_arg: crate::c_types::derived::CVec_NetAddressZ, mut announcement_message_arg: crate::lightning::ln::msgs::NodeAnnouncement) -> NodeAnnouncementInfo {
	let mut local_addresses_arg = Vec::new(); for mut item in addresses_arg.into_rust().drain(..) { local_addresses_arg.push( { item.into_native() }); };
	let mut local_announcement_message_arg = if announcement_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_message_arg.take_inner()) } }) };
	NodeAnnouncementInfo { inner: ObjOps::heap_alloc(nativeNodeAnnouncementInfo {
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		last_update: last_update_arg,
		rgb: rgb_arg.data,
		alias: alias_arg.data,
		addresses: local_addresses_arg,
		announcement_message: local_announcement_message_arg,
	}), is_owned: true }
}
impl Clone for NodeAnnouncementInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeAnnouncementInfo>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeAnnouncementInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeAnnouncementInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeAnnouncementInfo
pub extern "C" fn NodeAnnouncementInfo_clone(orig: &NodeAnnouncementInfo) -> NodeAnnouncementInfo {
	orig.clone()
}
#[no_mangle]
/// Serialize the NodeAnnouncementInfo object into a byte array which can be read by NodeAnnouncementInfo_read
pub extern "C" fn NodeAnnouncementInfo_write(obj: &NodeAnnouncementInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeAnnouncementInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeAnnouncementInfo) })
}
#[no_mangle]
/// Read a NodeAnnouncementInfo from a byte array, created by NodeAnnouncementInfo_write
pub extern "C" fn NodeAnnouncementInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeAnnouncementInfoDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::NodeAnnouncementInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::NodeAnnouncementInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::network_graph::NodeInfo as nativeNodeInfoImport;
pub(crate) type nativeNodeInfo = nativeNodeInfoImport;

/// Details about a node in the network, known from the network announcement.
#[must_use]
#[repr(C)]
pub struct NodeInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeInfo_free(this_obj: NodeInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeInfo); }
}
#[allow(unused)]
impl NodeInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// All valid channels a node has announced
#[no_mangle]
pub extern "C" fn NodeInfo_set_channels(this_ptr: &mut NodeInfo, mut val: crate::c_types::derived::CVec_u64Z) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channels = local_val;
}
/// Lowest fees enabling routing via any of the enabled, known channels to a node.
/// The two fields (flat and proportional fee) are independent,
/// meaning they don't have to refer to the same channel.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_get_lowest_inbound_channel_fees(this_ptr: &NodeInfo) -> crate::lightning::routing::network_graph::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().lowest_inbound_channel_fees;
	let mut local_inner_val = crate::lightning::routing::network_graph::RoutingFees { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::network_graph::RoutingFees<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Lowest fees enabling routing via any of the enabled, known channels to a node.
/// The two fields (flat and proportional fee) are independent,
/// meaning they don't have to refer to the same channel.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_set_lowest_inbound_channel_fees(this_ptr: &mut NodeInfo, mut val: crate::lightning::routing::network_graph::RoutingFees) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.lowest_inbound_channel_fees = local_val;
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_get_announcement_info(this_ptr: &NodeInfo) -> crate::lightning::routing::network_graph::NodeAnnouncementInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announcement_info;
	let mut local_inner_val = crate::lightning::routing::network_graph::NodeAnnouncementInfo { inner: unsafe { (if inner_val.is_none() { std::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::network_graph::NodeAnnouncementInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_set_announcement_info(this_ptr: &mut NodeInfo, mut val: crate::lightning::routing::network_graph::NodeAnnouncementInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announcement_info = local_val;
}
/// Constructs a new NodeInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn NodeInfo_new(mut channels_arg: crate::c_types::derived::CVec_u64Z, mut lowest_inbound_channel_fees_arg: crate::lightning::routing::network_graph::RoutingFees, mut announcement_info_arg: crate::lightning::routing::network_graph::NodeAnnouncementInfo) -> NodeInfo {
	let mut local_channels_arg = Vec::new(); for mut item in channels_arg.into_rust().drain(..) { local_channels_arg.push( { item }); };
	let mut local_lowest_inbound_channel_fees_arg = if lowest_inbound_channel_fees_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(lowest_inbound_channel_fees_arg.take_inner()) } }) };
	let mut local_announcement_info_arg = if announcement_info_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_info_arg.take_inner()) } }) };
	NodeInfo { inner: ObjOps::heap_alloc(nativeNodeInfo {
		channels: local_channels_arg,
		lowest_inbound_channel_fees: local_lowest_inbound_channel_fees_arg,
		announcement_info: local_announcement_info_arg,
	}), is_owned: true }
}
impl Clone for NodeInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeInfo>::is_null(self.inner) { std::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeInfo
pub extern "C" fn NodeInfo_clone(orig: &NodeInfo) -> NodeInfo {
	orig.clone()
}
#[no_mangle]
/// Serialize the NodeInfo object into a byte array which can be read by NodeInfo_read
pub extern "C" fn NodeInfo_write(obj: &NodeInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeInfo) })
}
#[no_mangle]
/// Read a NodeInfo from a byte array, created by NodeInfo_write
pub extern "C" fn NodeInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeInfoDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::NodeInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::NodeInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the NetworkGraph object into a byte array which can be read by NetworkGraph_read
pub extern "C" fn NetworkGraph_write(obj: &NetworkGraph) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NetworkGraph_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNetworkGraph) })
}
#[no_mangle]
/// Read a NetworkGraph from a byte array, created by NetworkGraph_write
pub extern "C" fn NetworkGraph_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NetworkGraphDecodeErrorZ {
	let res: Result<lightning::routing::network_graph::NetworkGraph, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::network_graph::NetworkGraph { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new, empty, network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_new(mut genesis_hash: crate::c_types::ThirtyTwoBytes) -> crate::lightning::routing::network_graph::NetworkGraph {
	let mut ret = lightning::routing::network_graph::NetworkGraph::new(::bitcoin::hash_types::BlockHash::from_slice(&genesis_hash.data[..]).unwrap());
	crate::lightning::routing::network_graph::NetworkGraph { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns a read-only view of the network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_read_only(this_arg: &NetworkGraph) -> crate::lightning::routing::network_graph::ReadOnlyNetworkGraph {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_only();
	crate::lightning::routing::network_graph::ReadOnlyNetworkGraph { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// For an already known node (from channel announcements), update its stored properties from a
/// given node announcement.
///
/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_node_from_announcement(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_node_from_announcement(msg.get_native_ref(), secp256k1::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// For an already known node (from channel announcements), update its stored properties from a
/// given node announcement without verifying the associated signatures. Because we aren't
/// given the associated signatures here we cannot relay the node announcement to any of our
/// peers.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_node_from_unsigned_announcement(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedNodeAnnouncement) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_node_from_unsigned_announcement(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Store or update channel info from a channel announcement.
///
/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
///
/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
/// the corresponding UTXO exists on chain and is correctly-formatted.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel_from_announcement(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::ChannelAnnouncement, mut chain_access: crate::c_types::derived::COption_AccessZ) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_from_announcement(msg.get_native_ref(), &local_chain_access, secp256k1::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Store or update channel info from a channel announcement without verifying the associated
/// signatures. Because we aren't given the associated signatures here we cannot relay the
/// channel announcement to any of our peers.
///
/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
/// the corresponding UTXO exists on chain and is correctly-formatted.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel_from_unsigned_announcement(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedChannelAnnouncement, mut chain_access: crate::c_types::derived::COption_AccessZ) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_from_unsigned_announcement(msg.get_native_ref(), &local_chain_access);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Close a channel if a corresponding HTLC fail was sent.
/// If permanent, removes a channel from the local storage.
/// May cause the removal of nodes too, if this was their last channel.
/// If not permanent, makes channels unavailable for routing.
#[no_mangle]
pub extern "C" fn NetworkGraph_close_channel_from_update(this_arg: &NetworkGraph, mut short_channel_id: u64, mut is_permanent: bool) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.close_channel_from_update(short_channel_id, is_permanent)
}

/// Marks a node in the graph as failed.
#[no_mangle]
pub extern "C" fn NetworkGraph_fail_node(this_arg: &NetworkGraph, mut _node_id: crate::c_types::PublicKey, mut is_permanent: bool) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.fail_node(&_node_id.into_rust(), is_permanent)
}

/// For an already known (from announcement) channel, update info about one of the directions
/// of the channel.
///
/// You probably don't want to call this directly, instead relying on a NetGraphMsgHandler's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel(msg.get_native_ref(), secp256k1::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// For an already known (from announcement) channel, update info about one of the directions
/// of the channel without verifying the associated signatures. Because we aren't given the
/// associated signatures here we cannot relay the channel update to any of our peers.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel_unsigned(this_arg: &NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedChannelUpdate) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_unsigned(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Get network addresses by node id.
/// Returns None if the requested node is completely unknown,
/// or if node announcement for the node was never received.
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_get_addresses(this_arg: &ReadOnlyNetworkGraph, mut pubkey: crate::c_types::PublicKey) -> crate::c_types::derived::COption_CVec_NetAddressZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_addresses(&pubkey.into_rust());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_NetAddressZZ::None } else { crate::c_types::derived::COption_CVec_NetAddressZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::lightning::ln::msgs::NetAddress::native_into(item) }); }; local_ret_0.into() }) };
	local_ret
}

