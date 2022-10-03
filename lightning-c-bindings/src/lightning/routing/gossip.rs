// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! The top-level network map tracking logic lives here.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::routing::gossip::NodeId as nativeNodeIdImport;
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
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for NodeId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeId>::is_null(self.inner) { core::ptr::null_mut() } else {
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
pub extern "C" fn NodeId_from_pubkey(mut pubkey: crate::c_types::PublicKey) -> crate::lightning::routing::gossip::NodeId {
	let mut ret = lightning::routing::gossip::NodeId::from_pubkey(&pubkey.into_rust());
	crate::lightning::routing::gossip::NodeId { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Get the public key slice from this NodeId
#[must_use]
#[no_mangle]
pub extern "C" fn NodeId_as_slice(this_arg: &crate::lightning::routing::gossip::NodeId) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_slice();
	let mut local_ret = crate::c_types::u8slice::from_slice(ret);
	local_ret
}

/// Checks if two NodeIds contain equal inner contents.
#[no_mangle]
pub extern "C" fn NodeId_hash(o: &NodeId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the NodeId object into a byte array which can be read by NodeId_read
pub extern "C" fn NodeId_write(obj: &crate::lightning::routing::gossip::NodeId) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeId_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeId) })
}
#[no_mangle]
/// Read a NodeId from a byte array, created by NodeId_write
pub extern "C" fn NodeId_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeIdDecodeErrorZ {
	let res: Result<lightning::routing::gossip::NodeId, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::NodeId { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::NetworkGraph as nativeNetworkGraphImport;
pub(crate) type nativeNetworkGraph = nativeNetworkGraphImport<crate::lightning::util::logger::Logger>;

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
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::routing::gossip::ReadOnlyNetworkGraph as nativeReadOnlyNetworkGraphImport;
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
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Update to the [`NetworkGraph`] based on payment failure information conveyed via the Onion
/// return packet by a node along the route. See [BOLT #4] for details.
///
/// [BOLT #4]: https://github.com/lightning/bolts/blob/master/04-onion-routing.md
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum NetworkUpdate {
	/// An error indicating a `channel_update` messages should be applied via
	/// [`NetworkGraph::update_channel`].
	ChannelUpdateMessage {
		/// The update to apply via [`NetworkGraph::update_channel`].
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// An error indicating that a channel failed to route a payment, which should be applied via
	/// [`NetworkGraph::channel_failed`].
	ChannelFailure {
		/// The short channel id of the closed channel.
		short_channel_id: u64,
		/// Whether the channel should be permanently removed or temporarily disabled until a new
		/// `channel_update` message is received.
		is_permanent: bool,
	},
	/// An error indicating that a node failed to route a payment, which should be applied via
	/// [`NetworkGraph::node_failed`].
	NodeFailure {
		/// The node id of the failed node.
		node_id: crate::c_types::PublicKey,
		/// Whether the node should be permanently removed from consideration or can be restored
		/// when a new `channel_update` message is received.
		is_permanent: bool,
	},
}
use lightning::routing::gossip::NetworkUpdate as NetworkUpdateImport;
pub(crate) type nativeNetworkUpdate = NetworkUpdateImport;

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
			NetworkUpdate::ChannelFailure {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				nativeNetworkUpdate::ChannelFailure {
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
			NetworkUpdate::ChannelFailure {mut short_channel_id, mut is_permanent, } => {
				nativeNetworkUpdate::ChannelFailure {
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
			nativeNetworkUpdate::ChannelFailure {ref short_channel_id, ref is_permanent, } => {
				let mut short_channel_id_nonref = (*short_channel_id).clone();
				let mut is_permanent_nonref = (*is_permanent).clone();
				NetworkUpdate::ChannelFailure {
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
			nativeNetworkUpdate::ChannelFailure {mut short_channel_id, mut is_permanent, } => {
				NetworkUpdate::ChannelFailure {
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
/// Utility method to constructs a new ChannelFailure-variant NetworkUpdate
pub extern "C" fn NetworkUpdate_channel_failure(short_channel_id: u64, is_permanent: bool) -> NetworkUpdate {
	NetworkUpdate::ChannelFailure {
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
pub extern "C" fn NetworkUpdate_write(obj: &crate::lightning::routing::gossip::NetworkUpdate) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a NetworkUpdate from a byte array, created by NetworkUpdate_write
pub extern "C" fn NetworkUpdate_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_NetworkUpdateZDecodeErrorZ {
	let res: Result<Option<lightning::routing::gossip::NetworkUpdate>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::gossip::NetworkUpdate::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::P2PGossipSync as nativeP2PGossipSyncImport;
pub(crate) type nativeP2PGossipSync = nativeP2PGossipSyncImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::chain::Access, crate::lightning::util::logger::Logger>;

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
pub struct P2PGossipSync {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeP2PGossipSync,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for P2PGossipSync {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeP2PGossipSync>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the P2PGossipSync, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn P2PGossipSync_free(this_obj: P2PGossipSync) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn P2PGossipSync_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeP2PGossipSync); }
}
#[allow(unused)]
impl P2PGossipSync {
	pub(crate) fn get_native_ref(&self) -> &'static nativeP2PGossipSync {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeP2PGossipSync {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeP2PGossipSync {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
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
pub extern "C" fn P2PGossipSync_new(network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut chain_access: crate::c_types::derived::COption_AccessZ, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::routing::gossip::P2PGossipSync {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = lightning::routing::gossip::P2PGossipSync::new(network_graph.get_native_ref(), local_chain_access, logger);
	crate::lightning::routing::gossip::P2PGossipSync { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Adds a provider used to check new announcements. Does not affect
/// existing announcements unless they are updated.
/// Add, update or remove the provider would replace the current one.
#[no_mangle]
pub extern "C" fn P2PGossipSync_add_chain_access(this_arg: &mut crate::lightning::routing::gossip::P2PGossipSync, mut chain_access: crate::c_types::derived::COption_AccessZ) {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::routing::gossip::nativeP2PGossipSync)) }.add_chain_access(local_chain_access)
}

impl From<nativeNetworkGraph> for crate::lightning::util::events::EventHandler {
	fn from(obj: nativeNetworkGraph) -> Self {
		let mut rust_obj = NetworkGraph { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = NetworkGraph_as_EventHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(NetworkGraph_free_void);
		ret
	}
}
/// Constructs a new EventHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn NetworkGraph_as_EventHandler(this_arg: &NetworkGraph) -> crate::lightning::util::events::EventHandler {
	crate::lightning::util::events::EventHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_event: NetworkGraph_EventHandler_handle_event,
	}
}

extern "C" fn NetworkGraph_EventHandler_handle_event(this_arg: *const c_void, event: &crate::lightning::util::events::Event) {
	<nativeNetworkGraph as lightning::util::events::EventHandler<>>::handle_event(unsafe { &mut *(this_arg as *mut nativeNetworkGraph) }, &event.to_native())
}

impl From<nativeP2PGossipSync> for crate::lightning::ln::msgs::RoutingMessageHandler {
	fn from(obj: nativeP2PGossipSync) -> Self {
		let mut rust_obj = P2PGossipSync { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = P2PGossipSync_as_RoutingMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(P2PGossipSync_free_void);
		ret
	}
}
/// Constructs a new RoutingMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned RoutingMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn P2PGossipSync_as_RoutingMessageHandler(this_arg: &P2PGossipSync) -> crate::lightning::ln::msgs::RoutingMessageHandler {
	crate::lightning::ln::msgs::RoutingMessageHandler {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		handle_node_announcement: P2PGossipSync_RoutingMessageHandler_handle_node_announcement,
		handle_channel_announcement: P2PGossipSync_RoutingMessageHandler_handle_channel_announcement,
		handle_channel_update: P2PGossipSync_RoutingMessageHandler_handle_channel_update,
		get_next_channel_announcement: P2PGossipSync_RoutingMessageHandler_get_next_channel_announcement,
		get_next_node_announcement: P2PGossipSync_RoutingMessageHandler_get_next_node_announcement,
		peer_connected: P2PGossipSync_RoutingMessageHandler_peer_connected,
		handle_reply_channel_range: P2PGossipSync_RoutingMessageHandler_handle_reply_channel_range,
		handle_reply_short_channel_ids_end: P2PGossipSync_RoutingMessageHandler_handle_reply_short_channel_ids_end,
		handle_query_channel_range: P2PGossipSync_RoutingMessageHandler_handle_query_channel_range,
		handle_query_short_channel_ids: P2PGossipSync_RoutingMessageHandler_handle_query_short_channel_ids,
		provided_node_features: P2PGossipSync_RoutingMessageHandler_provided_node_features,
		provided_init_features: P2PGossipSync_RoutingMessageHandler_provided_init_features,
		MessageSendEventsProvider: crate::lightning::util::events::MessageSendEventsProvider {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: P2PGossipSync_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_node_announcement(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_node_announcement(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_channel_announcement(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_announcement(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_channel_update(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_get_next_channel_announcement(this_arg: *const c_void, mut starting_point: u64) -> crate::c_types::derived::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_channel_announcement(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, starting_point);
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ::None } else { crate::c_types::derived::COption_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ::Some( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = (ret.unwrap()); let mut local_orig_ret_0_1 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_1.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((orig_ret_0_1.unwrap())) } }, is_owned: true }; let mut local_orig_ret_0_2 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_2.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((orig_ret_0_2.unwrap())) } }, is_owned: true }; let mut local_ret_0 = (crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, local_orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }) };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_get_next_node_announcement(this_arg: *const c_void, mut starting_point: crate::c_types::PublicKey) -> crate::lightning::ln::msgs::NodeAnnouncement {
	let mut local_starting_point_base = if starting_point.is_null() { None } else { Some( { starting_point.into_rust() }) }; let mut local_starting_point = local_starting_point_base.as_ref();
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_node_announcement(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, local_starting_point);
	let mut local_ret = crate::lightning::ln::msgs::NodeAnnouncement { inner: if ret.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((ret.unwrap())) } }, is_owned: true };
	local_ret
}
extern "C" fn P2PGossipSync_RoutingMessageHandler_peer_connected(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, init: &crate::lightning::ln::msgs::Init) {
	<nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust(), init.get_native_ref())
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_reply_channel_range(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::ReplyChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_channel_range(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_reply_short_channel_ids_end(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::ReplyShortChannelIdsEnd) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_short_channel_ids_end(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_query_channel_range(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::QueryChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_channel_range(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_handle_query_short_channel_ids(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut msg: crate::lightning::ln::msgs::QueryShortChannelIds) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_short_channel_ids(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_provided_node_features(this_arg: *const c_void) -> crate::lightning::ln::features::NodeFeatures {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::provided_node_features(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, );
	crate::lightning::ln::features::NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}
#[must_use]
extern "C" fn P2PGossipSync_RoutingMessageHandler_provided_init_features(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::features::InitFeatures {
	let mut ret = <nativeP2PGossipSync as lightning::ln::msgs::RoutingMessageHandler<>>::provided_init_features(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, &their_node_id.into_rust());
	crate::lightning::ln::features::InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeP2PGossipSync> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeP2PGossipSync) -> Self {
		let mut rust_obj = P2PGossipSync { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = P2PGossipSync_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(P2PGossipSync_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn P2PGossipSync_as_MessageSendEventsProvider(this_arg: &P2PGossipSync) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: P2PGossipSync_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn P2PGossipSync_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeP2PGossipSync as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeP2PGossipSync) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}


use lightning::routing::gossip::ChannelUpdateInfo as nativeChannelUpdateInfoImport;
pub(crate) type nativeChannelUpdateInfo = nativeChannelUpdateInfoImport;

/// Details about one direction of a channel as received within a [`ChannelUpdate`].
#[must_use]
#[repr(C)]
pub struct ChannelUpdateInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelUpdateInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelUpdateInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelUpdateInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelUpdateInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_free(this_obj: ChannelUpdateInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelUpdateInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeChannelUpdateInfo); }
}
#[allow(unused)]
impl ChannelUpdateInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelUpdateInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelUpdateInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelUpdateInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_last_update(this_ptr: &ChannelUpdateInfo) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().last_update;
	*inner_val
}
/// When the last update to the channel direction was issued.
/// Value is opaque, as set in the announcement.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_last_update(this_ptr: &mut ChannelUpdateInfo, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.last_update = val;
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_enabled(this_ptr: &ChannelUpdateInfo) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().enabled;
	*inner_val
}
/// Whether the channel can be currently used for payments (in this one direction).
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_enabled(this_ptr: &mut ChannelUpdateInfo, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.enabled = val;
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_cltv_expiry_delta(this_ptr: &ChannelUpdateInfo) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry_delta;
	*inner_val
}
/// The difference in CLTV values that you must have when routing through this channel.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_cltv_expiry_delta(this_ptr: &mut ChannelUpdateInfo, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry_delta = val;
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_htlc_minimum_msat(this_ptr: &ChannelUpdateInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_minimum_msat;
	*inner_val
}
/// The minimum value, which must be relayed to the next hop via the channel
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_htlc_minimum_msat(this_ptr: &mut ChannelUpdateInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_minimum_msat = val;
}
/// The maximum value which may be relayed to the next hop via the channel.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_htlc_maximum_msat(this_ptr: &ChannelUpdateInfo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_maximum_msat;
	*inner_val
}
/// The maximum value which may be relayed to the next hop via the channel.
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_htlc_maximum_msat(this_ptr: &mut ChannelUpdateInfo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_maximum_msat = val;
}
/// Fees charged when the channel is used for routing
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_fees(this_ptr: &ChannelUpdateInfo) -> crate::lightning::routing::gossip::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().fees;
	crate::lightning::routing::gossip::RoutingFees { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::gossip::RoutingFees<>) as *mut _) }, is_owned: false }
}
/// Fees charged when the channel is used for routing
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_fees(this_ptr: &mut ChannelUpdateInfo, mut val: crate::lightning::routing::gossip::RoutingFees) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.fees = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_get_last_update_message(this_ptr: &ChannelUpdateInfo) -> crate::lightning::ln::msgs::ChannelUpdate {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().last_update_message;
	let mut local_inner_val = crate::lightning::ln::msgs::ChannelUpdate { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::ChannelUpdate<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Most recent update for the channel received from the network
/// Mostly redundant with the data we store in fields explicitly.
/// Everything else is useful only for sending out for initial routing sync.
/// Not stored if contains excess data to prevent DoS.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_set_last_update_message(this_ptr: &mut ChannelUpdateInfo, mut val: crate::lightning::ln::msgs::ChannelUpdate) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.last_update_message = local_val;
}
/// Constructs a new ChannelUpdateInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelUpdateInfo_new(mut last_update_arg: u32, mut enabled_arg: bool, mut cltv_expiry_delta_arg: u16, mut htlc_minimum_msat_arg: u64, mut htlc_maximum_msat_arg: u64, mut fees_arg: crate::lightning::routing::gossip::RoutingFees, mut last_update_message_arg: crate::lightning::ln::msgs::ChannelUpdate) -> ChannelUpdateInfo {
	let mut local_last_update_message_arg = if last_update_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(last_update_message_arg.take_inner()) } }) };
	ChannelUpdateInfo { inner: ObjOps::heap_alloc(nativeChannelUpdateInfo {
		last_update: last_update_arg,
		enabled: enabled_arg,
		cltv_expiry_delta: cltv_expiry_delta_arg,
		htlc_minimum_msat: htlc_minimum_msat_arg,
		htlc_maximum_msat: htlc_maximum_msat_arg,
		fees: *unsafe { Box::from_raw(fees_arg.take_inner()) },
		last_update_message: local_last_update_message_arg,
	}), is_owned: true }
}
impl Clone for ChannelUpdateInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelUpdateInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelUpdateInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelUpdateInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelUpdateInfo
pub extern "C" fn ChannelUpdateInfo_clone(orig: &ChannelUpdateInfo) -> ChannelUpdateInfo {
	orig.clone()
}
#[no_mangle]
/// Serialize the ChannelUpdateInfo object into a byte array which can be read by ChannelUpdateInfo_read
pub extern "C" fn ChannelUpdateInfo_write(obj: &crate::lightning::routing::gossip::ChannelUpdateInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelUpdateInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelUpdateInfo) })
}
#[no_mangle]
/// Read a ChannelUpdateInfo from a byte array, created by ChannelUpdateInfo_write
pub extern "C" fn ChannelUpdateInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelUpdateInfoDecodeErrorZ {
	let res: Result<lightning::routing::gossip::ChannelUpdateInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::ChannelUpdateInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::ChannelInfo as nativeChannelInfoImport;
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
		self.inner = core::ptr::null_mut();
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
pub extern "C" fn ChannelInfo_get_node_one(this_ptr: &ChannelInfo) -> crate::lightning::routing::gossip::NodeId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_one;
	crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }
}
/// Source node of the first direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_one(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_one = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Details about the first direction of a channel
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_get_one_to_two(this_ptr: &ChannelInfo) -> crate::lightning::routing::gossip::ChannelUpdateInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().one_to_two;
	let mut local_inner_val = crate::lightning::routing::gossip::ChannelUpdateInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::gossip::ChannelUpdateInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the first direction of a channel
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_set_one_to_two(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::gossip::ChannelUpdateInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.one_to_two = local_val;
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_get_node_two(this_ptr: &ChannelInfo) -> crate::lightning::routing::gossip::NodeId {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().node_two;
	crate::lightning::routing::gossip::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::gossip::NodeId<>) as *mut _) }, is_owned: false }
}
/// Source node of the second direction of a channel
#[no_mangle]
pub extern "C" fn ChannelInfo_set_node_two(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::gossip::NodeId) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.node_two = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Details about the second direction of a channel
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_get_two_to_one(this_ptr: &ChannelInfo) -> crate::lightning::routing::gossip::ChannelUpdateInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().two_to_one;
	let mut local_inner_val = crate::lightning::routing::gossip::ChannelUpdateInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::gossip::ChannelUpdateInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Details about the second direction of a channel
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelInfo_set_two_to_one(this_ptr: &mut ChannelInfo, mut val: crate::lightning::routing::gossip::ChannelUpdateInfo) {
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
	let mut local_inner_val = crate::lightning::ln::msgs::ChannelAnnouncement { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::ChannelAnnouncement<>) as *mut _ }, is_owned: false };
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
impl Clone for ChannelInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
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
/// Returns a [`ChannelUpdateInfo`] based on the direction implied by the channel_flag.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelInfo_get_directional_info(this_arg: &crate::lightning::routing::gossip::ChannelInfo, mut channel_flags: u8) -> crate::lightning::routing::gossip::ChannelUpdateInfo {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_directional_info(channel_flags);
	let mut local_ret = crate::lightning::routing::gossip::ChannelUpdateInfo { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::ChannelUpdateInfo<>) as *mut _ }, is_owned: false };
	local_ret
}

#[no_mangle]
/// Serialize the ChannelInfo object into a byte array which can be read by ChannelInfo_read
pub extern "C" fn ChannelInfo_write(obj: &crate::lightning::routing::gossip::ChannelInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelInfo) })
}
#[no_mangle]
/// Read a ChannelInfo from a byte array, created by ChannelInfo_write
pub extern "C" fn ChannelInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelInfoDecodeErrorZ {
	let res: Result<lightning::routing::gossip::ChannelInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::ChannelInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::DirectedChannelInfo as nativeDirectedChannelInfoImport;
pub(crate) type nativeDirectedChannelInfo = nativeDirectedChannelInfoImport<'static>;

/// A wrapper around [`ChannelInfo`] representing information about the channel as directed from a
/// source node to a target node.
#[must_use]
#[repr(C)]
pub struct DirectedChannelInfo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDirectedChannelInfo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DirectedChannelInfo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDirectedChannelInfo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DirectedChannelInfo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DirectedChannelInfo_free(this_obj: DirectedChannelInfo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DirectedChannelInfo_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeDirectedChannelInfo); }
}
#[allow(unused)]
impl DirectedChannelInfo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDirectedChannelInfo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDirectedChannelInfo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDirectedChannelInfo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for DirectedChannelInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDirectedChannelInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DirectedChannelInfo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDirectedChannelInfo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DirectedChannelInfo
pub extern "C" fn DirectedChannelInfo_clone(orig: &DirectedChannelInfo) -> DirectedChannelInfo {
	orig.clone()
}
/// Returns information for the channel.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelInfo_channel(this_arg: &crate::lightning::routing::gossip::DirectedChannelInfo) -> crate::lightning::routing::gossip::ChannelInfo {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel();
	crate::lightning::routing::gossip::ChannelInfo { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::routing::gossip::ChannelInfo<>) as *mut _) }, is_owned: false }
}

/// Returns information for the direction.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelInfo_direction(this_arg: &crate::lightning::routing::gossip::DirectedChannelInfo) -> crate::lightning::routing::gossip::ChannelUpdateInfo {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.direction();
	let mut local_ret = crate::lightning::routing::gossip::ChannelUpdateInfo { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::ChannelUpdateInfo<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Returns the maximum HTLC amount allowed over the channel in the direction.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelInfo_htlc_maximum_msat(this_arg: &crate::lightning::routing::gossip::DirectedChannelInfo) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.htlc_maximum_msat();
	ret
}

/// Returns the [`EffectiveCapacity`] of the channel in the direction.
///
/// This is either the total capacity from the funding transaction, if known, or the
/// `htlc_maximum_msat` for the direction as advertised by the gossip network, if known,
/// otherwise.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelInfo_effective_capacity(this_arg: &crate::lightning::routing::gossip::DirectedChannelInfo) -> crate::lightning::routing::gossip::EffectiveCapacity {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.effective_capacity();
	crate::lightning::routing::gossip::EffectiveCapacity::native_into(ret)
}

/// The effective capacity of a channel for routing purposes.
///
/// While this may be smaller than the actual channel capacity, amounts greater than
/// [`Self::as_msat`] should not be routed through the channel.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum EffectiveCapacity {
	/// The available liquidity in the channel known from being a channel counterparty, and thus a
	/// direct hop.
	ExactLiquidity {
		/// Either the inbound or outbound liquidity depending on the direction, denominated in
		/// millisatoshi.
		liquidity_msat: u64,
	},
	/// The maximum HTLC amount in one direction as advertised on the gossip network.
	MaximumHTLC {
		/// The maximum HTLC amount denominated in millisatoshi.
		amount_msat: u64,
	},
	/// The total capacity of the channel as determined by the funding transaction.
	Total {
		/// The funding amount denominated in millisatoshi.
		capacity_msat: u64,
		/// The maximum HTLC amount denominated in millisatoshi.
		htlc_maximum_msat: crate::c_types::derived::COption_u64Z,
	},
	/// A capacity sufficient to route any payment, typically used for private channels provided by
	/// an invoice.
	Infinite,
	/// A capacity that is unknown possibly because either the chain state is unavailable to know
	/// the total capacity or the `htlc_maximum_msat` was not advertised on the gossip network.
	Unknown,
}
use lightning::routing::gossip::EffectiveCapacity as EffectiveCapacityImport;
pub(crate) type nativeEffectiveCapacity = EffectiveCapacityImport;

impl EffectiveCapacity {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeEffectiveCapacity {
		match self {
			EffectiveCapacity::ExactLiquidity {ref liquidity_msat, } => {
				let mut liquidity_msat_nonref = (*liquidity_msat).clone();
				nativeEffectiveCapacity::ExactLiquidity {
					liquidity_msat: liquidity_msat_nonref,
				}
			},
			EffectiveCapacity::MaximumHTLC {ref amount_msat, } => {
				let mut amount_msat_nonref = (*amount_msat).clone();
				nativeEffectiveCapacity::MaximumHTLC {
					amount_msat: amount_msat_nonref,
				}
			},
			EffectiveCapacity::Total {ref capacity_msat, ref htlc_maximum_msat, } => {
				let mut capacity_msat_nonref = (*capacity_msat).clone();
				let mut htlc_maximum_msat_nonref = (*htlc_maximum_msat).clone();
				let mut local_htlc_maximum_msat_nonref = if htlc_maximum_msat_nonref.is_some() { Some( { htlc_maximum_msat_nonref.take() }) } else { None };
				nativeEffectiveCapacity::Total {
					capacity_msat: capacity_msat_nonref,
					htlc_maximum_msat: local_htlc_maximum_msat_nonref,
				}
			},
			EffectiveCapacity::Infinite => nativeEffectiveCapacity::Infinite,
			EffectiveCapacity::Unknown => nativeEffectiveCapacity::Unknown,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeEffectiveCapacity {
		match self {
			EffectiveCapacity::ExactLiquidity {mut liquidity_msat, } => {
				nativeEffectiveCapacity::ExactLiquidity {
					liquidity_msat: liquidity_msat,
				}
			},
			EffectiveCapacity::MaximumHTLC {mut amount_msat, } => {
				nativeEffectiveCapacity::MaximumHTLC {
					amount_msat: amount_msat,
				}
			},
			EffectiveCapacity::Total {mut capacity_msat, mut htlc_maximum_msat, } => {
				let mut local_htlc_maximum_msat = if htlc_maximum_msat.is_some() { Some( { htlc_maximum_msat.take() }) } else { None };
				nativeEffectiveCapacity::Total {
					capacity_msat: capacity_msat,
					htlc_maximum_msat: local_htlc_maximum_msat,
				}
			},
			EffectiveCapacity::Infinite => nativeEffectiveCapacity::Infinite,
			EffectiveCapacity::Unknown => nativeEffectiveCapacity::Unknown,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeEffectiveCapacity) -> Self {
		match native {
			nativeEffectiveCapacity::ExactLiquidity {ref liquidity_msat, } => {
				let mut liquidity_msat_nonref = (*liquidity_msat).clone();
				EffectiveCapacity::ExactLiquidity {
					liquidity_msat: liquidity_msat_nonref,
				}
			},
			nativeEffectiveCapacity::MaximumHTLC {ref amount_msat, } => {
				let mut amount_msat_nonref = (*amount_msat).clone();
				EffectiveCapacity::MaximumHTLC {
					amount_msat: amount_msat_nonref,
				}
			},
			nativeEffectiveCapacity::Total {ref capacity_msat, ref htlc_maximum_msat, } => {
				let mut capacity_msat_nonref = (*capacity_msat).clone();
				let mut htlc_maximum_msat_nonref = (*htlc_maximum_msat).clone();
				let mut local_htlc_maximum_msat_nonref = if htlc_maximum_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { htlc_maximum_msat_nonref.unwrap() }) };
				EffectiveCapacity::Total {
					capacity_msat: capacity_msat_nonref,
					htlc_maximum_msat: local_htlc_maximum_msat_nonref,
				}
			},
			nativeEffectiveCapacity::Infinite => EffectiveCapacity::Infinite,
			nativeEffectiveCapacity::Unknown => EffectiveCapacity::Unknown,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeEffectiveCapacity) -> Self {
		match native {
			nativeEffectiveCapacity::ExactLiquidity {mut liquidity_msat, } => {
				EffectiveCapacity::ExactLiquidity {
					liquidity_msat: liquidity_msat,
				}
			},
			nativeEffectiveCapacity::MaximumHTLC {mut amount_msat, } => {
				EffectiveCapacity::MaximumHTLC {
					amount_msat: amount_msat,
				}
			},
			nativeEffectiveCapacity::Total {mut capacity_msat, mut htlc_maximum_msat, } => {
				let mut local_htlc_maximum_msat = if htlc_maximum_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { htlc_maximum_msat.unwrap() }) };
				EffectiveCapacity::Total {
					capacity_msat: capacity_msat,
					htlc_maximum_msat: local_htlc_maximum_msat,
				}
			},
			nativeEffectiveCapacity::Infinite => EffectiveCapacity::Infinite,
			nativeEffectiveCapacity::Unknown => EffectiveCapacity::Unknown,
		}
	}
}
/// Frees any resources used by the EffectiveCapacity
#[no_mangle]
pub extern "C" fn EffectiveCapacity_free(this_ptr: EffectiveCapacity) { }
/// Creates a copy of the EffectiveCapacity
#[no_mangle]
pub extern "C" fn EffectiveCapacity_clone(orig: &EffectiveCapacity) -> EffectiveCapacity {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new ExactLiquidity-variant EffectiveCapacity
pub extern "C" fn EffectiveCapacity_exact_liquidity(liquidity_msat: u64) -> EffectiveCapacity {
	EffectiveCapacity::ExactLiquidity {
		liquidity_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new MaximumHTLC-variant EffectiveCapacity
pub extern "C" fn EffectiveCapacity_maximum_htlc(amount_msat: u64) -> EffectiveCapacity {
	EffectiveCapacity::MaximumHTLC {
		amount_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new Total-variant EffectiveCapacity
pub extern "C" fn EffectiveCapacity_total(capacity_msat: u64, htlc_maximum_msat: crate::c_types::derived::COption_u64Z) -> EffectiveCapacity {
	EffectiveCapacity::Total {
		capacity_msat,
		htlc_maximum_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new Infinite-variant EffectiveCapacity
pub extern "C" fn EffectiveCapacity_infinite() -> EffectiveCapacity {
	EffectiveCapacity::Infinite}
#[no_mangle]
/// Utility method to constructs a new Unknown-variant EffectiveCapacity
pub extern "C" fn EffectiveCapacity_unknown() -> EffectiveCapacity {
	EffectiveCapacity::Unknown}
/// The presumed channel capacity denominated in millisatoshi for [`EffectiveCapacity::Unknown`] to
/// use when making routing decisions.

#[no_mangle]
pub static UNKNOWN_CHANNEL_CAPACITY_MSAT: u64 = lightning::routing::gossip::UNKNOWN_CHANNEL_CAPACITY_MSAT;
/// Returns the effective capacity denominated in millisatoshi.
#[must_use]
#[no_mangle]
pub extern "C" fn EffectiveCapacity_as_msat(this_arg: &crate::lightning::routing::gossip::EffectiveCapacity) -> u64 {
	let mut ret = this_arg.to_native().as_msat();
	ret
}


use lightning::routing::gossip::RoutingFees as nativeRoutingFeesImport;
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
		self.inner = core::ptr::null_mut();
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
			inner: if <*mut nativeRoutingFees>::is_null(self.inner) { core::ptr::null_mut() } else {
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
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
#[no_mangle]
/// Serialize the RoutingFees object into a byte array which can be read by RoutingFees_read
pub extern "C" fn RoutingFees_write(obj: &crate::lightning::routing::gossip::RoutingFees) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn RoutingFees_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeRoutingFees) })
}
#[no_mangle]
/// Read a RoutingFees from a byte array, created by RoutingFees_write
pub extern "C" fn RoutingFees_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_RoutingFeesDecodeErrorZ {
	let res: Result<lightning::routing::gossip::RoutingFees, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::RoutingFees { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::NodeAnnouncementInfo as nativeNodeAnnouncementInfoImport;
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
		self.inner = core::ptr::null_mut();
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
pub extern "C" fn NodeAnnouncementInfo_get_alias(this_ptr: &NodeAnnouncementInfo) -> crate::lightning::routing::gossip::NodeAlias {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().alias;
	crate::lightning::routing::gossip::NodeAlias { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::routing::gossip::NodeAlias<>) as *mut _) }, is_owned: false }
}
/// Moniker assigned to the node.
/// May be invalid or malicious (eg control chars),
/// should not be exposed to the user.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_set_alias(this_ptr: &mut NodeAnnouncementInfo, mut val: crate::lightning::routing::gossip::NodeAlias) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.alias = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Internet-level addresses via which one can connect to the node
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn NodeAnnouncementInfo_get_addresses(this_ptr: &NodeAnnouncementInfo) -> crate::c_types::derived::CVec_NetAddressZ {
	let mut inner_val = this_ptr.get_native_mut_ref().addresses.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { crate::lightning::ln::msgs::NetAddress::native_into(item) }); };
	local_inner_val.into()
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
	let mut local_inner_val = crate::lightning::ln::msgs::NodeAnnouncement { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::msgs::NodeAnnouncement<>) as *mut _ }, is_owned: false };
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
pub extern "C" fn NodeAnnouncementInfo_new(mut features_arg: crate::lightning::ln::features::NodeFeatures, mut last_update_arg: u32, mut rgb_arg: crate::c_types::ThreeBytes, mut alias_arg: crate::lightning::routing::gossip::NodeAlias, mut addresses_arg: crate::c_types::derived::CVec_NetAddressZ, mut announcement_message_arg: crate::lightning::ln::msgs::NodeAnnouncement) -> NodeAnnouncementInfo {
	let mut local_addresses_arg = Vec::new(); for mut item in addresses_arg.into_rust().drain(..) { local_addresses_arg.push( { item.into_native() }); };
	let mut local_announcement_message_arg = if announcement_message_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(announcement_message_arg.take_inner()) } }) };
	NodeAnnouncementInfo { inner: ObjOps::heap_alloc(nativeNodeAnnouncementInfo {
		features: *unsafe { Box::from_raw(features_arg.take_inner()) },
		last_update: last_update_arg,
		rgb: rgb_arg.data,
		alias: *unsafe { Box::from_raw(alias_arg.take_inner()) },
		addresses: local_addresses_arg,
		announcement_message: local_announcement_message_arg,
	}), is_owned: true }
}
impl Clone for NodeAnnouncementInfo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeAnnouncementInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
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
pub extern "C" fn NodeAnnouncementInfo_write(obj: &crate::lightning::routing::gossip::NodeAnnouncementInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeAnnouncementInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeAnnouncementInfo) })
}
#[no_mangle]
/// Read a NodeAnnouncementInfo from a byte array, created by NodeAnnouncementInfo_write
pub extern "C" fn NodeAnnouncementInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeAnnouncementInfoDecodeErrorZ {
	let res: Result<lightning::routing::gossip::NodeAnnouncementInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::NodeAnnouncementInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::NodeAlias as nativeNodeAliasImport;
pub(crate) type nativeNodeAlias = nativeNodeAliasImport;

/// A user-defined name for a node, which may be used when displaying the node in a graph.
///
/// Since node aliases are provided by third parties, they are a potential avenue for injection
/// attacks. Care must be taken when processing.
#[must_use]
#[repr(C)]
pub struct NodeAlias {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeAlias,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeAlias {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeAlias>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeAlias, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeAlias_free(this_obj: NodeAlias) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeAlias_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeNodeAlias); }
}
#[allow(unused)]
impl NodeAlias {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeAlias {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeAlias {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeAlias {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
#[no_mangle]
pub extern "C" fn NodeAlias_get_a(this_ptr: &NodeAlias) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().0;
	inner_val
}
#[no_mangle]
pub extern "C" fn NodeAlias_set_a(this_ptr: &mut NodeAlias, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.0 = val.data;
}
/// Constructs a new NodeAlias given each field
#[must_use]
#[no_mangle]
pub extern "C" fn NodeAlias_new(mut a_arg: crate::c_types::ThirtyTwoBytes) -> NodeAlias {
	NodeAlias { inner: ObjOps::heap_alloc(lightning::routing::gossip::NodeAlias (
		a_arg.data,
	)), is_owned: true }
}
impl Clone for NodeAlias {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeAlias>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeAlias_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeNodeAlias)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeAlias
pub extern "C" fn NodeAlias_clone(orig: &NodeAlias) -> NodeAlias {
	orig.clone()
}
#[no_mangle]
/// Serialize the NodeAlias object into a byte array which can be read by NodeAlias_read
pub extern "C" fn NodeAlias_write(obj: &crate::lightning::routing::gossip::NodeAlias) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeAlias_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeAlias) })
}
#[no_mangle]
/// Read a NodeAlias from a byte array, created by NodeAlias_write
pub extern "C" fn NodeAlias_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeAliasDecodeErrorZ {
	let res: Result<lightning::routing::gossip::NodeAlias, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::NodeAlias { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}

use lightning::routing::gossip::NodeInfo as nativeNodeInfoImport;
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
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// All valid channels a node has announced
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn NodeInfo_get_channels(this_ptr: &NodeInfo) -> crate::c_types::derived::CVec_u64Z {
	let mut inner_val = this_ptr.get_native_mut_ref().channels.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { item }); };
	local_inner_val.into()
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
pub extern "C" fn NodeInfo_get_lowest_inbound_channel_fees(this_ptr: &NodeInfo) -> crate::lightning::routing::gossip::RoutingFees {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().lowest_inbound_channel_fees;
	let mut local_inner_val = crate::lightning::routing::gossip::RoutingFees { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::gossip::RoutingFees<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// Lowest fees enabling routing via any of the enabled, known channels to a node.
/// The two fields (flat and proportional fee) are independent,
/// meaning they don't have to refer to the same channel.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_set_lowest_inbound_channel_fees(this_ptr: &mut NodeInfo, mut val: crate::lightning::routing::gossip::RoutingFees) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.lowest_inbound_channel_fees = local_val;
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_get_announcement_info(this_ptr: &NodeInfo) -> crate::lightning::routing::gossip::NodeAnnouncementInfo {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().announcement_info;
	let mut local_inner_val = crate::lightning::routing::gossip::NodeAnnouncementInfo { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::routing::gossip::NodeAnnouncementInfo<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// More information about a node from node_announcement.
/// Optional because we store a Node entry after learning about it from
/// a channel announcement, but before receiving a node announcement.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn NodeInfo_set_announcement_info(this_ptr: &mut NodeInfo, mut val: crate::lightning::routing::gossip::NodeAnnouncementInfo) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.announcement_info = local_val;
}
/// Constructs a new NodeInfo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn NodeInfo_new(mut channels_arg: crate::c_types::derived::CVec_u64Z, mut lowest_inbound_channel_fees_arg: crate::lightning::routing::gossip::RoutingFees, mut announcement_info_arg: crate::lightning::routing::gossip::NodeAnnouncementInfo) -> NodeInfo {
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
			inner: if <*mut nativeNodeInfo>::is_null(self.inner) { core::ptr::null_mut() } else {
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
pub extern "C" fn NodeInfo_write(obj: &crate::lightning::routing::gossip::NodeInfo) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NodeInfo_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeInfo) })
}
#[no_mangle]
/// Read a NodeInfo from a byte array, created by NodeInfo_write
pub extern "C" fn NodeInfo_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeInfoDecodeErrorZ {
	let res: Result<lightning::routing::gossip::NodeInfo, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::NodeInfo { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
#[no_mangle]
/// Serialize the NetworkGraph object into a byte array which can be read by NetworkGraph_read
pub extern "C" fn NetworkGraph_write(obj: &crate::lightning::routing::gossip::NetworkGraph) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn NetworkGraph_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNetworkGraph) })
}
#[no_mangle]
/// Read a NetworkGraph from a byte array, created by NetworkGraph_write
pub extern "C" fn NetworkGraph_read(ser: crate::c_types::u8slice, arg: crate::lightning::util::logger::Logger) -> crate::c_types::derived::CResult_NetworkGraphDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::routing::gossip::NetworkGraph { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_res
}
/// Creates a new, empty, network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_new(mut genesis_hash: crate::c_types::ThirtyTwoBytes, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::routing::gossip::NetworkGraph {
	let mut ret = lightning::routing::gossip::NetworkGraph::new(::bitcoin::hash_types::BlockHash::from_slice(&genesis_hash.data[..]).unwrap(), logger);
	crate::lightning::routing::gossip::NetworkGraph { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns a read-only view of the network graph.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_read_only(this_arg: &crate::lightning::routing::gossip::NetworkGraph) -> crate::lightning::routing::gossip::ReadOnlyNetworkGraph {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_only();
	crate::lightning::routing::gossip::ReadOnlyNetworkGraph { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// The unix timestamp provided by the most recent rapid gossip sync.
/// It will be set by the rapid sync process after every sync completion.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_get_last_rapid_gossip_sync_timestamp(this_arg: &crate::lightning::routing::gossip::NetworkGraph) -> crate::c_types::derived::COption_u32Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_last_rapid_gossip_sync_timestamp();
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { ret.unwrap() }) };
	local_ret
}

/// Update the unix timestamp provided by the most recent rapid gossip sync.
/// This should be done automatically by the rapid sync process after every sync completion.
#[no_mangle]
pub extern "C" fn NetworkGraph_set_last_rapid_gossip_sync_timestamp(this_arg: &crate::lightning::routing::gossip::NetworkGraph, mut last_rapid_gossip_sync_timestamp: u32) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.set_last_rapid_gossip_sync_timestamp(last_rapid_gossip_sync_timestamp)
}

/// For an already known node (from channel announcements), update its stored properties from a
/// given node announcement.
///
/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_node_from_announcement(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_node_from_announcement(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// For an already known node (from channel announcements), update its stored properties from a
/// given node announcement without verifying the associated signatures. Because we aren't
/// given the associated signatures here we cannot relay the node announcement to any of our
/// peers.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_node_from_unsigned_announcement(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedNodeAnnouncement) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_node_from_unsigned_announcement(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Store or update channel info from a channel announcement.
///
/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
///
/// If a `chain::Access` object is provided via `chain_access`, it will be called to verify
/// the corresponding UTXO exists on chain and is correctly-formatted.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel_from_announcement(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::ChannelAnnouncement, mut chain_access: crate::c_types::derived::COption_AccessZ) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_from_announcement(msg.get_native_ref(), &local_chain_access);
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
pub extern "C" fn NetworkGraph_update_channel_from_unsigned_announcement(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedChannelAnnouncement, mut chain_access: crate::c_types::derived::COption_AccessZ) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut local_chain_access = { /* chain_access*/ let chain_access_opt = chain_access; { } if chain_access_opt.is_none() { None } else { Some({ chain_access_opt.take() }) } };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_from_unsigned_announcement(msg.get_native_ref(), &local_chain_access);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Update channel from partial announcement data received via rapid gossip sync
///
/// `timestamp: u64`: Timestamp emulating the backdated original announcement receipt (by the
/// rapid gossip sync server)
///
/// All other parameters as used in [`msgs::UnsignedChannelAnnouncement`] fields.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_add_channel_from_partial_announcement(this_arg: &crate::lightning::routing::gossip::NetworkGraph, mut short_channel_id: u64, mut timestamp: u64, mut features: crate::lightning::ln::features::ChannelFeatures, mut node_id_1: crate::c_types::PublicKey, mut node_id_2: crate::c_types::PublicKey) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.add_channel_from_partial_announcement(short_channel_id, timestamp, *unsafe { Box::from_raw(features.take_inner()) }, node_id_1.into_rust(), node_id_2.into_rust());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Marks a channel in the graph as failed if a corresponding HTLC fail was sent.
/// If permanent, removes a channel from the local storage.
/// May cause the removal of nodes too, if this was their last channel.
/// If not permanent, makes channels unavailable for routing.
#[no_mangle]
pub extern "C" fn NetworkGraph_channel_failed(this_arg: &crate::lightning::routing::gossip::NetworkGraph, mut short_channel_id: u64, mut is_permanent: bool) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_failed(short_channel_id, is_permanent)
}

/// Marks a node in the graph as failed.
#[no_mangle]
pub extern "C" fn NetworkGraph_node_failed(this_arg: &crate::lightning::routing::gossip::NetworkGraph, mut _node_id: crate::c_types::PublicKey, mut is_permanent: bool) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.node_failed(&_node_id.into_rust(), is_permanent)
}

/// Removes information about channels that we haven't heard any updates about in some time.
/// This can be used regularly to prune the network graph of channels that likely no longer
/// exist.
///
/// While there is no formal requirement that nodes regularly re-broadcast their channel
/// updates every two weeks, the non-normative section of BOLT 7 currently suggests that
/// pruning occur for updates which are at least two weeks old, which we implement here.
///
/// Note that for users of the `lightning-background-processor` crate this method may be
/// automatically called regularly for you.
///
/// This method is only available with the `std` feature. See
/// [`NetworkGraph::remove_stale_channels_with_time`] for `no-std` use.
#[no_mangle]
pub extern "C" fn NetworkGraph_remove_stale_channels(this_arg: &crate::lightning::routing::gossip::NetworkGraph) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.remove_stale_channels()
}

/// Removes information about channels that we haven't heard any updates about in some time.
/// This can be used regularly to prune the network graph of channels that likely no longer
/// exist.
///
/// While there is no formal requirement that nodes regularly re-broadcast their channel
/// updates every two weeks, the non-normative section of BOLT 7 currently suggests that
/// pruning occur for updates which are at least two weeks old, which we implement here.
///
/// This function takes the current unix time as an argument. For users with the `std` feature
/// enabled, [`NetworkGraph::remove_stale_channels`] may be preferable.
#[no_mangle]
pub extern "C" fn NetworkGraph_remove_stale_channels_with_time(this_arg: &crate::lightning::routing::gossip::NetworkGraph, mut current_time_unix: u64) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.remove_stale_channels_with_time(current_time_unix)
}

/// For an already known (from announcement) channel, update info about one of the directions
/// of the channel.
///
/// You probably don't want to call this directly, instead relying on a P2PGossipSync's
/// RoutingMessageHandler implementation to call it indirectly. This may be useful to accept
/// routing messages from a source using a protocol other than the lightning P2P protocol.
///
/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
/// materially in the future will be rejected.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// For an already known (from announcement) channel, update info about one of the directions
/// of the channel without verifying the associated signatures. Because we aren't given the
/// associated signatures here we cannot relay the channel update to any of our peers.
///
/// If built with `no-std`, any updates with a timestamp more than two weeks in the past or
/// materially in the future will be rejected.
#[must_use]
#[no_mangle]
pub extern "C" fn NetworkGraph_update_channel_unsigned(this_arg: &crate::lightning::routing::gossip::NetworkGraph, msg: &crate::lightning::ln::msgs::UnsignedChannelUpdate) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_channel_unsigned(msg.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(e), is_owned: true } }).into() };
	local_ret
}

/// Returns information on a channel with the given id.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_channel(this_arg: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph, mut short_channel_id: u64) -> crate::lightning::routing::gossip::ChannelInfo {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel(short_channel_id);
	let mut local_ret = crate::lightning::routing::gossip::ChannelInfo { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::ChannelInfo<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Returns the list of channels in the graph
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_list_channels(this_arg: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) -> crate::c_types::derived::CVec_u64Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_channels();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}

/// Returns information on a node with the given id.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_node(this_arg: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph, node_id: &crate::lightning::routing::gossip::NodeId) -> crate::lightning::routing::gossip::NodeInfo {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.node(node_id.get_native_ref());
	let mut local_ret = crate::lightning::routing::gossip::NodeInfo { inner: unsafe { (if ret.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (ret.unwrap()) }) } as *const lightning::routing::gossip::NodeInfo<>) as *mut _ }, is_owned: false };
	local_ret
}

/// Returns the list of nodes in the graph
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_list_nodes(this_arg: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph) -> crate::c_types::derived::CVec_NodeIdZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_nodes();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::routing::gossip::NodeId { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Get network addresses by node id.
/// Returns None if the requested node is completely unknown,
/// or if node announcement for the node was never received.
#[must_use]
#[no_mangle]
pub extern "C" fn ReadOnlyNetworkGraph_get_addresses(this_arg: &crate::lightning::routing::gossip::ReadOnlyNetworkGraph, mut pubkey: crate::c_types::PublicKey) -> crate::c_types::derived::COption_CVec_NetAddressZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_addresses(&pubkey.into_rust());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_CVec_NetAddressZZ::None } else { crate::c_types::derived::COption_CVec_NetAddressZZ::Some( { let mut local_ret_0 = Vec::new(); for mut item in ret.unwrap().drain(..) { local_ret_0.push( { crate::lightning::ln::msgs::NetAddress::native_into(item) }); }; local_ret_0.into() }) };
	local_ret
}

