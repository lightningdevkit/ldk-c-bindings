// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Top level peer message handling and socket handling logic lives here.
//!
//! Instead of actually servicing sockets ourselves we require that you implement the
//! SocketDescriptor interface and use that to receive actions which you should perform on the
//! socket, and call into PeerManager with bytes read from the socket. The PeerManager will then
//! call into the provided message handlers (probably a ChannelManager and NetGraphmsgHandler) with messages
//! they should handle, and encoding/sending response messages.

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;


use lightning::ln::peer_handler::IgnoringMessageHandler as nativeIgnoringMessageHandlerImport;
type nativeIgnoringMessageHandler = nativeIgnoringMessageHandlerImport;

/// A dummy struct which implements `RoutingMessageHandler` without storing any routing information
/// or doing any processing. You can provide one of these as the route_handler in a MessageHandler.
#[must_use]
#[repr(C)]
pub struct IgnoringMessageHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeIgnoringMessageHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for IgnoringMessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeIgnoringMessageHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the IgnoringMessageHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_free(this_obj: IgnoringMessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn IgnoringMessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeIgnoringMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl IgnoringMessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeIgnoringMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new IgnoringMessageHandler given each field
#[must_use]
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_new() -> IgnoringMessageHandler {
	IgnoringMessageHandler { inner: Box::into_raw(Box::new(nativeIgnoringMessageHandler {
	})), is_owned: true }
}
impl From<nativeIgnoringMessageHandler> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeIgnoringMessageHandler) -> Self {
		let mut rust_obj = IgnoringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = IgnoringMessageHandler_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(IgnoringMessageHandler_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_as_MessageSendEventsProvider(this_arg: &IgnoringMessageHandler) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: IgnoringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn IgnoringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeIgnoringMessageHandler> for crate::lightning::ln::msgs::RoutingMessageHandler {
	fn from(obj: nativeIgnoringMessageHandler) -> Self {
		let mut rust_obj = IgnoringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = IgnoringMessageHandler_as_RoutingMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(IgnoringMessageHandler_free_void);
		ret
	}
}
/// Constructs a new RoutingMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned RoutingMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn IgnoringMessageHandler_as_RoutingMessageHandler(this_arg: &IgnoringMessageHandler) -> crate::lightning::ln::msgs::RoutingMessageHandler {
	crate::lightning::ln::msgs::RoutingMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		handle_node_announcement: IgnoringMessageHandler_RoutingMessageHandler_handle_node_announcement,
		handle_channel_announcement: IgnoringMessageHandler_RoutingMessageHandler_handle_channel_announcement,
		handle_channel_update: IgnoringMessageHandler_RoutingMessageHandler_handle_channel_update,
		handle_htlc_fail_channel_update: IgnoringMessageHandler_RoutingMessageHandler_handle_htlc_fail_channel_update,
		get_next_channel_announcements: IgnoringMessageHandler_RoutingMessageHandler_get_next_channel_announcements,
		get_next_node_announcements: IgnoringMessageHandler_RoutingMessageHandler_get_next_node_announcements,
		sync_routing_table: IgnoringMessageHandler_RoutingMessageHandler_sync_routing_table,
		handle_reply_channel_range: IgnoringMessageHandler_RoutingMessageHandler_handle_reply_channel_range,
		handle_reply_short_channel_ids_end: IgnoringMessageHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end,
		handle_query_channel_range: IgnoringMessageHandler_RoutingMessageHandler_handle_query_channel_range,
		handle_query_short_channel_ids: IgnoringMessageHandler_RoutingMessageHandler_handle_query_short_channel_ids,
		MessageSendEventsProvider: crate::lightning::util::events::MessageSendEventsProvider {
			this_arg: unsafe { (*this_arg).inner as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: IgnoringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_node_announcement(this_arg: *const c_void, _msg: &crate::lightning::ln::msgs::NodeAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_node_announcement(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_channel_announcement(this_arg: *const c_void, _msg: &crate::lightning::ln::msgs::ChannelAnnouncement) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_announcement(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_channel_update(this_arg: *const c_void, _msg: &crate::lightning::ln::msgs::ChannelUpdate) -> crate::c_types::derived::CResult_boolLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, unsafe { &*_msg.inner });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_htlc_fail_channel_update(this_arg: *const c_void, _update: &crate::lightning::ln::msgs::HTLCFailChannelUpdate) {
	<nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_htlc_fail_channel_update(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_update.to_native())
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_get_next_channel_announcements(this_arg: *const c_void, mut _starting_point: u64, mut _batch_amount: u8) -> crate::c_types::derived::CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_channel_announcements(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, _starting_point, _batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_1 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_1.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_1.unwrap()))) } }, is_owned: true }; let mut local_orig_ret_0_2 = crate::lightning::ln::msgs::ChannelUpdate { inner: if orig_ret_0_2.is_none() { std::ptr::null_mut() } else {  { Box::into_raw(Box::new((orig_ret_0_2.unwrap()))) } }, is_owned: true }; let mut local_ret_0 = (crate::lightning::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(orig_ret_0_0)), is_owned: true }, local_orig_ret_0_1, local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_get_next_node_announcements(this_arg: *const c_void, mut _starting_point: crate::c_types::PublicKey, mut _batch_amount: u8) -> crate::c_types::derived::CVec_NodeAnnouncementZ {
	let mut local__starting_point_base = if _starting_point.is_null() { None } else { Some( { _starting_point.into_rust() }) }; let mut local__starting_point = local__starting_point_base.as_ref();
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::get_next_node_announcements(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, local__starting_point, _batch_amount);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(item)), is_owned: true } }); };
	local_ret.into()
}
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_sync_routing_table(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _init: &crate::lightning::ln::msgs::Init) {
	<nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::sync_routing_table(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_init.inner })
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_reply_channel_range(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::lightning::ln::msgs::ReplyChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_channel_range(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_reply_short_channel_ids_end(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::lightning::ln::msgs::ReplyShortChannelIdsEnd) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_reply_short_channel_ids_end(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_query_channel_range(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::lightning::ln::msgs::QueryChannelRange) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_channel_range(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}
#[must_use]
extern "C" fn IgnoringMessageHandler_RoutingMessageHandler_handle_query_short_channel_ids(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _msg: crate::lightning::ln::msgs::QueryShortChannelIds) -> crate::c_types::derived::CResult_NoneLightningErrorZ {
	let mut ret = <nativeIgnoringMessageHandler as lightning::ln::msgs::RoutingMessageHandler<>>::handle_query_short_channel_ids(unsafe { &mut *(this_arg as *mut nativeIgnoringMessageHandler) }, &_their_node_id.into_rust(), *unsafe { Box::from_raw(_msg.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::LightningError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}


use lightning::ln::peer_handler::ErroringMessageHandler as nativeErroringMessageHandlerImport;
type nativeErroringMessageHandler = nativeErroringMessageHandlerImport;

/// A dummy struct which implements `ChannelMessageHandler` without having any channels.
/// You can provide one of these as the route_handler in a MessageHandler.
#[must_use]
#[repr(C)]
pub struct ErroringMessageHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeErroringMessageHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ErroringMessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeErroringMessageHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the ErroringMessageHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_free(this_obj: ErroringMessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn ErroringMessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeErroringMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl ErroringMessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeErroringMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new ErroringMessageHandler
#[must_use]
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_new() -> ErroringMessageHandler {
	let mut ret = lightning::ln::peer_handler::ErroringMessageHandler::new();
	ErroringMessageHandler { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

impl From<nativeErroringMessageHandler> for crate::lightning::util::events::MessageSendEventsProvider {
	fn from(obj: nativeErroringMessageHandler) -> Self {
		let mut rust_obj = ErroringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ErroringMessageHandler_as_MessageSendEventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ErroringMessageHandler_free_void);
		ret
	}
}
/// Constructs a new MessageSendEventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned MessageSendEventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_as_MessageSendEventsProvider(this_arg: &ErroringMessageHandler) -> crate::lightning::util::events::MessageSendEventsProvider {
	crate::lightning::util::events::MessageSendEventsProvider {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		get_and_clear_pending_msg_events: ErroringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
	}
}

#[must_use]
extern "C" fn ErroringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ {
	let mut ret = <nativeErroringMessageHandler as lightning::util::events::MessageSendEventsProvider<>>::get_and_clear_pending_msg_events(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::util::events::MessageSendEvent::native_into(item) }); };
	local_ret.into()
}

impl From<nativeErroringMessageHandler> for crate::lightning::ln::msgs::ChannelMessageHandler {
	fn from(obj: nativeErroringMessageHandler) -> Self {
		let mut rust_obj = ErroringMessageHandler { inner: Box::into_raw(Box::new(obj)), is_owned: true };
		let mut ret = ErroringMessageHandler_as_ChannelMessageHandler(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = std::ptr::null_mut();
		ret.free = Some(ErroringMessageHandler_free_void);
		ret
	}
}
/// Constructs a new ChannelMessageHandler which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ChannelMessageHandler must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ErroringMessageHandler_as_ChannelMessageHandler(this_arg: &ErroringMessageHandler) -> crate::lightning::ln::msgs::ChannelMessageHandler {
	crate::lightning::ln::msgs::ChannelMessageHandler {
		this_arg: unsafe { (*this_arg).inner as *mut c_void },
		free: None,
		handle_open_channel: ErroringMessageHandler_ChannelMessageHandler_handle_open_channel,
		handle_accept_channel: ErroringMessageHandler_ChannelMessageHandler_handle_accept_channel,
		handle_funding_created: ErroringMessageHandler_ChannelMessageHandler_handle_funding_created,
		handle_funding_signed: ErroringMessageHandler_ChannelMessageHandler_handle_funding_signed,
		handle_funding_locked: ErroringMessageHandler_ChannelMessageHandler_handle_funding_locked,
		handle_shutdown: ErroringMessageHandler_ChannelMessageHandler_handle_shutdown,
		handle_closing_signed: ErroringMessageHandler_ChannelMessageHandler_handle_closing_signed,
		handle_update_add_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_add_htlc,
		handle_update_fulfill_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fulfill_htlc,
		handle_update_fail_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_htlc,
		handle_update_fail_malformed_htlc: ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_malformed_htlc,
		handle_commitment_signed: ErroringMessageHandler_ChannelMessageHandler_handle_commitment_signed,
		handle_revoke_and_ack: ErroringMessageHandler_ChannelMessageHandler_handle_revoke_and_ack,
		handle_update_fee: ErroringMessageHandler_ChannelMessageHandler_handle_update_fee,
		handle_announcement_signatures: ErroringMessageHandler_ChannelMessageHandler_handle_announcement_signatures,
		peer_disconnected: ErroringMessageHandler_ChannelMessageHandler_peer_disconnected,
		peer_connected: ErroringMessageHandler_ChannelMessageHandler_peer_connected,
		handle_channel_reestablish: ErroringMessageHandler_ChannelMessageHandler_handle_channel_reestablish,
		handle_channel_update: ErroringMessageHandler_ChannelMessageHandler_handle_channel_update,
		handle_error: ErroringMessageHandler_ChannelMessageHandler_handle_error,
		MessageSendEventsProvider: crate::lightning::util::events::MessageSendEventsProvider {
			this_arg: unsafe { (*this_arg).inner as *mut c_void },
			free: None,
			get_and_clear_pending_msg_events: ErroringMessageHandler_MessageSendEventsProvider_get_and_clear_pending_msg_events,
		},
	}
}

extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_open_channel(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut _their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::OpenChannel) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_open_channel(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(_their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_accept_channel(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, mut _their_features: crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::AcceptChannel) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_accept_channel(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), *unsafe { Box::from_raw(_their_features.take_inner()) }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_created(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingCreated) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_created(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_funding_locked(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::FundingLocked) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_funding_locked(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_shutdown(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, _their_features: &crate::lightning::ln::features::InitFeatures, msg: &crate::lightning::ln::msgs::Shutdown) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_shutdown(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*_their_features.inner }, unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_closing_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ClosingSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_closing_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_add_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateAddHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_add_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fulfill_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFulfillHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fulfill_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fail_malformed_htlc(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFailMalformedHTLC) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fail_malformed_htlc(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_commitment_signed(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::CommitmentSigned) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_commitment_signed(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_revoke_and_ack(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::RevokeAndACK) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_revoke_and_ack(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_update_fee(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::UpdateFee) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_update_fee(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_announcement_signatures(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::AnnouncementSignatures) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_announcement_signatures(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_channel_reestablish(this_arg: *const c_void, mut their_node_id: crate::c_types::PublicKey, msg: &crate::lightning::ln::msgs::ChannelReestablish) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_reestablish(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &their_node_id.into_rust(), unsafe { &*msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_channel_update(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _msg: &crate::lightning::ln::msgs::ChannelUpdate) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_channel_update(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_peer_disconnected(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, mut _no_connection_possible: bool) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::peer_disconnected(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), _no_connection_possible)
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_peer_connected(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _msg: &crate::lightning::ln::msgs::Init) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::peer_connected(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_msg.inner })
}
extern "C" fn ErroringMessageHandler_ChannelMessageHandler_handle_error(this_arg: *const c_void, mut _their_node_id: crate::c_types::PublicKey, _msg: &crate::lightning::ln::msgs::ErrorMessage) {
	<nativeErroringMessageHandler as lightning::ln::msgs::ChannelMessageHandler<>>::handle_error(unsafe { &mut *(this_arg as *mut nativeErroringMessageHandler) }, &_their_node_id.into_rust(), unsafe { &*_msg.inner })
}


use lightning::ln::peer_handler::MessageHandler as nativeMessageHandlerImport;
type nativeMessageHandler = nativeMessageHandlerImport<crate::lightning::ln::msgs::ChannelMessageHandler, crate::lightning::ln::msgs::RoutingMessageHandler>;

/// Provides references to trait impls which handle different types of messages.
#[must_use]
#[repr(C)]
pub struct MessageHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMessageHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MessageHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMessageHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the MessageHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MessageHandler_free(this_obj: MessageHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn MessageHandler_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeMessageHandler); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl MessageHandler {
	pub(crate) fn take_inner(mut self) -> *mut nativeMessageHandler {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// A message handler which handles messages specific to channels. Usually this is just a
/// [`ChannelManager`] object or an [`ErroringMessageHandler`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
#[no_mangle]
pub extern "C" fn MessageHandler_get_chan_handler(this_ptr: &MessageHandler) -> *const crate::lightning::ln::msgs::ChannelMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.chan_handler;
	inner_val
}
/// A message handler which handles messages specific to channels. Usually this is just a
/// [`ChannelManager`] object or an [`ErroringMessageHandler`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
#[no_mangle]
pub extern "C" fn MessageHandler_set_chan_handler(this_ptr: &mut MessageHandler, mut val: crate::lightning::ln::msgs::ChannelMessageHandler) {
	unsafe { &mut *this_ptr.inner }.chan_handler = val;
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a [`NetGraphMsgHandler`] object or an
/// [`IgnoringMessageHandler`].
///
/// [`NetGraphMsgHandler`]: crate::routing::network_graph::NetGraphMsgHandler
#[no_mangle]
pub extern "C" fn MessageHandler_get_route_handler(this_ptr: &MessageHandler) -> *const crate::lightning::ln::msgs::RoutingMessageHandler {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.route_handler;
	inner_val
}
/// A message handler which handles messages updating our knowledge of the network channel
/// graph. Usually this is just a [`NetGraphMsgHandler`] object or an
/// [`IgnoringMessageHandler`].
///
/// [`NetGraphMsgHandler`]: crate::routing::network_graph::NetGraphMsgHandler
#[no_mangle]
pub extern "C" fn MessageHandler_set_route_handler(this_ptr: &mut MessageHandler, mut val: crate::lightning::ln::msgs::RoutingMessageHandler) {
	unsafe { &mut *this_ptr.inner }.route_handler = val;
}
/// Constructs a new MessageHandler given each field
#[must_use]
#[no_mangle]
pub extern "C" fn MessageHandler_new(mut chan_handler_arg: crate::lightning::ln::msgs::ChannelMessageHandler, mut route_handler_arg: crate::lightning::ln::msgs::RoutingMessageHandler) -> MessageHandler {
	MessageHandler { inner: Box::into_raw(Box::new(nativeMessageHandler {
		chan_handler: chan_handler_arg,
		route_handler: route_handler_arg,
	})), is_owned: true }
}
/// Provides an object which can be used to send data to and which uniquely identifies a connection
/// to a remote host. You will need to be able to generate multiple of these which meet Eq and
/// implement Hash to meet the PeerManager API.
///
/// For efficiency, Clone should be relatively cheap for this type.
///
/// Two descriptors may compare equal (by [`cmp::Eq`] and [`hash::Hash`]) as long as the original
/// has been disconnected, the [`PeerManager`] has been informed of the disconnection (either by it
/// having triggered the disconnection or a call to [`PeerManager::socket_disconnected`]), and no
/// further calls to the [`PeerManager`] related to the original socket occur. This allows you to
/// use a file descriptor for your SocketDescriptor directly, however for simplicity you may wish
/// to simply use another value which is guaranteed to be globally unique instead.
#[repr(C)]
pub struct SocketDescriptor {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Attempts to send some data from the given slice to the peer.
	///
	/// Returns the amount of data which was sent, possibly 0 if the socket has since disconnected.
	/// Note that in the disconnected case, [`PeerManager::socket_disconnected`] must still be
	/// called and further write attempts may occur until that time.
	///
	/// If the returned size is smaller than `data.len()`, a
	/// [`PeerManager::write_buffer_space_avail`] call must be made the next time more data can be
	/// written. Additionally, until a `send_data` event completes fully, no further
	/// [`PeerManager::read_event`] calls should be made for the same peer! Because this is to
	/// prevent denial-of-service issues, you should not read or buffer any data from the socket
	/// until then.
	///
	/// If a [`PeerManager::read_event`] call on this descriptor had previously returned true
	/// (indicating that read events should be paused to prevent DoS in the send buffer),
	/// `resume_read` may be set indicating that read events on this descriptor should resume. A
	/// `resume_read` of false carries no meaning, and should not cause any action.
	#[must_use]
	pub send_data: extern "C" fn (this_arg: *mut c_void, data: crate::c_types::u8slice, resume_read: bool) -> usize,
	/// Disconnect the socket pointed to by this SocketDescriptor.
	///
	/// You do *not* need to call [`PeerManager::socket_disconnected`] with this socket after this
	/// call (doing so is a noop).
	pub disconnect_socket: extern "C" fn (this_arg: *mut c_void),
	/// Checks if two objects are equal given this object's this_arg pointer and another object.
	pub eq: extern "C" fn (this_arg: *const c_void, other_arg: &SocketDescriptor) -> bool,
	/// Calculate a succinct non-cryptographic hash for an object given its this_arg pointer.
	/// This is used, for example, for inclusion of this object in a hash map.
	pub hash: extern "C" fn (this_arg: *const c_void) -> u64,
	/// Creates a copy of the object pointed to by this_arg, for a copy of this SocketDescriptor.
	/// Note that the ultimate copy of the SocketDescriptor will have all function pointers the same as the original.
	/// May be NULL if no action needs to be taken, the this_arg pointer will be copied into the new SocketDescriptor.
	pub clone: Option<extern "C" fn (this_arg: *const c_void) -> *mut c_void>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for SocketDescriptor {}
unsafe impl Sync for SocketDescriptor {}
impl std::cmp::Eq for SocketDescriptor {}
impl std::cmp::PartialEq for SocketDescriptor {
	fn eq(&self, o: &Self) -> bool { (self.eq)(self.this_arg, o) }
}
impl std::hash::Hash for SocketDescriptor {
	fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) { hasher.write_u64((self.hash)(self.this_arg)) }
}
#[no_mangle]
/// Creates a copy of a SocketDescriptor
pub extern "C" fn SocketDescriptor_clone(orig: &SocketDescriptor) -> SocketDescriptor {
	SocketDescriptor {
		this_arg: if let Some(f) = orig.clone { (f)(orig.this_arg) } else { orig.this_arg },
		send_data: Clone::clone(&orig.send_data),
		disconnect_socket: Clone::clone(&orig.disconnect_socket),
		eq: Clone::clone(&orig.eq),
		hash: Clone::clone(&orig.hash),
		clone: Clone::clone(&orig.clone),
		free: Clone::clone(&orig.free),
	}
}
impl Clone for SocketDescriptor {
	fn clone(&self) -> Self {
		SocketDescriptor_clone(self)
	}
}

use lightning::ln::peer_handler::SocketDescriptor as rustSocketDescriptor;
impl rustSocketDescriptor for SocketDescriptor {
	fn send_data(&mut self, mut data: &[u8], mut resume_read: bool) -> usize {
		let mut local_data = crate::c_types::u8slice::from_slice(data);
		let mut ret = (self.send_data)(self.this_arg, local_data, resume_read);
		ret
	}
	fn disconnect_socket(&mut self) {
		(self.disconnect_socket)(self.this_arg)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for SocketDescriptor {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SocketDescriptor_free(this_ptr: SocketDescriptor) { }
impl Drop for SocketDescriptor {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::ln::peer_handler::PeerHandleError as nativePeerHandleErrorImport;
type nativePeerHandleError = nativePeerHandleErrorImport;

/// Error for PeerManager errors. If you get one of these, you must disconnect the socket and
/// generate no further read_event/write_buffer_space_avail/socket_disconnected calls for the
/// descriptor.
#[must_use]
#[repr(C)]
pub struct PeerHandleError {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePeerHandleError,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PeerHandleError {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePeerHandleError>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the PeerHandleError, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PeerHandleError_free(this_obj: PeerHandleError) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PeerHandleError_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePeerHandleError); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PeerHandleError {
	pub(crate) fn take_inner(mut self) -> *mut nativePeerHandleError {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Used to indicate that we probably can't make any future connections to this peer, implying
/// we should go ahead and force-close any channels we have with it.
#[no_mangle]
pub extern "C" fn PeerHandleError_get_no_connection_possible(this_ptr: &PeerHandleError) -> bool {
	let mut inner_val = &mut unsafe { &mut *this_ptr.inner }.no_connection_possible;
	*inner_val
}
/// Used to indicate that we probably can't make any future connections to this peer, implying
/// we should go ahead and force-close any channels we have with it.
#[no_mangle]
pub extern "C" fn PeerHandleError_set_no_connection_possible(this_ptr: &mut PeerHandleError, mut val: bool) {
	unsafe { &mut *this_ptr.inner }.no_connection_possible = val;
}
/// Constructs a new PeerHandleError given each field
#[must_use]
#[no_mangle]
pub extern "C" fn PeerHandleError_new(mut no_connection_possible_arg: bool) -> PeerHandleError {
	PeerHandleError { inner: Box::into_raw(Box::new(nativePeerHandleError {
		no_connection_possible: no_connection_possible_arg,
	})), is_owned: true }
}
impl Clone for PeerHandleError {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativePeerHandleError>::is_null(self.inner) { std::ptr::null_mut() } else {
				Box::into_raw(Box::new(unsafe { &*self.inner }.clone())) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PeerHandleError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativePeerHandleError)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the PeerHandleError
pub extern "C" fn PeerHandleError_clone(orig: &PeerHandleError) -> PeerHandleError {
	orig.clone()
}

use lightning::ln::peer_handler::PeerManager as nativePeerManagerImport;
type nativePeerManager = nativePeerManagerImport<crate::lightning::ln::peer_handler::SocketDescriptor, crate::lightning::ln::msgs::ChannelMessageHandler, crate::lightning::ln::msgs::RoutingMessageHandler, crate::lightning::util::logger::Logger>;

/// A PeerManager manages a set of peers, described by their [`SocketDescriptor`] and marshalls
/// socket events into messages which it passes on to its [`MessageHandler`].
///
/// Locks are taken internally, so you must never assume that reentrancy from a
/// [`SocketDescriptor`] call back into [`PeerManager`] methods will not deadlock.
///
/// Calls to [`read_event`] will decode relevant messages and pass them to the
/// [`ChannelMessageHandler`], likely doing message processing in-line. Thus, the primary form of
/// parallelism in Rust-Lightning is in calls to [`read_event`]. Note, however, that calls to any
/// [`PeerManager`] functions related to the same connection must occur only in serial, making new
/// calls only after previous ones have returned.
///
/// Rather than using a plain PeerManager, it is preferable to use either a SimpleArcPeerManager
/// a SimpleRefPeerManager, for conciseness. See their documentation for more details, but
/// essentially you should default to using a SimpleRefPeerManager, and use a
/// SimpleArcPeerManager when you require a PeerManager with a static lifetime, such as when
/// you're using lightning-net-tokio.
///
/// [`read_event`]: PeerManager::read_event
#[must_use]
#[repr(C)]
pub struct PeerManager {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePeerManager,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PeerManager {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePeerManager>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(self.inner) };
		}
	}
}
/// Frees any resources used by the PeerManager, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PeerManager_free(this_obj: PeerManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
extern "C" fn PeerManager_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativePeerManager); }
}
#[allow(unused)]
/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
impl PeerManager {
	pub(crate) fn take_inner(mut self) -> *mut nativePeerManager {
		assert!(self.is_owned);
		let ret = self.inner;
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new PeerManager with the given message handlers and node_id secret key
/// ephemeral_random_data is used to derive per-connection ephemeral keys and must be
/// cryptographically secure random bytes.
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new(mut message_handler: crate::lightning::ln::peer_handler::MessageHandler, mut our_node_secret: crate::c_types::SecretKey, ephemeral_random_data: *const [u8; 32], mut logger: crate::lightning::util::logger::Logger) -> PeerManager {
	let mut ret = lightning::ln::peer_handler::PeerManager::new(*unsafe { Box::from_raw(message_handler.take_inner()) }, our_node_secret.into_rust(), unsafe { &*ephemeral_random_data}, logger);
	PeerManager { inner: Box::into_raw(Box::new(ret)), is_owned: true }
}

/// Get the list of node ids for peers which have completed the initial handshake.
///
/// For outbound connections, this will be the same as the their_node_id parameter passed in to
/// new_outbound_connection, however entries will only appear once the initial handshake has
/// completed and we are sure the remote peer has the private key for the given node_id.
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_get_peer_node_ids(this_arg: &PeerManager) -> crate::c_types::derived::CVec_PublicKeyZ {
	let mut ret = unsafe { &*this_arg.inner }.get_peer_node_ids();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::c_types::PublicKey::from_rust(&item) }); };
	local_ret.into()
}

/// Indicates a new outbound connection has been established to a node with the given node_id.
/// Note that if an Err is returned here you MUST NOT call socket_disconnected for the new
/// descriptor but must disconnect the connection immediately.
///
/// Returns a small number of bytes to send to the remote node (currently always 50).
///
/// Panics if descriptor is duplicative with some other descriptor which has not yet been
/// [`socket_disconnected()`].
///
/// [`socket_disconnected()`]: PeerManager::socket_disconnected
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new_outbound_connection(this_arg: &PeerManager, mut their_node_id: crate::c_types::PublicKey, mut descriptor: crate::lightning::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_CVec_u8ZPeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.new_outbound_connection(their_node_id.into_rust(), descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { item }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Indicates a new inbound connection has been established.
///
/// May refuse the connection by returning an Err, but will never write bytes to the remote end
/// (outbound connector always speaks first). Note that if an Err is returned here you MUST NOT
/// call socket_disconnected for the new descriptor but must disconnect the connection
/// immediately.
///
/// Panics if descriptor is duplicative with some other descriptor which has not yet been
/// [`socket_disconnected()`].
///
/// [`socket_disconnected()`]: PeerManager::socket_disconnected
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_new_inbound_connection(this_arg: &PeerManager, mut descriptor: crate::lightning::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_NonePeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.new_inbound_connection(descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Indicates that there is room to write data to the given socket descriptor.
///
/// May return an Err to indicate that the connection should be closed.
///
/// May call [`send_data`] on the descriptor passed in (or an equal descriptor) before
/// returning. Thus, be very careful with reentrancy issues! The invariants around calling
/// [`write_buffer_space_avail`] in case a write did not fully complete must still hold - be
/// ready to call `[write_buffer_space_avail`] again if a write call generated here isn't
/// sufficient!
///
/// [`send_data`]: SocketDescriptor::send_data
/// [`write_buffer_space_avail`]: PeerManager::write_buffer_space_avail
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_write_buffer_space_avail(this_arg: &PeerManager, descriptor: &mut crate::lightning::ln::peer_handler::SocketDescriptor) -> crate::c_types::derived::CResult_NonePeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.write_buffer_space_avail(descriptor);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Indicates that data was read from the given socket descriptor.
///
/// May return an Err to indicate that the connection should be closed.
///
/// Will *not* call back into [`send_data`] on any descriptors to avoid reentrancy complexity.
/// Thus, however, you should call [`process_events`] after any `read_event` to generate
/// [`send_data`] calls to handle responses.
///
/// If `Ok(true)` is returned, further read_events should not be triggered until a
/// [`send_data`] call on this descriptor has `resume_read` set (preventing DoS issues in the
/// send buffer).
///
/// [`send_data`]: SocketDescriptor::send_data
/// [`process_events`]: PeerManager::process_events
#[must_use]
#[no_mangle]
pub extern "C" fn PeerManager_read_event(this_arg: &PeerManager, peer_descriptor: &mut crate::lightning::ln::peer_handler::SocketDescriptor, mut data: crate::c_types::u8slice) -> crate::c_types::derived::CResult_boolPeerHandleErrorZ {
	let mut ret = unsafe { &*this_arg.inner }.read_event(peer_descriptor, data.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::peer_handler::PeerHandleError { inner: Box::into_raw(Box::new(e)), is_owned: true } }).into() };
	local_ret
}

/// Checks for any events generated by our handlers and processes them. Includes sending most
/// response messages as well as messages generated by calls to handler functions directly (eg
/// functions like [`ChannelManager::process_pending_htlc_forwards`] or [`send_payment`]).
///
/// May call [`send_data`] on [`SocketDescriptor`]s. Thus, be very careful with reentrancy
/// issues!
///
/// [`send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::process_pending_htlc_forwards`]: crate::ln::channelmanager::ChannelManager::process_pending_htlc_forwards
/// [`send_data`]: SocketDescriptor::send_data
#[no_mangle]
pub extern "C" fn PeerManager_process_events(this_arg: &PeerManager) {
	unsafe { &*this_arg.inner }.process_events()
}

/// Indicates that the given socket descriptor's connection is now closed.
#[no_mangle]
pub extern "C" fn PeerManager_socket_disconnected(this_arg: &PeerManager, descriptor: &crate::lightning::ln::peer_handler::SocketDescriptor) {
	unsafe { &*this_arg.inner }.socket_disconnected(descriptor)
}

/// Disconnect a peer given its node id.
///
/// Set `no_connection_possible` to true to prevent any further connection with this peer,
/// force-closing any channels we have with it.
///
/// If a peer is connected, this will call [`disconnect_socket`] on the descriptor for the
/// peer. Thus, be very careful about reentrancy issues.
///
/// [`disconnect_socket`]: SocketDescriptor::disconnect_socket
#[no_mangle]
pub extern "C" fn PeerManager_disconnect_by_node_id(this_arg: &PeerManager, mut node_id: crate::c_types::PublicKey, mut no_connection_possible: bool) {
	unsafe { &*this_arg.inner }.disconnect_by_node_id(node_id.into_rust(), no_connection_possible)
}

/// This function should be called roughly once every 30 seconds.
/// It will send pings to each peer and disconnect those which did not respond to the last
/// round of pings.
///
/// May call [`send_data`] on all [`SocketDescriptor`]s. Thus, be very careful with reentrancy
/// issues!
///
/// [`send_data`]: SocketDescriptor::send_data
#[no_mangle]
pub extern "C" fn PeerManager_timer_tick_occurred(this_arg: &PeerManager) {
	unsafe { &*this_arg.inner }.timer_tick_occurred()
}

