// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Events are returned from various bits in the library which indicate some action must be taken
//! by the client.
//!
//! Because we don't have a built-in runtime, it's up to the client to call events at a time in the
//! future, as well as generate and broadcast funding transactions handle payment preimages and a
//! few other things.

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call ChannelManager::funding_transaction_generated.
	/// Generated in ChannelManager message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// ChannelManager::funding_transaction_generated.
		temporary_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: crate::c_types::derived::CVec_u8Z,
		/// The value passed in to ChannelManager::create_channel
		user_channel_id: u64,
	},
	/// Indicates we've received money! Just gotta dig out that payment preimage and feed it to
	/// ChannelManager::claim_funds to get it....
	/// Note that if the preimage is not known or the amount paid is incorrect, you should call
	/// ChannelManager::fail_htlc_backwards to free up resources for this HTLC and avoid
	/// network congestion.
	/// The amount paid should be considered 'incorrect' when it is less than or more than twice
	/// the amount expected.
	/// If you fail to call either ChannelManager::claim_funds or
	/// ChannelManager::fail_htlc_backwards within the HTLC's timeout, the HTLC will be
	/// automatically failed.
	PaymentReceived {
		/// The hash for which the preimage should be handed to the ChannelManager.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. If provided, this can be handed directly to
		/// [`ChannelManager::claim_funds`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		payment_preimage: crate::c_types::ThirtyTwoBytes,
		/// The \"payment secret\". This authenticates the sender to the recipient, preventing a
		/// number of deanonymization attacks during the routing process.
		/// It is provided here for your reference, however its accuracy is enforced directly by
		/// [`ChannelManager`] using the values you previously provided to
		/// [`ChannelManager::create_inbound_payment`] or
		/// [`ChannelManager::create_inbound_payment_for_hash`].
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		payment_secret: crate::c_types::ThirtyTwoBytes,
		/// The value, in thousandths of a satoshi, that this payment is for. Note that you must
		/// compare this to the expected value before accepting the payment (as otherwise you are
		/// providing proof-of-payment for less than the value you expected!).
		amt: u64,
		/// This is the `user_payment_id` which was provided to
		/// [`ChannelManager::create_inbound_payment_for_hash`] or
		/// [`ChannelManager::create_inbound_payment`]. It has no meaning inside of LDK and is
		/// simply copied here. It may be used to correlate PaymentReceived events with invoice
		/// metadata stored elsewhere.
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::create_inbound_payment_for_hash`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
		user_payment_id: u64,
	},
	/// Indicates an outbound payment we made succeeded (ie it made it all the way to its target
	/// and we got back the payment preimage for it).
	PaymentSent {
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: crate::c_types::ThirtyTwoBytes,
	},
	/// Indicates an outbound payment we made failed. Probably some intermediary node dropped
	/// something. You may wish to retry with a different route.
	PaymentFailed {
		/// The hash which was given to ChannelManager::send_payment.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, you may
		/// retry the payment via a different route.
		rejected_by_dest: bool,
	},
	/// Used to indicate that ChannelManager::process_pending_htlc_forwards should be called at a
	/// time in the future.
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: u64,
	},
	/// Used to indicate that an output which you should know how to spend was confirmed on chain
	/// and is now spendable.
	/// Such an output will *not* ever be spent by rust-lightning, and are not at risk of your
	/// counterparty spending them due to some kind of timeout. Thus, you need to store them
	/// somewhere and spend them when you create on-chain transactions.
	SpendableOutputs {
		/// The outputs which you should store as spendable by you.
		outputs: crate::c_types::derived::CVec_SpendableOutputDescriptorZ,
	},
}
use lightning::util::events::Event as nativeEvent;
impl Event {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {ref temporary_channel_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = (*temporary_channel_id).clone();
				let mut channel_value_satoshis_nonref = (*channel_value_satoshis).clone();
				let mut output_script_nonref = (*output_script).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id_nonref.data,
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script_nonref.into_rust()),
					user_channel_id: user_channel_id_nonref,
				}
			},
			Event::PaymentReceived {ref payment_hash, ref payment_preimage, ref payment_secret, ref amt, ref user_payment_id, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentPreimage(payment_preimage_nonref.data) }) };
				let mut payment_secret_nonref = (*payment_secret).clone();
				let mut amt_nonref = (*amt).clone();
				let mut user_payment_id_nonref = (*user_payment_id).clone();
				nativeEvent::PaymentReceived {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: ::lightning::ln::PaymentSecret(payment_secret_nonref.data),
					amt: amt_nonref,
					user_payment_id: user_payment_id_nonref,
				}
			},
			Event::PaymentSent {ref payment_preimage, } => {
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				nativeEvent::PaymentSent {
					payment_preimage: ::lightning::ln::PaymentPreimage(payment_preimage_nonref.data),
				}
			},
			Event::PaymentFailed {ref payment_hash, ref rejected_by_dest, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut rejected_by_dest_nonref = (*rejected_by_dest).clone();
				nativeEvent::PaymentFailed {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					rejected_by_dest: rejected_by_dest_nonref,
				}
			},
			Event::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = (*time_forwardable).clone();
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: std::time::Duration::from_secs(time_forwardable_nonref),
				}
			},
			Event::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = (*outputs).clone();
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.into_rust().drain(..) { local_outputs_nonref.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {mut temporary_channel_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id.data,
					channel_value_satoshis: channel_value_satoshis,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script.into_rust()),
					user_channel_id: user_channel_id,
				}
			},
			Event::PaymentReceived {mut payment_hash, mut payment_preimage, mut payment_secret, mut amt, mut user_payment_id, } => {
				let mut local_payment_preimage = if payment_preimage.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentPreimage(payment_preimage.data) }) };
				nativeEvent::PaymentReceived {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					payment_preimage: local_payment_preimage,
					payment_secret: ::lightning::ln::PaymentSecret(payment_secret.data),
					amt: amt,
					user_payment_id: user_payment_id,
				}
			},
			Event::PaymentSent {mut payment_preimage, } => {
				nativeEvent::PaymentSent {
					payment_preimage: ::lightning::ln::PaymentPreimage(payment_preimage.data),
				}
			},
			Event::PaymentFailed {mut payment_hash, mut rejected_by_dest, } => {
				nativeEvent::PaymentFailed {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					rejected_by_dest: rejected_by_dest,
				}
			},
			Event::PendingHTLCsForwardable {mut time_forwardable, } => {
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: std::time::Duration::from_secs(time_forwardable),
				}
			},
			Event::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {ref temporary_channel_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = (*temporary_channel_id).clone();
				let mut channel_value_satoshis_nonref = (*channel_value_satoshis).clone();
				let mut output_script_nonref = (*output_script).clone();
				let mut user_channel_id_nonref = (*user_channel_id).clone();
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id_nonref },
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: output_script_nonref.into_bytes().into(),
					user_channel_id: user_channel_id_nonref,
				}
			},
			nativeEvent::PaymentReceived {ref payment_hash, ref payment_preimage, ref payment_secret, ref amt, ref user_payment_id, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_preimage_nonref.unwrap()).0 } } };
				let mut payment_secret_nonref = (*payment_secret).clone();
				let mut amt_nonref = (*amt).clone();
				let mut user_payment_id_nonref = (*user_payment_id).clone();
				Event::PaymentReceived {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret_nonref.0 },
					amt: amt_nonref,
					user_payment_id: user_payment_id_nonref,
				}
			},
			nativeEvent::PaymentSent {ref payment_preimage, } => {
				let mut payment_preimage_nonref = (*payment_preimage).clone();
				Event::PaymentSent {
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.0 },
				}
			},
			nativeEvent::PaymentFailed {ref payment_hash, ref rejected_by_dest, } => {
				let mut payment_hash_nonref = (*payment_hash).clone();
				let mut rejected_by_dest_nonref = (*rejected_by_dest).clone();
				Event::PaymentFailed {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					rejected_by_dest: rejected_by_dest_nonref,
				}
			},
			nativeEvent::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = (*time_forwardable).clone();
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable_nonref.as_secs(),
				}
			},
			nativeEvent::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = (*outputs).clone();
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.drain(..) { local_outputs_nonref.push( { crate::lightning::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs_nonref.into(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {mut temporary_channel_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id },
					channel_value_satoshis: channel_value_satoshis,
					output_script: output_script.into_bytes().into(),
					user_channel_id: user_channel_id,
				}
			},
			nativeEvent::PaymentReceived {mut payment_hash, mut payment_preimage, mut payment_secret, mut amt, mut user_payment_id, } => {
				let mut local_payment_preimage = if payment_preimage.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_preimage.unwrap()).0 } } };
				Event::PaymentReceived {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					payment_preimage: local_payment_preimage,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret.0 },
					amt: amt,
					user_payment_id: user_payment_id,
				}
			},
			nativeEvent::PaymentSent {mut payment_preimage, } => {
				Event::PaymentSent {
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage.0 },
				}
			},
			nativeEvent::PaymentFailed {mut payment_hash, mut rejected_by_dest, } => {
				Event::PaymentFailed {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					rejected_by_dest: rejected_by_dest,
				}
			},
			nativeEvent::PendingHTLCsForwardable {mut time_forwardable, } => {
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable.as_secs(),
				}
			},
			nativeEvent::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.drain(..) { local_outputs.push( { crate::lightning::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs.into(),
				}
			},
		}
	}
}
/// Frees any resources used by the Event
#[no_mangle]
pub extern "C" fn Event_free(this_ptr: Event) { }
/// Creates a copy of the Event
#[no_mangle]
pub extern "C" fn Event_clone(orig: &Event) -> Event {
	orig.clone()
}
#[no_mangle]
/// Serialize the Event object into a byte array which can be read by Event_read
pub extern "C" fn Event_write(obj: &Event) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum MessageSendEvent {
	/// Used to indicate that we've accepted a channel open and should send the accept_channel
	/// message provided to the given peer.
	SendAcceptChannel {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::AcceptChannel,
	},
	/// Used to indicate that we've initiated a channel open and should send the open_channel
	/// message provided to the given peer.
	SendOpenChannel {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::OpenChannel,
	},
	/// Used to indicate that a funding_created message should be sent to the peer with the given node_id.
	SendFundingCreated {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::FundingCreated,
	},
	/// Used to indicate that a funding_signed message should be sent to the peer with the given node_id.
	SendFundingSigned {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::FundingSigned,
	},
	/// Used to indicate that a funding_locked message should be sent to the peer with the given node_id.
	SendFundingLocked {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The funding_locked message which should be sent.
		msg: crate::lightning::ln::msgs::FundingLocked,
	},
	/// Used to indicate that an announcement_signatures message should be sent to the peer with the given node_id.
	SendAnnouncementSignatures {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The announcement_signatures message which should be sent.
		msg: crate::lightning::ln::msgs::AnnouncementSignatures,
	},
	/// Used to indicate that a series of HTLC update messages, as well as a commitment_signed
	/// message should be sent to the peer with the given node_id.
	UpdateHTLCs {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The update messages which should be sent. ALL messages in the struct should be sent!
		updates: crate::lightning::ln::msgs::CommitmentUpdate,
	},
	/// Used to indicate that a revoke_and_ack message should be sent to the peer with the given node_id.
	SendRevokeAndACK {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::RevokeAndACK,
	},
	/// Used to indicate that a closing_signed message should be sent to the peer with the given node_id.
	SendClosingSigned {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::ClosingSigned,
	},
	/// Used to indicate that a shutdown message should be sent to the peer with the given node_id.
	SendShutdown {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::Shutdown,
	},
	/// Used to indicate that a channel_reestablish message should be sent to the peer with the given node_id.
	SendChannelReestablish {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The message which should be sent.
		msg: crate::lightning::ln::msgs::ChannelReestablish,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to call
	/// ChannelManager::broadcast_node_announcement to trigger a BroadcastNodeAnnouncement event.
	/// This ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: crate::lightning::ln::msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: crate::lightning::ln::msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Broadcast an error downstream to be handled
	HandleError {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The action which should be taken.
		action: crate::lightning::ln::msgs::ErrorAction,
	},
	/// When a payment fails we may receive updates back from the hop where it failed. In such
	/// cases this event is generated so that we can inform the network graph of this information.
	PaymentFailureNetworkUpdate {
		/// The channel/node update which should be sent to NetGraphMsgHandler
		update: crate::lightning::ln::msgs::HTLCFailChannelUpdate,
	},
	/// Query a peer for channels with funding transaction UTXOs in a block range.
	SendChannelRangeQuery {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The query_channel_range which should be sent.
		msg: crate::lightning::ln::msgs::QueryChannelRange,
	},
	/// Request routing gossip messages from a peer for a list of channels identified by
	/// their short_channel_ids.
	SendShortIdsQuery {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The query_short_channel_ids which should be sent.
		msg: crate::lightning::ln::msgs::QueryShortChannelIds,
	},
	/// Sends a reply to a channel range query. This may be one of several SendReplyChannelRange events
	/// emitted during processing of the query.
	SendReplyChannelRange {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The reply_channel_range which should be sent.
		msg: crate::lightning::ln::msgs::ReplyChannelRange,
	},
}
use lightning::util::events::MessageSendEvent as nativeMessageSendEvent;
impl MessageSendEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendFundingLocked {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut updates_nonref = (*updates).clone();
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id_nonref.into_rust(),
					updates: *unsafe { Box::from_raw(updates_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut update_msg_nonref = (*update_msg).clone();
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut action_nonref = (*action).clone();
				nativeMessageSendEvent::HandleError {
					node_id: node_id_nonref.into_rust(),
					action: action_nonref.into_native(),
				}
			},
			MessageSendEvent::PaymentFailureNetworkUpdate {ref update, } => {
				let mut update_nonref = (*update).clone();
				nativeMessageSendEvent::PaymentFailureNetworkUpdate {
					update: update_nonref.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				nativeMessageSendEvent::SendReplyChannelRange {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingLocked {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendFundingLocked {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id.into_rust(),
					updates: *unsafe { Box::from_raw(updates.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {mut node_id, mut action, } => {
				nativeMessageSendEvent::HandleError {
					node_id: node_id.into_rust(),
					action: action.into_native(),
				}
			},
			MessageSendEvent::PaymentFailureNetworkUpdate {mut update, } => {
				nativeMessageSendEvent::PaymentFailureNetworkUpdate {
					update: update.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendReplyChannelRange {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendReplyChannelRange {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeMessageSendEvent) -> Self {
		match native {
			nativeMessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingLocked {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendFundingLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingLocked { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut updates_nonref = (*updates).clone();
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: Box::into_raw(Box::new(updates_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::Shutdown { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = (*msg).clone();
				let mut update_msg_nonref = (*update_msg).clone();
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(update_msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut action_nonref = (*action).clone();
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action_nonref),
				}
			},
			nativeMessageSendEvent::PaymentFailureNetworkUpdate {ref update, } => {
				let mut update_nonref = (*update).clone();
				MessageSendEvent::PaymentFailureNetworkUpdate {
					update: crate::lightning::ln::msgs::HTLCFailChannelUpdate::native_into(update_nonref),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = (*node_id).clone();
				let mut msg_nonref = (*msg).clone();
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: Box::into_raw(Box::new(msg_nonref)), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeMessageSendEvent) -> Self {
		match native {
			nativeMessageSendEvent::SendAcceptChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingLocked {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingLocked {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingLocked { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: Box::into_raw(Box::new(updates)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::Shutdown { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: Box::into_raw(Box::new(msg)), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(update_msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {mut node_id, mut action, } => {
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action),
				}
			},
			nativeMessageSendEvent::PaymentFailureNetworkUpdate {mut update, } => {
				MessageSendEvent::PaymentFailureNetworkUpdate {
					update: crate::lightning::ln::msgs::HTLCFailChannelUpdate::native_into(update),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {mut node_id, mut msg, } => {
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: Box::into_raw(Box::new(msg)), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the MessageSendEvent
#[no_mangle]
pub extern "C" fn MessageSendEvent_free(this_ptr: MessageSendEvent) { }
/// Creates a copy of the MessageSendEvent
#[no_mangle]
pub extern "C" fn MessageSendEvent_clone(orig: &MessageSendEvent) -> MessageSendEvent {
	orig.clone()
}
/// A trait indicating an object may generate message send events
#[repr(C)]
pub struct MessageSendEventsProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets the list of pending events which were generated by previous actions, clearing the list
	/// in the process.
	#[must_use]
	pub get_and_clear_pending_msg_events: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_MessageSendEventZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for MessageSendEventsProvider {}
unsafe impl Sync for MessageSendEventsProvider {}

use lightning::util::events::MessageSendEventsProvider as rustMessageSendEventsProvider;
impl rustMessageSendEventsProvider for MessageSendEventsProvider {
	fn get_and_clear_pending_msg_events(&self) -> Vec<lightning::util::events::MessageSendEvent> {
		let mut ret = (self.get_and_clear_pending_msg_events)(self.this_arg);
		let mut local_ret = Vec::new(); for mut item in ret.into_rust().drain(..) { local_ret.push( { item.into_native() }); };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for MessageSendEventsProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn MessageSendEventsProvider_free(this_ptr: MessageSendEventsProvider) { }
impl Drop for MessageSendEventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait indicating an object may generate events.
///
/// Events are processed by passing an [`EventHandler`] to [`process_pending_events`].
///
/// # Requirements
///
/// See [`process_pending_events`] for requirements around event processing.
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation. The handler must either act upon the event immediately
/// or preserve it for later handling.
///
/// Note, handlers may call back into the provider and thus deadlocking must be avoided. Be sure to
/// consult the provider's documentation on the implication of processing events and how a handler
/// may safely use the provider (e.g., see [`ChannelManager::process_pending_events`] and
/// [`ChainMonitor::process_pending_events`]).
///
/// (C-not implementable) As there is likely no reason for a user to implement this trait on their
/// own type(s).
///
/// [`process_pending_events`]: Self::process_pending_events
/// [`handle_event`]: EventHandler::handle_event
/// [`ChannelManager::process_pending_events`]: crate::ln::channelmanager::ChannelManager#method.process_pending_events
/// [`ChainMonitor::process_pending_events`]: crate::chain::chainmonitor::ChainMonitor#method.process_pending_events
#[repr(C)]
pub struct EventsProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Processes any events generated since the last call using the given event handler.
	///
	/// Subsequent calls must only process new events. However, handlers must be capable of handling
	/// duplicate events across process restarts. This may occur if the provider was recovered from
	/// an old state (i.e., it hadn't been successfully persisted after processing pending events).
	pub process_pending_events: extern "C" fn (this_arg: *const c_void, handler: crate::lightning::util::events::EventHandler),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EventsProvider {}
unsafe impl Sync for EventsProvider {}

use lightning::util::events::EventsProvider as rustEventsProvider;
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EventsProvider_free(this_ptr: EventsProvider) { }
impl Drop for EventsProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait implemented for objects handling events from [`EventsProvider`].
#[repr(C)]
pub struct EventHandler {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Handles the given [`Event`].
	///
	/// See [`EventsProvider`] for details that must be considered when implementing this method.
	pub handle_event: extern "C" fn (this_arg: *const c_void, event: crate::lightning::util::events::Event),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EventHandler {}
unsafe impl Sync for EventHandler {}

use lightning::util::events::EventHandler as rustEventHandler;
impl rustEventHandler for EventHandler {
	fn handle_event(&self, mut event: lightning::util::events::Event) {
		(self.handle_event)(self.this_arg, crate::lightning::util::events::Event::native_into(event))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for EventHandler {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EventHandler_free(this_ptr: EventHandler) { }
impl Drop for EventHandler {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
