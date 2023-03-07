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

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Some information provided on receipt of payment depends on whether the payment received is a
/// spontaneous payment or a \"conventional\" lightning payment that's paying an invoice.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PaymentPurpose {
	/// Information for receiving a payment that we generated an invoice for.
	InvoicePayment {
		/// The preimage to the payment_hash, if the payment hash (and secret) were fetched via
		/// [`ChannelManager::create_inbound_payment`]. If provided, this can be handed directly to
		/// [`ChannelManager::claim_funds`].
		///
		/// [`ChannelManager::create_inbound_payment`]: crate::ln::channelmanager::ChannelManager::create_inbound_payment
		/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
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
	},
	/// Because this is a spontaneous payment, the payer generated their own preimage rather than us
	/// (the payee) providing a preimage.
	SpontaneousPayment(
		crate::c_types::ThirtyTwoBytes),
}
use lightning::util::events::PaymentPurpose as PaymentPurposeImport;
pub(crate) type nativePaymentPurpose = PaymentPurposeImport;

impl PaymentPurpose {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePaymentPurpose {
		match self {
			PaymentPurpose::InvoicePayment {ref payment_preimage, ref payment_secret, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentPreimage(payment_preimage_nonref.data) }) };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				nativePaymentPurpose::InvoicePayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: ::lightning::ln::PaymentSecret(payment_secret_nonref.data),
				}
			},
			PaymentPurpose::SpontaneousPayment (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativePaymentPurpose::SpontaneousPayment (
					::lightning::ln::PaymentPreimage(a_nonref.data),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePaymentPurpose {
		match self {
			PaymentPurpose::InvoicePayment {mut payment_preimage, mut payment_secret, } => {
				let mut local_payment_preimage = if payment_preimage.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentPreimage(payment_preimage.data) }) };
				nativePaymentPurpose::InvoicePayment {
					payment_preimage: local_payment_preimage,
					payment_secret: ::lightning::ln::PaymentSecret(payment_secret.data),
				}
			},
			PaymentPurpose::SpontaneousPayment (mut a, ) => {
				nativePaymentPurpose::SpontaneousPayment (
					::lightning::ln::PaymentPreimage(a.data),
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePaymentPurpose) -> Self {
		match native {
			nativePaymentPurpose::InvoicePayment {ref payment_preimage, ref payment_secret, } => {
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut local_payment_preimage_nonref = if payment_preimage_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_preimage_nonref.unwrap()).0 } } };
				let mut payment_secret_nonref = Clone::clone(payment_secret);
				PaymentPurpose::InvoicePayment {
					payment_preimage: local_payment_preimage_nonref,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret_nonref.0 },
				}
			},
			nativePaymentPurpose::SpontaneousPayment (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				PaymentPurpose::SpontaneousPayment (
					crate::c_types::ThirtyTwoBytes { data: a_nonref.0 },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePaymentPurpose) -> Self {
		match native {
			nativePaymentPurpose::InvoicePayment {mut payment_preimage, mut payment_secret, } => {
				let mut local_payment_preimage = if payment_preimage.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_preimage.unwrap()).0 } } };
				PaymentPurpose::InvoicePayment {
					payment_preimage: local_payment_preimage,
					payment_secret: crate::c_types::ThirtyTwoBytes { data: payment_secret.0 },
				}
			},
			nativePaymentPurpose::SpontaneousPayment (mut a, ) => {
				PaymentPurpose::SpontaneousPayment (
					crate::c_types::ThirtyTwoBytes { data: a.0 },
				)
			},
		}
	}
}
/// Frees any resources used by the PaymentPurpose
#[no_mangle]
pub extern "C" fn PaymentPurpose_free(this_ptr: PaymentPurpose) { }
/// Creates a copy of the PaymentPurpose
#[no_mangle]
pub extern "C" fn PaymentPurpose_clone(orig: &PaymentPurpose) -> PaymentPurpose {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new InvoicePayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_invoice_payment(payment_preimage: crate::c_types::ThirtyTwoBytes, payment_secret: crate::c_types::ThirtyTwoBytes) -> PaymentPurpose {
	PaymentPurpose::InvoicePayment {
		payment_preimage,
		payment_secret,
	}
}
#[no_mangle]
/// Utility method to constructs a new SpontaneousPayment-variant PaymentPurpose
pub extern "C" fn PaymentPurpose_spontaneous_payment(a: crate::c_types::ThirtyTwoBytes) -> PaymentPurpose {
	PaymentPurpose::SpontaneousPayment(a, )
}
/// Checks if two PaymentPurposes contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PaymentPurpose_eq(a: &PaymentPurpose, b: &PaymentPurpose) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the PaymentPurpose object into a byte array which can be read by PaymentPurpose_read
pub extern "C" fn PaymentPurpose_write(obj: &crate::lightning::util::events::PaymentPurpose) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a PaymentPurpose from a byte array, created by PaymentPurpose_write
pub extern "C" fn PaymentPurpose_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_PaymentPurposeDecodeErrorZ {
	let res: Result<lightning::util::events::PaymentPurpose, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::util::events::PaymentPurpose::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// When the payment path failure took place and extra details about it. [`PathFailure::OnPath`] may
/// contain a [`NetworkUpdate`] that needs to be applied to the [`NetworkGraph`].
///
/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum PathFailure {
	/// We failed to initially send the payment and no HTLC was committed to. Contains the relevant
	/// error.
	InitialSend {
		/// The error surfaced from initial send.
		err: crate::lightning::util::errors::APIError,
	},
	/// A hop on the path failed to forward our payment.
	OnPath {
		/// If present, this [`NetworkUpdate`] should be applied to the [`NetworkGraph`] so that routing
		/// decisions can take into account the update.
		///
		/// [`NetworkUpdate`]: crate::routing::gossip::NetworkUpdate
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		network_update: crate::c_types::derived::COption_NetworkUpdateZ,
	},
}
use lightning::util::events::PathFailure as PathFailureImport;
pub(crate) type nativePathFailure = PathFailureImport;

impl PathFailure {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativePathFailure {
		match self {
			PathFailure::InitialSend {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativePathFailure::InitialSend {
					err: err_nonref.into_native(),
				}
			},
			PathFailure::OnPath {ref network_update, } => {
				let mut network_update_nonref = Clone::clone(network_update);
				let mut local_network_update_nonref = { /* network_update_nonref*/ let network_update_nonref_opt = network_update_nonref; { } if network_update_nonref_opt.is_none() { None } else { Some({ network_update_nonref_opt.take().into_native() }) } };
				nativePathFailure::OnPath {
					network_update: local_network_update_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativePathFailure {
		match self {
			PathFailure::InitialSend {mut err, } => {
				nativePathFailure::InitialSend {
					err: err.into_native(),
				}
			},
			PathFailure::OnPath {mut network_update, } => {
				let mut local_network_update = { /* network_update*/ let network_update_opt = network_update; { } if network_update_opt.is_none() { None } else { Some({ network_update_opt.take().into_native() }) } };
				nativePathFailure::OnPath {
					network_update: local_network_update,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativePathFailure) -> Self {
		match native {
			nativePathFailure::InitialSend {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				PathFailure::InitialSend {
					err: crate::lightning::util::errors::APIError::native_into(err_nonref),
				}
			},
			nativePathFailure::OnPath {ref network_update, } => {
				let mut network_update_nonref = Clone::clone(network_update);
				let mut local_network_update_nonref = if network_update_nonref.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::gossip::NetworkUpdate::native_into(network_update_nonref.unwrap()) }) };
				PathFailure::OnPath {
					network_update: local_network_update_nonref,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativePathFailure) -> Self {
		match native {
			nativePathFailure::InitialSend {mut err, } => {
				PathFailure::InitialSend {
					err: crate::lightning::util::errors::APIError::native_into(err),
				}
			},
			nativePathFailure::OnPath {mut network_update, } => {
				let mut local_network_update = if network_update.is_none() { crate::c_types::derived::COption_NetworkUpdateZ::None } else { crate::c_types::derived::COption_NetworkUpdateZ::Some( { crate::lightning::routing::gossip::NetworkUpdate::native_into(network_update.unwrap()) }) };
				PathFailure::OnPath {
					network_update: local_network_update,
				}
			},
		}
	}
}
/// Frees any resources used by the PathFailure
#[no_mangle]
pub extern "C" fn PathFailure_free(this_ptr: PathFailure) { }
/// Creates a copy of the PathFailure
#[no_mangle]
pub extern "C" fn PathFailure_clone(orig: &PathFailure) -> PathFailure {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new InitialSend-variant PathFailure
pub extern "C" fn PathFailure_initial_send(err: crate::lightning::util::errors::APIError) -> PathFailure {
	PathFailure::InitialSend {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new OnPath-variant PathFailure
pub extern "C" fn PathFailure_on_path(network_update: crate::c_types::derived::COption_NetworkUpdateZ) -> PathFailure {
	PathFailure::OnPath {
		network_update,
	}
}
/// Checks if two PathFailures contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn PathFailure_eq(a: &PathFailure, b: &PathFailure) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the PathFailure object into a byte array which can be read by PathFailure_read
pub extern "C" fn PathFailure_write(obj: &crate::lightning::util::events::PathFailure) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a PathFailure from a byte array, created by PathFailure_write
pub extern "C" fn PathFailure_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_PathFailureZDecodeErrorZ {
	let res: Result<Option<lightning::util::events::PathFailure>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_PathFailureZ::None } else { crate::c_types::derived::COption_PathFailureZ::Some( { crate::lightning::util::events::PathFailure::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The reason the channel was closed. See individual variants more details.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum ClosureReason {
	/// Closure generated from receiving a peer error message.
	///
	/// Our counterparty may have broadcasted their latest commitment state, and we have
	/// as well.
	CounterpartyForceClosed {
		/// The error which the peer sent us.
		///
		/// The string should be sanitized before it is used (e.g emitted to logs
		/// or printed to stdout). Otherwise, a well crafted error message may exploit
		/// a security vulnerability in the terminal emulator or the logging subsystem.
		peer_msg: crate::c_types::Str,
	},
	/// Closure generated from [`ChannelManager::force_close_channel`], called by the user.
	///
	/// [`ChannelManager::force_close_channel`]: crate::ln::channelmanager::ChannelManager::force_close_channel.
	HolderForceClosed,
	/// The channel was closed after negotiating a cooperative close and we've now broadcasted
	/// the cooperative close transaction. Note the shutdown may have been initiated by us.
	CooperativeClosure,
	/// A commitment transaction was confirmed on chain, closing the channel. Most likely this
	/// commitment transaction came from our counterparty, but it may also have come from
	/// a copy of our own `ChannelMonitor`.
	CommitmentTxConfirmed,
	/// The funding transaction failed to confirm in a timely manner on an inbound channel.
	FundingTimedOut,
	/// Closure generated from processing an event, likely a HTLC forward/relay/reception.
	ProcessingError {
		/// A developer-readable error message which we generated.
		err: crate::c_types::Str,
	},
	/// The peer disconnected prior to funding completing. In this case the spec mandates that we
	/// forget the channel entirely - we can attempt again if the peer reconnects.
	///
	/// This includes cases where we restarted prior to funding completion, including prior to the
	/// initial [`ChannelMonitor`] persistence completing.
	///
	/// In LDK versions prior to 0.0.107 this could also occur if we were unable to connect to the
	/// peer because of mutual incompatibility between us and our channel counterparty.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	DisconnectedPeer,
	/// Closure generated from `ChannelManager::read` if the [`ChannelMonitor`] is newer than
	/// the [`ChannelManager`] deserialized.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	OutdatedChannelManager,
}
use lightning::util::events::ClosureReason as ClosureReasonImport;
pub(crate) type nativeClosureReason = ClosureReasonImport;

impl ClosureReason {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeClosureReason {
		match self {
			ClosureReason::CounterpartyForceClosed {ref peer_msg, } => {
				let mut peer_msg_nonref = Clone::clone(peer_msg);
				nativeClosureReason::CounterpartyForceClosed {
					peer_msg: peer_msg_nonref.into_string(),
				}
			},
			ClosureReason::HolderForceClosed => nativeClosureReason::HolderForceClosed,
			ClosureReason::CooperativeClosure => nativeClosureReason::CooperativeClosure,
			ClosureReason::CommitmentTxConfirmed => nativeClosureReason::CommitmentTxConfirmed,
			ClosureReason::FundingTimedOut => nativeClosureReason::FundingTimedOut,
			ClosureReason::ProcessingError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				nativeClosureReason::ProcessingError {
					err: err_nonref.into_string(),
				}
			},
			ClosureReason::DisconnectedPeer => nativeClosureReason::DisconnectedPeer,
			ClosureReason::OutdatedChannelManager => nativeClosureReason::OutdatedChannelManager,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeClosureReason {
		match self {
			ClosureReason::CounterpartyForceClosed {mut peer_msg, } => {
				nativeClosureReason::CounterpartyForceClosed {
					peer_msg: peer_msg.into_string(),
				}
			},
			ClosureReason::HolderForceClosed => nativeClosureReason::HolderForceClosed,
			ClosureReason::CooperativeClosure => nativeClosureReason::CooperativeClosure,
			ClosureReason::CommitmentTxConfirmed => nativeClosureReason::CommitmentTxConfirmed,
			ClosureReason::FundingTimedOut => nativeClosureReason::FundingTimedOut,
			ClosureReason::ProcessingError {mut err, } => {
				nativeClosureReason::ProcessingError {
					err: err.into_string(),
				}
			},
			ClosureReason::DisconnectedPeer => nativeClosureReason::DisconnectedPeer,
			ClosureReason::OutdatedChannelManager => nativeClosureReason::OutdatedChannelManager,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeClosureReason) -> Self {
		match native {
			nativeClosureReason::CounterpartyForceClosed {ref peer_msg, } => {
				let mut peer_msg_nonref = Clone::clone(peer_msg);
				ClosureReason::CounterpartyForceClosed {
					peer_msg: peer_msg_nonref.into(),
				}
			},
			nativeClosureReason::HolderForceClosed => ClosureReason::HolderForceClosed,
			nativeClosureReason::CooperativeClosure => ClosureReason::CooperativeClosure,
			nativeClosureReason::CommitmentTxConfirmed => ClosureReason::CommitmentTxConfirmed,
			nativeClosureReason::FundingTimedOut => ClosureReason::FundingTimedOut,
			nativeClosureReason::ProcessingError {ref err, } => {
				let mut err_nonref = Clone::clone(err);
				ClosureReason::ProcessingError {
					err: err_nonref.into(),
				}
			},
			nativeClosureReason::DisconnectedPeer => ClosureReason::DisconnectedPeer,
			nativeClosureReason::OutdatedChannelManager => ClosureReason::OutdatedChannelManager,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeClosureReason) -> Self {
		match native {
			nativeClosureReason::CounterpartyForceClosed {mut peer_msg, } => {
				ClosureReason::CounterpartyForceClosed {
					peer_msg: peer_msg.into(),
				}
			},
			nativeClosureReason::HolderForceClosed => ClosureReason::HolderForceClosed,
			nativeClosureReason::CooperativeClosure => ClosureReason::CooperativeClosure,
			nativeClosureReason::CommitmentTxConfirmed => ClosureReason::CommitmentTxConfirmed,
			nativeClosureReason::FundingTimedOut => ClosureReason::FundingTimedOut,
			nativeClosureReason::ProcessingError {mut err, } => {
				ClosureReason::ProcessingError {
					err: err.into(),
				}
			},
			nativeClosureReason::DisconnectedPeer => ClosureReason::DisconnectedPeer,
			nativeClosureReason::OutdatedChannelManager => ClosureReason::OutdatedChannelManager,
		}
	}
}
/// Frees any resources used by the ClosureReason
#[no_mangle]
pub extern "C" fn ClosureReason_free(this_ptr: ClosureReason) { }
/// Creates a copy of the ClosureReason
#[no_mangle]
pub extern "C" fn ClosureReason_clone(orig: &ClosureReason) -> ClosureReason {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new CounterpartyForceClosed-variant ClosureReason
pub extern "C" fn ClosureReason_counterparty_force_closed(peer_msg: crate::c_types::Str) -> ClosureReason {
	ClosureReason::CounterpartyForceClosed {
		peer_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new HolderForceClosed-variant ClosureReason
pub extern "C" fn ClosureReason_holder_force_closed() -> ClosureReason {
	ClosureReason::HolderForceClosed}
#[no_mangle]
/// Utility method to constructs a new CooperativeClosure-variant ClosureReason
pub extern "C" fn ClosureReason_cooperative_closure() -> ClosureReason {
	ClosureReason::CooperativeClosure}
#[no_mangle]
/// Utility method to constructs a new CommitmentTxConfirmed-variant ClosureReason
pub extern "C" fn ClosureReason_commitment_tx_confirmed() -> ClosureReason {
	ClosureReason::CommitmentTxConfirmed}
#[no_mangle]
/// Utility method to constructs a new FundingTimedOut-variant ClosureReason
pub extern "C" fn ClosureReason_funding_timed_out() -> ClosureReason {
	ClosureReason::FundingTimedOut}
#[no_mangle]
/// Utility method to constructs a new ProcessingError-variant ClosureReason
pub extern "C" fn ClosureReason_processing_error(err: crate::c_types::Str) -> ClosureReason {
	ClosureReason::ProcessingError {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new DisconnectedPeer-variant ClosureReason
pub extern "C" fn ClosureReason_disconnected_peer() -> ClosureReason {
	ClosureReason::DisconnectedPeer}
#[no_mangle]
/// Utility method to constructs a new OutdatedChannelManager-variant ClosureReason
pub extern "C" fn ClosureReason_outdated_channel_manager() -> ClosureReason {
	ClosureReason::OutdatedChannelManager}
/// Checks if two ClosureReasons contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn ClosureReason_eq(a: &ClosureReason, b: &ClosureReason) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the ClosureReason object into a byte array which can be read by ClosureReason_read
pub extern "C" fn ClosureReason_write(obj: &crate::lightning::util::events::ClosureReason) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a ClosureReason from a byte array, created by ClosureReason_write
pub extern "C" fn ClosureReason_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_ClosureReasonZDecodeErrorZ {
	let res: Result<Option<lightning::util::events::ClosureReason>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_ClosureReasonZ::None } else { crate::c_types::derived::COption_ClosureReasonZ::Some( { crate::lightning::util::events::ClosureReason::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Intended destination of a failed HTLC as indicated in [`Event::HTLCHandlingFailed`].
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum HTLCDestination {
	/// We tried forwarding to a channel but failed to do so. An example of such an instance is when
	/// there is insufficient capacity in our outbound channel.
	NextHopChannel {
		/// The `node_id` of the next node. For backwards compatibility, this field is
		/// marked as optional, versions prior to 0.0.110 may not always be able to provide
		/// counterparty node information.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		node_id: crate::c_types::PublicKey,
		/// The outgoing `channel_id` between us and the next node.
		channel_id: crate::c_types::ThirtyTwoBytes,
	},
	/// Scenario where we are unsure of the next node to forward the HTLC to.
	UnknownNextHop {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64,
	},
	/// We couldn't forward to the outgoing scid. An example would be attempting to send a duplicate
	/// intercept HTLC.
	InvalidForward {
		/// Short channel id we are requesting to forward an HTLC to.
		requested_forward_scid: u64,
	},
	/// Failure scenario where an HTLC may have been forwarded to be intended for us,
	/// but is invalid for some reason, so we reject it.
	///
	/// Some of the reasons may include:
	/// * HTLC Timeouts
	/// * Expected MPP amount to claim does not equal HTLC total
	/// * Claimable amount does not match expected amount
	FailedPayment {
		/// The payment hash of the payment we attempted to process.
		payment_hash: crate::c_types::ThirtyTwoBytes,
	},
}
use lightning::util::events::HTLCDestination as HTLCDestinationImport;
pub(crate) type nativeHTLCDestination = HTLCDestinationImport;

impl HTLCDestination {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeHTLCDestination {
		match self {
			HTLCDestination::NextHopChannel {ref node_id, ref channel_id, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut local_node_id_nonref = if node_id_nonref.is_null() { None } else { Some( { node_id_nonref.into_rust() }) };
				let mut channel_id_nonref = Clone::clone(channel_id);
				nativeHTLCDestination::NextHopChannel {
					node_id: local_node_id_nonref,
					channel_id: channel_id_nonref.data,
				}
			},
			HTLCDestination::UnknownNextHop {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				nativeHTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			HTLCDestination::InvalidForward {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				nativeHTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			HTLCDestination::FailedPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				nativeHTLCDestination::FailedPayment {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeHTLCDestination {
		match self {
			HTLCDestination::NextHopChannel {mut node_id, mut channel_id, } => {
				let mut local_node_id = if node_id.is_null() { None } else { Some( { node_id.into_rust() }) };
				nativeHTLCDestination::NextHopChannel {
					node_id: local_node_id,
					channel_id: channel_id.data,
				}
			},
			HTLCDestination::UnknownNextHop {mut requested_forward_scid, } => {
				nativeHTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid,
				}
			},
			HTLCDestination::InvalidForward {mut requested_forward_scid, } => {
				nativeHTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid,
				}
			},
			HTLCDestination::FailedPayment {mut payment_hash, } => {
				nativeHTLCDestination::FailedPayment {
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeHTLCDestination) -> Self {
		match native {
			nativeHTLCDestination::NextHopChannel {ref node_id, ref channel_id, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut local_node_id_nonref = if node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(node_id_nonref.unwrap())) } };
				let mut channel_id_nonref = Clone::clone(channel_id);
				HTLCDestination::NextHopChannel {
					node_id: local_node_id_nonref,
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id_nonref },
				}
			},
			nativeHTLCDestination::UnknownNextHop {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				HTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			nativeHTLCDestination::InvalidForward {ref requested_forward_scid, } => {
				let mut requested_forward_scid_nonref = Clone::clone(requested_forward_scid);
				HTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid_nonref,
				}
			},
			nativeHTLCDestination::FailedPayment {ref payment_hash, } => {
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				HTLCDestination::FailedPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeHTLCDestination) -> Self {
		match native {
			nativeHTLCDestination::NextHopChannel {mut node_id, mut channel_id, } => {
				let mut local_node_id = if node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(node_id.unwrap())) } };
				HTLCDestination::NextHopChannel {
					node_id: local_node_id,
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id },
				}
			},
			nativeHTLCDestination::UnknownNextHop {mut requested_forward_scid, } => {
				HTLCDestination::UnknownNextHop {
					requested_forward_scid: requested_forward_scid,
				}
			},
			nativeHTLCDestination::InvalidForward {mut requested_forward_scid, } => {
				HTLCDestination::InvalidForward {
					requested_forward_scid: requested_forward_scid,
				}
			},
			nativeHTLCDestination::FailedPayment {mut payment_hash, } => {
				HTLCDestination::FailedPayment {
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
				}
			},
		}
	}
}
/// Frees any resources used by the HTLCDestination
#[no_mangle]
pub extern "C" fn HTLCDestination_free(this_ptr: HTLCDestination) { }
/// Creates a copy of the HTLCDestination
#[no_mangle]
pub extern "C" fn HTLCDestination_clone(orig: &HTLCDestination) -> HTLCDestination {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new NextHopChannel-variant HTLCDestination
pub extern "C" fn HTLCDestination_next_hop_channel(node_id: crate::c_types::PublicKey, channel_id: crate::c_types::ThirtyTwoBytes) -> HTLCDestination {
	HTLCDestination::NextHopChannel {
		node_id,
		channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new UnknownNextHop-variant HTLCDestination
pub extern "C" fn HTLCDestination_unknown_next_hop(requested_forward_scid: u64) -> HTLCDestination {
	HTLCDestination::UnknownNextHop {
		requested_forward_scid,
	}
}
#[no_mangle]
/// Utility method to constructs a new InvalidForward-variant HTLCDestination
pub extern "C" fn HTLCDestination_invalid_forward(requested_forward_scid: u64) -> HTLCDestination {
	HTLCDestination::InvalidForward {
		requested_forward_scid,
	}
}
#[no_mangle]
/// Utility method to constructs a new FailedPayment-variant HTLCDestination
pub extern "C" fn HTLCDestination_failed_payment(payment_hash: crate::c_types::ThirtyTwoBytes) -> HTLCDestination {
	HTLCDestination::FailedPayment {
		payment_hash,
	}
}
/// Checks if two HTLCDestinations contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn HTLCDestination_eq(a: &HTLCDestination, b: &HTLCDestination) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the HTLCDestination object into a byte array which can be read by HTLCDestination_read
pub extern "C" fn HTLCDestination_write(obj: &crate::lightning::util::events::HTLCDestination) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a HTLCDestination from a byte array, created by HTLCDestination_write
pub extern "C" fn HTLCDestination_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_HTLCDestinationZDecodeErrorZ {
	let res: Result<Option<lightning::util::events::HTLCDestination>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_HTLCDestinationZ::None } else { crate::c_types::derived::COption_HTLCDestinationZ::Some( { crate::lightning::util::events::HTLCDestination::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// An Event which you should probably take some action in response to.
///
/// Note that while Writeable and Readable are implemented for Event, you probably shouldn't use
/// them directly as they don't round-trip exactly (for example FundingGenerationReady is never
/// written as it makes no sense to respond to it after reconnecting to peers).
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Event {
	/// Used to indicate that the client should generate a funding transaction with the given
	/// parameters and then call [`ChannelManager::funding_transaction_generated`].
	/// Generated in [`ChannelManager`] message handling.
	/// Note that *all inputs* in the funding transaction must spend SegWit outputs or your
	/// counterparty can steal your funds!
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
	FundingGenerationReady {
		/// The random channel_id we picked which you'll need to pass into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		temporary_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The counterparty's node_id, which you'll need to pass back into
		/// [`ChannelManager::funding_transaction_generated`].
		///
		/// [`ChannelManager::funding_transaction_generated`]: crate::ln::channelmanager::ChannelManager::funding_transaction_generated
		counterparty_node_id: crate::c_types::PublicKey,
		/// The value, in satoshis, that the output should have.
		channel_value_satoshis: u64,
		/// The script which should be used in the transaction output.
		output_script: crate::c_types::derived::CVec_u8Z,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`], or a
		/// random value for an inbound channel. This may be zero for objects serialized with LDK
		/// versions prior to 0.0.113.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		user_channel_id: crate::c_types::U128,
	},
	/// Indicates that we've been offered a payment and it needs to be claimed via calling
	/// [`ChannelManager::claim_funds`] with the preimage given in [`PaymentPurpose`].
	///
	/// Note that if the preimage is not known, you should call
	/// [`ChannelManager::fail_htlc_backwards`] or [`ChannelManager::fail_htlc_backwards_with_reason`]
	/// to free up resources for this HTLC and avoid network congestion.
	/// If you fail to call either [`ChannelManager::claim_funds`], [`ChannelManager::fail_htlc_backwards`],
	/// or [`ChannelManager::fail_htlc_backwards_with_reason`] within the HTLC's timeout, the HTLC will be
	/// automatically failed.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment.
	///
	/// # Note
	/// This event used to be called `PaymentReceived` in LDK versions 0.0.112 and earlier.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	/// [`ChannelManager::fail_htlc_backwards`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards
	/// [`ChannelManager::fail_htlc_backwards_with_reason`]: crate::ln::channelmanager::ChannelManager::fail_htlc_backwards_with_reason
	PaymentClaimable {
		/// The node that will receive the payment after it has been claimed.
		/// This is useful to identify payments received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::chain::keysinterface::PhantomKeysManager
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		receiver_node_id: crate::c_types::PublicKey,
		/// The hash for which the preimage should be handed to the ChannelManager. Note that LDK will
		/// not stop you from registering duplicate payment hashes for inbound payments.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The value, in thousandths of a satoshi, that this payment is for.
		amount_msat: u64,
		/// Information for claiming this received payment, based on whether the purpose of the
		/// payment is to pay an invoice or to send a spontaneous payment.
		purpose: crate::lightning::util::events::PaymentPurpose,
		/// The `channel_id` indicating over which channel we received the payment.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		via_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The `user_channel_id` indicating over which channel we received the payment.
		via_user_channel_id: crate::c_types::derived::COption_u128Z,
	},
	/// Indicates a payment has been claimed and we've received money!
	///
	/// This most likely occurs when [`ChannelManager::claim_funds`] has been called in response
	/// to an [`Event::PaymentClaimable`]. However, if we previously crashed during a
	/// [`ChannelManager::claim_funds`] call you may see this event without a corresponding
	/// [`Event::PaymentClaimable`] event.
	///
	/// # Note
	/// LDK will not stop an inbound payment from being paid multiple times, so multiple
	/// `PaymentClaimable` events may be generated for the same payment. If you then call
	/// [`ChannelManager::claim_funds`] twice for the same [`Event::PaymentClaimable`] you may get
	/// multiple `PaymentClaimed` events.
	///
	/// [`ChannelManager::claim_funds`]: crate::ln::channelmanager::ChannelManager::claim_funds
	PaymentClaimed {
		/// The node that received the payment.
		/// This is useful to identify payments which were received via [phantom nodes].
		/// This field will always be filled in when the event was generated by LDK versions
		/// 0.0.113 and above.
		///
		/// [phantom nodes]: crate::chain::keysinterface::PhantomKeysManager
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		receiver_node_id: crate::c_types::PublicKey,
		/// The payment hash of the claimed payment. Note that LDK will not stop you from
		/// registering duplicate payment hashes for inbound payments.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The value, in thousandths of a satoshi, that this payment is for.
		amount_msat: u64,
		/// The purpose of the claimed payment, i.e. whether the payment was for an invoice or a
		/// spontaneous payment.
		purpose: crate::lightning::util::events::PaymentPurpose,
	},
	/// Indicates an outbound payment we made succeeded (i.e. it made it all the way to its target
	/// and we got back the payment preimage for it).
	///
	/// Note for MPP payments: in rare cases, this event may be preceded by a `PaymentPathFailed`
	/// event. In this situation, you SHOULD treat this payment as having succeeded.
	PaymentSent {
		/// The id returned by [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The preimage to the hash given to ChannelManager::send_payment.
		/// Note that this serves as a payment receipt, if you wish to have such a thing, you must
		/// store it somehow!
		payment_preimage: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The total fee which was spent at intermediate hops in this payment, across all paths.
		///
		/// Note that, like [`Route::get_total_fees`] this does *not* include any potential
		/// overpayment to the recipient node.
		///
		/// If the recipient or an intermediate node misbehaves and gives us free money, this may
		/// overstate the amount paid, though this is unlikely.
		///
		/// [`Route::get_total_fees`]: crate::routing::router::Route::get_total_fees
		fee_paid_msat: crate::c_types::derived::COption_u64Z,
	},
	/// Indicates an outbound payment failed. Individual [`Event::PaymentPathFailed`] events
	/// provide failure information for each path attempt in the payment, including retries.
	///
	/// This event is provided once there are no further pending HTLCs for the payment and the
	/// payment is no longer retryable, due either to the [`Retry`] provided or
	/// [`ChannelManager::abandon_payment`] having been called for the corresponding payment.
	///
	/// [`Retry`]: crate::ln::channelmanager::Retry
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentFailed {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::abandon_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::ThirtyTwoBytes,
	},
	/// Indicates that a path for an outbound payment was successful.
	///
	/// Always generated after [`Event::PaymentSent`] and thus useful for scoring channels. See
	/// [`Event::PaymentSent`] for obtaining the payment preimage.
	PaymentPathSuccessful {
		/// The id returned by [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The payment path that was successful.
		///
		/// May contain a closed channel if the HTLC sent along the path was fulfilled on chain.
		path: crate::c_types::derived::CVec_RouteHopZ,
	},
	/// Indicates an outbound HTLC we sent failed, likely due to an intermediary node being unable to
	/// handle the HTLC.
	///
	/// Note that this does *not* indicate that all paths for an MPP payment have failed, see
	/// [`Event::PaymentFailed`].
	///
	/// See [`ChannelManager::abandon_payment`] for giving up on this payment before its retries have
	/// been exhausted.
	///
	/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
	PaymentPathFailed {
		/// The id returned by [`ChannelManager::send_payment`] and used with
		/// [`ChannelManager::abandon_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		/// [`ChannelManager::abandon_payment`]: crate::ln::channelmanager::ChannelManager::abandon_payment
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash that was given to [`ChannelManager::send_payment`].
		///
		/// [`ChannelManager::send_payment`]: crate::ln::channelmanager::ChannelManager::send_payment
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// Indicates the payment was rejected for some reason by the recipient. This implies that
		/// the payment has failed, not just the route in question. If this is not set, the payment may
		/// be retried via a different route.
		payment_failed_permanently: bool,
		/// Extra error details based on the failure type. May contain an update that needs to be
		/// applied to the [`NetworkGraph`].
		///
		/// [`NetworkGraph`]: crate::routing::gossip::NetworkGraph
		failure: crate::lightning::util::events::PathFailure,
		/// The payment path that failed.
		path: crate::c_types::derived::CVec_RouteHopZ,
		/// The channel responsible for the failed payment path.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		///
		/// If this is `Some`, then the corresponding channel should be avoided when the payment is
		/// retried. May be `None` for older [`Event`] serializations.
		short_channel_id: crate::c_types::derived::COption_u64Z,
		/// Parameters used by LDK to compute a new [`Route`] when retrying the failed payment path.
		///
		/// [`Route`]: crate::routing::router::Route
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		retry: crate::lightning::routing::router::RouteParameters,
	},
	/// Indicates that a probe payment we sent returned successful, i.e., only failed at the destination.
	ProbeSuccessful {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The payment path that was successful.
		path: crate::c_types::derived::CVec_RouteHopZ,
	},
	/// Indicates that a probe payment we sent failed at an intermediary node on the path.
	ProbeFailed {
		/// The id returned by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_id: crate::c_types::ThirtyTwoBytes,
		/// The hash generated by [`ChannelManager::send_probe`].
		///
		/// [`ChannelManager::send_probe`]: crate::ln::channelmanager::ChannelManager::send_probe
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// The payment path that failed.
		path: crate::c_types::derived::CVec_RouteHopZ,
		/// The channel responsible for the failed probe.
		///
		/// Note that for route hints or for the first hop in a path this may be an SCID alias and
		/// may not refer to a channel in the public network graph. These aliases may also collide
		/// with channels in the public network graph.
		short_channel_id: crate::c_types::derived::COption_u64Z,
	},
	/// Used to indicate that [`ChannelManager::process_pending_htlc_forwards`] should be called at
	/// a time in the future.
	///
	/// [`ChannelManager::process_pending_htlc_forwards`]: crate::ln::channelmanager::ChannelManager::process_pending_htlc_forwards
	PendingHTLCsForwardable {
		/// The minimum amount of time that should be waited prior to calling
		/// process_pending_htlc_forwards. To increase the effort required to correlate payments,
		/// you should wait a random amount of time in roughly the range (now + time_forwardable,
		/// now + 5*time_forwardable).
		time_forwardable: u64,
	},
	/// Used to indicate that we've intercepted an HTLC forward. This event will only be generated if
	/// you've encoded an intercept scid in the receiver's invoice route hints using
	/// [`ChannelManager::get_intercept_scid`] and have set [`UserConfig::accept_intercept_htlcs`].
	///
	/// [`ChannelManager::forward_intercepted_htlc`] or
	/// [`ChannelManager::fail_intercepted_htlc`] MUST be called in response to this event. See
	/// their docs for more information.
	///
	/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
	/// [`UserConfig::accept_intercept_htlcs`]: crate::util::config::UserConfig::accept_intercept_htlcs
	/// [`ChannelManager::forward_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::forward_intercepted_htlc
	/// [`ChannelManager::fail_intercepted_htlc`]: crate::ln::channelmanager::ChannelManager::fail_intercepted_htlc
	HTLCIntercepted {
		/// An id to help LDK identify which HTLC is being forwarded or failed.
		intercept_id: crate::c_types::ThirtyTwoBytes,
		/// The fake scid that was programmed as the next hop's scid, generated using
		/// [`ChannelManager::get_intercept_scid`].
		///
		/// [`ChannelManager::get_intercept_scid`]: crate::ln::channelmanager::ChannelManager::get_intercept_scid
		requested_next_hop_scid: u64,
		/// The payment hash used for this HTLC.
		payment_hash: crate::c_types::ThirtyTwoBytes,
		/// How many msats were received on the inbound edge of this HTLC.
		inbound_amount_msat: u64,
		/// How many msats the payer intended to route to the next node. Depending on the reason you are
		/// intercepting this payment, you might take a fee by forwarding less than this amount.
		///
		/// Note that LDK will NOT check that expected fees were factored into this value. You MUST
		/// check that whatever fee you want has been included here or subtract it as required. Further,
		/// LDK will not stop you from forwarding more than you received.
		expected_outbound_amount_msat: u64,
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
	/// This event is generated when a payment has been successfully forwarded through us and a
	/// forwarding fee earned.
	PaymentForwarded {
		/// The incoming channel between the previous node and us. This is only `None` for events
		/// generated or serialized by versions prior to 0.0.107.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		prev_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The outgoing channel between the next node and us. This is only `None` for events
		/// generated or serialized by versions prior to 0.0.107.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		next_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The fee, in milli-satoshis, which was earned as a result of the payment.
		///
		/// Note that if we force-closed the channel over which we forwarded an HTLC while the HTLC
		/// was pending, the amount the next hop claimed will have been rounded down to the nearest
		/// whole satoshi. Thus, the fee calculated here may be higher than expected as we still
		/// claimed the full value in millisatoshis from the source. In this case,
		/// `claim_from_onchain_tx` will be set.
		///
		/// If the channel which sent us the payment has been force-closed, we will claim the funds
		/// via an on-chain transaction. In that case we do not yet know the on-chain transaction
		/// fees which we will spend and will instead set this to `None`. It is possible duplicate
		/// `PaymentForwarded` events are generated for the same payment iff `fee_earned_msat` is
		/// `None`.
		fee_earned_msat: crate::c_types::derived::COption_u64Z,
		/// If this is `true`, the forwarded HTLC was claimed by our counterparty via an on-chain
		/// transaction.
		claim_from_onchain_tx: bool,
	},
	/// Used to indicate that a channel with the given `channel_id` is ready to
	/// be used. This event is emitted either when the funding transaction has been confirmed
	/// on-chain, or, in case of a 0conf channel, when both parties have confirmed the channel
	/// establishment.
	ChannelReady {
		/// The channel_id of the channel that is ready.
		channel_id: crate::c_types::ThirtyTwoBytes,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for an inbound channel.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
		/// The node_id of the channel counterparty.
		counterparty_node_id: crate::c_types::PublicKey,
		/// The features that this channel will operate with.
		channel_type: crate::lightning::ln::features::ChannelTypeFeatures,
	},
	/// Used to indicate that a previously opened channel with the given `channel_id` is in the
	/// process of closure.
	ChannelClosed {
		/// The channel_id of the channel which has been closed. Note that on-chain transactions
		/// resolving the channel are likely still awaiting confirmation.
		channel_id: crate::c_types::ThirtyTwoBytes,
		/// The `user_channel_id` value passed in to [`ChannelManager::create_channel`] for outbound
		/// channels, or to [`ChannelManager::accept_inbound_channel`] for inbound channels if
		/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true. Otherwise
		/// `user_channel_id` will be randomized for inbound channels.
		/// This may be zero for inbound channels serialized prior to 0.0.113 and will always be
		/// zero for objects serialized with LDK versions prior to 0.0.102.
		///
		/// [`ChannelManager::create_channel`]: crate::ln::channelmanager::ChannelManager::create_channel
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
		user_channel_id: crate::c_types::U128,
		/// The reason the channel was closed.
		reason: crate::lightning::util::events::ClosureReason,
	},
	/// Used to indicate to the user that they can abandon the funding transaction and recycle the
	/// inputs for another purpose.
	DiscardFunding {
		/// The channel_id of the channel which has been closed.
		channel_id: crate::c_types::ThirtyTwoBytes,
		/// The full transaction received from the user
		transaction: crate::c_types::Transaction,
	},
	/// Indicates a request to open a new channel by a peer.
	///
	/// To accept the request, call [`ChannelManager::accept_inbound_channel`]. To reject the
	/// request, call [`ChannelManager::force_close_without_broadcasting_txn`].
	///
	/// The event is only triggered when a new open channel request is received and the
	/// [`UserConfig::manually_accept_inbound_channels`] config flag is set to true.
	///
	/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
	/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
	/// [`UserConfig::manually_accept_inbound_channels`]: crate::util::config::UserConfig::manually_accept_inbound_channels
	OpenChannelRequest {
		/// The temporary channel ID of the channel requested to be opened.
		///
		/// When responding to the request, the `temporary_channel_id` should be passed
		/// back to the ChannelManager through [`ChannelManager::accept_inbound_channel`] to accept,
		/// or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		temporary_channel_id: crate::c_types::ThirtyTwoBytes,
		/// The node_id of the counterparty requesting to open the channel.
		///
		/// When responding to the request, the `counterparty_node_id` should be passed
		/// back to the `ChannelManager` through [`ChannelManager::accept_inbound_channel`] to
		/// accept the request, or through [`ChannelManager::force_close_without_broadcasting_txn`] to reject the
		/// request.
		///
		/// [`ChannelManager::accept_inbound_channel`]: crate::ln::channelmanager::ChannelManager::accept_inbound_channel
		/// [`ChannelManager::force_close_without_broadcasting_txn`]: crate::ln::channelmanager::ChannelManager::force_close_without_broadcasting_txn
		counterparty_node_id: crate::c_types::PublicKey,
		/// The channel value of the requested channel.
		funding_satoshis: u64,
		/// Our starting balance in the channel if the request is accepted, in milli-satoshi.
		push_msat: u64,
		/// The features that this channel will operate with. If you reject the channel, a
		/// well-behaved counterparty may automatically re-attempt the channel with a new set of
		/// feature flags.
		///
		/// Note that if [`ChannelTypeFeatures::supports_scid_privacy`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.106.
		///
		/// Furthermore, note that if [`ChannelTypeFeatures::supports_zero_conf`] returns true on this type,
		/// the resulting [`ChannelManager`] will not be readable by versions of LDK prior to
		/// 0.0.107. Channels setting this type also need to get manually accepted via
		/// [`crate::ln::channelmanager::ChannelManager::accept_inbound_channel_from_trusted_peer_0conf`],
		/// or will be rejected otherwise.
		///
		/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
		channel_type: crate::lightning::ln::features::ChannelTypeFeatures,
	},
	/// Indicates that the HTLC was accepted, but could not be processed when or after attempting to
	/// forward it.
	///
	/// Some scenarios where this event may be sent include:
	/// * Insufficient capacity in the outbound channel
	/// * While waiting to forward the HTLC, the channel it is meant to be forwarded through closes
	/// * When an unknown SCID is requested for forwarding a payment.
	/// * Claiming an amount for an MPP payment that exceeds the HTLC total
	/// * The HTLC has timed out
	///
	/// This event, however, does not get generated if an HTLC fails to meet the forwarding
	/// requirements (i.e. insufficient fees paid, or a CLTV that is too soon).
	HTLCHandlingFailed {
		/// The channel over which the HTLC was received.
		prev_channel_id: crate::c_types::ThirtyTwoBytes,
		/// Destination of the HTLC that failed to be processed.
		failed_next_destination: crate::lightning::util::events::HTLCDestination,
	},
}
use lightning::util::events::Event as EventImport;
pub(crate) type nativeEvent = EventImport;

impl Event {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {ref temporary_channel_id, ref counterparty_node_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_value_satoshis_nonref = Clone::clone(channel_value_satoshis);
				let mut output_script_nonref = Clone::clone(output_script);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id_nonref.data,
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script_nonref.into_rust()),
					user_channel_id: user_channel_id_nonref.into(),
				}
			},
			Event::PaymentClaimable {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, ref via_channel_id, ref via_user_channel_id, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_null() { None } else { Some( { receiver_node_id_nonref.into_rust() }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut via_channel_id_nonref = Clone::clone(via_channel_id);
				let mut local_via_channel_id_nonref = if via_channel_id_nonref.data == [0; 32] { None } else { Some( { via_channel_id_nonref.data }) };
				let mut via_user_channel_id_nonref = Clone::clone(via_user_channel_id);
				let mut local_via_user_channel_id_nonref = { /* via_user_channel_id_nonref*/ let via_user_channel_id_nonref_opt = via_user_channel_id_nonref; { } if via_user_channel_id_nonref_opt.is_none() { None } else { Some({ via_user_channel_id_nonref_opt.take().into() }) } };
				nativeEvent::PaymentClaimable {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					amount_msat: amount_msat_nonref,
					purpose: purpose_nonref.into_native(),
					via_channel_id: local_via_channel_id_nonref,
					via_user_channel_id: local_via_user_channel_id_nonref,
				}
			},
			Event::PaymentClaimed {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_null() { None } else { Some( { receiver_node_id_nonref.into_rust() }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				nativeEvent::PaymentClaimed {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					amount_msat: amount_msat_nonref,
					purpose: purpose_nonref.into_native(),
				}
			},
			Event::PaymentSent {ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data) }) };
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut fee_paid_msat_nonref = Clone::clone(fee_paid_msat);
				let mut local_fee_paid_msat_nonref = if fee_paid_msat_nonref.is_some() { Some( { fee_paid_msat_nonref.take() }) } else { None };
				nativeEvent::PaymentSent {
					payment_id: local_payment_id_nonref,
					payment_preimage: ::lightning::ln::PaymentPreimage(payment_preimage_nonref.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					fee_paid_msat: local_fee_paid_msat_nonref,
				}
			},
			Event::PaymentFailed {ref payment_id, ref payment_hash, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				nativeEvent::PaymentFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
				}
			},
			Event::PaymentPathSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = if payment_hash_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentHash(payment_hash_nonref.data) }) };
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.into_rust().drain(..) { local_path_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeEvent::PaymentPathSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: local_payment_hash_nonref,
					path: local_path_nonref,
				}
			},
			Event::PaymentPathFailed {ref payment_id, ref payment_hash, ref payment_failed_permanently, ref failure, ref path, ref short_channel_id, ref retry, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data) }) };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut payment_failed_permanently_nonref = Clone::clone(payment_failed_permanently);
				let mut failure_nonref = Clone::clone(failure);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.into_rust().drain(..) { local_path_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_some() { Some( { short_channel_id_nonref.take() }) } else { None };
				let mut retry_nonref = Clone::clone(retry);
				let mut local_retry_nonref = if retry_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(retry_nonref.take_inner()) } }) };
				nativeEvent::PaymentPathFailed {
					payment_id: local_payment_id_nonref,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					payment_failed_permanently: payment_failed_permanently_nonref,
					failure: failure_nonref.into_native(),
					path: local_path_nonref,
					short_channel_id: local_short_channel_id_nonref,
					retry: local_retry_nonref,
				}
			},
			Event::ProbeSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.into_rust().drain(..) { local_path_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeEvent::ProbeSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					path: local_path_nonref,
				}
			},
			Event::ProbeFailed {ref payment_id, ref payment_hash, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.into_rust().drain(..) { local_path_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_some() { Some( { short_channel_id_nonref.take() }) } else { None };
				nativeEvent::ProbeFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id_nonref.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					path: local_path_nonref,
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			Event::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = Clone::clone(time_forwardable);
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: core::time::Duration::from_secs(time_forwardable_nonref),
				}
			},
			Event::HTLCIntercepted {ref intercept_id, ref requested_next_hop_scid, ref payment_hash, ref inbound_amount_msat, ref expected_outbound_amount_msat, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut requested_next_hop_scid_nonref = Clone::clone(requested_next_hop_scid);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut inbound_amount_msat_nonref = Clone::clone(inbound_amount_msat);
				let mut expected_outbound_amount_msat_nonref = Clone::clone(expected_outbound_amount_msat);
				nativeEvent::HTLCIntercepted {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id_nonref.data),
					requested_next_hop_scid: requested_next_hop_scid_nonref,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash_nonref.data),
					inbound_amount_msat: inbound_amount_msat_nonref,
					expected_outbound_amount_msat: expected_outbound_amount_msat_nonref,
				}
			},
			Event::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.into_rust().drain(..) { local_outputs_nonref.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs_nonref,
				}
			},
			Event::PaymentForwarded {ref prev_channel_id, ref next_channel_id, ref fee_earned_msat, ref claim_from_onchain_tx, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut local_prev_channel_id_nonref = if prev_channel_id_nonref.data == [0; 32] { None } else { Some( { prev_channel_id_nonref.data }) };
				let mut next_channel_id_nonref = Clone::clone(next_channel_id);
				let mut local_next_channel_id_nonref = if next_channel_id_nonref.data == [0; 32] { None } else { Some( { next_channel_id_nonref.data }) };
				let mut fee_earned_msat_nonref = Clone::clone(fee_earned_msat);
				let mut local_fee_earned_msat_nonref = if fee_earned_msat_nonref.is_some() { Some( { fee_earned_msat_nonref.take() }) } else { None };
				let mut claim_from_onchain_tx_nonref = Clone::clone(claim_from_onchain_tx);
				nativeEvent::PaymentForwarded {
					prev_channel_id: local_prev_channel_id_nonref,
					next_channel_id: local_next_channel_id_nonref,
					fee_earned_msat: local_fee_earned_msat_nonref,
					claim_from_onchain_tx: claim_from_onchain_tx_nonref,
				}
			},
			Event::ChannelReady {ref channel_id, ref user_channel_id, ref counterparty_node_id, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_type_nonref = Clone::clone(channel_type);
				nativeEvent::ChannelReady {
					channel_id: channel_id_nonref.data,
					user_channel_id: user_channel_id_nonref.into(),
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					channel_type: *unsafe { Box::from_raw(channel_type_nonref.take_inner()) },
				}
			},
			Event::ChannelClosed {ref channel_id, ref user_channel_id, ref reason, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut reason_nonref = Clone::clone(reason);
				nativeEvent::ChannelClosed {
					channel_id: channel_id_nonref.data,
					user_channel_id: user_channel_id_nonref.into(),
					reason: reason_nonref.into_native(),
				}
			},
			Event::DiscardFunding {ref channel_id, ref transaction, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut transaction_nonref = Clone::clone(transaction);
				nativeEvent::DiscardFunding {
					channel_id: channel_id_nonref.data,
					transaction: transaction_nonref.into_bitcoin(),
				}
			},
			Event::OpenChannelRequest {ref temporary_channel_id, ref counterparty_node_id, ref funding_satoshis, ref push_msat, ref channel_type, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_satoshis_nonref = Clone::clone(funding_satoshis);
				let mut push_msat_nonref = Clone::clone(push_msat);
				let mut channel_type_nonref = Clone::clone(channel_type);
				nativeEvent::OpenChannelRequest {
					temporary_channel_id: temporary_channel_id_nonref.data,
					counterparty_node_id: counterparty_node_id_nonref.into_rust(),
					funding_satoshis: funding_satoshis_nonref,
					push_msat: push_msat_nonref,
					channel_type: *unsafe { Box::from_raw(channel_type_nonref.take_inner()) },
				}
			},
			Event::HTLCHandlingFailed {ref prev_channel_id, ref failed_next_destination, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut failed_next_destination_nonref = Clone::clone(failed_next_destination);
				nativeEvent::HTLCHandlingFailed {
					prev_channel_id: prev_channel_id_nonref.data,
					failed_next_destination: failed_next_destination_nonref.into_native(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeEvent {
		match self {
			Event::FundingGenerationReady {mut temporary_channel_id, mut counterparty_node_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				nativeEvent::FundingGenerationReady {
					temporary_channel_id: temporary_channel_id.data,
					counterparty_node_id: counterparty_node_id.into_rust(),
					channel_value_satoshis: channel_value_satoshis,
					output_script: ::bitcoin::blockdata::script::Script::from(output_script.into_rust()),
					user_channel_id: user_channel_id.into(),
				}
			},
			Event::PaymentClaimable {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, mut via_channel_id, mut via_user_channel_id, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_null() { None } else { Some( { receiver_node_id.into_rust() }) };
				let mut local_via_channel_id = if via_channel_id.data == [0; 32] { None } else { Some( { via_channel_id.data }) };
				let mut local_via_user_channel_id = { /* via_user_channel_id*/ let via_user_channel_id_opt = via_user_channel_id; { } if via_user_channel_id_opt.is_none() { None } else { Some({ via_user_channel_id_opt.take().into() }) } };
				nativeEvent::PaymentClaimable {
					receiver_node_id: local_receiver_node_id,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					amount_msat: amount_msat,
					purpose: purpose.into_native(),
					via_channel_id: local_via_channel_id,
					via_user_channel_id: local_via_user_channel_id,
				}
			},
			Event::PaymentClaimed {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_null() { None } else { Some( { receiver_node_id.into_rust() }) };
				nativeEvent::PaymentClaimed {
					receiver_node_id: local_receiver_node_id,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					amount_msat: amount_msat,
					purpose: purpose.into_native(),
				}
			},
			Event::PaymentSent {mut payment_id, mut payment_preimage, mut payment_hash, mut fee_paid_msat, } => {
				let mut local_payment_id = if payment_id.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentId(payment_id.data) }) };
				let mut local_fee_paid_msat = if fee_paid_msat.is_some() { Some( { fee_paid_msat.take() }) } else { None };
				nativeEvent::PaymentSent {
					payment_id: local_payment_id,
					payment_preimage: ::lightning::ln::PaymentPreimage(payment_preimage.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					fee_paid_msat: local_fee_paid_msat,
				}
			},
			Event::PaymentFailed {mut payment_id, mut payment_hash, } => {
				nativeEvent::PaymentFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
				}
			},
			Event::PaymentPathSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_payment_hash = if payment_hash.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentHash(payment_hash.data) }) };
				let mut local_path = Vec::new(); for mut item in path.into_rust().drain(..) { local_path.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeEvent::PaymentPathSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: local_payment_hash,
					path: local_path,
				}
			},
			Event::PaymentPathFailed {mut payment_id, mut payment_hash, mut payment_failed_permanently, mut failure, mut path, mut short_channel_id, mut retry, } => {
				let mut local_payment_id = if payment_id.data == [0; 32] { None } else { Some( { ::lightning::ln::channelmanager::PaymentId(payment_id.data) }) };
				let mut local_path = Vec::new(); for mut item in path.into_rust().drain(..) { local_path.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut local_short_channel_id = if short_channel_id.is_some() { Some( { short_channel_id.take() }) } else { None };
				let mut local_retry = if retry.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(retry.take_inner()) } }) };
				nativeEvent::PaymentPathFailed {
					payment_id: local_payment_id,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					payment_failed_permanently: payment_failed_permanently,
					failure: failure.into_native(),
					path: local_path,
					short_channel_id: local_short_channel_id,
					retry: local_retry,
				}
			},
			Event::ProbeSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_path = Vec::new(); for mut item in path.into_rust().drain(..) { local_path.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeEvent::ProbeSuccessful {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					path: local_path,
				}
			},
			Event::ProbeFailed {mut payment_id, mut payment_hash, mut path, mut short_channel_id, } => {
				let mut local_path = Vec::new(); for mut item in path.into_rust().drain(..) { local_path.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut local_short_channel_id = if short_channel_id.is_some() { Some( { short_channel_id.take() }) } else { None };
				nativeEvent::ProbeFailed {
					payment_id: ::lightning::ln::channelmanager::PaymentId(payment_id.data),
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					path: local_path,
					short_channel_id: local_short_channel_id,
				}
			},
			Event::PendingHTLCsForwardable {mut time_forwardable, } => {
				nativeEvent::PendingHTLCsForwardable {
					time_forwardable: core::time::Duration::from_secs(time_forwardable),
				}
			},
			Event::HTLCIntercepted {mut intercept_id, mut requested_next_hop_scid, mut payment_hash, mut inbound_amount_msat, mut expected_outbound_amount_msat, } => {
				nativeEvent::HTLCIntercepted {
					intercept_id: ::lightning::ln::channelmanager::InterceptId(intercept_id.data),
					requested_next_hop_scid: requested_next_hop_scid,
					payment_hash: ::lightning::ln::PaymentHash(payment_hash.data),
					inbound_amount_msat: inbound_amount_msat,
					expected_outbound_amount_msat: expected_outbound_amount_msat,
				}
			},
			Event::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_native() }); };
				nativeEvent::SpendableOutputs {
					outputs: local_outputs,
				}
			},
			Event::PaymentForwarded {mut prev_channel_id, mut next_channel_id, mut fee_earned_msat, mut claim_from_onchain_tx, } => {
				let mut local_prev_channel_id = if prev_channel_id.data == [0; 32] { None } else { Some( { prev_channel_id.data }) };
				let mut local_next_channel_id = if next_channel_id.data == [0; 32] { None } else { Some( { next_channel_id.data }) };
				let mut local_fee_earned_msat = if fee_earned_msat.is_some() { Some( { fee_earned_msat.take() }) } else { None };
				nativeEvent::PaymentForwarded {
					prev_channel_id: local_prev_channel_id,
					next_channel_id: local_next_channel_id,
					fee_earned_msat: local_fee_earned_msat,
					claim_from_onchain_tx: claim_from_onchain_tx,
				}
			},
			Event::ChannelReady {mut channel_id, mut user_channel_id, mut counterparty_node_id, mut channel_type, } => {
				nativeEvent::ChannelReady {
					channel_id: channel_id.data,
					user_channel_id: user_channel_id.into(),
					counterparty_node_id: counterparty_node_id.into_rust(),
					channel_type: *unsafe { Box::from_raw(channel_type.take_inner()) },
				}
			},
			Event::ChannelClosed {mut channel_id, mut user_channel_id, mut reason, } => {
				nativeEvent::ChannelClosed {
					channel_id: channel_id.data,
					user_channel_id: user_channel_id.into(),
					reason: reason.into_native(),
				}
			},
			Event::DiscardFunding {mut channel_id, mut transaction, } => {
				nativeEvent::DiscardFunding {
					channel_id: channel_id.data,
					transaction: transaction.into_bitcoin(),
				}
			},
			Event::OpenChannelRequest {mut temporary_channel_id, mut counterparty_node_id, mut funding_satoshis, mut push_msat, mut channel_type, } => {
				nativeEvent::OpenChannelRequest {
					temporary_channel_id: temporary_channel_id.data,
					counterparty_node_id: counterparty_node_id.into_rust(),
					funding_satoshis: funding_satoshis,
					push_msat: push_msat,
					channel_type: *unsafe { Box::from_raw(channel_type.take_inner()) },
				}
			},
			Event::HTLCHandlingFailed {mut prev_channel_id, mut failed_next_destination, } => {
				nativeEvent::HTLCHandlingFailed {
					prev_channel_id: prev_channel_id.data,
					failed_next_destination: failed_next_destination.into_native(),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {ref temporary_channel_id, ref counterparty_node_id, ref channel_value_satoshis, ref output_script, ref user_channel_id, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_value_satoshis_nonref = Clone::clone(channel_value_satoshis);
				let mut output_script_nonref = Clone::clone(output_script);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id_nonref },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					channel_value_satoshis: channel_value_satoshis_nonref,
					output_script: output_script_nonref.into_bytes().into(),
					user_channel_id: user_channel_id_nonref.into(),
				}
			},
			nativeEvent::PaymentClaimable {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, ref via_channel_id, ref via_user_channel_id, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id_nonref.unwrap())) } };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				let mut via_channel_id_nonref = Clone::clone(via_channel_id);
				let mut local_via_channel_id_nonref = if via_channel_id_nonref.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (via_channel_id_nonref.unwrap()) } } };
				let mut via_user_channel_id_nonref = Clone::clone(via_user_channel_id);
				let mut local_via_user_channel_id_nonref = if via_user_channel_id_nonref.is_none() { crate::c_types::derived::COption_u128Z::None } else { crate::c_types::derived::COption_u128Z::Some( { via_user_channel_id_nonref.unwrap().into() }) };
				Event::PaymentClaimable {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					amount_msat: amount_msat_nonref,
					purpose: crate::lightning::util::events::PaymentPurpose::native_into(purpose_nonref),
					via_channel_id: local_via_channel_id_nonref,
					via_user_channel_id: local_via_user_channel_id_nonref,
				}
			},
			nativeEvent::PaymentClaimed {ref receiver_node_id, ref payment_hash, ref amount_msat, ref purpose, } => {
				let mut receiver_node_id_nonref = Clone::clone(receiver_node_id);
				let mut local_receiver_node_id_nonref = if receiver_node_id_nonref.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id_nonref.unwrap())) } };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut amount_msat_nonref = Clone::clone(amount_msat);
				let mut purpose_nonref = Clone::clone(purpose);
				Event::PaymentClaimed {
					receiver_node_id: local_receiver_node_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					amount_msat: amount_msat_nonref,
					purpose: crate::lightning::util::events::PaymentPurpose::native_into(purpose_nonref),
				}
			},
			nativeEvent::PaymentSent {ref payment_id, ref payment_preimage, ref payment_hash, ref fee_paid_msat, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_id_nonref.unwrap()).0 } } };
				let mut payment_preimage_nonref = Clone::clone(payment_preimage);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut fee_paid_msat_nonref = Clone::clone(fee_paid_msat);
				let mut local_fee_paid_msat_nonref = if fee_paid_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_paid_msat_nonref.unwrap() }) };
				Event::PaymentSent {
					payment_id: local_payment_id_nonref,
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					fee_paid_msat: local_fee_paid_msat_nonref,
				}
			},
			nativeEvent::PaymentFailed {ref payment_id, ref payment_hash, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				Event::PaymentFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
				}
			},
			nativeEvent::PaymentPathSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut local_payment_hash_nonref = if payment_hash_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_hash_nonref.unwrap()).0 } } };
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.drain(..) { local_path_nonref.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				Event::PaymentPathSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: local_payment_hash_nonref,
					path: local_path_nonref.into(),
				}
			},
			nativeEvent::PaymentPathFailed {ref payment_id, ref payment_hash, ref payment_failed_permanently, ref failure, ref path, ref short_channel_id, ref retry, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut local_payment_id_nonref = if payment_id_nonref.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_id_nonref.unwrap()).0 } } };
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut payment_failed_permanently_nonref = Clone::clone(payment_failed_permanently);
				let mut failure_nonref = Clone::clone(failure);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.drain(..) { local_path_nonref.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id_nonref.unwrap() }) };
				let mut retry_nonref = Clone::clone(retry);
				let mut local_retry_nonref = crate::lightning::routing::router::RouteParameters { inner: if retry_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((retry_nonref.unwrap())) } }, is_owned: true };
				Event::PaymentPathFailed {
					payment_id: local_payment_id_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					payment_failed_permanently: payment_failed_permanently_nonref,
					failure: crate::lightning::util::events::PathFailure::native_into(failure_nonref),
					path: local_path_nonref.into(),
					short_channel_id: local_short_channel_id_nonref,
					retry: local_retry_nonref,
				}
			},
			nativeEvent::ProbeSuccessful {ref payment_id, ref payment_hash, ref path, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.drain(..) { local_path_nonref.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				Event::ProbeSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					path: local_path_nonref.into(),
				}
			},
			nativeEvent::ProbeFailed {ref payment_id, ref payment_hash, ref path, ref short_channel_id, } => {
				let mut payment_id_nonref = Clone::clone(payment_id);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut path_nonref = Clone::clone(path);
				let mut local_path_nonref = Vec::new(); for mut item in path_nonref.drain(..) { local_path_nonref.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut short_channel_id_nonref = Clone::clone(short_channel_id);
				let mut local_short_channel_id_nonref = if short_channel_id_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id_nonref.unwrap() }) };
				Event::ProbeFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id_nonref.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					path: local_path_nonref.into(),
					short_channel_id: local_short_channel_id_nonref,
				}
			},
			nativeEvent::PendingHTLCsForwardable {ref time_forwardable, } => {
				let mut time_forwardable_nonref = Clone::clone(time_forwardable);
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable_nonref.as_secs(),
				}
			},
			nativeEvent::HTLCIntercepted {ref intercept_id, ref requested_next_hop_scid, ref payment_hash, ref inbound_amount_msat, ref expected_outbound_amount_msat, } => {
				let mut intercept_id_nonref = Clone::clone(intercept_id);
				let mut requested_next_hop_scid_nonref = Clone::clone(requested_next_hop_scid);
				let mut payment_hash_nonref = Clone::clone(payment_hash);
				let mut inbound_amount_msat_nonref = Clone::clone(inbound_amount_msat);
				let mut expected_outbound_amount_msat_nonref = Clone::clone(expected_outbound_amount_msat);
				Event::HTLCIntercepted {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id_nonref.0 },
					requested_next_hop_scid: requested_next_hop_scid_nonref,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash_nonref.0 },
					inbound_amount_msat: inbound_amount_msat_nonref,
					expected_outbound_amount_msat: expected_outbound_amount_msat_nonref,
				}
			},
			nativeEvent::SpendableOutputs {ref outputs, } => {
				let mut outputs_nonref = Clone::clone(outputs);
				let mut local_outputs_nonref = Vec::new(); for mut item in outputs_nonref.drain(..) { local_outputs_nonref.push( { crate::lightning::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs_nonref.into(),
				}
			},
			nativeEvent::PaymentForwarded {ref prev_channel_id, ref next_channel_id, ref fee_earned_msat, ref claim_from_onchain_tx, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut local_prev_channel_id_nonref = if prev_channel_id_nonref.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (prev_channel_id_nonref.unwrap()) } } };
				let mut next_channel_id_nonref = Clone::clone(next_channel_id);
				let mut local_next_channel_id_nonref = if next_channel_id_nonref.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (next_channel_id_nonref.unwrap()) } } };
				let mut fee_earned_msat_nonref = Clone::clone(fee_earned_msat);
				let mut local_fee_earned_msat_nonref = if fee_earned_msat_nonref.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_earned_msat_nonref.unwrap() }) };
				let mut claim_from_onchain_tx_nonref = Clone::clone(claim_from_onchain_tx);
				Event::PaymentForwarded {
					prev_channel_id: local_prev_channel_id_nonref,
					next_channel_id: local_next_channel_id_nonref,
					fee_earned_msat: local_fee_earned_msat_nonref,
					claim_from_onchain_tx: claim_from_onchain_tx_nonref,
				}
			},
			nativeEvent::ChannelReady {ref channel_id, ref user_channel_id, ref counterparty_node_id, ref channel_type, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut channel_type_nonref = Clone::clone(channel_type);
				Event::ChannelReady {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id_nonref },
					user_channel_id: user_channel_id_nonref.into(),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					channel_type: crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type_nonref), is_owned: true },
				}
			},
			nativeEvent::ChannelClosed {ref channel_id, ref user_channel_id, ref reason, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut user_channel_id_nonref = Clone::clone(user_channel_id);
				let mut reason_nonref = Clone::clone(reason);
				Event::ChannelClosed {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id_nonref },
					user_channel_id: user_channel_id_nonref.into(),
					reason: crate::lightning::util::events::ClosureReason::native_into(reason_nonref),
				}
			},
			nativeEvent::DiscardFunding {ref channel_id, ref transaction, } => {
				let mut channel_id_nonref = Clone::clone(channel_id);
				let mut transaction_nonref = Clone::clone(transaction);
				Event::DiscardFunding {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id_nonref },
					transaction: crate::c_types::Transaction::from_bitcoin(&transaction_nonref),
				}
			},
			nativeEvent::OpenChannelRequest {ref temporary_channel_id, ref counterparty_node_id, ref funding_satoshis, ref push_msat, ref channel_type, } => {
				let mut temporary_channel_id_nonref = Clone::clone(temporary_channel_id);
				let mut counterparty_node_id_nonref = Clone::clone(counterparty_node_id);
				let mut funding_satoshis_nonref = Clone::clone(funding_satoshis);
				let mut push_msat_nonref = Clone::clone(push_msat);
				let mut channel_type_nonref = Clone::clone(channel_type);
				Event::OpenChannelRequest {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id_nonref },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id_nonref),
					funding_satoshis: funding_satoshis_nonref,
					push_msat: push_msat_nonref,
					channel_type: crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type_nonref), is_owned: true },
				}
			},
			nativeEvent::HTLCHandlingFailed {ref prev_channel_id, ref failed_next_destination, } => {
				let mut prev_channel_id_nonref = Clone::clone(prev_channel_id);
				let mut failed_next_destination_nonref = Clone::clone(failed_next_destination);
				Event::HTLCHandlingFailed {
					prev_channel_id: crate::c_types::ThirtyTwoBytes { data: prev_channel_id_nonref },
					failed_next_destination: crate::lightning::util::events::HTLCDestination::native_into(failed_next_destination_nonref),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeEvent) -> Self {
		match native {
			nativeEvent::FundingGenerationReady {mut temporary_channel_id, mut counterparty_node_id, mut channel_value_satoshis, mut output_script, mut user_channel_id, } => {
				Event::FundingGenerationReady {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					channel_value_satoshis: channel_value_satoshis,
					output_script: output_script.into_bytes().into(),
					user_channel_id: user_channel_id.into(),
				}
			},
			nativeEvent::PaymentClaimable {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, mut via_channel_id, mut via_user_channel_id, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id.unwrap())) } };
				let mut local_via_channel_id = if via_channel_id.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (via_channel_id.unwrap()) } } };
				let mut local_via_user_channel_id = if via_user_channel_id.is_none() { crate::c_types::derived::COption_u128Z::None } else { crate::c_types::derived::COption_u128Z::Some( { via_user_channel_id.unwrap().into() }) };
				Event::PaymentClaimable {
					receiver_node_id: local_receiver_node_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					amount_msat: amount_msat,
					purpose: crate::lightning::util::events::PaymentPurpose::native_into(purpose),
					via_channel_id: local_via_channel_id,
					via_user_channel_id: local_via_user_channel_id,
				}
			},
			nativeEvent::PaymentClaimed {mut receiver_node_id, mut payment_hash, mut amount_msat, mut purpose, } => {
				let mut local_receiver_node_id = if receiver_node_id.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(receiver_node_id.unwrap())) } };
				Event::PaymentClaimed {
					receiver_node_id: local_receiver_node_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					amount_msat: amount_msat,
					purpose: crate::lightning::util::events::PaymentPurpose::native_into(purpose),
				}
			},
			nativeEvent::PaymentSent {mut payment_id, mut payment_preimage, mut payment_hash, mut fee_paid_msat, } => {
				let mut local_payment_id = if payment_id.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_id.unwrap()).0 } } };
				let mut local_fee_paid_msat = if fee_paid_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_paid_msat.unwrap() }) };
				Event::PaymentSent {
					payment_id: local_payment_id,
					payment_preimage: crate::c_types::ThirtyTwoBytes { data: payment_preimage.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					fee_paid_msat: local_fee_paid_msat,
				}
			},
			nativeEvent::PaymentFailed {mut payment_id, mut payment_hash, } => {
				Event::PaymentFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
				}
			},
			nativeEvent::PaymentPathSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_payment_hash = if payment_hash.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_hash.unwrap()).0 } } };
				let mut local_path = Vec::new(); for mut item in path.drain(..) { local_path.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				Event::PaymentPathSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: local_payment_hash,
					path: local_path.into(),
				}
			},
			nativeEvent::PaymentPathFailed {mut payment_id, mut payment_hash, mut payment_failed_permanently, mut failure, mut path, mut short_channel_id, mut retry, } => {
				let mut local_payment_id = if payment_id.is_none() { crate::c_types::ThirtyTwoBytes::null() } else {  { crate::c_types::ThirtyTwoBytes { data: (payment_id.unwrap()).0 } } };
				let mut local_path = Vec::new(); for mut item in path.drain(..) { local_path.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut local_short_channel_id = if short_channel_id.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id.unwrap() }) };
				let mut local_retry = crate::lightning::routing::router::RouteParameters { inner: if retry.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((retry.unwrap())) } }, is_owned: true };
				Event::PaymentPathFailed {
					payment_id: local_payment_id,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					payment_failed_permanently: payment_failed_permanently,
					failure: crate::lightning::util::events::PathFailure::native_into(failure),
					path: local_path.into(),
					short_channel_id: local_short_channel_id,
					retry: local_retry,
				}
			},
			nativeEvent::ProbeSuccessful {mut payment_id, mut payment_hash, mut path, } => {
				let mut local_path = Vec::new(); for mut item in path.drain(..) { local_path.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				Event::ProbeSuccessful {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					path: local_path.into(),
				}
			},
			nativeEvent::ProbeFailed {mut payment_id, mut payment_hash, mut path, mut short_channel_id, } => {
				let mut local_path = Vec::new(); for mut item in path.drain(..) { local_path.push( { crate::lightning::routing::router::RouteHop { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut local_short_channel_id = if short_channel_id.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { short_channel_id.unwrap() }) };
				Event::ProbeFailed {
					payment_id: crate::c_types::ThirtyTwoBytes { data: payment_id.0 },
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					path: local_path.into(),
					short_channel_id: local_short_channel_id,
				}
			},
			nativeEvent::PendingHTLCsForwardable {mut time_forwardable, } => {
				Event::PendingHTLCsForwardable {
					time_forwardable: time_forwardable.as_secs(),
				}
			},
			nativeEvent::HTLCIntercepted {mut intercept_id, mut requested_next_hop_scid, mut payment_hash, mut inbound_amount_msat, mut expected_outbound_amount_msat, } => {
				Event::HTLCIntercepted {
					intercept_id: crate::c_types::ThirtyTwoBytes { data: intercept_id.0 },
					requested_next_hop_scid: requested_next_hop_scid,
					payment_hash: crate::c_types::ThirtyTwoBytes { data: payment_hash.0 },
					inbound_amount_msat: inbound_amount_msat,
					expected_outbound_amount_msat: expected_outbound_amount_msat,
				}
			},
			nativeEvent::SpendableOutputs {mut outputs, } => {
				let mut local_outputs = Vec::new(); for mut item in outputs.drain(..) { local_outputs.push( { crate::lightning::chain::keysinterface::SpendableOutputDescriptor::native_into(item) }); };
				Event::SpendableOutputs {
					outputs: local_outputs.into(),
				}
			},
			nativeEvent::PaymentForwarded {mut prev_channel_id, mut next_channel_id, mut fee_earned_msat, mut claim_from_onchain_tx, } => {
				let mut local_prev_channel_id = if prev_channel_id.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (prev_channel_id.unwrap()) } } };
				let mut local_next_channel_id = if next_channel_id.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (next_channel_id.unwrap()) } } };
				let mut local_fee_earned_msat = if fee_earned_msat.is_none() { crate::c_types::derived::COption_u64Z::None } else { crate::c_types::derived::COption_u64Z::Some( { fee_earned_msat.unwrap() }) };
				Event::PaymentForwarded {
					prev_channel_id: local_prev_channel_id,
					next_channel_id: local_next_channel_id,
					fee_earned_msat: local_fee_earned_msat,
					claim_from_onchain_tx: claim_from_onchain_tx,
				}
			},
			nativeEvent::ChannelReady {mut channel_id, mut user_channel_id, mut counterparty_node_id, mut channel_type, } => {
				Event::ChannelReady {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id },
					user_channel_id: user_channel_id.into(),
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					channel_type: crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type), is_owned: true },
				}
			},
			nativeEvent::ChannelClosed {mut channel_id, mut user_channel_id, mut reason, } => {
				Event::ChannelClosed {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id },
					user_channel_id: user_channel_id.into(),
					reason: crate::lightning::util::events::ClosureReason::native_into(reason),
				}
			},
			nativeEvent::DiscardFunding {mut channel_id, mut transaction, } => {
				Event::DiscardFunding {
					channel_id: crate::c_types::ThirtyTwoBytes { data: channel_id },
					transaction: crate::c_types::Transaction::from_bitcoin(&transaction),
				}
			},
			nativeEvent::OpenChannelRequest {mut temporary_channel_id, mut counterparty_node_id, mut funding_satoshis, mut push_msat, mut channel_type, } => {
				Event::OpenChannelRequest {
					temporary_channel_id: crate::c_types::ThirtyTwoBytes { data: temporary_channel_id },
					counterparty_node_id: crate::c_types::PublicKey::from_rust(&counterparty_node_id),
					funding_satoshis: funding_satoshis,
					push_msat: push_msat,
					channel_type: crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(channel_type), is_owned: true },
				}
			},
			nativeEvent::HTLCHandlingFailed {mut prev_channel_id, mut failed_next_destination, } => {
				Event::HTLCHandlingFailed {
					prev_channel_id: crate::c_types::ThirtyTwoBytes { data: prev_channel_id },
					failed_next_destination: crate::lightning::util::events::HTLCDestination::native_into(failed_next_destination),
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
/// Utility method to constructs a new FundingGenerationReady-variant Event
pub extern "C" fn Event_funding_generation_ready(temporary_channel_id: crate::c_types::ThirtyTwoBytes, counterparty_node_id: crate::c_types::PublicKey, channel_value_satoshis: u64, output_script: crate::c_types::derived::CVec_u8Z, user_channel_id: crate::c_types::U128) -> Event {
	Event::FundingGenerationReady {
		temporary_channel_id,
		counterparty_node_id,
		channel_value_satoshis,
		output_script,
		user_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentClaimable-variant Event
pub extern "C" fn Event_payment_claimable(receiver_node_id: crate::c_types::PublicKey, payment_hash: crate::c_types::ThirtyTwoBytes, amount_msat: u64, purpose: crate::lightning::util::events::PaymentPurpose, via_channel_id: crate::c_types::ThirtyTwoBytes, via_user_channel_id: crate::c_types::derived::COption_u128Z) -> Event {
	Event::PaymentClaimable {
		receiver_node_id,
		payment_hash,
		amount_msat,
		purpose,
		via_channel_id,
		via_user_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentClaimed-variant Event
pub extern "C" fn Event_payment_claimed(receiver_node_id: crate::c_types::PublicKey, payment_hash: crate::c_types::ThirtyTwoBytes, amount_msat: u64, purpose: crate::lightning::util::events::PaymentPurpose) -> Event {
	Event::PaymentClaimed {
		receiver_node_id,
		payment_hash,
		amount_msat,
		purpose,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentSent-variant Event
pub extern "C" fn Event_payment_sent(payment_id: crate::c_types::ThirtyTwoBytes, payment_preimage: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, fee_paid_msat: crate::c_types::derived::COption_u64Z) -> Event {
	Event::PaymentSent {
		payment_id,
		payment_preimage,
		payment_hash,
		fee_paid_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentFailed-variant Event
pub extern "C" fn Event_payment_failed(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes) -> Event {
	Event::PaymentFailed {
		payment_id,
		payment_hash,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentPathSuccessful-variant Event
pub extern "C" fn Event_payment_path_successful(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, path: crate::c_types::derived::CVec_RouteHopZ) -> Event {
	Event::PaymentPathSuccessful {
		payment_id,
		payment_hash,
		path,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentPathFailed-variant Event
pub extern "C" fn Event_payment_path_failed(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, payment_failed_permanently: bool, failure: crate::lightning::util::events::PathFailure, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: crate::c_types::derived::COption_u64Z, retry: crate::lightning::routing::router::RouteParameters) -> Event {
	Event::PaymentPathFailed {
		payment_id,
		payment_hash,
		payment_failed_permanently,
		failure,
		path,
		short_channel_id,
		retry,
	}
}
#[no_mangle]
/// Utility method to constructs a new ProbeSuccessful-variant Event
pub extern "C" fn Event_probe_successful(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, path: crate::c_types::derived::CVec_RouteHopZ) -> Event {
	Event::ProbeSuccessful {
		payment_id,
		payment_hash,
		path,
	}
}
#[no_mangle]
/// Utility method to constructs a new ProbeFailed-variant Event
pub extern "C" fn Event_probe_failed(payment_id: crate::c_types::ThirtyTwoBytes, payment_hash: crate::c_types::ThirtyTwoBytes, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: crate::c_types::derived::COption_u64Z) -> Event {
	Event::ProbeFailed {
		payment_id,
		payment_hash,
		path,
		short_channel_id,
	}
}
#[no_mangle]
/// Utility method to constructs a new PendingHTLCsForwardable-variant Event
pub extern "C" fn Event_pending_htlcs_forwardable(time_forwardable: u64) -> Event {
	Event::PendingHTLCsForwardable {
		time_forwardable,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCIntercepted-variant Event
pub extern "C" fn Event_htlcintercepted(intercept_id: crate::c_types::ThirtyTwoBytes, requested_next_hop_scid: u64, payment_hash: crate::c_types::ThirtyTwoBytes, inbound_amount_msat: u64, expected_outbound_amount_msat: u64) -> Event {
	Event::HTLCIntercepted {
		intercept_id,
		requested_next_hop_scid,
		payment_hash,
		inbound_amount_msat,
		expected_outbound_amount_msat,
	}
}
#[no_mangle]
/// Utility method to constructs a new SpendableOutputs-variant Event
pub extern "C" fn Event_spendable_outputs(outputs: crate::c_types::derived::CVec_SpendableOutputDescriptorZ) -> Event {
	Event::SpendableOutputs {
		outputs,
	}
}
#[no_mangle]
/// Utility method to constructs a new PaymentForwarded-variant Event
pub extern "C" fn Event_payment_forwarded(prev_channel_id: crate::c_types::ThirtyTwoBytes, next_channel_id: crate::c_types::ThirtyTwoBytes, fee_earned_msat: crate::c_types::derived::COption_u64Z, claim_from_onchain_tx: bool) -> Event {
	Event::PaymentForwarded {
		prev_channel_id,
		next_channel_id,
		fee_earned_msat,
		claim_from_onchain_tx,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelReady-variant Event
pub extern "C" fn Event_channel_ready(channel_id: crate::c_types::ThirtyTwoBytes, user_channel_id: crate::c_types::U128, counterparty_node_id: crate::c_types::PublicKey, channel_type: crate::lightning::ln::features::ChannelTypeFeatures) -> Event {
	Event::ChannelReady {
		channel_id,
		user_channel_id,
		counterparty_node_id,
		channel_type,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelClosed-variant Event
pub extern "C" fn Event_channel_closed(channel_id: crate::c_types::ThirtyTwoBytes, user_channel_id: crate::c_types::U128, reason: crate::lightning::util::events::ClosureReason) -> Event {
	Event::ChannelClosed {
		channel_id,
		user_channel_id,
		reason,
	}
}
#[no_mangle]
/// Utility method to constructs a new DiscardFunding-variant Event
pub extern "C" fn Event_discard_funding(channel_id: crate::c_types::ThirtyTwoBytes, transaction: crate::c_types::Transaction) -> Event {
	Event::DiscardFunding {
		channel_id,
		transaction,
	}
}
#[no_mangle]
/// Utility method to constructs a new OpenChannelRequest-variant Event
pub extern "C" fn Event_open_channel_request(temporary_channel_id: crate::c_types::ThirtyTwoBytes, counterparty_node_id: crate::c_types::PublicKey, funding_satoshis: u64, push_msat: u64, channel_type: crate::lightning::ln::features::ChannelTypeFeatures) -> Event {
	Event::OpenChannelRequest {
		temporary_channel_id,
		counterparty_node_id,
		funding_satoshis,
		push_msat,
		channel_type,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCHandlingFailed-variant Event
pub extern "C" fn Event_htlchandling_failed(prev_channel_id: crate::c_types::ThirtyTwoBytes, failed_next_destination: crate::lightning::util::events::HTLCDestination) -> Event {
	Event::HTLCHandlingFailed {
		prev_channel_id,
		failed_next_destination,
	}
}
/// Checks if two Events contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Event_eq(a: &Event, b: &Event) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the Event object into a byte array which can be read by Event_read
pub extern "C" fn Event_write(obj: &crate::lightning::util::events::Event) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a Event from a byte array, created by Event_write
pub extern "C" fn Event_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_COption_EventZDecodeErrorZ {
	let res: Result<Option<lightning::util::events::Event>, lightning::ln::msgs::DecodeError> = crate::c_types::maybe_deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_res_0 = if o.is_none() { crate::c_types::derived::COption_EventZ::None } else { crate::c_types::derived::COption_EventZ::Some( { crate::lightning::util::events::Event::native_into(o.unwrap()) }) }; local_res_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// An event generated by ChannelManager which indicates a message should be sent to a peer (or
/// broadcast to most peers).
/// These events are handled by PeerManager::process_events if you are using a PeerManager.
#[derive(Clone)]
#[must_use]
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
	/// Used to indicate that a channel_ready message should be sent to the peer with the given node_id.
	SendChannelReady {
		/// The node_id of the node which should receive these message(s)
		node_id: crate::c_types::PublicKey,
		/// The channel_ready message which should be sent.
		msg: crate::lightning::ln::msgs::ChannelReady,
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
	/// Used to send a channel_announcement and channel_update to a specific peer, likely on
	/// initial connection to ensure our peers know about our channels.
	SendChannelAnnouncement {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
		/// The channel_announcement which should be sent.
		msg: crate::lightning::ln::msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		update_msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_announcement and channel_update should be broadcast to all
	/// peers (except the peer with node_id either msg.contents.node_id_1 or msg.contents.node_id_2).
	///
	/// Note that after doing so, you very likely (unless you did so very recently) want to
	/// broadcast a node_announcement (e.g. via [`PeerManager::broadcast_node_announcement`]). This
	/// ensures that any nodes which see our channel_announcement also have a relevant
	/// node_announcement, including relevant feature flags which may be important for routing
	/// through or to us.
	///
	/// [`PeerManager::broadcast_node_announcement`]: crate::ln::peer_handler::PeerManager::broadcast_node_announcement
	BroadcastChannelAnnouncement {
		/// The channel_announcement which should be sent.
		msg: crate::lightning::ln::msgs::ChannelAnnouncement,
		/// The followup channel_update which should be sent.
		///
		/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None
		update_msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a channel_update should be broadcast to all peers.
	BroadcastChannelUpdate {
		/// The channel_update which should be sent.
		msg: crate::lightning::ln::msgs::ChannelUpdate,
	},
	/// Used to indicate that a node_announcement should be broadcast to all peers.
	BroadcastNodeAnnouncement {
		/// The node_announcement which should be sent.
		msg: crate::lightning::ln::msgs::NodeAnnouncement,
	},
	/// Used to indicate that a channel_update should be sent to a single peer.
	/// In contrast to [`Self::BroadcastChannelUpdate`], this is used when the channel is a
	/// private channel and we shouldn't be informing all of our peers of channel parameters.
	SendChannelUpdate {
		/// The node_id of the node which should receive this message
		node_id: crate::c_types::PublicKey,
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
	/// Sends a timestamp filter for inbound gossip. This should be sent on each new connection to
	/// enable receiving gossip messages from the peer.
	SendGossipTimestampFilter {
		/// The node_id of this message recipient
		node_id: crate::c_types::PublicKey,
		/// The gossip_timestamp_filter which should be sent.
		msg: crate::lightning::ln::msgs::GossipTimestampFilter,
	},
}
use lightning::util::events::MessageSendEvent as MessageSendEventImport;
pub(crate) type nativeMessageSendEvent = MessageSendEventImport;

impl MessageSendEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeMessageSendEvent {
		match self {
			MessageSendEvent::SendAcceptChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendAcceptChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendOpenChannel {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendFundingCreated {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendFundingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReady {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelReady {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendAnnouncementSignatures {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut updates_nonref = Clone::clone(updates);
				nativeMessageSendEvent::UpdateHTLCs {
					node_id: node_id_nonref.into_rust(),
					updates: *unsafe { Box::from_raw(updates_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendRevokeAndACK {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendClosingSigned {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendShutdown {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelReestablish {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelAnnouncement {ref node_id, ref msg, ref update_msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				nativeMessageSendEvent::SendChannelAnnouncement {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				let mut local_update_msg_nonref = if update_msg_nonref.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(update_msg_nonref.take_inner()) } }) };
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
					update_msg: local_update_msg_nonref,
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelUpdate {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelUpdate {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut action_nonref = Clone::clone(action);
				nativeMessageSendEvent::HandleError {
					node_id: node_id_nonref.into_rust(),
					action: action_nonref.into_native(),
				}
			},
			MessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendChannelRangeQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendShortIdsQuery {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendReplyChannelRange {
					node_id: node_id_nonref.into_rust(),
					msg: *unsafe { Box::from_raw(msg_nonref.take_inner()) },
				}
			},
			MessageSendEvent::SendGossipTimestampFilter {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				nativeMessageSendEvent::SendGossipTimestampFilter {
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
			MessageSendEvent::SendChannelReady {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelReady {
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
			MessageSendEvent::SendChannelAnnouncement {mut node_id, mut msg, mut update_msg, } => {
				nativeMessageSendEvent::SendChannelAnnouncement {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: *unsafe { Box::from_raw(update_msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				let mut local_update_msg = if update_msg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(update_msg.take_inner()) } }) };
				nativeMessageSendEvent::BroadcastChannelAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
					update_msg: local_update_msg,
				}
			},
			MessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				nativeMessageSendEvent::BroadcastChannelUpdate {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				nativeMessageSendEvent::BroadcastNodeAnnouncement {
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::SendChannelUpdate {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendChannelUpdate {
					node_id: node_id.into_rust(),
					msg: *unsafe { Box::from_raw(msg.take_inner()) },
				}
			},
			MessageSendEvent::HandleError {mut node_id, mut action, } => {
				nativeMessageSendEvent::HandleError {
					node_id: node_id.into_rust(),
					action: action.into_native(),
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
			MessageSendEvent::SendGossipTimestampFilter {mut node_id, mut msg, } => {
				nativeMessageSendEvent::SendGossipTimestampFilter {
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
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendAcceptChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReady {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelReady {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelReady { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {ref node_id, ref updates, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut updates_nonref = Clone::clone(updates);
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: ObjOps::heap_alloc(updates_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::Shutdown { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelAnnouncement {ref node_id, ref msg, ref update_msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				MessageSendEvent::SendChannelAnnouncement {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(update_msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {ref msg, ref update_msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				let mut update_msg_nonref = Clone::clone(update_msg);
				let mut local_update_msg_nonref = crate::lightning::ln::msgs::ChannelUpdate { inner: if update_msg_nonref.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((update_msg_nonref.unwrap())) } }, is_owned: true };
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
					update_msg: local_update_msg_nonref,
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {ref msg, } => {
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelUpdate {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelUpdate {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {ref node_id, ref action, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut action_nonref = Clone::clone(action);
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action_nonref),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendGossipTimestampFilter {ref node_id, ref msg, } => {
				let mut node_id_nonref = Clone::clone(node_id);
				let mut msg_nonref = Clone::clone(msg);
				MessageSendEvent::SendGossipTimestampFilter {
					node_id: crate::c_types::PublicKey::from_rust(&node_id_nonref),
					msg: crate::lightning::ln::msgs::GossipTimestampFilter { inner: ObjOps::heap_alloc(msg_nonref), is_owned: true },
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
					msg: crate::lightning::ln::msgs::AcceptChannel { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendOpenChannel {mut node_id, mut msg, } => {
				MessageSendEvent::SendOpenChannel {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::OpenChannel { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingCreated {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingCreated {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingCreated { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendFundingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendFundingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::FundingSigned { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReady {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReady {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelReady { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendAnnouncementSignatures {mut node_id, mut msg, } => {
				MessageSendEvent::SendAnnouncementSignatures {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::AnnouncementSignatures { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::UpdateHTLCs {mut node_id, mut updates, } => {
				MessageSendEvent::UpdateHTLCs {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					updates: crate::lightning::ln::msgs::CommitmentUpdate { inner: ObjOps::heap_alloc(updates), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendRevokeAndACK {mut node_id, mut msg, } => {
				MessageSendEvent::SendRevokeAndACK {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::RevokeAndACK { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendClosingSigned {mut node_id, mut msg, } => {
				MessageSendEvent::SendClosingSigned {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ClosingSigned { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShutdown {mut node_id, mut msg, } => {
				MessageSendEvent::SendShutdown {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::Shutdown { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelReestablish {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelReestablish {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelReestablish { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelAnnouncement {mut node_id, mut msg, mut update_msg, } => {
				MessageSendEvent::SendChannelAnnouncement {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
					update_msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(update_msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastChannelAnnouncement {mut msg, mut update_msg, } => {
				let mut local_update_msg = crate::lightning::ln::msgs::ChannelUpdate { inner: if update_msg.is_none() { core::ptr::null_mut() } else {  { ObjOps::heap_alloc((update_msg.unwrap())) } }, is_owned: true };
				MessageSendEvent::BroadcastChannelAnnouncement {
					msg: crate::lightning::ln::msgs::ChannelAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
					update_msg: local_update_msg,
				}
			},
			nativeMessageSendEvent::BroadcastChannelUpdate {mut msg, } => {
				MessageSendEvent::BroadcastChannelUpdate {
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::BroadcastNodeAnnouncement {mut msg, } => {
				MessageSendEvent::BroadcastNodeAnnouncement {
					msg: crate::lightning::ln::msgs::NodeAnnouncement { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendChannelUpdate {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelUpdate {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ChannelUpdate { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::HandleError {mut node_id, mut action, } => {
				MessageSendEvent::HandleError {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					action: crate::lightning::ln::msgs::ErrorAction::native_into(action),
				}
			},
			nativeMessageSendEvent::SendChannelRangeQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendChannelRangeQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryChannelRange { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendShortIdsQuery {mut node_id, mut msg, } => {
				MessageSendEvent::SendShortIdsQuery {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::QueryShortChannelIds { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendReplyChannelRange {mut node_id, mut msg, } => {
				MessageSendEvent::SendReplyChannelRange {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::ReplyChannelRange { inner: ObjOps::heap_alloc(msg), is_owned: true },
				}
			},
			nativeMessageSendEvent::SendGossipTimestampFilter {mut node_id, mut msg, } => {
				MessageSendEvent::SendGossipTimestampFilter {
					node_id: crate::c_types::PublicKey::from_rust(&node_id),
					msg: crate::lightning::ln::msgs::GossipTimestampFilter { inner: ObjOps::heap_alloc(msg), is_owned: true },
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
#[no_mangle]
/// Utility method to constructs a new SendAcceptChannel-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_accept_channel(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::AcceptChannel) -> MessageSendEvent {
	MessageSendEvent::SendAcceptChannel {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendOpenChannel-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_open_channel(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::OpenChannel) -> MessageSendEvent {
	MessageSendEvent::SendOpenChannel {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendFundingCreated-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_funding_created(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::FundingCreated) -> MessageSendEvent {
	MessageSendEvent::SendFundingCreated {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendFundingSigned-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_funding_signed(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::FundingSigned) -> MessageSendEvent {
	MessageSendEvent::SendFundingSigned {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelReady-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_ready(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelReady) -> MessageSendEvent {
	MessageSendEvent::SendChannelReady {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendAnnouncementSignatures-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_announcement_signatures(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::AnnouncementSignatures) -> MessageSendEvent {
	MessageSendEvent::SendAnnouncementSignatures {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new UpdateHTLCs-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_update_htlcs(node_id: crate::c_types::PublicKey, updates: crate::lightning::ln::msgs::CommitmentUpdate) -> MessageSendEvent {
	MessageSendEvent::UpdateHTLCs {
		node_id,
		updates,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendRevokeAndACK-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_revoke_and_ack(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::RevokeAndACK) -> MessageSendEvent {
	MessageSendEvent::SendRevokeAndACK {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendClosingSigned-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_closing_signed(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ClosingSigned) -> MessageSendEvent {
	MessageSendEvent::SendClosingSigned {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendShutdown-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_shutdown(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::Shutdown) -> MessageSendEvent {
	MessageSendEvent::SendShutdown {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelReestablish-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_reestablish(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelReestablish) -> MessageSendEvent {
	MessageSendEvent::SendChannelReestablish {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_announcement(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelAnnouncement, update_msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::SendChannelAnnouncement {
		node_id,
		msg,
		update_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastChannelAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_channel_announcement(msg: crate::lightning::ln::msgs::ChannelAnnouncement, update_msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::BroadcastChannelAnnouncement {
		msg,
		update_msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastChannelUpdate-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_channel_update(msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::BroadcastChannelUpdate {
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new BroadcastNodeAnnouncement-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_broadcast_node_announcement(msg: crate::lightning::ln::msgs::NodeAnnouncement) -> MessageSendEvent {
	MessageSendEvent::BroadcastNodeAnnouncement {
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelUpdate-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_update(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ChannelUpdate) -> MessageSendEvent {
	MessageSendEvent::SendChannelUpdate {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new HandleError-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_handle_error(node_id: crate::c_types::PublicKey, action: crate::lightning::ln::msgs::ErrorAction) -> MessageSendEvent {
	MessageSendEvent::HandleError {
		node_id,
		action,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendChannelRangeQuery-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_channel_range_query(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::QueryChannelRange) -> MessageSendEvent {
	MessageSendEvent::SendChannelRangeQuery {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendShortIdsQuery-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_short_ids_query(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::QueryShortChannelIds) -> MessageSendEvent {
	MessageSendEvent::SendShortIdsQuery {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendReplyChannelRange-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_reply_channel_range(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::ReplyChannelRange) -> MessageSendEvent {
	MessageSendEvent::SendReplyChannelRange {
		node_id,
		msg,
	}
}
#[no_mangle]
/// Utility method to constructs a new SendGossipTimestampFilter-variant MessageSendEvent
pub extern "C" fn MessageSendEvent_send_gossip_timestamp_filter(node_id: crate::c_types::PublicKey, msg: crate::lightning::ln::msgs::GossipTimestampFilter) -> MessageSendEvent {
	MessageSendEvent::SendGossipTimestampFilter {
		node_id,
		msg,
	}
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
#[no_mangle]
pub(crate) extern "C" fn MessageSendEventsProvider_clone_fields(orig: &MessageSendEventsProvider) -> MessageSendEventsProvider {
	MessageSendEventsProvider {
		this_arg: orig.this_arg,
		get_and_clear_pending_msg_events: Clone::clone(&orig.get_and_clear_pending_msg_events),
		free: Clone::clone(&orig.free),
	}
}

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
impl core::ops::Deref for MessageSendEventsProvider {
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
/// A trait indicating an object may generate onion messages to send
#[repr(C)]
pub struct OnionMessageProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets the next pending onion message for the peer with the given node id.
	///
	/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
	#[must_use]
	pub next_onion_message_for_peer: extern "C" fn (this_arg: *const c_void, peer_node_id: crate::c_types::PublicKey) -> crate::lightning::ln::msgs::OnionMessage,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for OnionMessageProvider {}
unsafe impl Sync for OnionMessageProvider {}
#[no_mangle]
pub(crate) extern "C" fn OnionMessageProvider_clone_fields(orig: &OnionMessageProvider) -> OnionMessageProvider {
	OnionMessageProvider {
		this_arg: orig.this_arg,
		next_onion_message_for_peer: Clone::clone(&orig.next_onion_message_for_peer),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::events::OnionMessageProvider as rustOnionMessageProvider;
impl rustOnionMessageProvider for OnionMessageProvider {
	fn next_onion_message_for_peer(&self, mut peer_node_id: bitcoin::secp256k1::PublicKey) -> Option<lightning::ln::msgs::OnionMessage> {
		let mut ret = (self.next_onion_message_for_peer)(self.this_arg, crate::c_types::PublicKey::from_rust(&peer_node_id));
		let mut local_ret = if ret.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(ret.take_inner()) } }) };
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for OnionMessageProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn OnionMessageProvider_free(this_ptr: OnionMessageProvider) { }
impl Drop for OnionMessageProvider {
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
/// Implementations of this trait may also feature an async version of event handling, as shown with
/// [`ChannelManager::process_pending_events_async`] and
/// [`ChainMonitor::process_pending_events_async`].
///
/// # Requirements
///
/// When using this trait, [`process_pending_events`] will call [`handle_event`] for each pending
/// event since the last invocation.
///
/// In order to ensure no [`Event`]s are lost, implementors of this trait will persist [`Event`]s
/// and replay any unhandled events on startup. An [`Event`] is considered handled when
/// [`process_pending_events`] returns, thus handlers MUST fully handle [`Event`]s and persist any
/// relevant changes to disk *before* returning.
///
/// Further, because an application may crash between an [`Event`] being handled and the
/// implementor of this trait being re-serialized, [`Event`] handling must be idempotent - in
/// effect, [`Event`]s may be replayed.
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
/// [`ChannelManager::process_pending_events_async`]: crate::ln::channelmanager::ChannelManager::process_pending_events_async
/// [`ChainMonitor::process_pending_events_async`]: crate::chain::chainmonitor::ChainMonitor::process_pending_events_async
#[repr(C)]
pub struct EventsProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Processes any events generated since the last call using the given event handler.
	///
	/// See the trait-level documentation for requirements.
	pub process_pending_events: extern "C" fn (this_arg: *const c_void, handler: crate::lightning::util::events::EventHandler),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EventsProvider {}
unsafe impl Sync for EventsProvider {}
#[no_mangle]
pub(crate) extern "C" fn EventsProvider_clone_fields(orig: &EventsProvider) -> EventsProvider {
	EventsProvider {
		this_arg: orig.this_arg,
		process_pending_events: Clone::clone(&orig.process_pending_events),
		free: Clone::clone(&orig.free),
	}
}

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
///
/// An async variation also exists for implementations of [`EventsProvider`] that support async
/// event handling. The async event handler should satisfy the generic bounds: `F:
/// core::future::Future, H: Fn(Event) -> F`.
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
#[no_mangle]
pub(crate) extern "C" fn EventHandler_clone_fields(orig: &EventHandler) -> EventHandler {
	EventHandler {
		this_arg: orig.this_arg,
		handle_event: Clone::clone(&orig.handle_event),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::events::EventHandler as rustEventHandler;
impl rustEventHandler for EventHandler {
	fn handle_event(&self, mut event: lightning::util::events::Event) {
		(self.handle_event)(self.this_arg, crate::lightning::util::events::Event::native_into(event))
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for EventHandler {
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
