// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities for paying Lightning invoices.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Builds the necessary parameters to pay or pre-flight probe the given zero-amount
/// [`Bolt11Invoice`] using [`ChannelManager::send_payment`] or
/// [`ChannelManager::send_preflight_probes`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has an amount specified, in which case
/// [`payment_parameters_from_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
#[no_mangle]
pub extern "C" fn payment_parameters_from_zero_amount_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice, mut amount_msat: u64) -> crate::c_types::derived::CResult_C3Tuple_ThirtyTwoBytesRecipientOnionFieldsRouteParametersZNoneZ {
	let mut ret = lightning_invoice::payment::payment_parameters_from_zero_amount_invoice(invoice.get_native_ref(), amount_msat);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }, crate::lightning::routing::router::RouteParameters { inner: ObjOps::heap_alloc(orig_ret_0_2), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Builds the necessary parameters to pay or pre-flight probe the given [`Bolt11Invoice`] using
/// [`ChannelManager::send_payment`] or [`ChannelManager::send_preflight_probes`].
///
/// Prior to paying, you must ensure that the [`Bolt11Invoice::payment_hash`] is unique and the
/// same [`PaymentHash`] has never been paid before.
///
/// Will always succeed unless the invoice has no amount specified, in which case
/// [`payment_parameters_from_zero_amount_invoice`] should be used.
///
/// [`ChannelManager::send_payment`]: lightning::ln::channelmanager::ChannelManager::send_payment
/// [`ChannelManager::send_preflight_probes`]: lightning::ln::channelmanager::ChannelManager::send_preflight_probes
#[no_mangle]
pub extern "C" fn payment_parameters_from_invoice(invoice: &crate::lightning_invoice::Bolt11Invoice) -> crate::c_types::derived::CResult_C3Tuple_ThirtyTwoBytesRecipientOnionFieldsRouteParametersZNoneZ {
	let mut ret = lightning_invoice::payment::payment_parameters_from_invoice(invoice.get_native_ref());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.0 }, crate::lightning::ln::outbound_payment::RecipientOnionFields { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }, crate::lightning::routing::router::RouteParameters { inner: ObjOps::heap_alloc(orig_ret_0_2), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

