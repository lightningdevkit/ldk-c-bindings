// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities to create an invoice.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Utility to create an invoice that can be paid to one of multiple nodes, or a \"phantom invoice.\"
/// See [`PhantomKeysManager`] for more information on phantom node payments.
///
/// `phantom_route_hints` parameter:
/// * Contains channel info for all nodes participating in the phantom invoice
/// * Entries are retrieved from a call to [`ChannelManager::get_phantom_route_hints`] on each
///   participating node
/// * It is fine to cache `phantom_route_hints` and reuse it across invoices, as long as the data is
///   updated when a channel becomes disabled or closes
/// * Note that if too many channels are included in [`PhantomRouteHints::channels`], the invoice
///   may be too long for QR code scanning. To fix this, `PhantomRouteHints::channels` may be pared
///   down
///
/// `payment_hash` can be specified if you have a specific need for a custom payment hash (see the difference
/// between [`ChannelManager::create_inbound_payment`] and [`ChannelManager::create_inbound_payment_for_hash`]).
/// If `None` is provided for `payment_hash`, then one will be created.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// `duration_since_epoch` is the current time since epoch in seconds.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`] - 3.
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// Note that the provided `keys_manager`'s `NodeSigner` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::sign::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
///
/// This can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_phantom_invoice(mut amt_msat: crate::c_types::derived::COption_u64Z, mut payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ, mut description: crate::c_types::Str, mut invoice_expiry_delta_secs: u32, mut phantom_route_hints: crate::c_types::derived::CVec_PhantomRouteHintsZ, mut entropy_source: crate::lightning::sign::EntropySource, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z, mut duration_since_epoch: u64) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_payment_hash = { /*payment_hash*/ let payment_hash_opt = payment_hash; if payment_hash_opt.is_none() { None } else { Some({ { ::lightning::ln::PaymentHash({ payment_hash_opt.take() }.data) }})} };
	let mut local_phantom_route_hints = Vec::new(); for mut item in phantom_route_hints.into_rust().drain(..) { local_phantom_route_hints.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_phantom_invoice::<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger>(local_amt_msat, local_payment_hash, description.into_string(), invoice_expiry_delta_secs, local_phantom_route_hints, entropy_source, node_signer, logger, network.into_native(), local_min_final_cltv_expiry_delta, core::time::Duration::from_secs(duration_since_epoch));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// Utility to create an invoice that can be paid to one of multiple nodes, or a \"phantom invoice.\"
/// See [`PhantomKeysManager`] for more information on phantom node payments.
///
/// `phantom_route_hints` parameter:
/// * Contains channel info for all nodes participating in the phantom invoice
/// * Entries are retrieved from a call to [`ChannelManager::get_phantom_route_hints`] on each
///   participating node
/// * It is fine to cache `phantom_route_hints` and reuse it across invoices, as long as the data is
///   updated when a channel becomes disabled or closes
/// * Note that the route hints generated from `phantom_route_hints` will be limited to a maximum
///   of 3 hints to ensure that the invoice can be scanned in a QR code. These hints are selected
///   in the order that the nodes in `PhantomRouteHints` are specified, selecting one hint per node
///   until the maximum is hit. Callers may provide as many `PhantomRouteHints::channels` as
///   desired, but note that some nodes will be trimmed if more than 3 nodes are provided.
///
/// `description_hash` is a SHA-256 hash of the description text
///
/// `payment_hash` can be specified if you have a specific need for a custom payment hash (see the difference
/// between [`ChannelManager::create_inbound_payment`] and [`ChannelManager::create_inbound_payment_for_hash`]).
/// If `None` is provided for `payment_hash`, then one will be created.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// `duration_since_epoch` is the current time since epoch in seconds.
///
/// Note that the provided `keys_manager`'s `NodeSigner` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::sign::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
///
/// This can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_phantom_invoice_with_description_hash(mut amt_msat: crate::c_types::derived::COption_u64Z, mut payment_hash: crate::c_types::derived::COption_ThirtyTwoBytesZ, mut invoice_expiry_delta_secs: u32, mut description_hash: crate::lightning_invoice::Sha256, mut phantom_route_hints: crate::c_types::derived::CVec_PhantomRouteHintsZ, mut entropy_source: crate::lightning::sign::EntropySource, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z, mut duration_since_epoch: u64) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_payment_hash = { /*payment_hash*/ let payment_hash_opt = payment_hash; if payment_hash_opt.is_none() { None } else { Some({ { ::lightning::ln::PaymentHash({ payment_hash_opt.take() }.data) }})} };
	let mut local_phantom_route_hints = Vec::new(); for mut item in phantom_route_hints.into_rust().drain(..) { local_phantom_route_hints.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_phantom_invoice_with_description_hash::<crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::util::logger::Logger>(local_amt_msat, local_payment_hash, invoice_expiry_delta_secs, *unsafe { Box::from_raw(description_hash.take_inner()) }, local_phantom_route_hints, entropy_source, node_signer, logger, network.into_native(), local_min_final_cltv_expiry_delta, core::time::Duration::from_secs(duration_since_epoch));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut invoice_expiry_delta_secs: u32, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), node_signer, logger, network.into_native(), local_amt_msat, description.into_string(), invoice_expiry_delta_secs, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
/// Use this variant if you want to pass the `description_hash` to the invoice.
///
/// `invoice_expiry_delta_secs` describes the number of seconds that the invoice is valid for
/// in excess of the current time.
///
/// You can specify a custom `min_final_cltv_expiry_delta`, or let LDK default it to
/// [`MIN_FINAL_CLTV_EXPIRY_DELTA`]. The provided expiry must be at least [`MIN_FINAL_CLTV_EXPIRY_DELTA`].
/// Note that LDK will add a buffer of 3 blocks to the delta to allow for up to a few new block
/// confirmations during routing.
///
/// [`MIN_FINAL_CLTV_EXPIRY_DETLA`]: lightning::ln::channelmanager::MIN_FINAL_CLTV_EXPIRY_DELTA
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_with_description_hash(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description_hash: crate::lightning_invoice::Sha256, mut invoice_expiry_delta_secs: u32, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_with_description_hash::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), node_signer, logger, network.into_native(), local_amt_msat, *unsafe { Box::from_raw(description_hash.take_inner()) }, invoice_expiry_delta_secs, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager_with_description_hash`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description_hash: crate::lightning_invoice::Sha256, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), node_signer, logger, network.into_native(), local_amt_msat, *unsafe { Box::from_raw(description_hash.take_inner()) }, core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_and_duration_since_epoch(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_and_duration_since_epoch::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), node_signer, logger, network.into_native(), local_amt_msat, description.into_string(), core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs, local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager_and_duration_since_epoch`]
/// This version allows for providing a custom [`PaymentHash`] for the invoice.
/// This may be useful if you're building an on-chain swap or involving another protocol where
/// the payment hash is also involved outside the scope of lightning.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut node_signer: crate::lightning::sign::NodeSigner, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut min_final_cltv_expiry_delta: crate::c_types::derived::COption_u16Z) -> crate::c_types::derived::CResult_Bolt11InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_min_final_cltv_expiry_delta = if min_final_cltv_expiry_delta.is_some() { Some( { min_final_cltv_expiry_delta.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), node_signer, logger, network.into_native(), local_amt_msat, description.into_string(), core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs, ::lightning::ln::PaymentHash(payment_hash.data), local_min_final_cltv_expiry_delta);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Bolt11Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

