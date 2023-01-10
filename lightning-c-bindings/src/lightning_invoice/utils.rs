// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities to create an invoice.

use alloc::str::FromStr;
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
/// Note that the provided `keys_manager`'s `KeysInterface` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::chain::keysinterface::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
///
/// Note that payment_hash (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_phantom_invoice(mut amt_msat: crate::c_types::derived::COption_u64Z, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut description: crate::c_types::Str, mut invoice_expiry_delta_secs: u32, mut phantom_route_hints: crate::c_types::derived::CVec_PhantomRouteHintsZ, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_payment_hash = if payment_hash.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentHash(payment_hash.data) }) };
	let mut local_phantom_route_hints = Vec::new(); for mut item in phantom_route_hints.into_rust().drain(..) { local_phantom_route_hints.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning_invoice::utils::create_phantom_invoice::<crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::util::logger::Logger>(local_amt_msat, local_payment_hash, description.into_string(), invoice_expiry_delta_secs, local_phantom_route_hints, keys_manager, logger, network.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
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
/// * Note that if too many channels are included in [`PhantomRouteHints::channels`], the invoice
///   may be too long for QR code scanning. To fix this, `PhantomRouteHints::channels` may be pared
///   down
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
/// Note that the provided `keys_manager`'s `KeysInterface` implementation must support phantom
/// invoices in its `sign_invoice` implementation ([`PhantomKeysManager`] satisfies this
/// requirement).
///
/// [`PhantomKeysManager`]: lightning::chain::keysinterface::PhantomKeysManager
/// [`ChannelManager::get_phantom_route_hints`]: lightning::ln::channelmanager::ChannelManager::get_phantom_route_hints
/// [`ChannelManager::create_inbound_payment`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment
/// [`ChannelManager::create_inbound_payment_for_hash`]: lightning::ln::channelmanager::ChannelManager::create_inbound_payment_for_hash
/// [`PhantomRouteHints::channels`]: lightning::ln::channelmanager::PhantomRouteHints::channels
///
/// Note that payment_hash (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn create_phantom_invoice_with_description_hash(mut amt_msat: crate::c_types::derived::COption_u64Z, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut invoice_expiry_delta_secs: u32, mut description_hash: crate::lightning_invoice::Sha256, mut phantom_route_hints: crate::c_types::derived::CVec_PhantomRouteHintsZ, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut local_payment_hash = if payment_hash.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentHash(payment_hash.data) }) };
	let mut local_phantom_route_hints = Vec::new(); for mut item in phantom_route_hints.into_rust().drain(..) { local_phantom_route_hints.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning_invoice::utils::create_phantom_invoice_with_description_hash::<crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::util::logger::Logger>(local_amt_msat, local_payment_hash, invoice_expiry_delta_secs, *unsafe { Box::from_raw(description_hash.take_inner()) }, local_phantom_route_hints, keys_manager, logger, network.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
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
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), keys_manager, logger, network.into_native(), local_amt_msat, description.into_string(), invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
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
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_with_description_hash(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description_hash: crate::lightning_invoice::Sha256, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_with_description_hash::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), keys_manager, logger, network.into_native(), local_amt_msat, *unsafe { Box::from_raw(description_hash.take_inner()) }, invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager_with_description_hash`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description_hash: crate::lightning_invoice::Sha256, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_with_description_hash_and_duration_since_epoch::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), keys_manager, logger, network.into_native(), local_amt_msat, *unsafe { Box::from_raw(description_hash.take_inner()) }, core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager`]
/// This version can be used in a `no_std` environment, where [`std::time::SystemTime`] is not
/// available and the current time is supplied by the caller.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_and_duration_since_epoch(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_and_duration_since_epoch::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), keys_manager, logger, network.into_native(), local_amt_msat, description.into_string(), core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

/// See [`create_invoice_from_channelmanager_and_duration_since_epoch`]
/// This version allows for providing a custom [`PaymentHash`] for the invoice.
/// This may be useful if you're building an on-chain swap or involving another protocol where
/// the payment hash is also involved outside the scope of lightning.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut logger: crate::lightning::util::logger::Logger, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str, mut duration_since_epoch: u64, mut invoice_expiry_delta_secs: u32, mut payment_hash: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager_and_duration_since_epoch_with_payment_hash::<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>(channelmanager.get_native_ref(), keys_manager, logger, network.into_native(), local_amt_msat, description.into_string(), core::time::Duration::from_secs(duration_since_epoch), invoice_expiry_delta_secs, ::lightning::ln::PaymentHash(payment_hash.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

impl From<nativeChannelManager> for crate::lightning_invoice::payment::Payer {
	fn from(obj: nativeChannelManager) -> Self {
		let mut rust_obj = ChannelManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChannelManager_as_Payer(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChannelManager_free_void);
		ret
	}
}
/// Constructs a new Payer which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Payer must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChannelManager_as_Payer(this_arg: &ChannelManager) -> crate::lightning_invoice::payment::Payer {
	crate::lightning_invoice::payment::Payer {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		node_id: ChannelManager_Payer_node_id,
		first_hops: ChannelManager_Payer_first_hops,
		send_payment: ChannelManager_Payer_send_payment,
		send_spontaneous_payment: ChannelManager_Payer_send_spontaneous_payment,
		retry_payment: ChannelManager_Payer_retry_payment,
		abandon_payment: ChannelManager_Payer_abandon_payment,
		inflight_htlcs: ChannelManager_Payer_inflight_htlcs,
	}
}

#[must_use]
extern "C" fn ChannelManager_Payer_node_id(this_arg: *const c_void) -> crate::c_types::PublicKey {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::node_id(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	crate::c_types::PublicKey::from_rust(&ret)
}
#[must_use]
extern "C" fn ChannelManager_Payer_first_hops(this_arg: *const c_void) -> crate::c_types::derived::CVec_ChannelDetailsZ {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::first_hops(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::ln::channelmanager::ChannelDetails { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}
#[must_use]
extern "C" fn ChannelManager_Payer_send_payment(this_arg: *const c_void, route: &crate::lightning::routing::router::Route, mut payment_hash: crate::c_types::ThirtyTwoBytes, mut payment_secret: crate::c_types::ThirtyTwoBytes, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut local_payment_secret = if payment_secret.data == [0; 32] { None } else { Some( { ::lightning::ln::PaymentSecret(payment_secret.data) }) };
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::send_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, route.get_native_ref(), ::lightning::ln::PaymentHash(payment_hash.data), &local_payment_secret, ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChannelManager_Payer_send_spontaneous_payment(this_arg: *const c_void, route: &crate::lightning::routing::router::Route, mut payment_preimage: crate::c_types::ThirtyTwoBytes, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::send_spontaneous_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, route.get_native_ref(), ::lightning::ln::PaymentPreimage(payment_preimage.data), ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChannelManager_Payer_retry_payment(this_arg: *const c_void, route: &crate::lightning::routing::router::Route, mut payment_id: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NonePaymentSendFailureZ {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::retry_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, route.get_native_ref(), ::lightning::ln::channelmanager::PaymentId(payment_id.data));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::channelmanager::PaymentSendFailure::native_into(e) }).into() };
	local_ret
}
extern "C" fn ChannelManager_Payer_abandon_payment(this_arg: *const c_void, mut payment_id: crate::c_types::ThirtyTwoBytes) {
	<nativeChannelManager as lightning_invoice::payment::Payer<>>::abandon_payment(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, ::lightning::ln::channelmanager::PaymentId(payment_id.data))
}
#[must_use]
extern "C" fn ChannelManager_Payer_inflight_htlcs(this_arg: *const c_void) -> crate::lightning::routing::router::InFlightHtlcs {
	let mut ret = <nativeChannelManager as lightning_invoice::payment::Payer<>>::inflight_htlcs(unsafe { &mut *(this_arg as *mut nativeChannelManager) }, );
	crate::lightning::routing::router::InFlightHtlcs { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

use crate::lightning::ln::channelmanager::nativeChannelManager as nativeChannelManager;
use crate::lightning::ln::channelmanager::ChannelManager;
use crate::lightning::ln::channelmanager::ChannelManager_free_void;
