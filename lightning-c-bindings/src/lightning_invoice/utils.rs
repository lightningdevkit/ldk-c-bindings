// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Convenient utilities to create an invoice.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// Utility to construct an invoice. Generally, unless you want to do something like a custom
/// cltv_expiry, this is what you should be using to create an invoice. The reason being, this
/// method stores the invoice's payment secret and preimage in `ChannelManager`, so (a) the user
/// doesn't have to store preimage/payment secret information and (b) `ChannelManager` can verify
/// that the payment secret is valid when the invoice is paid.
#[no_mangle]
pub extern "C" fn create_invoice_from_channelmanager(channelmanager: &crate::lightning::ln::channelmanager::ChannelManager, mut keys_manager: crate::lightning::chain::keysinterface::KeysInterface, mut network: crate::lightning_invoice::Currency, mut amt_msat: crate::c_types::derived::COption_u64Z, mut description: crate::c_types::Str) -> crate::c_types::derived::CResult_InvoiceSignOrCreationErrorZ {
	let mut local_amt_msat = if amt_msat.is_some() { Some( { amt_msat.take() }) } else { None };
	let mut ret = lightning_invoice::utils::create_invoice_from_channelmanager(channelmanager.get_native_ref(), keys_manager, network.into_native(), local_amt_msat, description.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning_invoice::Invoice { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_invoice::SignOrCreationError::native_into(e) }).into() };
	local_ret
}

