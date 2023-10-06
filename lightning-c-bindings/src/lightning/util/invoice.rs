// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Low level invoice utilities.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Construct the invoice's HRP and signatureless data into a preimage to be hashed.
#[no_mangle]
pub extern "C" fn construct_invoice_preimage(mut hrp_bytes: crate::c_types::u8slice, mut data_without_signature: crate::c_types::derived::CVec_U5Z) -> crate::c_types::derived::CVec_u8Z {
	let mut local_data_without_signature = Vec::new(); for mut item in data_without_signature.into_rust().drain(..) { local_data_without_signature.push( { item.into() }); };
	let mut ret = lightning::util::invoice::construct_invoice_preimage(hrp_bytes.to_slice(), &local_data_without_signature[..]);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { item }); };
	local_ret.into()
}

