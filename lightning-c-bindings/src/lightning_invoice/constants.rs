// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

/// Tag constants as specified in BOLT11

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;


#[no_mangle]
pub static TAG_PAYMENT_HASH: u8 = lightning_invoice::constants::TAG_PAYMENT_HASH;

#[no_mangle]
pub static TAG_DESCRIPTION: u8 = lightning_invoice::constants::TAG_DESCRIPTION;

#[no_mangle]
pub static TAG_PAYEE_PUB_KEY: u8 = lightning_invoice::constants::TAG_PAYEE_PUB_KEY;

#[no_mangle]
pub static TAG_DESCRIPTION_HASH: u8 = lightning_invoice::constants::TAG_DESCRIPTION_HASH;

#[no_mangle]
pub static TAG_EXPIRY_TIME: u8 = lightning_invoice::constants::TAG_EXPIRY_TIME;

#[no_mangle]
pub static TAG_MIN_FINAL_CLTV_EXPIRY: u8 = lightning_invoice::constants::TAG_MIN_FINAL_CLTV_EXPIRY;

#[no_mangle]
pub static TAG_FALLBACK: u8 = lightning_invoice::constants::TAG_FALLBACK;

#[no_mangle]
pub static TAG_PRIVATE_ROUTE: u8 = lightning_invoice::constants::TAG_PRIVATE_ROUTE;

#[no_mangle]
pub static TAG_PAYMENT_SECRET: u8 = lightning_invoice::constants::TAG_PAYMENT_SECRET;

#[no_mangle]
pub static TAG_FEATURES: u8 = lightning_invoice::constants::TAG_FEATURES;
