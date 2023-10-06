// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Onion Messages: sending, receiving, forwarding, and ancillary utilities live here
//!
//! Onion messages are multi-purpose messages sent between peers over the lightning network. In the
//! near future, they will be used to communicate invoices for [offers], unlocking use cases such as
//! static invoices, refunds and proof of payer. Further, you will be able to accept payments
//! without revealing your node id through the use of [blinded paths].
//!
//! LDK sends and receives onion messages via the [`OnionMessenger`]. See its documentation for more
//! information on its usage.
//!
//! [offers]: <https://github.com/lightning/bolts/pull/798>
//! [blinded paths]: crate::blinded_path::BlindedPath

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod messenger;
pub mod offers;
pub mod packet;
