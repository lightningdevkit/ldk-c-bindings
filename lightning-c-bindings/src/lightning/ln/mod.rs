// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! High level lightning structs and impls live here.
//!
//! You probably want to create a channelmanager::ChannelManager, and a routing::NetGraphMsgHandler first.
//! Then, you probably want to pass them both on to a peer_handler::PeerManager and use that to
//! create/manage connections and call get_and_clear_pending_events after each action, handling
//! them appropriately.
//!
//! When you want to open/close a channel or send a payment, call into your ChannelManager and when
//! you want to learn things about the network topology (eg get a route for sending a payment),
//! call into your NetGraphMsgHandler.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod channelmanager;
pub mod msgs;
pub mod peer_handler;
pub mod chan_utils;
pub mod features;
pub mod script;
pub mod wire;
mod peer_channel_encryptor {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod channel {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
mod onion_utils {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
