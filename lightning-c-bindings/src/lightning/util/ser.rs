// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! A very simple serialization framework which is used to serialize/deserialize messages as well
//! as ChannelsManagers and ChannelMonitors.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// serialization buffer size

#[no_mangle]
pub static MAX_BUF_SIZE: usize = lightning::util::ser::MAX_BUF_SIZE;
