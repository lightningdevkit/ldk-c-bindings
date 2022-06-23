// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

/// Core functionality of this crate

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Update network graph from binary data.
/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
///
/// `network_graph`: network graph to be updated
///
/// `update_data`: `&[u8]` binary stream that comprises the update data
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_update_network_graph(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync, mut update_data: crate::c_types::u8slice) -> crate::c_types::derived::CResult_u32GraphSyncErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_network_graph(update_data.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_rapid_gossip_sync::error::GraphSyncError::native_into(e) }).into() };
	local_ret
}

