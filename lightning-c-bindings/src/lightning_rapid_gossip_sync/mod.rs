// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This crate exposes client functionality to rapidly sync gossip data, aimed primarily at mobile
//! devices.
//!
//! The rapid gossip sync server will provide a compressed response containing differential gossip
//! data. The gossip data is formatted compactly, omitting signatures and opportunistically
//! incremental where previous channel updates are known. This mechanism is enabled when the
//! timestamp of the last known channel update is communicated. A reference server implementation
//! can be found [on Github](https://github.com/lightningdevkit/rapid-gossip-sync-server).
//!
//! The primary benefit of this syncing mechanism is that it allows a low-powered client to offload
//! the validation of gossip signatures to a semi-trusted server. This enables the client to
//! privately calculate routes for payments, and to do so much faster than requiring a full
//! peer-to-peer gossip sync to complete.
//!
//! The server calculates its response on the basis of a client-provided `latest_seen` timestamp,
//! i.e., the server will return all rapid gossip sync data it has seen after the given timestamp.
//!
//! # Getting Started
//! Firstly, the data needs to be retrieved from the server. For example, you could use the server
//! at <https://rapidsync.lightningdevkit.org> with the following request format:
//!
//! ```shell
//! curl -o rapid_sync.lngossip https://rapidsync.lightningdevkit.org/snapshot/<last_sync_timestamp>
//! ```
//! Note that the first ever rapid sync should use `0` for `last_sync_timestamp`.
//!
//! After the gossip data snapshot has been downloaded, one of the client's graph processing
//! functions needs to be called. In this example, we process the update by reading its contents
//! from disk, which we do by calling [`RapidGossipSync::update_network_graph`]:
//!
//! ```
//! use bitcoin::blockdata::constants::genesis_block;
//! use bitcoin::Network;
//! use lightning::routing::gossip::NetworkGraph;
//! use lightning_rapid_gossip_sync::RapidGossipSync;
//!
//! # use lightning::util::logger::{Logger, Record};
//! # struct FakeLogger {}
//! # impl Logger for FakeLogger {
//! #     fn log(&self, record: &Record) { unimplemented!() }
//! # }
//! # let logger = FakeLogger {};
//!
//! let block_hash = genesis_block(Network::Bitcoin).header.block_hash();
//! let network_graph = NetworkGraph::new(block_hash, &logger);
//! let rapid_sync = RapidGossipSync::new(&network_graph);
//! let snapshot_contents: &[u8] = &[0; 0];
//! let new_last_sync_timestamp_result = rapid_sync.update_network_graph(snapshot_contents);
//! ```

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

pub mod error;
mod processing {

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning_rapid_gossip_sync::RapidGossipSync as nativeRapidGossipSyncImport;
pub(crate) type nativeRapidGossipSync = nativeRapidGossipSyncImport<&'static lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>, crate::lightning::util::logger::Logger>;

/// The main Rapid Gossip Sync object.
///
/// See [crate-level documentation] for usage.
///
/// [crate-level documentation]: crate
#[must_use]
#[repr(C)]
pub struct RapidGossipSync {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRapidGossipSync,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for RapidGossipSync {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRapidGossipSync>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the RapidGossipSync, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn RapidGossipSync_free(this_obj: RapidGossipSync) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn RapidGossipSync_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRapidGossipSync); }
}
#[allow(unused)]
impl RapidGossipSync {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRapidGossipSync {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRapidGossipSync {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRapidGossipSync {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Instantiate a new [`RapidGossipSync`] instance.
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_new(network_graph: &crate::lightning::routing::gossip::NetworkGraph) -> crate::lightning_rapid_gossip_sync::RapidGossipSync {
	let mut ret = lightning_rapid_gossip_sync::RapidGossipSync::new(network_graph.get_native_ref());
	crate::lightning_rapid_gossip_sync::RapidGossipSync { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

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

/// Returns whether a rapid gossip sync has completed at least once.
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_is_initial_sync_complete(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_initial_sync_complete();
	ret
}

