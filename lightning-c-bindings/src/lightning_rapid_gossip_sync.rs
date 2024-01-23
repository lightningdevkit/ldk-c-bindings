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
//! #     fn log(&self, record: Record) { }
//! # }
//! # let logger = FakeLogger {};
//!
//! let network_graph = NetworkGraph::new(Network::Bitcoin, &logger);
//! let rapid_sync = RapidGossipSync::new(&network_graph, &logger);
//! let snapshot_contents: &[u8] = &[0; 0];
//! // In no-std you need to provide the current time in unix epoch seconds
//! // otherwise you can use update_network_graph
//! let current_time_unix = 0;
//! let new_last_sync_timestamp_result = rapid_sync.update_network_graph_no_std(snapshot_contents, Some(current_time_unix));
//! ```

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod processing {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}
/// All-encompassing standard error type that processing can return
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum GraphSyncError {
	/// Error trying to read the update data, typically due to an erroneous data length indication
	/// that is greater than the actual amount of data provided
	DecodeError(
		crate::lightning::ln::msgs::DecodeError),
	/// Error applying the patch to the network graph, usually the result of updates that are too
	/// old or missing prerequisite data to the application of updates out of order
	LightningError(
		crate::lightning::ln::msgs::LightningError),
}
use lightning_rapid_gossip_sync::GraphSyncError as GraphSyncErrorImport;
pub(crate) type nativeGraphSyncError = GraphSyncErrorImport;

impl GraphSyncError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeGraphSyncError {
		match self {
			GraphSyncError::DecodeError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeGraphSyncError::DecodeError (
					a_nonref.into_native(),
				)
			},
			GraphSyncError::LightningError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeGraphSyncError::LightningError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeGraphSyncError {
		match self {
			GraphSyncError::DecodeError (mut a, ) => {
				nativeGraphSyncError::DecodeError (
					a.into_native(),
				)
			},
			GraphSyncError::LightningError (mut a, ) => {
				nativeGraphSyncError::LightningError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &GraphSyncErrorImport) -> Self {
		let native = unsafe { &*(native as *const _ as *const c_void as *const nativeGraphSyncError) };
		match native {
			nativeGraphSyncError::DecodeError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				GraphSyncError::DecodeError (
					crate::lightning::ln::msgs::DecodeError::native_into(a_nonref),
				)
			},
			nativeGraphSyncError::LightningError (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				GraphSyncError::LightningError (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeGraphSyncError) -> Self {
		match native {
			nativeGraphSyncError::DecodeError (mut a, ) => {
				GraphSyncError::DecodeError (
					crate::lightning::ln::msgs::DecodeError::native_into(a),
				)
			},
			nativeGraphSyncError::LightningError (mut a, ) => {
				GraphSyncError::LightningError (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the GraphSyncError
#[no_mangle]
pub extern "C" fn GraphSyncError_free(this_ptr: GraphSyncError) { }
/// Creates a copy of the GraphSyncError
#[no_mangle]
pub extern "C" fn GraphSyncError_clone(orig: &GraphSyncError) -> GraphSyncError {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn GraphSyncError_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const GraphSyncError)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn GraphSyncError_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut GraphSyncError) };
}
#[no_mangle]
/// Utility method to constructs a new DecodeError-variant GraphSyncError
pub extern "C" fn GraphSyncError_decode_error(a: crate::lightning::ln::msgs::DecodeError) -> GraphSyncError {
	GraphSyncError::DecodeError(a, )
}
#[no_mangle]
/// Utility method to constructs a new LightningError-variant GraphSyncError
pub extern "C" fn GraphSyncError_lightning_error(a: crate::lightning::ln::msgs::LightningError) -> GraphSyncError {
	GraphSyncError::LightningError(a, )
}
/// Get a string which allows debug introspection of a GraphSyncError object
pub extern "C" fn GraphSyncError_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning_rapid_gossip_sync::GraphSyncError }).into()}

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
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeRapidGossipSync) };
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
pub extern "C" fn RapidGossipSync_new(network_graph: &crate::lightning::routing::gossip::NetworkGraph, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning_rapid_gossip_sync::RapidGossipSync {
	let mut ret = lightning_rapid_gossip_sync::RapidGossipSync::new(network_graph.get_native_ref(), logger);
	crate::lightning_rapid_gossip_sync::RapidGossipSync { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Sync gossip data from a file.
/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
///
/// `network_graph`: The network graph to apply the updates to
///
/// `sync_path`: Path to the file where the gossip update data is located
///
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_sync_network_graph_with_file_path(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync, mut sync_path: crate::c_types::Str) -> crate::c_types::derived::CResult_u32GraphSyncErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sync_network_graph_with_file_path(sync_path.into_str());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_rapid_gossip_sync::GraphSyncError::native_into(e) }).into() };
	local_ret
}

/// Update network graph from binary data.
/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
///
/// `update_data`: `&[u8]` binary stream that comprises the update data
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_update_network_graph(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync, mut update_data: crate::c_types::u8slice) -> crate::c_types::derived::CResult_u32GraphSyncErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_network_graph(update_data.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_rapid_gossip_sync::GraphSyncError::native_into(e) }).into() };
	local_ret
}

/// Update network graph from binary data.
/// Returns the last sync timestamp to be used the next time rapid sync data is queried.
///
/// `update_data`: `&[u8]` binary stream that comprises the update data
/// `current_time_unix`: `Option<u64>` optional current timestamp to verify data age
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_update_network_graph_no_std(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync, mut update_data: crate::c_types::u8slice, mut current_time_unix: crate::c_types::derived::COption_u64Z) -> crate::c_types::derived::CResult_u32GraphSyncErrorZ {
	let mut local_current_time_unix = if current_time_unix.is_some() { Some( { current_time_unix.take() }) } else { None };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.update_network_graph_no_std(update_data.to_slice(), local_current_time_unix);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning_rapid_gossip_sync::GraphSyncError::native_into(e) }).into() };
	local_ret
}

/// Returns whether a rapid gossip sync has completed at least once.
#[must_use]
#[no_mangle]
pub extern "C" fn RapidGossipSync_is_initial_sync_complete(this_arg: &crate::lightning_rapid_gossip_sync::RapidGossipSync) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_initial_sync_complete();
	ret
}

