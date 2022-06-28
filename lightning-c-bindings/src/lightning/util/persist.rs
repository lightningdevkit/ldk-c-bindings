// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module contains a simple key-value store trait KVStorePersister that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Trait that handles persisting a [`ChannelManager`], [`NetworkGraph`], and [`MultiThreadedLockableScore`] to disk.
#[repr(C)]
pub struct Persister {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	#[must_use]
	pub persist_manager: extern "C" fn (this_arg: *const c_void, channel_manager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NoneErrorZ,
	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	#[must_use]
	pub persist_graph: extern "C" fn (this_arg: *const c_void, network_graph: &crate::lightning::routing::gossip::NetworkGraph) -> crate::c_types::derived::CResult_NoneErrorZ,
	/// Persist the given [`MultiThreadedLockableScore`] to disk, returning an error if persistence failed.
	#[must_use]
	pub persist_scorer: extern "C" fn (this_arg: *const c_void, scorer: &crate::lightning::routing::scoring::MultiThreadedLockableScore) -> crate::c_types::derived::CResult_NoneErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Persister {}
unsafe impl Sync for Persister {}
#[no_mangle]
pub(crate) extern "C" fn Persister_clone_fields(orig: &Persister) -> Persister {
	Persister {
		this_arg: orig.this_arg,
		persist_manager: Clone::clone(&orig.persist_manager),
		persist_graph: Clone::clone(&orig.persist_graph),
		persist_scorer: Clone::clone(&orig.persist_scorer),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::persist::Persister as rustPersister;
impl<'a> rustPersister<'a, crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger, crate::lightning::routing::scoring::Score> for Persister {
	fn persist_manager(&self, mut channel_manager: &lightning::ln::channelmanager::ChannelManager<crate::lightning::chain::keysinterface::Sign, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::keysinterface::KeysInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger>) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_manager)(self.this_arg, &crate::lightning::ln::channelmanager::ChannelManager { inner: unsafe { ObjOps::nonnull_ptr_to_inner((channel_manager as *const lightning::ln::channelmanager::ChannelManager<_, _, _, _, _, _, >) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn persist_graph(&self, mut network_graph: &lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_graph)(self.this_arg, &crate::lightning::routing::gossip::NetworkGraph { inner: unsafe { ObjOps::nonnull_ptr_to_inner((network_graph as *const lightning::routing::gossip::NetworkGraph<_, >) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn persist_scorer(&self, mut scorer: &lightning::routing::scoring::MultiThreadedLockableScore<crate::lightning::routing::scoring::Score>) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_scorer)(self.this_arg, &crate::lightning::routing::scoring::MultiThreadedLockableScore { inner: unsafe { ObjOps::nonnull_ptr_to_inner((scorer as *const lightning::routing::scoring::MultiThreadedLockableScore<_, >) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Persister {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Persister_free(this_ptr: Persister) { }
impl Drop for Persister {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
