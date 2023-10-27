// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! This module contains a simple key-value store trait [`KVStore`] that
//! allows one to implement the persistence for [`ChannelManager`], [`NetworkGraph`],
//! and [`ChannelMonitor`] all in one place.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// The maximum number of characters namespaces and keys may have.

#[no_mangle]
pub static KVSTORE_NAMESPACE_KEY_MAX_LEN: usize = lightning::util::persist::KVSTORE_NAMESPACE_KEY_MAX_LEN;
/// Provides an interface that allows storage and retrieval of persisted values that are associated
/// with given keys.
///
/// In order to avoid collisions the key space is segmented based on the given `primary_namespace`s
/// and `secondary_namespace`s. Implementations of this trait are free to handle them in different
/// ways, as long as per-namespace key uniqueness is asserted.
///
/// Keys and namespaces are required to be valid ASCII strings in the range of
/// [`KVSTORE_NAMESPACE_KEY_ALPHABET`] and no longer than [`KVSTORE_NAMESPACE_KEY_MAX_LEN`]. Empty
/// primary namespaces and secondary namespaces (`\"\"`) are assumed to be a valid, however, if
/// `primary_namespace` is empty, `secondary_namespace` is required to be empty, too. This means
/// that concerns should always be separated by primary namespace first, before secondary
/// namespaces are used. While the number of primary namespaces will be relatively small and is
/// determined at compile time, there may be many secondary namespaces per primary namespace. Note
/// that per-namespace uniqueness needs to also hold for keys *and* namespaces in any given
/// namespace, i.e., conflicts between keys and equally named
/// primary namespaces/secondary namespaces must be avoided.
///
/// **Note:** Users migrating custom persistence backends from the pre-v0.0.117 `KVStorePersister`
/// interface can use a concatenation of `[{primary_namespace}/[{secondary_namespace}/]]{key}` to
/// recover a `key` compatible with the data model previously assumed by `KVStorePersister::persist`.
#[repr(C)]
pub struct KVStore {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the data stored for the given `primary_namespace`, `secondary_namespace`, and
	/// `key`.
	///
	/// Returns an [`ErrorKind::NotFound`] if the given `key` could not be found in the given
	/// `primary_namespace` and `secondary_namespace`.
	///
	/// [`ErrorKind::NotFound`]: io::ErrorKind::NotFound
	pub read: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_u8ZIOErrorZ,
	/// Persists the given data under the given `key`.
	///
	/// Will create the given `primary_namespace` and `secondary_namespace` if not already present
	/// in the store.
	pub write: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str, buf: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Removes any data that had previously been persisted under the given `key`.
	///
	/// If the `lazy` flag is set to `true`, the backend implementation might choose to lazily
	/// remove the given `key` at some point in time after the method returns, e.g., as part of an
	/// eventual batch deletion of multiple keys. As a consequence, subsequent calls to
	/// [`KVStore::list`] might include the removed key until the changes are actually persisted.
	///
	/// Note that while setting the `lazy` flag reduces the I/O burden of multiple subsequent
	/// `remove` calls, it also influences the atomicity guarantees as lazy `remove`s could
	/// potentially get lost on crash after the method returns. Therefore, this flag should only be
	/// set for `remove` operations that can be safely replayed at a later time.
	///
	/// Returns successfully if no data will be stored for the given `primary_namespace`,
	/// `secondary_namespace`, and `key`, independently of whether it was present before its
	/// invokation or not.
	pub remove: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str, key: crate::c_types::Str, lazy: bool) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Returns a list of keys that are stored under the given `secondary_namespace` in
	/// `primary_namespace`.
	///
	/// Returns the keys in arbitrary order, so users requiring a particular order need to sort the
	/// returned keys. Returns an empty list if `primary_namespace` or `secondary_namespace` is unknown.
	pub list: extern "C" fn (this_arg: *const c_void, primary_namespace: crate::c_types::Str, secondary_namespace: crate::c_types::Str) -> crate::c_types::derived::CResult_CVec_StrZIOErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for KVStore {}
unsafe impl Sync for KVStore {}
#[allow(unused)]
pub(crate) fn KVStore_clone_fields(orig: &KVStore) -> KVStore {
	KVStore {
		this_arg: orig.this_arg,
		read: Clone::clone(&orig.read),
		write: Clone::clone(&orig.write),
		remove: Clone::clone(&orig.remove),
		list: Clone::clone(&orig.list),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::persist::KVStore as rustKVStore;
impl rustKVStore for KVStore {
	fn read(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str) -> Result<Vec<u8>, lightning::io::Error> {
		let mut ret = (self.read)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn write(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut buf: &[u8]) -> Result<(), lightning::io::Error> {
		let mut local_buf = crate::c_types::u8slice::from_slice(buf);
		let mut ret = (self.write)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), local_buf);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn remove(&self, mut primary_namespace: &str, mut secondary_namespace: &str, mut key: &str, mut lazy: bool) -> Result<(), lightning::io::Error> {
		let mut ret = (self.remove)(self.this_arg, primary_namespace.into(), secondary_namespace.into(), key.into(), lazy);
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn list(&self, mut primary_namespace: &str, mut secondary_namespace: &str) -> Result<Vec<String>, lightning::io::Error> {
		let mut ret = (self.list)(self.this_arg, primary_namespace.into(), secondary_namespace.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { item.into_string() }); }; local_ret_0 }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for KVStore {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for KVStore {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn KVStore_free(this_ptr: KVStore) { }
impl Drop for KVStore {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// Trait that handles persisting a [`ChannelManager`], [`NetworkGraph`], and [`WriteableScore`] to disk.
#[repr(C)]
pub struct Persister {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Persist the given ['ChannelManager'] to disk, returning an error if persistence failed.
	pub persist_manager: extern "C" fn (this_arg: *const c_void, channel_manager: &crate::lightning::ln::channelmanager::ChannelManager) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Persist the given [`NetworkGraph`] to disk, returning an error if persistence failed.
	pub persist_graph: extern "C" fn (this_arg: *const c_void, network_graph: &crate::lightning::routing::gossip::NetworkGraph) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Persist the given [`WriteableScore`] to disk, returning an error if persistence failed.
	pub persist_scorer: extern "C" fn (this_arg: *const c_void, scorer: &crate::lightning::routing::scoring::WriteableScore) -> crate::c_types::derived::CResult_NoneIOErrorZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Persister {}
unsafe impl Sync for Persister {}
#[allow(unused)]
pub(crate) fn Persister_clone_fields(orig: &Persister) -> Persister {
	Persister {
		this_arg: orig.this_arg,
		persist_manager: Clone::clone(&orig.persist_manager),
		persist_graph: Clone::clone(&orig.persist_graph),
		persist_scorer: Clone::clone(&orig.persist_scorer),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::persist::Persister as rustPersister;
impl<'a> rustPersister<'a, crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger, crate::lightning::routing::scoring::WriteableScore> for Persister {
	fn persist_manager(&self, mut channel_manager: &lightning::ln::channelmanager::ChannelManager<crate::lightning::chain::Watch, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::sign::EntropySource, crate::lightning::sign::NodeSigner, crate::lightning::sign::SignerProvider, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::routing::router::Router, crate::lightning::util::logger::Logger>) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_manager)(self.this_arg, &crate::lightning::ln::channelmanager::ChannelManager { inner: unsafe { ObjOps::nonnull_ptr_to_inner((channel_manager as *const lightning::ln::channelmanager::ChannelManager<_, _, _, _, _, _, _, _, >) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn persist_graph(&self, mut network_graph: &lightning::routing::gossip::NetworkGraph<crate::lightning::util::logger::Logger>) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_graph)(self.this_arg, &crate::lightning::routing::gossip::NetworkGraph { inner: unsafe { ObjOps::nonnull_ptr_to_inner((network_graph as *const lightning::routing::gossip::NetworkGraph<_, >) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).to_rust() })};
		local_ret
	}
	fn persist_scorer(&self, mut scorer: &crate::lightning::routing::scoring::WriteableScore) -> Result<(), lightning::io::Error> {
		let mut ret = (self.persist_scorer)(self.this_arg, scorer);
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
impl core::ops::DerefMut for Persister {
	fn deref_mut(&mut self) -> &mut Self {
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
/// Read previously persisted [`ChannelMonitor`]s from the store.
#[no_mangle]
pub extern "C" fn read_channel_monitors(mut kv_store: crate::lightning::util::persist::KVStore, mut entropy_source: crate::lightning::sign::EntropySource, mut signer_provider: crate::lightning::sign::SignerProvider) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesChannelMonitorZZIOErrorZ {
	let mut ret = lightning::util::persist::read_channel_monitors::<crate::lightning::util::persist::KVStore, crate::lightning::sign::EntropySource, crate::lightning::sign::SignerProvider>(kv_store, entropy_source, signer_provider);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_0.into_inner() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}


use lightning::util::persist::MonitorUpdatingPersister as nativeMonitorUpdatingPersisterImport;
pub(crate) type nativeMonitorUpdatingPersister = nativeMonitorUpdatingPersisterImport<crate::lightning::util::persist::KVStore, crate::lightning::util::logger::Logger, crate::lightning::sign::EntropySource, crate::lightning::sign::SignerProvider>;

/// Implements [`Persist`] in a way that writes and reads both [`ChannelMonitor`]s and
/// [`ChannelMonitorUpdate`]s.
///
/// # Overview
///
/// The main benefit this provides over the [`KVStore`]'s [`Persist`] implementation is decreased
/// I/O bandwidth and storage churn, at the expense of more IOPS (including listing, reading, and
/// deleting) and complexity. This is because it writes channel monitor differential updates,
/// whereas the other (default) implementation rewrites the entire monitor on each update. For
/// routing nodes, updates can happen many times per second to a channel, and monitors can be tens
/// of megabytes (or more). Updates can be as small as a few hundred bytes.
///
/// Note that monitors written with `MonitorUpdatingPersister` are _not_ backward-compatible with
/// the default [`KVStore`]'s [`Persist`] implementation. They have a prepended byte sequence,
/// [`MONITOR_UPDATING_PERSISTER_PREPEND_SENTINEL`], applied to prevent deserialization with other
/// persisters. This is because monitors written by this struct _may_ have unapplied updates. In
/// order to downgrade, you must ensure that all updates are applied to the monitor, and remove the
/// sentinel bytes.
///
/// # Storing monitors
///
/// Monitors are stored by implementing the [`Persist`] trait, which has two functions:
///
///   - [`Persist::persist_new_channel`], which persists whole [`ChannelMonitor`]s.
///   - [`Persist::update_persisted_channel`], which persists only a [`ChannelMonitorUpdate`]
///
/// Whole [`ChannelMonitor`]s are stored in the [`CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE`],
/// using the familiar encoding of an [`OutPoint`] (for example, `[SOME-64-CHAR-HEX-STRING]_1`).
///
/// Each [`ChannelMonitorUpdate`] is stored in a dynamic secondary namespace, as follows:
///
///   - primary namespace: [`CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE`]
///   - secondary namespace: [the monitor's encoded outpoint name]
///
/// Under that secondary namespace, each update is stored with a number string, like `21`, which
/// represents its `update_id` value.
///
/// For example, consider this channel, named for its transaction ID and index, or [`OutPoint`]:
///
///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
///   - Index: `1`
///
/// Full channel monitors would be stored at a single key:
///
/// `[CHANNEL_MONITOR_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
///
/// Updates would be stored as follows (with `/` delimiting primary_namespace/secondary_namespace/key):
///
/// ```text
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/1
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/2
/// [CHANNEL_MONITOR_UPDATE_PERSISTENCE_PRIMARY_NAMESPACE]/deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1/3
/// ```
/// ... and so on.
///
/// # Reading channel state from storage
///
/// Channel state can be reconstructed by calling
/// [`MonitorUpdatingPersister::read_all_channel_monitors_with_updates`]. Alternatively, users can
/// list channel monitors themselves and load channels individually using
/// [`MonitorUpdatingPersister::read_channel_monitor_with_updates`].
/// 
/// ## EXTREMELY IMPORTANT
/// 
/// It is extremely important that your [`KVStore::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly: that is, when a file is not found, and _only_ in
/// that circumstance (not when there is really a permissions error, for example). This is because
/// neither channel monitor reading function lists updates. Instead, either reads the monitor, and
/// using its stored `update_id`, synthesizes update storage keys, and tries them in sequence until
/// one is not found. All _other_ errors will be bubbled up in the function's [`Result`].
///
/// # Pruning stale channel updates
///
/// Stale updates are pruned when a full monitor is written. The old monitor is first read, and if
/// that succeeds, updates in the range between the old and new monitors are deleted. The `lazy`
/// flag is used on the [`KVStore::remove`] method, so there are no guarantees that the deletions
/// will complete. However, stale updates are not a problem for data integrity, since updates are
/// only read that are higher than the stored [`ChannelMonitor`]'s `update_id`.
///
/// If you have many stale updates stored (such as after a crash with pending lazy deletes), and
/// would like to get rid of them, consider using the
/// [`MonitorUpdatingPersister::cleanup_stale_updates`] function.
#[must_use]
#[repr(C)]
pub struct MonitorUpdatingPersister {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorUpdatingPersister,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MonitorUpdatingPersister {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMonitorUpdatingPersister>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MonitorUpdatingPersister, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_free(this_obj: MonitorUpdatingPersister) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorUpdatingPersister_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMonitorUpdatingPersister) };
}
#[allow(unused)]
impl MonitorUpdatingPersister {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMonitorUpdatingPersister {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMonitorUpdatingPersister {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMonitorUpdatingPersister {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a new [`MonitorUpdatingPersister`].
///
/// The `maximum_pending_updates` parameter controls how many updates may be stored before a
/// [`MonitorUpdatingPersister`] consolidates updates by writing a full monitor. Note that
/// consolidation will frequently occur with fewer updates than what you set here; this number
/// is merely the maximum that may be stored. When setting this value, consider that for higher
/// values of `maximum_pending_updates`:
/// 
///   - [`MonitorUpdatingPersister`] will tend to write more [`ChannelMonitorUpdate`]s than
/// [`ChannelMonitor`]s, approaching one [`ChannelMonitor`] write for every
/// `maximum_pending_updates` [`ChannelMonitorUpdate`]s.
///   - [`MonitorUpdatingPersister`] will issue deletes differently. Lazy deletes will come in
/// \"waves\" for each [`ChannelMonitor`] write. A larger `maximum_pending_updates` means bigger,
/// less frequent \"waves.\"
///   - [`MonitorUpdatingPersister`] will potentially have more listing to do if you need to run
/// [`MonitorUpdatingPersister::cleanup_stale_updates`].
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_new(mut kv_store: crate::lightning::util::persist::KVStore, mut logger: crate::lightning::util::logger::Logger, mut maximum_pending_updates: u64, mut entropy_source: crate::lightning::sign::EntropySource, mut signer_provider: crate::lightning::sign::SignerProvider) -> crate::lightning::util::persist::MonitorUpdatingPersister {
	let mut ret = lightning::util::persist::MonitorUpdatingPersister::new(kv_store, logger, maximum_pending_updates, entropy_source, signer_provider);
	crate::lightning::util::persist::MonitorUpdatingPersister { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Reads all stored channel monitors, along with any stored updates for them.
///
/// It is extremely important that your [`KVStore::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
/// documentation for [`MonitorUpdatingPersister`].
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_read_all_channel_monitors_with_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister, broadcaster: &crate::lightning::chain::chaininterface::BroadcasterInterface, fee_estimator: &crate::lightning::chain::chaininterface::FeeEstimator) -> crate::c_types::derived::CResult_CVec_C2Tuple_ThirtyTwoBytesChannelMonitorZZIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_all_channel_monitors_with_updates(broadcaster, fee_estimator);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let (mut orig_ret_0_0_0, mut orig_ret_0_0_1) = item; let mut local_ret_0_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0_0.into_inner() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_0_1), is_owned: true }).into(); local_ret_0_0 }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

/// Read a single channel monitor, along with any stored updates for it.
///
/// It is extremely important that your [`KVStore::read`] implementation uses the
/// [`io::ErrorKind::NotFound`] variant correctly. For more information, please see the
/// documentation for [`MonitorUpdatingPersister`].
///
/// For `monitor_key`, channel storage keys be the channel's transaction ID and index, or
/// [`OutPoint`], with an underscore `_` between them. For example, given:
///
///   - Transaction ID: `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
///   - Index: `1`
///
/// The correct `monitor_key` would be:
/// `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef_1`
/// 
/// Loading a large number of monitors will be faster if done in parallel. You can use this
/// function to accomplish this. Take care to limit the number of parallel readers.
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_read_channel_monitor_with_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister, broadcaster: &crate::lightning::chain::chaininterface::BroadcasterInterface, fee_estimator: &crate::lightning::chain::chaininterface::FeeEstimator, mut monitor_key: crate::c_types::Str) -> crate::c_types::derived::CResult_C2Tuple_ThirtyTwoBytesChannelMonitorZIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.read_channel_monitor_with_updates(broadcaster, fee_estimator, monitor_key.into_string());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.into_inner() }, crate::lightning::chain::channelmonitor::ChannelMonitor { inner: ObjOps::heap_alloc(orig_ret_0_1), is_owned: true }).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

/// Cleans up stale updates for all monitors.
///
/// This function works by first listing all monitors, and then for each of them, listing all
/// updates. The updates that have an `update_id` less than or equal to than the stored monitor
/// are deleted. The deletion can either be lazy or non-lazy based on the `lazy` flag; this will
/// be passed to [`KVStore::remove`].
#[must_use]
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_cleanup_stale_updates(this_arg: &crate::lightning::util::persist::MonitorUpdatingPersister, mut lazy: bool) -> crate::c_types::derived::CResult_NoneIOErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.cleanup_stale_updates(lazy);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::c_types::IOError::from_rust(e) }).into() };
	local_ret
}

impl From<nativeMonitorUpdatingPersister> for crate::lightning::chain::chainmonitor::Persist {
	fn from(obj: nativeMonitorUpdatingPersister) -> Self {
		let rust_obj = crate::lightning::util::persist::MonitorUpdatingPersister { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = MonitorUpdatingPersister_as_Persist(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(MonitorUpdatingPersister_free_void);
		ret
	}
}
/// Constructs a new Persist which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Persist must be freed before this_arg is
#[no_mangle]
pub extern "C" fn MonitorUpdatingPersister_as_Persist(this_arg: &MonitorUpdatingPersister) -> crate::lightning::chain::chainmonitor::Persist {
	crate::lightning::chain::chainmonitor::Persist {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		persist_new_channel: MonitorUpdatingPersister_Persist_persist_new_channel,
		update_persisted_channel: MonitorUpdatingPersister_Persist_update_persisted_channel,
	}
}

#[must_use]
extern "C" fn MonitorUpdatingPersister_Persist_persist_new_channel(this_arg: *const c_void, mut channel_id: crate::lightning::chain::transaction::OutPoint, data: &crate::lightning::chain::channelmonitor::ChannelMonitor, mut update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::lightning::chain::ChannelMonitorUpdateStatus {
	let mut ret = <nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<_>>::persist_new_channel(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, *unsafe { Box::from_raw(channel_id.take_inner()) }, data.get_native_ref(), *unsafe { Box::from_raw(update_id.take_inner()) });
	crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(ret)
}
#[must_use]
extern "C" fn MonitorUpdatingPersister_Persist_update_persisted_channel(this_arg: *const c_void, mut channel_id: crate::lightning::chain::transaction::OutPoint, mut update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, data: &crate::lightning::chain::channelmonitor::ChannelMonitor, mut update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::lightning::chain::ChannelMonitorUpdateStatus {
	let mut local_update = if update.inner.is_null() { None } else { Some( { update.get_native_ref() }) };
	let mut ret = <nativeMonitorUpdatingPersister as lightning::chain::chainmonitor::Persist<_>>::update_persisted_channel(unsafe { &mut *(this_arg as *mut nativeMonitorUpdatingPersister) }, *unsafe { Box::from_raw(channel_id.take_inner()) }, local_update, data.get_native_ref(), *unsafe { Box::from_raw(update_id.take_inner()) });
	crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(ret)
}

