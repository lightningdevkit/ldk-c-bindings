// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Logic to connect off-chain channel management with on-chain transaction monitoring.
//!
//! [`ChainMonitor`] is an implementation of [`chain::Watch`] used both to process blocks and to
//! update [`ChannelMonitor`]s accordingly. If any on-chain events need further processing, it will
//! make those available as [`MonitorEvent`]s to be consumed.
//!
//! [`ChainMonitor`] is parameterized by an optional chain source, which must implement the
//! [`chain::Filter`] trait. This provides a mechanism to signal new relevant outputs back to light
//! clients, such that transactions spending those outputs are included in block data.
//!
//! [`ChainMonitor`] may be used directly to monitor channels locally or as a part of a distributed
//! setup to monitor channels remotely. In the latter case, a custom [`chain::Watch`] implementation
//! would be responsible for routing each update to a remote server and for retrieving monitor
//! events. The remote server would make use of [`ChainMonitor`] for block processing and for
//! servicing [`ChannelMonitor`] updates from the client.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod update_origin {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

}

use lightning::chain::chainmonitor::MonitorUpdateId as nativeMonitorUpdateIdImport;
pub(crate) type nativeMonitorUpdateId = nativeMonitorUpdateIdImport;

/// An opaque identifier describing a specific [`Persist`] method call.
#[must_use]
#[repr(C)]
pub struct MonitorUpdateId {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeMonitorUpdateId,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for MonitorUpdateId {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeMonitorUpdateId>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the MonitorUpdateId, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn MonitorUpdateId_free(this_obj: MonitorUpdateId) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorUpdateId_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeMonitorUpdateId) };
}
#[allow(unused)]
impl MonitorUpdateId {
	pub(crate) fn get_native_ref(&self) -> &'static nativeMonitorUpdateId {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeMonitorUpdateId {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeMonitorUpdateId {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for MonitorUpdateId {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeMonitorUpdateId>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn MonitorUpdateId_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeMonitorUpdateId)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the MonitorUpdateId
pub extern "C" fn MonitorUpdateId_clone(orig: &MonitorUpdateId) -> MonitorUpdateId {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the MonitorUpdateId.
#[no_mangle]
pub extern "C" fn MonitorUpdateId_hash(o: &MonitorUpdateId) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two MonitorUpdateIds contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn MonitorUpdateId_eq(a: &MonitorUpdateId, b: &MonitorUpdateId) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// `Persist` defines behavior for persisting channel monitors: this could mean
/// writing once to disk, and/or uploading to one or more backup services.
///
/// Persistence can happen in one of two ways - synchronously completing before the trait method
/// calls return or asynchronously in the background.
///
/// # For those implementing synchronous persistence
///
///  * If persistence completes fully (including any relevant `fsync()` calls), the implementation
///    should return [`ChannelMonitorUpdateStatus::Completed`], indicating normal channel operation
///    should continue.
///
///  * If persistence fails for some reason, implementations should consider returning
///    [`ChannelMonitorUpdateStatus::InProgress`] and retry all pending persistence operations in
///    the background with [`ChainMonitor::list_pending_monitor_updates`] and
///    [`ChainMonitor::get_monitor`].
///
///    Once a full [`ChannelMonitor`] has been persisted, all pending updates for that channel can
///    be marked as complete via [`ChainMonitor::channel_monitor_updated`].
///
///    If at some point no further progress can be made towards persisting the pending updates, the
///    node should simply shut down.
///
///  * If the persistence has failed and cannot be retried further (e.g. because of an outage),
///    [`ChannelMonitorUpdateStatus::UnrecoverableError`] can be used, though this will result in
///    an immediate panic and future operations in LDK generally failing.
///
/// # For those implementing asynchronous persistence
///
///  All calls should generally spawn a background task and immediately return
///  [`ChannelMonitorUpdateStatus::InProgress`]. Once the update completes,
///  [`ChainMonitor::channel_monitor_updated`] should be called with the corresponding
///  [`MonitorUpdateId`].
///
///  Note that unlike the direct [`chain::Watch`] interface,
///  [`ChainMonitor::channel_monitor_updated`] must be called once for *each* update which occurs.
///
///  If at some point no further progress can be made towards persisting a pending update, the node
///  should simply shut down. Until then, the background task should either loop indefinitely, or
///  persistence should be regularly retried with [`ChainMonitor::list_pending_monitor_updates`]
///  and [`ChainMonitor::get_monitor`] (note that if a full monitor is persisted all pending
///  monitor updates may be marked completed).
///
/// # Using remote watchtowers
///
/// Watchtowers may be updated as a part of an implementation of this trait, utilizing the async
/// update process described above while the watchtower is being updated. The following methods are
/// provided for bulding transactions for a watchtower:
/// [`ChannelMonitor::initial_counterparty_commitment_tx`],
/// [`ChannelMonitor::counterparty_commitment_txs_from_update`],
/// [`ChannelMonitor::sign_to_local_justice_tx`], [`TrustedCommitmentTransaction::revokeable_output_index`],
/// [`TrustedCommitmentTransaction::build_to_local_justice_tx`].
///
/// [`TrustedCommitmentTransaction::revokeable_output_index`]: crate::ln::chan_utils::TrustedCommitmentTransaction::revokeable_output_index
/// [`TrustedCommitmentTransaction::build_to_local_justice_tx`]: crate::ln::chan_utils::TrustedCommitmentTransaction::build_to_local_justice_tx
#[repr(C)]
pub struct Persist {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Persist a new channel's data in response to a [`chain::Watch::watch_channel`] call. This is
	/// called by [`ChannelManager`] for new channels, or may be called directly, e.g. on startup.
	///
	/// The data can be stored any way you want, but the identifier provided by LDK is the
	/// channel's outpoint (and it is up to you to maintain a correct mapping between the outpoint
	/// and the stored channel data). Note that you **must** persist every new monitor to disk.
	///
	/// The `update_id` is used to identify this call to [`ChainMonitor::channel_monitor_updated`],
	/// if you return [`ChannelMonitorUpdateStatus::InProgress`].
	///
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`
	/// and [`ChannelMonitorUpdateStatus`] for requirements when returning errors.
	///
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	pub persist_new_channel: extern "C" fn (this_arg: *const c_void, channel_id: crate::lightning::chain::transaction::OutPoint, data: &crate::lightning::chain::channelmonitor::ChannelMonitor, update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::lightning::chain::ChannelMonitorUpdateStatus,
	/// Update one channel's data. The provided [`ChannelMonitor`] has already applied the given
	/// update.
	///
	/// Note that on every update, you **must** persist either the [`ChannelMonitorUpdate`] or the
	/// updated monitor itself to disk/backups. See the [`Persist`] trait documentation for more
	/// details.
	///
	/// During blockchain synchronization operations, and in some rare cases, this may be called with
	/// no [`ChannelMonitorUpdate`], in which case the full [`ChannelMonitor`] needs to be persisted.
	/// Note that after the full [`ChannelMonitor`] is persisted any previous
	/// [`ChannelMonitorUpdate`]s which were persisted should be discarded - they can no longer be
	/// applied to the persisted [`ChannelMonitor`] as they were already applied.
	///
	/// If an implementer chooses to persist the updates only, they need to make
	/// sure that all the updates are applied to the `ChannelMonitors` *before*
	/// the set of channel monitors is given to the `ChannelManager`
	/// deserialization routine. See [`ChannelMonitor::update_monitor`] for
	/// applying a monitor update to a monitor. If full `ChannelMonitors` are
	/// persisted, then there is no need to persist individual updates.
	///
	/// Note that there could be a performance tradeoff between persisting complete
	/// channel monitors on every update vs. persisting only updates and applying
	/// them in batches. The size of each monitor grows `O(number of state updates)`
	/// whereas updates are small and `O(1)`.
	///
	/// The `update_id` is used to identify this call to [`ChainMonitor::channel_monitor_updated`],
	/// if you return [`ChannelMonitorUpdateStatus::InProgress`].
	///
	/// See [`Writeable::write`] on [`ChannelMonitor`] for writing out a `ChannelMonitor`,
	/// [`Writeable::write`] on [`ChannelMonitorUpdate`] for writing out an update, and
	/// [`ChannelMonitorUpdateStatus`] for requirements when returning errors.
	///
	/// [`Writeable::write`]: crate::util::ser::Writeable::write
	///
	/// Note that update (or a relevant inner pointer) may be NULL or all-0s to represent None
	pub update_persisted_channel: extern "C" fn (this_arg: *const c_void, channel_id: crate::lightning::chain::transaction::OutPoint, update: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, data: &crate::lightning::chain::channelmonitor::ChannelMonitor, update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::lightning::chain::ChannelMonitorUpdateStatus,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Persist {}
unsafe impl Sync for Persist {}
pub(crate) fn Persist_clone_fields(orig: &Persist) -> Persist {
	Persist {
		this_arg: orig.this_arg,
		persist_new_channel: Clone::clone(&orig.persist_new_channel),
		update_persisted_channel: Clone::clone(&orig.update_persisted_channel),
		free: Clone::clone(&orig.free),
	}
}

use lightning::chain::chainmonitor::Persist as rustPersist;
impl rustPersist<crate::lightning::sign::WriteableEcdsaChannelSigner> for Persist {
	fn persist_new_channel(&self, mut channel_id: lightning::chain::transaction::OutPoint, mut data: &lightning::chain::channelmonitor::ChannelMonitor<crate::lightning::sign::WriteableEcdsaChannelSigner>, mut update_id: lightning::chain::chainmonitor::MonitorUpdateId) -> lightning::chain::ChannelMonitorUpdateStatus {
		let mut ret = (self.persist_new_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(channel_id), is_owned: true }, &crate::lightning::chain::channelmonitor::ChannelMonitor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((data as *const lightning::chain::channelmonitor::ChannelMonitor<_, >) as *mut _) }, is_owned: false }, crate::lightning::chain::chainmonitor::MonitorUpdateId { inner: ObjOps::heap_alloc(update_id), is_owned: true });
		ret.into_native()
	}
	fn update_persisted_channel(&self, mut channel_id: lightning::chain::transaction::OutPoint, mut update: Option<&lightning::chain::channelmonitor::ChannelMonitorUpdate>, mut data: &lightning::chain::channelmonitor::ChannelMonitor<crate::lightning::sign::WriteableEcdsaChannelSigner>, mut update_id: lightning::chain::chainmonitor::MonitorUpdateId) -> lightning::chain::ChannelMonitorUpdateStatus {
		let mut local_update = crate::lightning::chain::channelmonitor::ChannelMonitorUpdate { inner: unsafe { (if update.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (update.unwrap()) }) } as *const lightning::chain::channelmonitor::ChannelMonitorUpdate<>) as *mut _ }, is_owned: false };
		let mut ret = (self.update_persisted_channel)(self.this_arg, crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(channel_id), is_owned: true }, local_update, &crate::lightning::chain::channelmonitor::ChannelMonitor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((data as *const lightning::chain::channelmonitor::ChannelMonitor<_, >) as *mut _) }, is_owned: false }, crate::lightning::chain::chainmonitor::MonitorUpdateId { inner: ObjOps::heap_alloc(update_id), is_owned: true });
		ret.into_native()
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Persist {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for Persist {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Persist_free(this_ptr: Persist) { }
impl Drop for Persist {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::chain::chainmonitor::LockedChannelMonitor as nativeLockedChannelMonitorImport;
pub(crate) type nativeLockedChannelMonitor = nativeLockedChannelMonitorImport<'static, crate::lightning::sign::WriteableEcdsaChannelSigner>;

/// A read-only reference to a current ChannelMonitor.
///
/// Note that this holds a mutex in [`ChainMonitor`] and may block other events until it is
/// released.
#[must_use]
#[repr(C)]
pub struct LockedChannelMonitor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLockedChannelMonitor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for LockedChannelMonitor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLockedChannelMonitor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LockedChannelMonitor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LockedChannelMonitor_free(this_obj: LockedChannelMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LockedChannelMonitor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeLockedChannelMonitor) };
}
#[allow(unused)]
impl LockedChannelMonitor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLockedChannelMonitor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLockedChannelMonitor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLockedChannelMonitor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::chain::chainmonitor::ChainMonitor as nativeChainMonitorImport;
pub(crate) type nativeChainMonitor = nativeChainMonitorImport<crate::lightning::sign::WriteableEcdsaChannelSigner, crate::lightning::chain::Filter, crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::chain::chaininterface::FeeEstimator, crate::lightning::util::logger::Logger, crate::lightning::chain::chainmonitor::Persist>;

/// An implementation of [`chain::Watch`] for monitoring channels.
///
/// Connected and disconnected blocks must be provided to `ChainMonitor` as documented by
/// [`chain::Watch`]. May be used in conjunction with [`ChannelManager`] to monitor channels locally
/// or used independently to monitor channels remotely. See the [module-level documentation] for
/// details.
///
/// Note that `ChainMonitor` should regularly trigger rebroadcasts/fee bumps of pending claims from
/// a force-closed channel. This is crucial in preventing certain classes of pinning attacks,
/// detecting substantial mempool feerate changes between blocks, and ensuring reliability if
/// broadcasting fails. We recommend invoking this every 30 seconds, or lower if running in an
/// environment with spotty connections, like on mobile.
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [module-level documentation]: crate::chain::chainmonitor
/// [`rebroadcast_pending_claims`]: Self::rebroadcast_pending_claims
#[must_use]
#[repr(C)]
pub struct ChainMonitor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChainMonitor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChainMonitor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChainMonitor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChainMonitor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChainMonitor_free(this_obj: ChainMonitor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChainMonitor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChainMonitor) };
}
#[allow(unused)]
impl ChainMonitor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChainMonitor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChainMonitor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChainMonitor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Creates a new `ChainMonitor` used to watch on-chain activity pertaining to channels.
///
/// When an optional chain source implementing [`chain::Filter`] is provided, the chain monitor
/// will call back to it indicating transactions and outputs of interest. This allows clients to
/// pre-filter blocks or only fetch blocks matching a compact filter. Otherwise, clients may
/// always need to fetch full blocks absent another means for determining which blocks contain
/// transactions relevant to the watched channels.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_new(mut chain_source: crate::c_types::derived::COption_FilterZ, mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut logger: crate::lightning::util::logger::Logger, mut feeest: crate::lightning::chain::chaininterface::FeeEstimator, mut persister: crate::lightning::chain::chainmonitor::Persist) -> crate::lightning::chain::chainmonitor::ChainMonitor {
	let mut local_chain_source = { /*chain_source*/ let chain_source_opt = chain_source; if chain_source_opt.is_none() { None } else { Some({ { { chain_source_opt.take() } }})} };
	let mut ret = lightning::chain::chainmonitor::ChainMonitor::new(local_chain_source, broadcaster, logger, feeest, persister);
	crate::lightning::chain::chainmonitor::ChainMonitor { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Gets the balances in the contained [`ChannelMonitor`]s which are claimable on-chain or
/// claims which are awaiting confirmation.
///
/// Includes the balances from each [`ChannelMonitor`] *except* those included in
/// `ignored_channels`, allowing you to filter out balances from channels which are still open
/// (and whose balance should likely be pulled from the [`ChannelDetails`]).
///
/// See [`ChannelMonitor::get_claimable_balances`] for more details on the exact criteria for
/// inclusion in the return value.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_get_claimable_balances(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor, mut ignored_channels: crate::c_types::derived::CVec_ChannelDetailsZ) -> crate::c_types::derived::CVec_BalanceZ {
	let mut local_ignored_channels = Vec::new(); for mut item in ignored_channels.as_slice().iter() { local_ignored_channels.push( { item.get_native_ref() }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_claimable_balances(&local_ignored_channels[..]);
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::chain::channelmonitor::Balance::native_into(item) }); };
	local_ret.into()
}

/// Gets the [`LockedChannelMonitor`] for a given funding outpoint, returning an `Err` if no
/// such [`ChannelMonitor`] is currently being monitored for.
///
/// Note that the result holds a mutex over our monitor set, and should not be held
/// indefinitely.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_get_monitor(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor, mut funding_txo: crate::lightning::chain::transaction::OutPoint) -> crate::c_types::derived::CResult_LockedChannelMonitorNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_monitor(*unsafe { Box::from_raw(funding_txo.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::chain::chainmonitor::LockedChannelMonitor { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Lists the funding outpoint of each [`ChannelMonitor`] being monitored.
///
/// Note that [`ChannelMonitor`]s are not removed when a channel is closed as they are always
/// monitoring for on-chain state resolutions.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_list_monitors(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor) -> crate::c_types::derived::CVec_OutPointZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_monitors();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
	local_ret.into()
}

/// Lists the pending updates for each [`ChannelMonitor`] (by `OutPoint` being monitored).
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_list_pending_monitor_updates(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor) -> crate::c_types::derived::CVec_C2Tuple_OutPointCVec_MonitorUpdateIdZZZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.list_pending_monitor_updates();
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.drain(..) { local_orig_ret_0_1.push( { crate::lightning::chain::chainmonitor::MonitorUpdateId { inner: ObjOps::heap_alloc(item), is_owned: true } }); }; let mut local_ret_0 = (crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, local_orig_ret_0_1.into()).into(); local_ret_0 }); };
	local_ret.into()
}

/// Indicates the persistence of a [`ChannelMonitor`] has completed after
/// [`ChannelMonitorUpdateStatus::InProgress`] was returned from an update operation.
///
/// Thus, the anticipated use is, at a high level:
///  1) This [`ChainMonitor`] calls [`Persist::update_persisted_channel`] which stores the
///     update to disk and begins updating any remote (e.g. watchtower/backup) copies,
///     returning [`ChannelMonitorUpdateStatus::InProgress`],
///  2) once all remote copies are updated, you call this function with the
///     `completed_update_id` that completed, and once all pending updates have completed the
///     channel will be re-enabled.
///
/// Returns an [`APIError::APIMisuseError`] if `funding_txo` does not match any currently
/// registered [`ChannelMonitor`]s.
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_channel_monitor_updated(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor, mut funding_txo: crate::lightning::chain::transaction::OutPoint, mut completed_update_id: crate::lightning::chain::chainmonitor::MonitorUpdateId) -> crate::c_types::derived::CResult_NoneAPIErrorZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_monitor_updated(*unsafe { Box::from_raw(funding_txo.take_inner()) }, *unsafe { Box::from_raw(completed_update_id.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::util::errors::APIError::native_into(e) }).into() };
	local_ret
}

/// Gets a [`Future`] that completes when an event is available either via
/// [`chain::Watch::release_pending_monitor_events`] or
/// [`EventsProvider::process_pending_events`].
///
/// Note that callbacks registered on the [`Future`] MUST NOT call back into this
/// [`ChainMonitor`] and should instead register actions to be taken later.
///
/// [`EventsProvider::process_pending_events`]: crate::events::EventsProvider::process_pending_events
#[must_use]
#[no_mangle]
pub extern "C" fn ChainMonitor_get_update_future(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor) -> crate::lightning::util::wakers::Future {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_update_future();
	crate::lightning::util::wakers::Future { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Triggers rebroadcasts/fee-bumps of pending claims from a force-closed channel. This is
/// crucial in preventing certain classes of pinning attacks, detecting substantial mempool
/// feerate changes between blocks, and ensuring reliability if broadcasting fails. We recommend
/// invoking this every 30 seconds, or lower if running in an environment with spotty
/// connections, like on mobile.
#[no_mangle]
pub extern "C" fn ChainMonitor_rebroadcast_pending_claims(this_arg: &crate::lightning::chain::chainmonitor::ChainMonitor) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.rebroadcast_pending_claims()
}

impl From<nativeChainMonitor> for crate::lightning::chain::Listen {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Listen(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Listen which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Listen must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Listen(this_arg: &ChainMonitor) -> crate::lightning::chain::Listen {
	crate::lightning::chain::Listen {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		filtered_block_connected: ChainMonitor_Listen_filtered_block_connected,
		block_connected: ChainMonitor_Listen_block_connected,
		block_disconnected: ChainMonitor_Listen_block_disconnected,
	}
}

extern "C" fn ChainMonitor_Listen_filtered_block_connected(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeChainMonitor as lightning::chain::Listen<>>::filtered_block_connected(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn ChainMonitor_Listen_block_connected(this_arg: *const c_void, mut block: crate::c_types::u8slice, mut height: u32) {
	<nativeChainMonitor as lightning::chain::Listen<>>::block_connected(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(block.to_slice()).unwrap(), height)
}
extern "C" fn ChainMonitor_Listen_block_disconnected(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChainMonitor as lightning::chain::Listen<>>::block_disconnected(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}

impl From<nativeChainMonitor> for crate::lightning::chain::Confirm {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Confirm(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Confirm which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Confirm must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Confirm(this_arg: &ChainMonitor) -> crate::lightning::chain::Confirm {
	crate::lightning::chain::Confirm {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		transactions_confirmed: ChainMonitor_Confirm_transactions_confirmed,
		transaction_unconfirmed: ChainMonitor_Confirm_transaction_unconfirmed,
		best_block_updated: ChainMonitor_Confirm_best_block_updated,
		get_relevant_txids: ChainMonitor_Confirm_get_relevant_txids,
	}
}

extern "C" fn ChainMonitor_Confirm_transactions_confirmed(this_arg: *const c_void, header: *const [u8; 80], mut txdata: crate::c_types::derived::CVec_C2Tuple_usizeTransactionZZ, mut height: u32) {
	let mut local_txdata = Vec::new(); for mut item in txdata.into_rust().drain(..) { local_txdata.push( { let (mut orig_txdata_0_0, mut orig_txdata_0_1) = item.to_rust(); let mut local_txdata_0 = (orig_txdata_0_0, orig_txdata_0_1.into_bitcoin()); local_txdata_0 }); };
	<nativeChainMonitor as lightning::chain::Confirm<>>::transactions_confirmed(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), &local_txdata.iter().map(|(a, b)| (*a, b)).collect::<Vec<_>>()[..], height)
}
extern "C" fn ChainMonitor_Confirm_transaction_unconfirmed(this_arg: *const c_void, txid: *const [u8; 32]) {
	<nativeChainMonitor as lightning::chain::Confirm<>>::transaction_unconfirmed(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::hash_types::Txid::from_slice(&unsafe { &*txid }[..]).unwrap())
}
extern "C" fn ChainMonitor_Confirm_best_block_updated(this_arg: *const c_void, header: *const [u8; 80], mut height: u32) {
	<nativeChainMonitor as lightning::chain::Confirm<>>::best_block_updated(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, &::bitcoin::consensus::encode::deserialize(unsafe { &*header }).unwrap(), height)
}
#[must_use]
extern "C" fn ChainMonitor_Confirm_get_relevant_txids(this_arg: *const c_void) -> crate::c_types::derived::CVec_C2Tuple_ThirtyTwoBytesCOption_ThirtyTwoBytesZZZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Confirm<>>::get_relevant_txids(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1) = item; let mut local_orig_ret_0_1 = if orig_ret_0_1.is_none() { crate::c_types::derived::COption_ThirtyTwoBytesZ::None } else { crate::c_types::derived::COption_ThirtyTwoBytesZ::Some( { crate::c_types::ThirtyTwoBytes { data: orig_ret_0_1.unwrap().into_inner() } }) }; let mut local_ret_0 = (crate::c_types::ThirtyTwoBytes { data: orig_ret_0_0.into_inner() }, local_orig_ret_0_1).into(); local_ret_0 }); };
	local_ret.into()
}

impl From<nativeChainMonitor> for crate::lightning::chain::Watch {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_Watch(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new Watch which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned Watch must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_Watch(this_arg: &ChainMonitor) -> crate::lightning::chain::Watch {
	crate::lightning::chain::Watch {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		watch_channel: ChainMonitor_Watch_watch_channel,
		update_channel: ChainMonitor_Watch_update_channel,
		release_pending_monitor_events: ChainMonitor_Watch_release_pending_monitor_events,
	}
}

#[must_use]
extern "C" fn ChainMonitor_Watch_watch_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, mut monitor: crate::lightning::chain::channelmonitor::ChannelMonitor) -> crate::c_types::derived::CResult_ChannelMonitorUpdateStatusNoneZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::watch_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, *unsafe { Box::from_raw(monitor.take_inner()) });
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn ChainMonitor_Watch_update_channel(this_arg: *const c_void, mut funding_txo: crate::lightning::chain::transaction::OutPoint, update: &crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> crate::lightning::chain::ChannelMonitorUpdateStatus {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::update_channel(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, *unsafe { Box::from_raw(funding_txo.take_inner()) }, update.get_native_ref());
	crate::lightning::chain::ChannelMonitorUpdateStatus::native_into(ret)
}
#[must_use]
extern "C" fn ChainMonitor_Watch_release_pending_monitor_events(this_arg: *const c_void) -> crate::c_types::derived::CVec_C3Tuple_OutPointCVec_MonitorEventZPublicKeyZZ {
	let mut ret = <nativeChainMonitor as lightning::chain::Watch<_>>::release_pending_monitor_events(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, );
	let mut local_ret = Vec::new(); for mut item in ret.drain(..) { local_ret.push( { let (mut orig_ret_0_0, mut orig_ret_0_1, mut orig_ret_0_2) = item; let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.drain(..) { local_orig_ret_0_1.push( { crate::lightning::chain::channelmonitor::MonitorEvent::native_into(item) }); }; let mut local_orig_ret_0_2 = if orig_ret_0_2.is_none() { crate::c_types::PublicKey::null() } else {  { crate::c_types::PublicKey::from_rust(&(orig_ret_0_2.unwrap())) } }; let mut local_ret_0 = (crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(orig_ret_0_0), is_owned: true }, local_orig_ret_0_1.into(), local_orig_ret_0_2).into(); local_ret_0 }); };
	local_ret.into()
}

impl From<nativeChainMonitor> for crate::lightning::events::EventsProvider {
	fn from(obj: nativeChainMonitor) -> Self {
		let mut rust_obj = ChainMonitor { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = ChainMonitor_as_EventsProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(ChainMonitor_free_void);
		ret
	}
}
/// Constructs a new EventsProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EventsProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn ChainMonitor_as_EventsProvider(this_arg: &ChainMonitor) -> crate::lightning::events::EventsProvider {
	crate::lightning::events::EventsProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		process_pending_events: ChainMonitor_EventsProvider_process_pending_events,
	}
}

extern "C" fn ChainMonitor_EventsProvider_process_pending_events(this_arg: *const c_void, mut handler: crate::lightning::events::EventHandler) {
	<nativeChainMonitor as lightning::events::EventsProvider<>>::process_pending_events(unsafe { &mut *(this_arg as *mut nativeChainMonitor) }, handler)
}

