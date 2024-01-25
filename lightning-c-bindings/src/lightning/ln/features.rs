// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Feature flag definitions for the Lightning protocol according to [BOLT #9].
//!
//! Lightning nodes advertise a supported set of operation through feature flags. Features are
//! applicable for a specific context as indicated in some [messages]. [`Features`] encapsulates
//! behavior for specifying and checking feature flags for a particular context. Each feature is
//! defined internally by a trait specifying the corresponding flags (i.e., even and odd bits).
//!
//! Whether a feature is considered \"known\" or \"unknown\" is relative to the implementation, whereas
//! the term \"supports\" is used in reference to a particular set of [`Features`]. That is, a node
//! supports a feature if it advertises the feature (as either required or optional) to its peers.
//! And the implementation can interpret a feature if the feature is known to it.
//!
//! The following features are currently required in the LDK:
//! - `VariableLengthOnion` - requires/supports variable-length routing onion payloads
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `StaticRemoteKey` - requires/supports static key for remote output
//!     (see [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more information).
//!
//! The following features are currently supported in the LDK:
//! - `DataLossProtect` - requires/supports that a node which has somehow fallen behind, e.g., has been restored from an old backup,
//!     can detect that it has fallen behind
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `InitialRoutingSync` - requires/supports that the sending node needs a complete routing information dump
//!     (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md#initial-sync) for more information).
//! - `UpfrontShutdownScript` - commits to a shutdown scriptpubkey when opening a channel
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `GossipQueries` - requires/supports more sophisticated gossip control
//!     (see [BOLT-7](https://github.com/lightning/bolts/blob/master/07-routing-gossip.md) for more information).
//! - `PaymentSecret` - requires/supports that a node supports payment_secret field
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md) for more information).
//! - `BasicMPP` - requires/supports that a node can receive basic multi-part payments
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#basic-multi-part-payments) for more information).
//! - `Wumbo` - requires/supports that a node create large channels. Called `option_support_large_channel` in the spec.
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-open_channel-message) for more information).
//! - `AnchorsZeroFeeHtlcTx` - requires/supports that commitment transactions include anchor outputs
//!     and HTLC transactions are pre-signed with zero fee (see
//!     [BOLT-3](https://github.com/lightning/bolts/blob/master/03-transactions.md) for more
//!     information).
//! - `RouteBlinding` - requires/supports that a node can relay payments over blinded paths
//!     (see [BOLT-4](https://github.com/lightning/bolts/blob/master/04-onion-routing.md#route-blinding) for more information).
//! - `ShutdownAnySegwit` - requires/supports that future segwit versions are allowed in `shutdown`
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `OnionMessages` - requires/supports forwarding onion messages
//!     (see [BOLT-7](https://github.com/lightning/bolts/pull/759/files) for more information).
//! - `ChannelType` - node supports the channel_type field in open/accept
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `SCIDPrivacy` - supply channel aliases for routing
//!     (see [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md) for more information).
//! - `PaymentMetadata` - include additional data in invoices which is passed to recipients in the
//!      onion.
//!      (see [BOLT-11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md) for
//!      more).
//! - `ZeroConf` - supports accepting HTLCs and using channels prior to funding confirmation
//!      (see
//!      [BOLT-2](https://github.com/lightning/bolts/blob/master/02-peer-protocol.md#the-channel_ready-message)
//!      for more info).
//! - `Keysend` - send funds to a node without an invoice
//!     (see the [`Keysend` feature assignment proposal](https://github.com/lightning/bolts/issues/605#issuecomment-606679798) for more information).
//!
//! LDK knows about the following features, but does not support them:
//! - `AnchorsNonzeroFeeHtlcTx` - the initial version of anchor outputs, which was later found to be
//!     vulnerable (see this
//!     [mailing list post](https://lists.linuxfoundation.org/pipermail/lightning-dev/2020-September/002796.html)
//!     for more information).
//!
//! [BOLT #9]: https://github.com/lightning/bolts/blob/master/09-features.md
//! [messages]: crate::ln::msgs

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

mod sealed {

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_data_loss_protect_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_data_loss_protect_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_data_loss_protect_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_data_loss_protect_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_data_loss_protect(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_data_loss_protect();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_data_loss_protect_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_data_loss_protect_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_data_loss_protect_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_data_loss_protect_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_data_loss_protect(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_data_loss_protect();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_data_loss_protect(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_data_loss_protect();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_data_loss_protect(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_data_loss_protect();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_initial_routing_sync_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_initial_routing_sync_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_initial_routing_sync_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_initial_routing_sync_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_initial_routing_sync(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.initial_routing_sync();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_upfront_shutdown_script_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_upfront_shutdown_script_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_upfront_shutdown_script_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_upfront_shutdown_script_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_upfront_shutdown_script(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_upfront_shutdown_script();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_upfront_shutdown_script_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_upfront_shutdown_script_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_upfront_shutdown_script_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_upfront_shutdown_script_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_upfront_shutdown_script(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_upfront_shutdown_script();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_upfront_shutdown_script(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_upfront_shutdown_script();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_upfront_shutdown_script(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_upfront_shutdown_script();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_gossip_queries_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_gossip_queries_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_gossip_queries_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_gossip_queries_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_gossip_queries(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_gossip_queries();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_gossip_queries_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_gossip_queries_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_gossip_queries_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_gossip_queries_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_gossip_queries(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_gossip_queries();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_gossip_queries(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_gossip_queries();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_gossip_queries(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_gossip_queries();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_variable_length_onion_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_variable_length_onion_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_variable_length_onion_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_variable_length_onion_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_variable_length_onion(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_variable_length_onion();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_variable_length_onion_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_variable_length_onion_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_variable_length_onion_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_variable_length_onion_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_variable_length_onion(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_variable_length_onion();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_variable_length_onion_optional(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_variable_length_onion_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_variable_length_onion_required(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_variable_length_onion_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_supports_variable_length_onion(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_variable_length_onion();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_variable_length_onion(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_variable_length_onion();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_variable_length_onion(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_variable_length_onion();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_variable_length_onion(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_variable_length_onion();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_static_remote_key_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_static_remote_key_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_static_remote_key_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_static_remote_key_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_static_remote_key(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_static_remote_key();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_static_remote_key_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_static_remote_key_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_static_remote_key_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_static_remote_key_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_static_remote_key(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_static_remote_key();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_static_remote_key_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_static_remote_key_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_static_remote_key_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_static_remote_key_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_static_remote_key(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_static_remote_key();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_static_remote_key(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_static_remote_key();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_static_remote_key(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_static_remote_key();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_static_remote_key(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_static_remote_key();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_payment_secret_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_payment_secret_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_payment_secret_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_payment_secret_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_payment_secret(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_payment_secret();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_payment_secret_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_payment_secret_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_payment_secret_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_payment_secret_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_payment_secret(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_payment_secret();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_payment_secret_optional(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_payment_secret_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_payment_secret_required(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_payment_secret_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_supports_payment_secret(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_payment_secret();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_payment_secret(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_payment_secret();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_payment_secret(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_payment_secret();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_payment_secret(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_payment_secret();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_basic_mpp_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_basic_mpp_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_basic_mpp_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_basic_mpp_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_basic_mpp(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_basic_mpp();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_basic_mpp_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_basic_mpp_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_basic_mpp_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_basic_mpp_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_basic_mpp(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_basic_mpp();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_basic_mpp_optional(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_basic_mpp_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_basic_mpp_required(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_basic_mpp_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_supports_basic_mpp(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_basic_mpp();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_basic_mpp_optional(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_basic_mpp_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_basic_mpp_required(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_basic_mpp_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_supports_basic_mpp(this_arg: &crate::lightning::ln::features::Bolt12InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_basic_mpp();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_basic_mpp(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_basic_mpp();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_basic_mpp(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_basic_mpp();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_basic_mpp(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_basic_mpp();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_requires_basic_mpp(this_arg: &crate::lightning::ln::features::Bolt12InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_basic_mpp();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_wumbo_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_wumbo_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_wumbo_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_wumbo_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_wumbo(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_wumbo();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_wumbo_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_wumbo_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_wumbo_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_wumbo_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_wumbo(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_wumbo();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_wumbo(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_wumbo();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_wumbo(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_wumbo();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_anchors_nonzero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_anchors_nonzero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_anchors_nonzero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_anchors_nonzero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_anchors_nonzero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_anchors_nonzero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_anchors_nonzero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_anchors_nonzero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_anchors_nonzero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_anchors_nonzero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_anchors_nonzero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_anchors_nonzero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_anchors_nonzero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_nonzero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_anchors_zero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_anchors_zero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_anchors_zero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_anchors_zero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_zero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_anchors_zero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_anchors_zero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_anchors_zero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_anchors_zero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_zero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_anchors_zero_fee_htlc_tx_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_anchors_zero_fee_htlc_tx_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_anchors_zero_fee_htlc_tx_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_anchors_zero_fee_htlc_tx_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_anchors_zero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_zero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_zero_fee_htlc_tx();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_anchors_zero_fee_htlc_tx(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_anchors_zero_fee_htlc_tx();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_route_blinding_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_route_blinding_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_route_blinding_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_route_blinding_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_route_blinding(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_route_blinding();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_route_blinding_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_route_blinding_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_route_blinding_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_route_blinding_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_route_blinding(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_route_blinding();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_route_blinding(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_route_blinding();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_route_blinding(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_route_blinding();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_shutdown_any_segwit_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_shutdown_any_segwit_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_shutdown_any_segwit_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_shutdown_any_segwit_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_shutdown_anysegwit(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_shutdown_anysegwit();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_shutdown_any_segwit_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_shutdown_any_segwit_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_shutdown_any_segwit_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_shutdown_any_segwit_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_shutdown_anysegwit(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_shutdown_anysegwit();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_shutdown_anysegwit(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_shutdown_anysegwit();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_shutdown_anysegwit(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_shutdown_anysegwit();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_taproot_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_taproot_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_taproot_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_taproot_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_taproot(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_taproot();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_taproot_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_taproot_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_taproot_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_taproot_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_taproot(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_taproot();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_taproot_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_taproot_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_taproot_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_taproot_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_taproot(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_taproot();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_taproot(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_taproot();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_taproot(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_taproot();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_taproot(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_taproot();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_onion_messages_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_onion_messages_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_onion_messages_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_onion_messages_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_onion_messages(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_onion_messages();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_onion_messages_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_onion_messages_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_onion_messages_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_onion_messages_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_onion_messages(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_onion_messages();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_onion_messages(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_onion_messages();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_onion_messages(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_onion_messages();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_channel_type_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_channel_type_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_channel_type_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_channel_type_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_channel_type(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_channel_type();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_channel_type_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_channel_type_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_channel_type_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_channel_type_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_channel_type(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_channel_type();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_channel_type(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_channel_type();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_channel_type(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_channel_type();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_scid_privacy_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_scid_privacy_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_scid_privacy_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_scid_privacy_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_scid_privacy(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_scid_privacy();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_scid_privacy_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_scid_privacy_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_scid_privacy_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_scid_privacy_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_scid_privacy(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_scid_privacy();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_scid_privacy_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_scid_privacy_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_scid_privacy_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_scid_privacy_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_scid_privacy(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_scid_privacy();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_scid_privacy(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_scid_privacy();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_scid_privacy(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_scid_privacy();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_scid_privacy(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_scid_privacy();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_payment_metadata_optional(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_payment_metadata_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_payment_metadata_required(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_payment_metadata_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_supports_payment_metadata(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_payment_metadata();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_payment_metadata(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_payment_metadata();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn InitFeatures_set_zero_conf_optional(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_zero_conf_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn InitFeatures_set_zero_conf_required(this_arg: &mut crate::lightning::ln::features::InitFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_zero_conf_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_supports_zero_conf(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_zero_conf();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_zero_conf_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_zero_conf_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_zero_conf_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_zero_conf_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_zero_conf(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_zero_conf();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_zero_conf_optional(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_zero_conf_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_zero_conf_required(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_zero_conf_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_supports_zero_conf(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_zero_conf();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_zero_conf(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_zero_conf();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_zero_conf(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_zero_conf();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_zero_conf(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_zero_conf();
	ret
}

/// Set this feature as optional.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_keysend_optional(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_keysend_optional()
}

/// Set this feature as required.
#[no_mangle]
pub extern "C" fn NodeFeatures_set_keysend_required(this_arg: &mut crate::lightning::ln::features::NodeFeatures) {
	unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_keysend_required()
}

/// Checks if this feature is supported.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_supports_keysend(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.supports_keysend();
	ret
}

/// Checks if this feature is required.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_keysend(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_keysend();
	ret
}

}
/// Checks if two InitFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InitFeatures_eq(a: &InitFeatures, b: &InitFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two NodeFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn NodeFeatures_eq(a: &NodeFeatures, b: &NodeFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two ChannelFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelFeatures_eq(a: &ChannelFeatures, b: &ChannelFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two Bolt11InvoiceFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_eq(a: &Bolt11InvoiceFeatures, b: &Bolt11InvoiceFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two OfferFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn OfferFeatures_eq(a: &OfferFeatures, b: &OfferFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two InvoiceRequestFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_eq(a: &InvoiceRequestFeatures, b: &InvoiceRequestFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two Bolt12InvoiceFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_eq(a: &Bolt12InvoiceFeatures, b: &Bolt12InvoiceFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two BlindedHopFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_eq(a: &BlindedHopFeatures, b: &BlindedHopFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Checks if two ChannelTypeFeaturess contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_eq(a: &ChannelTypeFeatures, b: &ChannelTypeFeatures) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for InitFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInitFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InitFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInitFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InitFeatures
pub extern "C" fn InitFeatures_clone(orig: &InitFeatures) -> InitFeatures {
	orig.clone()
}
impl Clone for NodeFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeNodeFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeNodeFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the NodeFeatures
pub extern "C" fn NodeFeatures_clone(orig: &NodeFeatures) -> NodeFeatures {
	orig.clone()
}
impl Clone for ChannelFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelFeatures
pub extern "C" fn ChannelFeatures_clone(orig: &ChannelFeatures) -> ChannelFeatures {
	orig.clone()
}
impl Clone for Bolt11InvoiceFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt11InvoiceFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11InvoiceFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt11InvoiceFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt11InvoiceFeatures
pub extern "C" fn Bolt11InvoiceFeatures_clone(orig: &Bolt11InvoiceFeatures) -> Bolt11InvoiceFeatures {
	orig.clone()
}
impl Clone for OfferFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeOfferFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeOfferFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the OfferFeatures
pub extern "C" fn OfferFeatures_clone(orig: &OfferFeatures) -> OfferFeatures {
	orig.clone()
}
impl Clone for InvoiceRequestFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInvoiceRequestFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInvoiceRequestFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InvoiceRequestFeatures
pub extern "C" fn InvoiceRequestFeatures_clone(orig: &InvoiceRequestFeatures) -> InvoiceRequestFeatures {
	orig.clone()
}
impl Clone for Bolt12InvoiceFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBolt12InvoiceFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12InvoiceFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBolt12InvoiceFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Bolt12InvoiceFeatures
pub extern "C" fn Bolt12InvoiceFeatures_clone(orig: &Bolt12InvoiceFeatures) -> Bolt12InvoiceFeatures {
	orig.clone()
}
impl Clone for BlindedHopFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBlindedHopFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHopFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeBlindedHopFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BlindedHopFeatures
pub extern "C" fn BlindedHopFeatures_clone(orig: &BlindedHopFeatures) -> BlindedHopFeatures {
	orig.clone()
}
impl Clone for ChannelTypeFeatures {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelTypeFeatures>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTypeFeatures_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeChannelTypeFeatures)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelTypeFeatures
pub extern "C" fn ChannelTypeFeatures_clone(orig: &ChannelTypeFeatures) -> ChannelTypeFeatures {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the InitFeatures.
#[no_mangle]
pub extern "C" fn InitFeatures_hash(o: &InitFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the NodeFeatures.
#[no_mangle]
pub extern "C" fn NodeFeatures_hash(o: &NodeFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the ChannelFeatures.
#[no_mangle]
pub extern "C" fn ChannelFeatures_hash(o: &ChannelFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the Bolt11InvoiceFeatures.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_hash(o: &Bolt11InvoiceFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the OfferFeatures.
#[no_mangle]
pub extern "C" fn OfferFeatures_hash(o: &OfferFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the InvoiceRequestFeatures.
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_hash(o: &InvoiceRequestFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the Bolt12InvoiceFeatures.
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_hash(o: &Bolt12InvoiceFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the BlindedHopFeatures.
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_hash(o: &BlindedHopFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Generates a non-cryptographic 64-bit hash of the ChannelTypeFeatures.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_hash(o: &ChannelTypeFeatures) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Get a string which allows debug introspection of a InitFeatures object
pub extern "C" fn InitFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::InitFeatures }).into()}
/// Get a string which allows debug introspection of a NodeFeatures object
pub extern "C" fn NodeFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::NodeFeatures }).into()}
/// Get a string which allows debug introspection of a ChannelFeatures object
pub extern "C" fn ChannelFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::ChannelFeatures }).into()}
/// Get a string which allows debug introspection of a Bolt11InvoiceFeatures object
pub extern "C" fn Bolt11InvoiceFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::Bolt11InvoiceFeatures }).into()}
/// Get a string which allows debug introspection of a OfferFeatures object
pub extern "C" fn OfferFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::OfferFeatures }).into()}
/// Get a string which allows debug introspection of a InvoiceRequestFeatures object
pub extern "C" fn InvoiceRequestFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::InvoiceRequestFeatures }).into()}
/// Get a string which allows debug introspection of a Bolt12InvoiceFeatures object
pub extern "C" fn Bolt12InvoiceFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::Bolt12InvoiceFeatures }).into()}
/// Get a string which allows debug introspection of a BlindedHopFeatures object
pub extern "C" fn BlindedHopFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::BlindedHopFeatures }).into()}
/// Get a string which allows debug introspection of a ChannelTypeFeatures object
pub extern "C" fn ChannelTypeFeatures_debug_str_void(o: *const c_void) -> Str {
	alloc::format!("{:?}", unsafe { o as *const crate::lightning::ln::features::ChannelTypeFeatures }).into()}

use lightning::ln::features::InitFeatures as nativeInitFeaturesImport;
pub(crate) type nativeInitFeatures = nativeInitFeaturesImport;

/// Features used within an `init` message.
#[must_use]
#[repr(C)]
pub struct InitFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInitFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InitFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInitFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InitFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InitFeatures_free(this_obj: InitFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InitFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInitFeatures) };
}
#[allow(unused)]
impl InitFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInitFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInitFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInitFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::NodeFeatures as nativeNodeFeaturesImport;
pub(crate) type nativeNodeFeatures = nativeNodeFeaturesImport;

/// Features used within a `node_announcement` message.
#[must_use]
#[repr(C)]
pub struct NodeFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeNodeFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for NodeFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeNodeFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the NodeFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn NodeFeatures_free(this_obj: NodeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn NodeFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeNodeFeatures) };
}
#[allow(unused)]
impl NodeFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeNodeFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeNodeFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeNodeFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelFeatures as nativeChannelFeaturesImport;
pub(crate) type nativeChannelFeatures = nativeChannelFeaturesImport;

/// Features used within a `channel_announcement` message.
#[must_use]
#[repr(C)]
pub struct ChannelFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelFeatures_free(this_obj: ChannelFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelFeatures) };
}
#[allow(unused)]
impl ChannelFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::Bolt11InvoiceFeatures as nativeBolt11InvoiceFeaturesImport;
pub(crate) type nativeBolt11InvoiceFeatures = nativeBolt11InvoiceFeaturesImport;

/// Features used within an invoice.
#[must_use]
#[repr(C)]
pub struct Bolt11InvoiceFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt11InvoiceFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt11InvoiceFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt11InvoiceFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt11InvoiceFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_free(this_obj: Bolt11InvoiceFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt11InvoiceFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt11InvoiceFeatures) };
}
#[allow(unused)]
impl Bolt11InvoiceFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt11InvoiceFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt11InvoiceFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt11InvoiceFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::OfferFeatures as nativeOfferFeaturesImport;
pub(crate) type nativeOfferFeatures = nativeOfferFeaturesImport;

/// Features used within an `offer`.
#[must_use]
#[repr(C)]
pub struct OfferFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeOfferFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for OfferFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeOfferFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the OfferFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn OfferFeatures_free(this_obj: OfferFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn OfferFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeOfferFeatures) };
}
#[allow(unused)]
impl OfferFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeOfferFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeOfferFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeOfferFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::InvoiceRequestFeatures as nativeInvoiceRequestFeaturesImport;
pub(crate) type nativeInvoiceRequestFeatures = nativeInvoiceRequestFeaturesImport;

/// Features used within an `invoice_request`.
#[must_use]
#[repr(C)]
pub struct InvoiceRequestFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInvoiceRequestFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InvoiceRequestFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInvoiceRequestFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InvoiceRequestFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_free(this_obj: InvoiceRequestFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InvoiceRequestFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInvoiceRequestFeatures) };
}
#[allow(unused)]
impl InvoiceRequestFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInvoiceRequestFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInvoiceRequestFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInvoiceRequestFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::Bolt12InvoiceFeatures as nativeBolt12InvoiceFeaturesImport;
pub(crate) type nativeBolt12InvoiceFeatures = nativeBolt12InvoiceFeaturesImport;

/// Features used within an `invoice`.
#[must_use]
#[repr(C)]
pub struct Bolt12InvoiceFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBolt12InvoiceFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Bolt12InvoiceFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBolt12InvoiceFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Bolt12InvoiceFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_free(this_obj: Bolt12InvoiceFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Bolt12InvoiceFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBolt12InvoiceFeatures) };
}
#[allow(unused)]
impl Bolt12InvoiceFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBolt12InvoiceFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBolt12InvoiceFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBolt12InvoiceFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::BlindedHopFeatures as nativeBlindedHopFeaturesImport;
pub(crate) type nativeBlindedHopFeatures = nativeBlindedHopFeaturesImport;

/// Features used within BOLT 4 encrypted_data_tlv and BOLT 12 blinded_payinfo
#[must_use]
#[repr(C)]
pub struct BlindedHopFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBlindedHopFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BlindedHopFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBlindedHopFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BlindedHopFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_free(this_obj: BlindedHopFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BlindedHopFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBlindedHopFeatures) };
}
#[allow(unused)]
impl BlindedHopFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBlindedHopFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBlindedHopFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBlindedHopFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}

use lightning::ln::features::ChannelTypeFeatures as nativeChannelTypeFeaturesImport;
pub(crate) type nativeChannelTypeFeatures = nativeChannelTypeFeaturesImport;

/// Features used within the channel_type field in an OpenChannel message.
///
/// A channel is always of some known \"type\", describing the transaction formats used and the exact
/// semantics of our interaction with our peer.
///
/// Note that because a channel is a specific type which is proposed by the opener and accepted by
/// the counterparty, only required features are allowed here.
///
/// This is serialized differently from other feature types - it is not prefixed by a length, and
/// thus must only appear inside a TLV where its length is known in advance.
#[must_use]
#[repr(C)]
pub struct ChannelTypeFeatures {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelTypeFeatures,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelTypeFeatures {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelTypeFeatures>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelTypeFeatures, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_free(this_obj: ChannelTypeFeatures) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTypeFeatures_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelTypeFeatures) };
}
#[allow(unused)]
impl ChannelTypeFeatures {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelTypeFeatures {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelTypeFeatures {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelTypeFeatures {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_empty() -> crate::lightning::ln::features::InitFeatures {
	let mut ret = lightning::ln::features::InitFeatures::empty();
	crate::lightning::ln::features::InitFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::InitFeatures, other: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::InitFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::InitFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::InitFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::InitFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn InitFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::InitFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInitFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_empty() -> crate::lightning::ln::features::NodeFeatures {
	let mut ret = lightning::ln::features::NodeFeatures::empty();
	crate::lightning::ln::features::NodeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::NodeFeatures, other: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::NodeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::NodeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::NodeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::NodeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn NodeFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::NodeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeNodeFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_empty() -> crate::lightning::ln::features::ChannelFeatures {
	let mut ret = lightning::ln::features::ChannelFeatures::empty();
	crate::lightning::ln::features::ChannelFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::ChannelFeatures, other: &crate::lightning::ln::features::ChannelFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::ChannelFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::ChannelFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::ChannelFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::ChannelFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::ChannelFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_empty() -> crate::lightning::ln::features::Bolt11InvoiceFeatures {
	let mut ret = lightning::ln::features::Bolt11InvoiceFeatures::empty();
	crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures, other: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt11InvoiceFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::Bolt11InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt11InvoiceFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_empty() -> crate::lightning::ln::features::OfferFeatures {
	let mut ret = lightning::ln::features::OfferFeatures::empty();
	crate::lightning::ln::features::OfferFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::OfferFeatures, other: &crate::lightning::ln::features::OfferFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::OfferFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::OfferFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeOfferFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::OfferFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeOfferFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::OfferFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeOfferFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn OfferFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::OfferFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeOfferFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_empty() -> crate::lightning::ln::features::InvoiceRequestFeatures {
	let mut ret = lightning::ln::features::InvoiceRequestFeatures::empty();
	crate::lightning::ln::features::InvoiceRequestFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::InvoiceRequestFeatures, other: &crate::lightning::ln::features::InvoiceRequestFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::InvoiceRequestFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::InvoiceRequestFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInvoiceRequestFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::InvoiceRequestFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInvoiceRequestFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::InvoiceRequestFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInvoiceRequestFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn InvoiceRequestFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::InvoiceRequestFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeInvoiceRequestFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_empty() -> crate::lightning::ln::features::Bolt12InvoiceFeatures {
	let mut ret = lightning::ln::features::Bolt12InvoiceFeatures::empty();
	crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::Bolt12InvoiceFeatures, other: &crate::lightning::ln::features::Bolt12InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::Bolt12InvoiceFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn Bolt12InvoiceFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::Bolt12InvoiceFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBolt12InvoiceFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_empty() -> crate::lightning::ln::features::BlindedHopFeatures {
	let mut ret = lightning::ln::features::BlindedHopFeatures::empty();
	crate::lightning::ln::features::BlindedHopFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::BlindedHopFeatures, other: &crate::lightning::ln::features::BlindedHopFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::BlindedHopFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::BlindedHopFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBlindedHopFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::BlindedHopFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBlindedHopFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::BlindedHopFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBlindedHopFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn BlindedHopFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::BlindedHopFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeBlindedHopFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Create a blank Features with no features set
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_empty() -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut ret = lightning::ln::features::ChannelTypeFeatures::empty();
	crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns true if this `Features` object contains required features unknown by `other`.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_unknown_bits_from(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures, other: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits_from(other.get_native_ref());
	ret
}

/// Returns true if this `Features` object contains unknown feature flags which are set as
/// \"required\".
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_requires_unknown_bits(this_arg: &crate::lightning::ln::features::ChannelTypeFeatures) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.requires_unknown_bits();
	ret
}

/// Sets a required feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_required_feature_bit(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_required_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional feature bit. Errors if `bit` is outside the feature range as defined
/// by [BOLT 9].
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [BOLT 9]: https://github.com/lightning/bolts/blob/master/09-features.md
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_optional_feature_bit(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_optional_feature_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets a required custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Required bits are even. If an odd bit is given, then the corresponding even bit will
/// be set instead (i.e., `bit - 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_required_custom_bit(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_required_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sets an optional custom feature bit. Errors if `bit` is outside the custom range as defined
/// by [bLIP 2] or if it is a known `T` feature.
///
/// Note: Optional bits are odd. If an even bit is given, then the corresponding odd bit will be
/// set instead (i.e., `bit + 1`).
///
/// [bLIP 2]: https://github.com/lightning/blips/blob/master/blip-0002.md#feature-bits
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTypeFeatures_set_optional_custom_bit(this_arg: &mut crate::lightning::ln::features::ChannelTypeFeatures, mut bit: usize) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::features::nativeChannelTypeFeatures)) }.set_optional_custom_bit(bit);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

#[no_mangle]
/// Serialize the InitFeatures object into a byte array which can be read by InitFeatures_read
pub extern "C" fn InitFeatures_write(obj: &crate::lightning::ln::features::InitFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn InitFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInitFeatures) })
}
#[no_mangle]
/// Read a InitFeatures from a byte array, created by InitFeatures_write
pub extern "C" fn InitFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_InitFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::InitFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::InitFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelFeatures object into a byte array which can be read by ChannelFeatures_read
pub extern "C" fn ChannelFeatures_write(obj: &crate::lightning::ln::features::ChannelFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelFeatures) })
}
#[no_mangle]
/// Read a ChannelFeatures from a byte array, created by ChannelFeatures_write
pub extern "C" fn ChannelFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::ChannelFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::ChannelFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the NodeFeatures object into a byte array which can be read by NodeFeatures_read
pub extern "C" fn NodeFeatures_write(obj: &crate::lightning::ln::features::NodeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn NodeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeNodeFeatures) })
}
#[no_mangle]
/// Read a NodeFeatures from a byte array, created by NodeFeatures_write
pub extern "C" fn NodeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_NodeFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::NodeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::NodeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt11InvoiceFeatures object into a byte array which can be read by Bolt11InvoiceFeatures_read
pub extern "C" fn Bolt11InvoiceFeatures_write(obj: &crate::lightning::ln::features::Bolt11InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt11InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBolt11InvoiceFeatures) })
}
#[no_mangle]
/// Read a Bolt11InvoiceFeatures from a byte array, created by Bolt11InvoiceFeatures_write
pub extern "C" fn Bolt11InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt11InvoiceFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::Bolt11InvoiceFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::Bolt11InvoiceFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the Bolt12InvoiceFeatures object into a byte array which can be read by Bolt12InvoiceFeatures_read
pub extern "C" fn Bolt12InvoiceFeatures_write(obj: &crate::lightning::ln::features::Bolt12InvoiceFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn Bolt12InvoiceFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBolt12InvoiceFeatures) })
}
#[no_mangle]
/// Read a Bolt12InvoiceFeatures from a byte array, created by Bolt12InvoiceFeatures_write
pub extern "C" fn Bolt12InvoiceFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_Bolt12InvoiceFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::Bolt12InvoiceFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::Bolt12InvoiceFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the BlindedHopFeatures object into a byte array which can be read by BlindedHopFeatures_read
pub extern "C" fn BlindedHopFeatures_write(obj: &crate::lightning::ln::features::BlindedHopFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn BlindedHopFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBlindedHopFeatures) })
}
#[no_mangle]
/// Read a BlindedHopFeatures from a byte array, created by BlindedHopFeatures_write
pub extern "C" fn BlindedHopFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BlindedHopFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::BlindedHopFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::BlindedHopFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelTypeFeatures object into a byte array which can be read by ChannelTypeFeatures_read
pub extern "C" fn ChannelTypeFeatures_write(obj: &crate::lightning::ln::features::ChannelTypeFeatures) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[allow(unused)]
pub(crate) extern "C" fn ChannelTypeFeatures_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelTypeFeatures) })
}
#[no_mangle]
/// Read a ChannelTypeFeatures from a byte array, created by ChannelTypeFeatures_write
pub extern "C" fn ChannelTypeFeatures_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelTypeFeaturesDecodeErrorZ {
	let res: Result<lightning::ln::features::ChannelTypeFeatures, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::features::ChannelTypeFeatures { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
