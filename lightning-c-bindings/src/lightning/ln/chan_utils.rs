// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Various utilities for building scripts and deriving keys related to channels. These are
//! largely of interest for those implementing the traits on [`crate::sign`] by hand.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Maximum number of one-way in-flight HTLC (protocol-level value).

#[no_mangle]
pub static MAX_HTLCS: u16 = lightning::ln::chan_utils::MAX_HTLCS;
/// The weight of a BIP141 witnessScript for a BOLT3's \"offered HTLC output\" on a commitment transaction, non-anchor variant.

#[no_mangle]
pub static OFFERED_HTLC_SCRIPT_WEIGHT: usize = lightning::ln::chan_utils::OFFERED_HTLC_SCRIPT_WEIGHT;
/// The weight of a BIP141 witnessScript for a BOLT3's \"offered HTLC output\" on a commitment transaction, anchor variant.

#[no_mangle]
pub static OFFERED_HTLC_SCRIPT_WEIGHT_ANCHORS: usize = lightning::ln::chan_utils::OFFERED_HTLC_SCRIPT_WEIGHT_ANCHORS;
/// The weight of a BIP141 witnessScript for a BOLT3's \"received HTLC output\" can vary in function of its CLTV argument value.
/// We define a range that encompasses both its non-anchors and anchors variants.
/// This is the maximum post-anchor value.

#[no_mangle]
pub static MAX_ACCEPTED_HTLC_SCRIPT_WEIGHT: usize = lightning::ln::chan_utils::MAX_ACCEPTED_HTLC_SCRIPT_WEIGHT;
/// The upper bound weight of an anchor input.

#[no_mangle]
pub static ANCHOR_INPUT_WITNESS_WEIGHT: u64 = lightning::ln::chan_utils::ANCHOR_INPUT_WITNESS_WEIGHT;
/// The upper bound weight of an HTLC timeout input from a commitment transaction with anchor
/// outputs.

#[no_mangle]
pub static HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT: u64 = lightning::ln::chan_utils::HTLC_TIMEOUT_INPUT_ANCHOR_WITNESS_WEIGHT;
/// The upper bound weight of an HTLC success input from a commitment transaction with anchor
/// outputs.

#[no_mangle]
pub static HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT: u64 = lightning::ln::chan_utils::HTLC_SUCCESS_INPUT_ANCHOR_WITNESS_WEIGHT;
/// Gets the weight for an HTLC-Success transaction.
#[no_mangle]
pub extern "C" fn htlc_success_tx_weight(channel_type_features: &crate::lightning::ln::features::ChannelTypeFeatures) -> u64 {
	let mut ret = lightning::ln::chan_utils::htlc_success_tx_weight(channel_type_features.get_native_ref());
	ret
}

/// Gets the weight for an HTLC-Timeout transaction.
#[no_mangle]
pub extern "C" fn htlc_timeout_tx_weight(channel_type_features: &crate::lightning::ln::features::ChannelTypeFeatures) -> u64 {
	let mut ret = lightning::ln::chan_utils::htlc_timeout_tx_weight(channel_type_features.get_native_ref());
	ret
}

/// Describes the type of HTLC claim as determined by analyzing the witness.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum HTLCClaim {
	/// Claims an offered output on a commitment transaction through the timeout path.
	OfferedTimeout,
	/// Claims an offered output on a commitment transaction through the success path.
	OfferedPreimage,
	/// Claims an accepted output on a commitment transaction through the timeout path.
	AcceptedTimeout,
	/// Claims an accepted output on a commitment transaction through the success path.
	AcceptedPreimage,
	/// Claims an offered/accepted output on a commitment transaction through the revocation path.
	Revocation,
}
use lightning::ln::chan_utils::HTLCClaim as HTLCClaimImport;
pub(crate) type nativeHTLCClaim = HTLCClaimImport;

impl HTLCClaim {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeHTLCClaim {
		match self {
			HTLCClaim::OfferedTimeout => nativeHTLCClaim::OfferedTimeout,
			HTLCClaim::OfferedPreimage => nativeHTLCClaim::OfferedPreimage,
			HTLCClaim::AcceptedTimeout => nativeHTLCClaim::AcceptedTimeout,
			HTLCClaim::AcceptedPreimage => nativeHTLCClaim::AcceptedPreimage,
			HTLCClaim::Revocation => nativeHTLCClaim::Revocation,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeHTLCClaim {
		match self {
			HTLCClaim::OfferedTimeout => nativeHTLCClaim::OfferedTimeout,
			HTLCClaim::OfferedPreimage => nativeHTLCClaim::OfferedPreimage,
			HTLCClaim::AcceptedTimeout => nativeHTLCClaim::AcceptedTimeout,
			HTLCClaim::AcceptedPreimage => nativeHTLCClaim::AcceptedPreimage,
			HTLCClaim::Revocation => nativeHTLCClaim::Revocation,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeHTLCClaim) -> Self {
		match native {
			nativeHTLCClaim::OfferedTimeout => HTLCClaim::OfferedTimeout,
			nativeHTLCClaim::OfferedPreimage => HTLCClaim::OfferedPreimage,
			nativeHTLCClaim::AcceptedTimeout => HTLCClaim::AcceptedTimeout,
			nativeHTLCClaim::AcceptedPreimage => HTLCClaim::AcceptedPreimage,
			nativeHTLCClaim::Revocation => HTLCClaim::Revocation,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeHTLCClaim) -> Self {
		match native {
			nativeHTLCClaim::OfferedTimeout => HTLCClaim::OfferedTimeout,
			nativeHTLCClaim::OfferedPreimage => HTLCClaim::OfferedPreimage,
			nativeHTLCClaim::AcceptedTimeout => HTLCClaim::AcceptedTimeout,
			nativeHTLCClaim::AcceptedPreimage => HTLCClaim::AcceptedPreimage,
			nativeHTLCClaim::Revocation => HTLCClaim::Revocation,
		}
	}
}
/// Creates a copy of the HTLCClaim
#[no_mangle]
pub extern "C" fn HTLCClaim_clone(orig: &HTLCClaim) -> HTLCClaim {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new OfferedTimeout-variant HTLCClaim
pub extern "C" fn HTLCClaim_offered_timeout() -> HTLCClaim {
	HTLCClaim::OfferedTimeout}
#[no_mangle]
/// Utility method to constructs a new OfferedPreimage-variant HTLCClaim
pub extern "C" fn HTLCClaim_offered_preimage() -> HTLCClaim {
	HTLCClaim::OfferedPreimage}
#[no_mangle]
/// Utility method to constructs a new AcceptedTimeout-variant HTLCClaim
pub extern "C" fn HTLCClaim_accepted_timeout() -> HTLCClaim {
	HTLCClaim::AcceptedTimeout}
#[no_mangle]
/// Utility method to constructs a new AcceptedPreimage-variant HTLCClaim
pub extern "C" fn HTLCClaim_accepted_preimage() -> HTLCClaim {
	HTLCClaim::AcceptedPreimage}
#[no_mangle]
/// Utility method to constructs a new Revocation-variant HTLCClaim
pub extern "C" fn HTLCClaim_revocation() -> HTLCClaim {
	HTLCClaim::Revocation}
/// Checks if two HTLCClaims contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn HTLCClaim_eq(a: &HTLCClaim, b: &HTLCClaim) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Check if a given input witness attempts to claim a HTLC.
#[must_use]
#[no_mangle]
pub extern "C" fn HTLCClaim_from_witness(mut witness: crate::c_types::Witness) -> crate::c_types::derived::COption_HTLCClaimZ {
	let mut ret = lightning::ln::chan_utils::HTLCClaim::from_witness(&witness.into_bitcoin());
	let mut local_ret = if ret.is_none() { crate::c_types::derived::COption_HTLCClaimZ::None } else { crate::c_types::derived::COption_HTLCClaimZ::Some( { crate::lightning::ln::chan_utils::HTLCClaim::native_into(ret.unwrap()) }) };
	local_ret
}

/// Build the commitment secret from the seed and the commitment number
#[no_mangle]
pub extern "C" fn build_commitment_secret(commitment_seed: *const [u8; 32], mut idx: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = lightning::ln::chan_utils::build_commitment_secret(unsafe { &*commitment_seed}, idx);
	crate::c_types::ThirtyTwoBytes { data: ret }
}

/// Build a closing transaction
#[no_mangle]
pub extern "C" fn build_closing_transaction(mut to_holder_value_sat: u64, mut to_counterparty_value_sat: u64, mut to_holder_script: crate::c_types::derived::CVec_u8Z, mut to_counterparty_script: crate::c_types::derived::CVec_u8Z, mut funding_outpoint: crate::lightning::chain::transaction::OutPoint) -> crate::c_types::Transaction {
	let mut ret = lightning::ln::chan_utils::build_closing_transaction(to_holder_value_sat, to_counterparty_value_sat, ::bitcoin::blockdata::script::Script::from(to_holder_script.into_rust()), ::bitcoin::blockdata::script::Script::from(to_counterparty_script.into_rust()), crate::c_types::C_to_bitcoin_outpoint(funding_outpoint));
	crate::c_types::Transaction::from_bitcoin(&ret)
}


use lightning::ln::chan_utils::CounterpartyCommitmentSecrets as nativeCounterpartyCommitmentSecretsImport;
pub(crate) type nativeCounterpartyCommitmentSecrets = nativeCounterpartyCommitmentSecretsImport;

/// Implements the per-commitment secret storage scheme from
/// [BOLT 3](https://github.com/lightning/bolts/blob/dcbf8583976df087c79c3ce0b535311212e6812d/03-transactions.md#efficient-per-commitment-secret-storage).
///
/// Allows us to keep track of all of the revocation secrets of our counterparty in just 50*32 bytes
/// or so.
#[must_use]
#[repr(C)]
pub struct CounterpartyCommitmentSecrets {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCounterpartyCommitmentSecrets,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for CounterpartyCommitmentSecrets {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCounterpartyCommitmentSecrets>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CounterpartyCommitmentSecrets, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CounterpartyCommitmentSecrets_free(this_obj: CounterpartyCommitmentSecrets) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyCommitmentSecrets_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCounterpartyCommitmentSecrets) };
}
#[allow(unused)]
impl CounterpartyCommitmentSecrets {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCounterpartyCommitmentSecrets {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCounterpartyCommitmentSecrets {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCounterpartyCommitmentSecrets {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for CounterpartyCommitmentSecrets {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCounterpartyCommitmentSecrets>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyCommitmentSecrets_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCounterpartyCommitmentSecrets)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CounterpartyCommitmentSecrets
pub extern "C" fn CounterpartyCommitmentSecrets_clone(orig: &CounterpartyCommitmentSecrets) -> CounterpartyCommitmentSecrets {
	orig.clone()
}
/// Creates a new empty `CounterpartyCommitmentSecrets` structure.
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyCommitmentSecrets_new() -> crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets {
	let mut ret = lightning::ln::chan_utils::CounterpartyCommitmentSecrets::new();
	crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the minimum index of all stored secrets. Note that indexes start
/// at 1 << 48 and get decremented by one for each new secret.
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyCommitmentSecrets_get_min_seen_secret(this_arg: &crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_min_seen_secret();
	ret
}

/// Inserts the `secret` at `idx`. Returns `Ok(())` if the secret
/// was generated in accordance with BOLT 3 and is consistent with previous secrets.
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyCommitmentSecrets_provide_secret(this_arg: &mut crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets, mut idx: u64, mut secret: crate::c_types::ThirtyTwoBytes) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = unsafe { &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::lightning::ln::chan_utils::nativeCounterpartyCommitmentSecrets)) }.provide_secret(idx, secret.data);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Returns the secret at `idx`.
/// Returns `None` if `idx` is < [`CounterpartyCommitmentSecrets::get_min_seen_secret`].
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyCommitmentSecrets_get_secret(this_arg: &crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets, mut idx: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_secret(idx);
	let mut local_ret = if ret.is_none() { crate::c_types::ThirtyTwoBytes { data: [0; 32] } } else {  { crate::c_types::ThirtyTwoBytes { data: (ret.unwrap()) } } };
	local_ret
}

#[no_mangle]
/// Serialize the CounterpartyCommitmentSecrets object into a byte array which can be read by CounterpartyCommitmentSecrets_read
pub extern "C" fn CounterpartyCommitmentSecrets_write(obj: &crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn CounterpartyCommitmentSecrets_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCounterpartyCommitmentSecrets) })
}
#[no_mangle]
/// Read a CounterpartyCommitmentSecrets from a byte array, created by CounterpartyCommitmentSecrets_write
pub extern "C" fn CounterpartyCommitmentSecrets_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CounterpartyCommitmentSecretsDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::CounterpartyCommitmentSecrets, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::CounterpartyCommitmentSecrets { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Derives a per-commitment-transaction private key (eg an htlc key or delayed_payment key)
/// from the base secret and the per_commitment_point.
#[no_mangle]
pub extern "C" fn derive_private_key(mut per_commitment_point: crate::c_types::PublicKey, base_secret: *const [u8; 32]) -> crate::c_types::SecretKey {
	let mut ret = lightning::ln::chan_utils::derive_private_key(secp256k1::global::SECP256K1, &per_commitment_point.into_rust(), &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *base_secret}[..]).unwrap());
	crate::c_types::SecretKey::from_rust(ret)
}

/// Derives a per-commitment-transaction public key (eg an htlc key or a delayed_payment key)
/// from the base point and the per_commitment_key. This is the public equivalent of
/// derive_private_key - using only public keys to derive a public key instead of private keys.
#[no_mangle]
pub extern "C" fn derive_public_key(mut per_commitment_point: crate::c_types::PublicKey, mut base_point: crate::c_types::PublicKey) -> crate::c_types::PublicKey {
	let mut ret = lightning::ln::chan_utils::derive_public_key(secp256k1::global::SECP256K1, &per_commitment_point.into_rust(), &base_point.into_rust());
	crate::c_types::PublicKey::from_rust(&ret)
}

/// Derives a per-commitment-transaction revocation key from its constituent parts.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_secret always come from cheater
/// and revocation_base_secret always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
#[no_mangle]
pub extern "C" fn derive_private_revocation_key(per_commitment_secret: *const [u8; 32], countersignatory_revocation_base_secret: *const [u8; 32]) -> crate::c_types::SecretKey {
	let mut ret = lightning::ln::chan_utils::derive_private_revocation_key(secp256k1::global::SECP256K1, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *per_commitment_secret}[..]).unwrap(), &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *countersignatory_revocation_base_secret}[..]).unwrap());
	crate::c_types::SecretKey::from_rust(ret)
}

/// Derives a per-commitment-transaction revocation public key from its constituent parts. This is
/// the public equivalend of derive_private_revocation_key - using only public keys to derive a
/// public key instead of private keys.
///
/// Only the cheating participant owns a valid witness to propagate a revoked
/// commitment transaction, thus per_commitment_point always come from cheater
/// and revocation_base_point always come from punisher, which is the broadcaster
/// of the transaction spending with this key knowledge.
///
/// Note that this is infallible iff we trust that at least one of the two input keys are randomly
/// generated (ie our own).
#[no_mangle]
pub extern "C" fn derive_public_revocation_key(mut per_commitment_point: crate::c_types::PublicKey, mut countersignatory_revocation_base_point: crate::c_types::PublicKey) -> crate::c_types::PublicKey {
	let mut ret = lightning::ln::chan_utils::derive_public_revocation_key(secp256k1::global::SECP256K1, &per_commitment_point.into_rust(), &countersignatory_revocation_base_point.into_rust());
	crate::c_types::PublicKey::from_rust(&ret)
}


use lightning::ln::chan_utils::TxCreationKeys as nativeTxCreationKeysImport;
pub(crate) type nativeTxCreationKeys = nativeTxCreationKeysImport;

/// The set of public keys which are used in the creation of one commitment transaction.
/// These are derived from the channel base keys and per-commitment data.
///
/// A broadcaster key is provided from potential broadcaster of the computed transaction.
/// A countersignatory key is coming from a protocol participant unable to broadcast the
/// transaction.
///
/// These keys are assumed to be good, either because the code derived them from
/// channel basepoints via the new function, or they were obtained via
/// CommitmentTransaction.trust().keys() because we trusted the source of the
/// pre-calculated keys.
#[must_use]
#[repr(C)]
pub struct TxCreationKeys {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTxCreationKeys,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for TxCreationKeys {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTxCreationKeys>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TxCreationKeys, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TxCreationKeys_free(this_obj: TxCreationKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxCreationKeys_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTxCreationKeys) };
}
#[allow(unused)]
impl TxCreationKeys {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTxCreationKeys {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTxCreationKeys {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTxCreationKeys {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The broadcaster's per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_per_commitment_point(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().per_commitment_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The broadcaster's per-commitment public key which was used to derive the other keys.
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_per_commitment_point(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.per_commitment_point = val.into_rust();
}
/// The revocation key which is used to allow the broadcaster of the commitment
/// transaction to provide their counterparty the ability to punish them if they broadcast
/// an old state.
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_revocation_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().revocation_key;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The revocation key which is used to allow the broadcaster of the commitment
/// transaction to provide their counterparty the ability to punish them if they broadcast
/// an old state.
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_revocation_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.revocation_key = val.into_rust();
}
/// Broadcaster's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_broadcaster_htlc_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().broadcaster_htlc_key;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Broadcaster's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_broadcaster_htlc_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.broadcaster_htlc_key = val.into_rust();
}
/// Countersignatory's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_countersignatory_htlc_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().countersignatory_htlc_key;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Countersignatory's HTLC Key
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_countersignatory_htlc_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.countersignatory_htlc_key = val.into_rust();
}
/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
#[no_mangle]
pub extern "C" fn TxCreationKeys_get_broadcaster_delayed_payment_key(this_ptr: &TxCreationKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().broadcaster_delayed_payment_key;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Broadcaster's Payment Key (which isn't allowed to be spent from for some delay)
#[no_mangle]
pub extern "C" fn TxCreationKeys_set_broadcaster_delayed_payment_key(this_ptr: &mut TxCreationKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.broadcaster_delayed_payment_key = val.into_rust();
}
/// Constructs a new TxCreationKeys given each field
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_new(mut per_commitment_point_arg: crate::c_types::PublicKey, mut revocation_key_arg: crate::c_types::PublicKey, mut broadcaster_htlc_key_arg: crate::c_types::PublicKey, mut countersignatory_htlc_key_arg: crate::c_types::PublicKey, mut broadcaster_delayed_payment_key_arg: crate::c_types::PublicKey) -> TxCreationKeys {
	TxCreationKeys { inner: ObjOps::heap_alloc(nativeTxCreationKeys {
		per_commitment_point: per_commitment_point_arg.into_rust(),
		revocation_key: revocation_key_arg.into_rust(),
		broadcaster_htlc_key: broadcaster_htlc_key_arg.into_rust(),
		countersignatory_htlc_key: countersignatory_htlc_key_arg.into_rust(),
		broadcaster_delayed_payment_key: broadcaster_delayed_payment_key_arg.into_rust(),
	}), is_owned: true }
}
/// Checks if two TxCreationKeyss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn TxCreationKeys_eq(a: &TxCreationKeys, b: &TxCreationKeys) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
impl Clone for TxCreationKeys {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeTxCreationKeys>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TxCreationKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeTxCreationKeys)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the TxCreationKeys
pub extern "C" fn TxCreationKeys_clone(orig: &TxCreationKeys) -> TxCreationKeys {
	orig.clone()
}
#[no_mangle]
/// Serialize the TxCreationKeys object into a byte array which can be read by TxCreationKeys_read
pub extern "C" fn TxCreationKeys_write(obj: &crate::lightning::ln::chan_utils::TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn TxCreationKeys_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeTxCreationKeys) })
}
#[no_mangle]
/// Read a TxCreationKeys from a byte array, created by TxCreationKeys_write
pub extern "C" fn TxCreationKeys_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_TxCreationKeysDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::TxCreationKeys, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::TxCreationKeys { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::chan_utils::ChannelPublicKeys as nativeChannelPublicKeysImport;
pub(crate) type nativeChannelPublicKeys = nativeChannelPublicKeysImport;

/// One counterparty's public keys which do not change over the life of a channel.
#[must_use]
#[repr(C)]
pub struct ChannelPublicKeys {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelPublicKeys,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelPublicKeys {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelPublicKeys>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelPublicKeys, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_free(this_obj: ChannelPublicKeys) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelPublicKeys_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelPublicKeys) };
}
#[allow(unused)]
impl ChannelPublicKeys {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelPublicKeys {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelPublicKeys {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelPublicKeys {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The public key which is used to sign all commitment transactions, as it appears in the
/// on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_funding_pubkey(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_pubkey;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The public key which is used to sign all commitment transactions, as it appears in the
/// on-chain channel lock-in 2-of-2 multisig output.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_funding_pubkey(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_pubkey = val.into_rust();
}
/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
/// revocation keys. This is combined with the per-commitment-secret generated by the
/// counterparty to create a secret which the counterparty can reveal to revoke previous
/// states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_revocation_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().revocation_basepoint;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The base point which is used (with derive_public_revocation_key) to derive per-commitment
/// revocation keys. This is combined with the per-commitment-secret generated by the
/// counterparty to create a secret which the counterparty can reveal to revoke previous
/// states.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_revocation_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.revocation_basepoint = val.into_rust();
}
/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
/// static across every commitment transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_payment_point(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The public key on which the non-broadcaster (ie the countersignatory) receives an immediately
/// spendable primary channel balance on the broadcaster's commitment transaction. This key is
/// static across every commitment transaction.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_payment_point(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_point = val.into_rust();
}
/// The base point which is used (with derive_public_key) to derive a per-commitment payment
/// public key which receives non-HTLC-encumbered funds which are only available for spending
/// after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_delayed_payment_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().delayed_payment_basepoint;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The base point which is used (with derive_public_key) to derive a per-commitment payment
/// public key which receives non-HTLC-encumbered funds which are only available for spending
/// after some delay (or can be claimed via the revocation path).
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_delayed_payment_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.delayed_payment_basepoint = val.into_rust();
}
/// The base point which is used (with derive_public_key) to derive a per-commitment public key
/// which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_get_htlc_basepoint(this_ptr: &ChannelPublicKeys) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_basepoint;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The base point which is used (with derive_public_key) to derive a per-commitment public key
/// which is used to encumber HTLC-in-flight outputs.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_set_htlc_basepoint(this_ptr: &mut ChannelPublicKeys, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_basepoint = val.into_rust();
}
/// Constructs a new ChannelPublicKeys given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_new(mut funding_pubkey_arg: crate::c_types::PublicKey, mut revocation_basepoint_arg: crate::c_types::PublicKey, mut payment_point_arg: crate::c_types::PublicKey, mut delayed_payment_basepoint_arg: crate::c_types::PublicKey, mut htlc_basepoint_arg: crate::c_types::PublicKey) -> ChannelPublicKeys {
	ChannelPublicKeys { inner: ObjOps::heap_alloc(nativeChannelPublicKeys {
		funding_pubkey: funding_pubkey_arg.into_rust(),
		revocation_basepoint: revocation_basepoint_arg.into_rust(),
		payment_point: payment_point_arg.into_rust(),
		delayed_payment_basepoint: delayed_payment_basepoint_arg.into_rust(),
		htlc_basepoint: htlc_basepoint_arg.into_rust(),
	}), is_owned: true }
}
impl Clone for ChannelPublicKeys {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelPublicKeys>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelPublicKeys_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelPublicKeys)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelPublicKeys
pub extern "C" fn ChannelPublicKeys_clone(orig: &ChannelPublicKeys) -> ChannelPublicKeys {
	orig.clone()
}
/// Checks if two ChannelPublicKeyss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelPublicKeys_eq(a: &ChannelPublicKeys, b: &ChannelPublicKeys) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the ChannelPublicKeys object into a byte array which can be read by ChannelPublicKeys_read
pub extern "C" fn ChannelPublicKeys_write(obj: &crate::lightning::ln::chan_utils::ChannelPublicKeys) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelPublicKeys_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelPublicKeys) })
}
#[no_mangle]
/// Read a ChannelPublicKeys from a byte array, created by ChannelPublicKeys_write
pub extern "C" fn ChannelPublicKeys_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelPublicKeysDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::ChannelPublicKeys, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Create per-state keys from channel base points and the per-commitment point.
/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_derive_new(mut per_commitment_point: crate::c_types::PublicKey, mut broadcaster_delayed_payment_base: crate::c_types::PublicKey, mut broadcaster_htlc_base: crate::c_types::PublicKey, mut countersignatory_revocation_base: crate::c_types::PublicKey, mut countersignatory_htlc_base: crate::c_types::PublicKey) -> crate::lightning::ln::chan_utils::TxCreationKeys {
	let mut ret = lightning::ln::chan_utils::TxCreationKeys::derive_new(secp256k1::global::SECP256K1, &per_commitment_point.into_rust(), &broadcaster_delayed_payment_base.into_rust(), &broadcaster_htlc_base.into_rust(), &countersignatory_revocation_base.into_rust(), &countersignatory_htlc_base.into_rust());
	crate::lightning::ln::chan_utils::TxCreationKeys { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Generate per-state keys from channel static keys.
/// Key set is asymmetric and can't be used as part of counter-signatory set of transactions.
#[must_use]
#[no_mangle]
pub extern "C" fn TxCreationKeys_from_channel_static_keys(mut per_commitment_point: crate::c_types::PublicKey, broadcaster_keys: &crate::lightning::ln::chan_utils::ChannelPublicKeys, countersignatory_keys: &crate::lightning::ln::chan_utils::ChannelPublicKeys) -> crate::lightning::ln::chan_utils::TxCreationKeys {
	let mut ret = lightning::ln::chan_utils::TxCreationKeys::from_channel_static_keys(&per_commitment_point.into_rust(), broadcaster_keys.get_native_ref(), countersignatory_keys.get_native_ref(), secp256k1::global::SECP256K1);
	crate::lightning::ln::chan_utils::TxCreationKeys { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// The maximum length of a script returned by get_revokeable_redeemscript.

#[no_mangle]
pub static REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH: usize = lightning::ln::chan_utils::REVOKEABLE_REDEEMSCRIPT_MAX_LENGTH;
/// A script either spendable by the revocation
/// key or the broadcaster_delayed_payment_key and satisfying the relative-locktime OP_CSV constrain.
/// Encumbering a `to_holder` output on a commitment transaction or 2nd-stage HTLC transactions.
#[no_mangle]
pub extern "C" fn get_revokeable_redeemscript(mut revocation_key: crate::c_types::PublicKey, mut contest_delay: u16, mut broadcaster_delayed_payment_key: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_revokeable_redeemscript(&revocation_key.into_rust(), contest_delay, &broadcaster_delayed_payment_key.into_rust());
	ret.into_bytes().into()
}


use lightning::ln::chan_utils::HTLCOutputInCommitment as nativeHTLCOutputInCommitmentImport;
pub(crate) type nativeHTLCOutputInCommitment = nativeHTLCOutputInCommitmentImport;

/// Information about an HTLC as it appears in a commitment transaction
#[must_use]
#[repr(C)]
pub struct HTLCOutputInCommitment {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHTLCOutputInCommitment,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for HTLCOutputInCommitment {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHTLCOutputInCommitment>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HTLCOutputInCommitment, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_free(this_obj: HTLCOutputInCommitment) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCOutputInCommitment_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHTLCOutputInCommitment) };
}
#[allow(unused)]
impl HTLCOutputInCommitment {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHTLCOutputInCommitment {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHTLCOutputInCommitment {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHTLCOutputInCommitment {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
/// Note that this is not the same as whether it is ountbound *from us*. To determine that you
/// need to compare this value to whether the commitment transaction in question is that of
/// the counterparty or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_offered(this_ptr: &HTLCOutputInCommitment) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().offered;
	*inner_val
}
/// Whether the HTLC was \"offered\" (ie outbound in relation to this commitment transaction).
/// Note that this is not the same as whether it is ountbound *from us*. To determine that you
/// need to compare this value to whether the commitment transaction in question is that of
/// the counterparty or our own.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_offered(this_ptr: &mut HTLCOutputInCommitment, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.offered = val;
}
/// The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
/// this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_amount_msat(this_ptr: &HTLCOutputInCommitment) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().amount_msat;
	*inner_val
}
/// The value, in msat, of the HTLC. The value as it appears in the commitment transaction is
/// this divided by 1000.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_amount_msat(this_ptr: &mut HTLCOutputInCommitment, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.amount_msat = val;
}
/// The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_cltv_expiry(this_ptr: &HTLCOutputInCommitment) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().cltv_expiry;
	*inner_val
}
/// The CLTV lock-time at which this HTLC expires.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_cltv_expiry(this_ptr: &mut HTLCOutputInCommitment, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.cltv_expiry = val;
}
/// The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_payment_hash(this_ptr: &HTLCOutputInCommitment) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_hash;
	&inner_val.0
}
/// The hash of the preimage which unlocks this HTLC.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_payment_hash(this_ptr: &mut HTLCOutputInCommitment, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_hash = ::lightning::ln::PaymentHash(val.data);
}
/// The position within the commitment transactions' outputs. This may be None if the value is
/// below the dust limit (in which case no output appears in the commitment transaction and the
/// value is spent to additional transaction fees).
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_get_transaction_output_index(this_ptr: &HTLCOutputInCommitment) -> crate::c_types::derived::COption_u32Z {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().transaction_output_index;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_u32Z::None } else { crate::c_types::derived::COption_u32Z::Some( { inner_val.unwrap() }) };
	local_inner_val
}
/// The position within the commitment transactions' outputs. This may be None if the value is
/// below the dust limit (in which case no output appears in the commitment transaction and the
/// value is spent to additional transaction fees).
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_set_transaction_output_index(this_ptr: &mut HTLCOutputInCommitment, mut val: crate::c_types::derived::COption_u32Z) {
	let mut local_val = if val.is_some() { Some( { val.take() }) } else { None };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.transaction_output_index = local_val;
}
/// Constructs a new HTLCOutputInCommitment given each field
#[must_use]
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_new(mut offered_arg: bool, mut amount_msat_arg: u64, mut cltv_expiry_arg: u32, mut payment_hash_arg: crate::c_types::ThirtyTwoBytes, mut transaction_output_index_arg: crate::c_types::derived::COption_u32Z) -> HTLCOutputInCommitment {
	let mut local_transaction_output_index_arg = if transaction_output_index_arg.is_some() { Some( { transaction_output_index_arg.take() }) } else { None };
	HTLCOutputInCommitment { inner: ObjOps::heap_alloc(nativeHTLCOutputInCommitment {
		offered: offered_arg,
		amount_msat: amount_msat_arg,
		cltv_expiry: cltv_expiry_arg,
		payment_hash: ::lightning::ln::PaymentHash(payment_hash_arg.data),
		transaction_output_index: local_transaction_output_index_arg,
	}), is_owned: true }
}
impl Clone for HTLCOutputInCommitment {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHTLCOutputInCommitment>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HTLCOutputInCommitment_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHTLCOutputInCommitment)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HTLCOutputInCommitment
pub extern "C" fn HTLCOutputInCommitment_clone(orig: &HTLCOutputInCommitment) -> HTLCOutputInCommitment {
	orig.clone()
}
/// Checks if two HTLCOutputInCommitments contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn HTLCOutputInCommitment_eq(a: &HTLCOutputInCommitment, b: &HTLCOutputInCommitment) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the HTLCOutputInCommitment object into a byte array which can be read by HTLCOutputInCommitment_read
pub extern "C" fn HTLCOutputInCommitment_write(obj: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn HTLCOutputInCommitment_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHTLCOutputInCommitment) })
}
#[no_mangle]
/// Read a HTLCOutputInCommitment from a byte array, created by HTLCOutputInCommitment_write
pub extern "C" fn HTLCOutputInCommitment_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HTLCOutputInCommitmentDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::HTLCOutputInCommitment, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Gets the witness redeemscript for an HTLC output in a commitment transaction. Note that htlc
/// does not need to have its previous_output_index filled.
#[no_mangle]
pub extern "C" fn get_htlc_redeemscript(htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment, channel_type_features: &crate::lightning::ln::features::ChannelTypeFeatures, keys: &crate::lightning::ln::chan_utils::TxCreationKeys) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_htlc_redeemscript(htlc.get_native_ref(), channel_type_features.get_native_ref(), keys.get_native_ref());
	ret.into_bytes().into()
}

/// Gets the redeemscript for a funding output from the two funding public keys.
/// Note that the order of funding public keys does not matter.
#[no_mangle]
pub extern "C" fn make_funding_redeemscript(mut broadcaster: crate::c_types::PublicKey, mut countersignatory: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::make_funding_redeemscript(&broadcaster.into_rust(), &countersignatory.into_rust());
	ret.into_bytes().into()
}

/// Builds an unsigned HTLC-Success or HTLC-Timeout transaction from the given channel and HTLC
/// parameters. This is used by [`TrustedCommitmentTransaction::get_htlc_sigs`] to fetch the
/// transaction which needs signing, and can be used to construct an HTLC transaction which is
/// broadcastable given a counterparty HTLC signature.
///
/// Panics if htlc.transaction_output_index.is_none() (as such HTLCs do not appear in the
/// commitment transaction).
#[no_mangle]
pub extern "C" fn build_htlc_transaction(commitment_txid: *const [u8; 32], mut feerate_per_kw: u32, mut contest_delay: u16, htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment, channel_type_features: &crate::lightning::ln::features::ChannelTypeFeatures, mut broadcaster_delayed_payment_key: crate::c_types::PublicKey, mut revocation_key: crate::c_types::PublicKey) -> crate::c_types::Transaction {
	let mut ret = lightning::ln::chan_utils::build_htlc_transaction(&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*commitment_txid }[..]).unwrap(), feerate_per_kw, contest_delay, htlc.get_native_ref(), channel_type_features.get_native_ref(), &broadcaster_delayed_payment_key.into_rust(), &revocation_key.into_rust());
	crate::c_types::Transaction::from_bitcoin(&ret)
}

/// Returns the witness required to satisfy and spend a HTLC input.
#[no_mangle]
pub extern "C" fn build_htlc_input_witness(mut local_sig: crate::c_types::Signature, mut remote_sig: crate::c_types::Signature, mut preimage: crate::c_types::derived::COption_PaymentPreimageZ, mut redeem_script: crate::c_types::u8slice, channel_type_features: &crate::lightning::ln::features::ChannelTypeFeatures) -> crate::c_types::Witness {
	let mut local_preimage = { /*preimage*/ let preimage_opt = preimage; if preimage_opt.is_none() { None } else { Some({ { ::lightning::ln::PaymentPreimage({ preimage_opt.take() }.data) }})} };
	let mut ret = lightning::ln::chan_utils::build_htlc_input_witness(&local_sig.into_rust(), &remote_sig.into_rust(), &local_preimage, &::bitcoin::blockdata::script::Script::from(Vec::from(redeem_script.to_slice())), channel_type_features.get_native_ref());
	crate::c_types::Witness::from_bitcoin(&ret)
}

/// Gets the witnessScript for the to_remote output when anchors are enabled.
#[no_mangle]
pub extern "C" fn get_to_countersignatory_with_anchors_redeemscript(mut payment_point: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_to_countersignatory_with_anchors_redeemscript(&payment_point.into_rust());
	ret.into_bytes().into()
}

/// Gets the witnessScript for an anchor output from the funding public key.
/// The witness in the spending input must be:
/// <BIP 143 funding_signature>
/// After 16 blocks of confirmation, an alternative satisfying witness could be:
/// <>
/// (empty vector required to satisfy compliance with MINIMALIF-standard rule)
#[no_mangle]
pub extern "C" fn get_anchor_redeemscript(mut funding_pubkey: crate::c_types::PublicKey) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = lightning::ln::chan_utils::get_anchor_redeemscript(&funding_pubkey.into_rust());
	ret.into_bytes().into()
}

/// Returns the witness required to satisfy and spend an anchor input.
#[no_mangle]
pub extern "C" fn build_anchor_input_witness(mut funding_key: crate::c_types::PublicKey, mut funding_sig: crate::c_types::Signature) -> crate::c_types::Witness {
	let mut ret = lightning::ln::chan_utils::build_anchor_input_witness(&funding_key.into_rust(), &funding_sig.into_rust());
	crate::c_types::Witness::from_bitcoin(&ret)
}


use lightning::ln::chan_utils::ChannelTransactionParameters as nativeChannelTransactionParametersImport;
pub(crate) type nativeChannelTransactionParameters = nativeChannelTransactionParametersImport;

/// Per-channel data used to build transactions in conjunction with the per-commitment data (CommitmentTransaction).
/// The fields are organized by holder/counterparty.
///
/// Normally, this is converted to the broadcaster/countersignatory-organized DirectedChannelTransactionParameters
/// before use, via the as_holder_broadcastable and as_counterparty_broadcastable functions.
#[must_use]
#[repr(C)]
pub struct ChannelTransactionParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeChannelTransactionParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeChannelTransactionParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ChannelTransactionParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_free(this_obj: ChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeChannelTransactionParameters) };
}
#[allow(unused)]
impl ChannelTransactionParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeChannelTransactionParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeChannelTransactionParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Holder public keys
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_holder_pubkeys(this_ptr: &ChannelTransactionParameters) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().holder_pubkeys;
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}
/// Holder public keys
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_holder_pubkeys(this_ptr: &mut ChannelTransactionParameters, mut val: crate::lightning::ln::chan_utils::ChannelPublicKeys) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.holder_pubkeys = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The contest delay selected by the holder, which applies to counterparty-broadcast transactions
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_holder_selected_contest_delay(this_ptr: &ChannelTransactionParameters) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().holder_selected_contest_delay;
	*inner_val
}
/// The contest delay selected by the holder, which applies to counterparty-broadcast transactions
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_holder_selected_contest_delay(this_ptr: &mut ChannelTransactionParameters, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.holder_selected_contest_delay = val;
}
/// Whether the holder is the initiator of this channel.
/// This is an input to the commitment number obscure factor computation.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_is_outbound_from_holder(this_ptr: &ChannelTransactionParameters) -> bool {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().is_outbound_from_holder;
	*inner_val
}
/// Whether the holder is the initiator of this channel.
/// This is an input to the commitment number obscure factor computation.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_is_outbound_from_holder(this_ptr: &mut ChannelTransactionParameters, mut val: bool) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.is_outbound_from_holder = val;
}
/// The late-bound counterparty channel transaction parameters.
/// These parameters are populated at the point in the protocol where the counterparty provides them.
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_counterparty_parameters(this_ptr: &ChannelTransactionParameters) -> crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().counterparty_parameters;
	let mut local_inner_val = crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::ln::chan_utils::CounterpartyChannelTransactionParameters<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The late-bound counterparty channel transaction parameters.
/// These parameters are populated at the point in the protocol where the counterparty provides them.
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_counterparty_parameters(this_ptr: &mut ChannelTransactionParameters, mut val: crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty_parameters = local_val;
}
/// The late-bound funding outpoint
///
/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_funding_outpoint(this_ptr: &ChannelTransactionParameters) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_outpoint;
	let mut local_inner_val = crate::lightning::chain::transaction::OutPoint { inner: unsafe { (if inner_val.is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner( { (inner_val.as_ref().unwrap()) }) } as *const lightning::chain::transaction::OutPoint<>) as *mut _ }, is_owned: false };
	local_inner_val
}
/// The late-bound funding outpoint
///
/// Note that val (or a relevant inner pointer) may be NULL or all-0s to represent None
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_funding_outpoint(this_ptr: &mut ChannelTransactionParameters, mut val: crate::lightning::chain::transaction::OutPoint) {
	let mut local_val = if val.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(val.take_inner()) } }) };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_outpoint = local_val;
}
/// This channel's type, as negotiated during channel open. For old objects where this field
/// wasn't serialized, it will default to static_remote_key at deserialization.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_get_channel_type_features(this_ptr: &ChannelTransactionParameters) -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_type_features;
	crate::lightning::ln::features::ChannelTypeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::features::ChannelTypeFeatures<>) as *mut _) }, is_owned: false }
}
/// This channel's type, as negotiated during channel open. For old objects where this field
/// wasn't serialized, it will default to static_remote_key at deserialization.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_set_channel_type_features(this_ptr: &mut ChannelTransactionParameters, mut val: crate::lightning::ln::features::ChannelTypeFeatures) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_type_features = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Constructs a new ChannelTransactionParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_new(mut holder_pubkeys_arg: crate::lightning::ln::chan_utils::ChannelPublicKeys, mut holder_selected_contest_delay_arg: u16, mut is_outbound_from_holder_arg: bool, mut counterparty_parameters_arg: crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters, mut funding_outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut channel_type_features_arg: crate::lightning::ln::features::ChannelTypeFeatures) -> ChannelTransactionParameters {
	let mut local_counterparty_parameters_arg = if counterparty_parameters_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(counterparty_parameters_arg.take_inner()) } }) };
	let mut local_funding_outpoint_arg = if funding_outpoint_arg.inner.is_null() { None } else { Some( { *unsafe { Box::from_raw(funding_outpoint_arg.take_inner()) } }) };
	ChannelTransactionParameters { inner: ObjOps::heap_alloc(nativeChannelTransactionParameters {
		holder_pubkeys: *unsafe { Box::from_raw(holder_pubkeys_arg.take_inner()) },
		holder_selected_contest_delay: holder_selected_contest_delay_arg,
		is_outbound_from_holder: is_outbound_from_holder_arg,
		counterparty_parameters: local_counterparty_parameters_arg,
		funding_outpoint: local_funding_outpoint_arg,
		channel_type_features: *unsafe { Box::from_raw(channel_type_features_arg.take_inner()) },
	}), is_owned: true }
}
impl Clone for ChannelTransactionParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeChannelTransactionParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ChannelTransactionParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeChannelTransactionParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ChannelTransactionParameters
pub extern "C" fn ChannelTransactionParameters_clone(orig: &ChannelTransactionParameters) -> ChannelTransactionParameters {
	orig.clone()
}
/// Checks if two ChannelTransactionParameterss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_eq(a: &ChannelTransactionParameters, b: &ChannelTransactionParameters) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::ln::chan_utils::CounterpartyChannelTransactionParameters as nativeCounterpartyChannelTransactionParametersImport;
pub(crate) type nativeCounterpartyChannelTransactionParameters = nativeCounterpartyChannelTransactionParametersImport;

/// Late-bound per-channel counterparty data used to build transactions.
#[must_use]
#[repr(C)]
pub struct CounterpartyChannelTransactionParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCounterpartyChannelTransactionParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for CounterpartyChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCounterpartyChannelTransactionParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CounterpartyChannelTransactionParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_free(this_obj: CounterpartyChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCounterpartyChannelTransactionParameters) };
}
#[allow(unused)]
impl CounterpartyChannelTransactionParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCounterpartyChannelTransactionParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCounterpartyChannelTransactionParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCounterpartyChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Counter-party public keys
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_get_pubkeys(this_ptr: &CounterpartyChannelTransactionParameters) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().pubkeys;
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}
/// Counter-party public keys
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_set_pubkeys(this_ptr: &mut CounterpartyChannelTransactionParameters, mut val: crate::lightning::ln::chan_utils::ChannelPublicKeys) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.pubkeys = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The contest delay selected by the counterparty, which applies to holder-broadcast transactions
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_get_selected_contest_delay(this_ptr: &CounterpartyChannelTransactionParameters) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().selected_contest_delay;
	*inner_val
}
/// The contest delay selected by the counterparty, which applies to holder-broadcast transactions
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_set_selected_contest_delay(this_ptr: &mut CounterpartyChannelTransactionParameters, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.selected_contest_delay = val;
}
/// Constructs a new CounterpartyChannelTransactionParameters given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_new(mut pubkeys_arg: crate::lightning::ln::chan_utils::ChannelPublicKeys, mut selected_contest_delay_arg: u16) -> CounterpartyChannelTransactionParameters {
	CounterpartyChannelTransactionParameters { inner: ObjOps::heap_alloc(nativeCounterpartyChannelTransactionParameters {
		pubkeys: *unsafe { Box::from_raw(pubkeys_arg.take_inner()) },
		selected_contest_delay: selected_contest_delay_arg,
	}), is_owned: true }
}
impl Clone for CounterpartyChannelTransactionParameters {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCounterpartyChannelTransactionParameters>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CounterpartyChannelTransactionParameters_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCounterpartyChannelTransactionParameters)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CounterpartyChannelTransactionParameters
pub extern "C" fn CounterpartyChannelTransactionParameters_clone(orig: &CounterpartyChannelTransactionParameters) -> CounterpartyChannelTransactionParameters {
	orig.clone()
}
/// Checks if two CounterpartyChannelTransactionParameterss contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn CounterpartyChannelTransactionParameters_eq(a: &CounterpartyChannelTransactionParameters, b: &CounterpartyChannelTransactionParameters) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Whether the late bound parameters are populated.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_is_populated(this_arg: &crate::lightning::ln::chan_utils::ChannelTransactionParameters) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_populated();
	ret
}

/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
/// given that the holder is the broadcaster.
///
/// self.is_populated() must be true before calling this function.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_as_holder_broadcastable(this_arg: &crate::lightning::ln::chan_utils::ChannelTransactionParameters) -> crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_holder_broadcastable();
	crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Convert the holder/counterparty parameters to broadcaster/countersignatory-organized parameters,
/// given that the counterparty is the broadcaster.
///
/// self.is_populated() must be true before calling this function.
#[must_use]
#[no_mangle]
pub extern "C" fn ChannelTransactionParameters_as_counterparty_broadcastable(this_arg: &crate::lightning::ln::chan_utils::ChannelTransactionParameters) -> crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.as_counterparty_broadcastable();
	crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the CounterpartyChannelTransactionParameters object into a byte array which can be read by CounterpartyChannelTransactionParameters_read
pub extern "C" fn CounterpartyChannelTransactionParameters_write(obj: &crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn CounterpartyChannelTransactionParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCounterpartyChannelTransactionParameters) })
}
#[no_mangle]
/// Read a CounterpartyChannelTransactionParameters from a byte array, created by CounterpartyChannelTransactionParameters_write
pub extern "C" fn CounterpartyChannelTransactionParameters_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::CounterpartyChannelTransactionParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
#[no_mangle]
/// Serialize the ChannelTransactionParameters object into a byte array which can be read by ChannelTransactionParameters_read
pub extern "C" fn ChannelTransactionParameters_write(obj: &crate::lightning::ln::chan_utils::ChannelTransactionParameters) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn ChannelTransactionParameters_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeChannelTransactionParameters) })
}
#[no_mangle]
/// Read a ChannelTransactionParameters from a byte array, created by ChannelTransactionParameters_write
pub extern "C" fn ChannelTransactionParameters_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_ChannelTransactionParametersDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::ChannelTransactionParameters, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::ChannelTransactionParameters { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::ln::chan_utils::DirectedChannelTransactionParameters as nativeDirectedChannelTransactionParametersImport;
pub(crate) type nativeDirectedChannelTransactionParameters = nativeDirectedChannelTransactionParametersImport<'static>;

/// Static channel fields used to build transactions given per-commitment fields, organized by
/// broadcaster/countersignatory.
///
/// This is derived from the holder/counterparty-organized ChannelTransactionParameters via the
/// as_holder_broadcastable and as_counterparty_broadcastable functions.
#[must_use]
#[repr(C)]
pub struct DirectedChannelTransactionParameters {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDirectedChannelTransactionParameters,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DirectedChannelTransactionParameters {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDirectedChannelTransactionParameters>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DirectedChannelTransactionParameters, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_free(this_obj: DirectedChannelTransactionParameters) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DirectedChannelTransactionParameters_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDirectedChannelTransactionParameters) };
}
#[allow(unused)]
impl DirectedChannelTransactionParameters {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDirectedChannelTransactionParameters {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDirectedChannelTransactionParameters {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDirectedChannelTransactionParameters {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Get the channel pubkeys for the broadcaster
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_broadcaster_pubkeys(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.broadcaster_pubkeys();
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}

/// Get the channel pubkeys for the countersignatory
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_countersignatory_pubkeys(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.countersignatory_pubkeys();
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}

/// Get the contest delay applicable to the transactions.
/// Note that the contest delay was selected by the countersignatory.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_contest_delay(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> u16 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.contest_delay();
	ret
}

/// Whether the channel is outbound from the broadcaster.
///
/// The boolean representing the side that initiated the channel is
/// an input to the commitment number obscure factor computation.
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_is_outbound(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_outbound();
	ret
}

/// The funding outpoint
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_funding_outpoint(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> crate::lightning::chain::transaction::OutPoint {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.funding_outpoint();
	crate::c_types::bitcoin_to_C_outpoint(&ret)
}

/// Whether to use anchors for this channel
#[must_use]
#[no_mangle]
pub extern "C" fn DirectedChannelTransactionParameters_channel_type_features(this_arg: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters) -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_type_features();
	crate::lightning::ln::features::ChannelTypeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::ChannelTypeFeatures<>) as *mut _) }, is_owned: false }
}


use lightning::ln::chan_utils::HolderCommitmentTransaction as nativeHolderCommitmentTransactionImport;
pub(crate) type nativeHolderCommitmentTransaction = nativeHolderCommitmentTransactionImport;

/// Information needed to build and sign a holder's commitment transaction.
///
/// The transaction is only signed once we are ready to broadcast.
#[must_use]
#[repr(C)]
pub struct HolderCommitmentTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeHolderCommitmentTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for HolderCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeHolderCommitmentTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the HolderCommitmentTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_free(this_obj: HolderCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HolderCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeHolderCommitmentTransaction) };
}
#[allow(unused)]
impl HolderCommitmentTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeHolderCommitmentTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeHolderCommitmentTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeHolderCommitmentTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Our counterparty's signature for the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_counterparty_sig(this_ptr: &HolderCommitmentTransaction) -> crate::c_types::Signature {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().counterparty_sig;
	crate::c_types::Signature::from_rust(&inner_val)
}
/// Our counterparty's signature for the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_counterparty_sig(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::Signature) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty_sig = val.into_rust();
}
/// All non-dust counterparty HTLC signatures, in the order they appear in the transaction
///
/// Returns a copy of the field.
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_get_counterparty_htlc_sigs(this_ptr: &HolderCommitmentTransaction) -> crate::c_types::derived::CVec_SignatureZ {
	let mut inner_val = this_ptr.get_native_mut_ref().counterparty_htlc_sigs.clone();
	let mut local_inner_val = Vec::new(); for mut item in inner_val.drain(..) { local_inner_val.push( { crate::c_types::Signature::from_rust(&item) }); };
	local_inner_val.into()
}
/// All non-dust counterparty HTLC signatures, in the order they appear in the transaction
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_set_counterparty_htlc_sigs(this_ptr: &mut HolderCommitmentTransaction, mut val: crate::c_types::derived::CVec_SignatureZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { item.into_rust() }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.counterparty_htlc_sigs = local_val;
}
impl Clone for HolderCommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeHolderCommitmentTransaction>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn HolderCommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeHolderCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the HolderCommitmentTransaction
pub extern "C" fn HolderCommitmentTransaction_clone(orig: &HolderCommitmentTransaction) -> HolderCommitmentTransaction {
	orig.clone()
}
#[no_mangle]
/// Serialize the HolderCommitmentTransaction object into a byte array which can be read by HolderCommitmentTransaction_read
pub extern "C" fn HolderCommitmentTransaction_write(obj: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn HolderCommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeHolderCommitmentTransaction) })
}
#[no_mangle]
/// Read a HolderCommitmentTransaction from a byte array, created by HolderCommitmentTransaction_write
pub extern "C" fn HolderCommitmentTransaction_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_HolderCommitmentTransactionDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::HolderCommitmentTransaction, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Create a new holder transaction with the given counterparty signatures.
/// The funding keys are used to figure out which signature should go first when building the transaction for broadcast.
#[must_use]
#[no_mangle]
pub extern "C" fn HolderCommitmentTransaction_new(mut commitment_tx: crate::lightning::ln::chan_utils::CommitmentTransaction, mut counterparty_sig: crate::c_types::Signature, mut counterparty_htlc_sigs: crate::c_types::derived::CVec_SignatureZ, mut holder_funding_key: crate::c_types::PublicKey, mut counterparty_funding_key: crate::c_types::PublicKey) -> crate::lightning::ln::chan_utils::HolderCommitmentTransaction {
	let mut local_counterparty_htlc_sigs = Vec::new(); for mut item in counterparty_htlc_sigs.into_rust().drain(..) { local_counterparty_htlc_sigs.push( { item.into_rust() }); };
	let mut ret = lightning::ln::chan_utils::HolderCommitmentTransaction::new(*unsafe { Box::from_raw(commitment_tx.take_inner()) }, counterparty_sig.into_rust(), local_counterparty_htlc_sigs, &holder_funding_key.into_rust(), &counterparty_funding_key.into_rust());
	crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::ln::chan_utils::BuiltCommitmentTransaction as nativeBuiltCommitmentTransactionImport;
pub(crate) type nativeBuiltCommitmentTransaction = nativeBuiltCommitmentTransactionImport;

/// A pre-built Bitcoin commitment transaction and its txid.
#[must_use]
#[repr(C)]
pub struct BuiltCommitmentTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBuiltCommitmentTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BuiltCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBuiltCommitmentTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BuiltCommitmentTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_free(this_obj: BuiltCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BuiltCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBuiltCommitmentTransaction) };
}
#[allow(unused)]
impl BuiltCommitmentTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBuiltCommitmentTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBuiltCommitmentTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBuiltCommitmentTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The commitment transaction
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_transaction(this_ptr: &BuiltCommitmentTransaction) -> crate::c_types::Transaction {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().transaction;
	crate::c_types::Transaction::from_bitcoin(inner_val)
}
/// The commitment transaction
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_set_transaction(this_ptr: &mut BuiltCommitmentTransaction, mut val: crate::c_types::Transaction) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.transaction = val.into_bitcoin();
}
/// The txid for the commitment transaction.
///
/// This is provided as a performance optimization, instead of calling transaction.txid()
/// multiple times.
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_txid(this_ptr: &BuiltCommitmentTransaction) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().txid;
	inner_val.as_inner()
}
/// The txid for the commitment transaction.
///
/// This is provided as a performance optimization, instead of calling transaction.txid()
/// multiple times.
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_set_txid(this_ptr: &mut BuiltCommitmentTransaction, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.txid = ::bitcoin::hash_types::Txid::from_slice(&val.data[..]).unwrap();
}
/// Constructs a new BuiltCommitmentTransaction given each field
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_new(mut transaction_arg: crate::c_types::Transaction, mut txid_arg: crate::c_types::ThirtyTwoBytes) -> BuiltCommitmentTransaction {
	BuiltCommitmentTransaction { inner: ObjOps::heap_alloc(nativeBuiltCommitmentTransaction {
		transaction: transaction_arg.into_bitcoin(),
		txid: ::bitcoin::hash_types::Txid::from_slice(&txid_arg.data[..]).unwrap(),
	}), is_owned: true }
}
impl Clone for BuiltCommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeBuiltCommitmentTransaction>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BuiltCommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeBuiltCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the BuiltCommitmentTransaction
pub extern "C" fn BuiltCommitmentTransaction_clone(orig: &BuiltCommitmentTransaction) -> BuiltCommitmentTransaction {
	orig.clone()
}
#[no_mangle]
/// Serialize the BuiltCommitmentTransaction object into a byte array which can be read by BuiltCommitmentTransaction_read
pub extern "C" fn BuiltCommitmentTransaction_write(obj: &crate::lightning::ln::chan_utils::BuiltCommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn BuiltCommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeBuiltCommitmentTransaction) })
}
#[no_mangle]
/// Read a BuiltCommitmentTransaction from a byte array, created by BuiltCommitmentTransaction_write
pub extern "C" fn BuiltCommitmentTransaction_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_BuiltCommitmentTransactionDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::BuiltCommitmentTransaction, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::BuiltCommitmentTransaction { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Get the SIGHASH_ALL sighash value of the transaction.
///
/// This can be used to verify a signature.
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_get_sighash_all(this_arg: &crate::lightning::ln::chan_utils::BuiltCommitmentTransaction, mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_sighash_all(&::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis);
	crate::c_types::ThirtyTwoBytes { data: ret.as_ref().clone() }
}

/// Signs the counterparty's commitment transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_sign_counterparty_commitment(this_arg: &crate::lightning::ln::chan_utils::BuiltCommitmentTransaction, funding_key: *const [u8; 32], mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::Signature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign_counterparty_commitment(&::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, secp256k1::global::SECP256K1);
	crate::c_types::Signature::from_rust(&ret)
}

/// Signs the holder commitment transaction because we are about to broadcast it.
#[must_use]
#[no_mangle]
pub extern "C" fn BuiltCommitmentTransaction_sign_holder_commitment(this_arg: &crate::lightning::ln::chan_utils::BuiltCommitmentTransaction, funding_key: *const [u8; 32], mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64, entropy_source: &crate::lightning::sign::EntropySource) -> crate::c_types::Signature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign_holder_commitment(&::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, entropy_source, secp256k1::global::SECP256K1);
	crate::c_types::Signature::from_rust(&ret)
}


use lightning::ln::chan_utils::ClosingTransaction as nativeClosingTransactionImport;
pub(crate) type nativeClosingTransaction = nativeClosingTransactionImport;

/// This class tracks the per-transaction information needed to build a closing transaction and will
/// actually build it and sign.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[must_use]
#[repr(C)]
pub struct ClosingTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeClosingTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for ClosingTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeClosingTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the ClosingTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn ClosingTransaction_free(this_obj: ClosingTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClosingTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeClosingTransaction) };
}
#[allow(unused)]
impl ClosingTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeClosingTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeClosingTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeClosingTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for ClosingTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeClosingTransaction>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn ClosingTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeClosingTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the ClosingTransaction
pub extern "C" fn ClosingTransaction_clone(orig: &ClosingTransaction) -> ClosingTransaction {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the ClosingTransaction.
#[no_mangle]
pub extern "C" fn ClosingTransaction_hash(o: &ClosingTransaction) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two ClosingTransactions contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn ClosingTransaction_eq(a: &ClosingTransaction, b: &ClosingTransaction) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Construct an object of the class
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_new(mut to_holder_value_sat: u64, mut to_counterparty_value_sat: u64, mut to_holder_script: crate::c_types::derived::CVec_u8Z, mut to_counterparty_script: crate::c_types::derived::CVec_u8Z, mut funding_outpoint: crate::lightning::chain::transaction::OutPoint) -> crate::lightning::ln::chan_utils::ClosingTransaction {
	let mut ret = lightning::ln::chan_utils::ClosingTransaction::new(to_holder_value_sat, to_counterparty_value_sat, ::bitcoin::blockdata::script::Script::from(to_holder_script.into_rust()), ::bitcoin::blockdata::script::Script::from(to_counterparty_script.into_rust()), crate::c_types::C_to_bitcoin_outpoint(funding_outpoint));
	crate::lightning::ln::chan_utils::ClosingTransaction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Trust our pre-built transaction.
///
/// Applies a wrapper which allows access to the transaction.
///
/// This should only be used if you fully trust the builder of this object. It should not
/// be used by an external signer - instead use the verify function.
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_trust(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::lightning::ln::chan_utils::TrustedClosingTransaction {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.trust();
	crate::lightning::ln::chan_utils::TrustedClosingTransaction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Verify our pre-built transaction.
///
/// Applies a wrapper which allows access to the transaction.
///
/// An external validating signer must call this method before signing
/// or using the built transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_verify(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction, mut funding_outpoint: crate::lightning::chain::transaction::OutPoint) -> crate::c_types::derived::CResult_TrustedClosingTransactionNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify(crate::c_types::C_to_bitcoin_outpoint(funding_outpoint));
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::TrustedClosingTransaction { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// The value to be sent to the holder, or zero if the output will be omitted
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_to_holder_value_sat(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_holder_value_sat();
	ret
}

/// The value to be sent to the counterparty, or zero if the output will be omitted
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_to_counterparty_value_sat(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_counterparty_value_sat();
	ret
}

/// The destination of the holder's output
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_to_holder_script(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_holder_script();
	crate::c_types::u8slice::from_slice(&ret[..])
}

/// The destination of the counterparty's output
#[must_use]
#[no_mangle]
pub extern "C" fn ClosingTransaction_to_counterparty_script(this_arg: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::c_types::u8slice {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_counterparty_script();
	crate::c_types::u8slice::from_slice(&ret[..])
}


use lightning::ln::chan_utils::TrustedClosingTransaction as nativeTrustedClosingTransactionImport;
pub(crate) type nativeTrustedClosingTransaction = nativeTrustedClosingTransactionImport<'static>;

/// A wrapper on ClosingTransaction indicating that the built bitcoin
/// transaction is trusted.
///
/// See trust() and verify() functions on CommitmentTransaction.
///
/// This structure implements Deref.
#[must_use]
#[repr(C)]
pub struct TrustedClosingTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTrustedClosingTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for TrustedClosingTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTrustedClosingTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TrustedClosingTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TrustedClosingTransaction_free(this_obj: TrustedClosingTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TrustedClosingTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTrustedClosingTransaction) };
}
#[allow(unused)]
impl TrustedClosingTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTrustedClosingTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTrustedClosingTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTrustedClosingTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The pre-built Bitcoin commitment transaction
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedClosingTransaction_built_transaction(this_arg: &crate::lightning::ln::chan_utils::TrustedClosingTransaction) -> crate::c_types::Transaction {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.built_transaction();
	crate::c_types::Transaction::from_bitcoin(ret)
}

/// Get the SIGHASH_ALL sighash value of the transaction.
///
/// This can be used to verify a signature.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedClosingTransaction_get_sighash_all(this_arg: &crate::lightning::ln::chan_utils::TrustedClosingTransaction, mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_sighash_all(&::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis);
	crate::c_types::ThirtyTwoBytes { data: ret.as_ref().clone() }
}

/// Sign a transaction, either because we are counter-signing the counterparty's transaction or
/// because we are about to broadcast a holder transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedClosingTransaction_sign(this_arg: &crate::lightning::ln::chan_utils::TrustedClosingTransaction, funding_key: *const [u8; 32], mut funding_redeemscript: crate::c_types::u8slice, mut channel_value_satoshis: u64) -> crate::c_types::Signature {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign(&::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *funding_key}[..]).unwrap(), &::bitcoin::blockdata::script::Script::from(Vec::from(funding_redeemscript.to_slice())), channel_value_satoshis, secp256k1::global::SECP256K1);
	crate::c_types::Signature::from_rust(&ret)
}


use lightning::ln::chan_utils::CommitmentTransaction as nativeCommitmentTransactionImport;
pub(crate) type nativeCommitmentTransaction = nativeCommitmentTransactionImport;

/// This class tracks the per-transaction information needed to build a commitment transaction and will
/// actually build it and sign.  It is used for holder transactions that we sign only when needed
/// and for transactions we sign for the counterparty.
///
/// This class can be used inside a signer implementation to generate a signature given the relevant
/// secret key.
#[must_use]
#[repr(C)]
pub struct CommitmentTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCommitmentTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for CommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCommitmentTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CommitmentTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CommitmentTransaction_free(this_obj: CommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CommitmentTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCommitmentTransaction) };
}
#[allow(unused)]
impl CommitmentTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCommitmentTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCommitmentTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCommitmentTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for CommitmentTransaction {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCommitmentTransaction>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CommitmentTransaction_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeCommitmentTransaction)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CommitmentTransaction
pub extern "C" fn CommitmentTransaction_clone(orig: &CommitmentTransaction) -> CommitmentTransaction {
	orig.clone()
}
#[no_mangle]
/// Serialize the CommitmentTransaction object into a byte array which can be read by CommitmentTransaction_read
pub extern "C" fn CommitmentTransaction_write(obj: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn CommitmentTransaction_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeCommitmentTransaction) })
}
#[no_mangle]
/// Read a CommitmentTransaction from a byte array, created by CommitmentTransaction_write
pub extern "C" fn CommitmentTransaction_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_CommitmentTransactionDecodeErrorZ {
	let res: Result<lightning::ln::chan_utils::CommitmentTransaction, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::CommitmentTransaction { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// The backwards-counting commitment number
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_commitment_number(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.commitment_number();
	ret
}

/// The value to be sent to the broadcaster
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_to_broadcaster_value_sat(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_broadcaster_value_sat();
	ret
}

/// The value to be sent to the counterparty
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_to_countersignatory_value_sat(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> u64 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.to_countersignatory_value_sat();
	ret
}

/// The feerate paid per 1000-weight-unit in this commitment transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_feerate_per_kw(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> u32 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.feerate_per_kw();
	ret
}

/// Trust our pre-built transaction and derived transaction creation public keys.
///
/// Applies a wrapper which allows access to these fields.
///
/// This should only be used if you fully trust the builder of this object.  It should not
/// be used by an external signer - instead use the verify function.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_trust(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction) -> crate::lightning::ln::chan_utils::TrustedCommitmentTransaction {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.trust();
	crate::lightning::ln::chan_utils::TrustedCommitmentTransaction { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Verify our pre-built transaction and derived transaction creation public keys.
///
/// Applies a wrapper which allows access to these fields.
///
/// An external validating signer must call this method before signing
/// or using the built transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn CommitmentTransaction_verify(this_arg: &crate::lightning::ln::chan_utils::CommitmentTransaction, channel_parameters: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters, broadcaster_keys: &crate::lightning::ln::chan_utils::ChannelPublicKeys, countersignatory_keys: &crate::lightning::ln::chan_utils::ChannelPublicKeys) -> crate::c_types::derived::CResult_TrustedCommitmentTransactionNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.verify(channel_parameters.get_native_ref(), broadcaster_keys.get_native_ref(), countersignatory_keys.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::chan_utils::TrustedCommitmentTransaction { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::ln::chan_utils::TrustedCommitmentTransaction as nativeTrustedCommitmentTransactionImport;
pub(crate) type nativeTrustedCommitmentTransaction = nativeTrustedCommitmentTransactionImport<'static>;

/// A wrapper on CommitmentTransaction indicating that the derived fields (the built bitcoin
/// transaction and the transaction creation keys) are trusted.
///
/// See trust() and verify() functions on CommitmentTransaction.
///
/// This structure implements Deref.
#[must_use]
#[repr(C)]
pub struct TrustedCommitmentTransaction {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeTrustedCommitmentTransaction,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for TrustedCommitmentTransaction {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeTrustedCommitmentTransaction>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the TrustedCommitmentTransaction, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_free(this_obj: TrustedCommitmentTransaction) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn TrustedCommitmentTransaction_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeTrustedCommitmentTransaction) };
}
#[allow(unused)]
impl TrustedCommitmentTransaction {
	pub(crate) fn get_native_ref(&self) -> &'static nativeTrustedCommitmentTransaction {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeTrustedCommitmentTransaction {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeTrustedCommitmentTransaction {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The transaction ID of the built Bitcoin transaction
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_txid(this_arg: &crate::lightning::ln::chan_utils::TrustedCommitmentTransaction) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.txid();
	crate::c_types::ThirtyTwoBytes { data: ret.into_inner() }
}

/// The pre-built Bitcoin commitment transaction
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_built_transaction(this_arg: &crate::lightning::ln::chan_utils::TrustedCommitmentTransaction) -> crate::lightning::ln::chan_utils::BuiltCommitmentTransaction {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.built_transaction();
	crate::lightning::ln::chan_utils::BuiltCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::BuiltCommitmentTransaction<>) as *mut _) }, is_owned: false }
}

/// The pre-calculated transaction creation public keys.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_keys(this_arg: &crate::lightning::ln::chan_utils::TrustedCommitmentTransaction) -> crate::lightning::ln::chan_utils::TxCreationKeys {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.keys();
	crate::lightning::ln::chan_utils::TxCreationKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::TxCreationKeys<>) as *mut _) }, is_owned: false }
}

/// Should anchors be used.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_channel_type_features(this_arg: &crate::lightning::ln::chan_utils::TrustedCommitmentTransaction) -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_type_features();
	crate::lightning::ln::features::ChannelTypeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::ChannelTypeFeatures<>) as *mut _) }, is_owned: false }
}

/// Get a signature for each HTLC which was included in the commitment transaction (ie for
/// which HTLCOutputInCommitment::transaction_output_index.is_some()).
///
/// The returned Vec has one entry for each HTLC, and in the same order.
///
/// This function is only valid in the holder commitment context, it always uses EcdsaSighashType::All.
#[must_use]
#[no_mangle]
pub extern "C" fn TrustedCommitmentTransaction_get_htlc_sigs(this_arg: &crate::lightning::ln::chan_utils::TrustedCommitmentTransaction, htlc_base_key: *const [u8; 32], channel_parameters: &crate::lightning::ln::chan_utils::DirectedChannelTransactionParameters, entropy_source: &crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_CVec_SignatureZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_htlc_sigs(&::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *htlc_base_key}[..]).unwrap(), channel_parameters.get_native_ref(), entropy_source, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { crate::c_types::Signature::from_rust(&item) }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Commitment transaction numbers which appear in the transactions themselves are XOR'd with a
/// shared secret first. This prevents on-chain observers from discovering how many commitment
/// transactions occurred in a channel before it was closed.
///
/// This function gets the shared secret from relevant channel public keys and can be used to
/// \"decrypt\" the commitment transaction number given a commitment transaction on-chain.
#[no_mangle]
pub extern "C" fn get_commitment_transaction_number_obscure_factor(mut broadcaster_payment_basepoint: crate::c_types::PublicKey, mut countersignatory_payment_basepoint: crate::c_types::PublicKey, mut outbound_from_broadcaster: bool) -> u64 {
	let mut ret = lightning::ln::chan_utils::get_commitment_transaction_number_obscure_factor(&broadcaster_payment_basepoint.into_rust(), &countersignatory_payment_basepoint.into_rust(), outbound_from_broadcaster);
	ret
}

