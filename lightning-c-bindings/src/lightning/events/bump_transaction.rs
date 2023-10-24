// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities for bumping transactions originating from [`Event`]s.
//!
//! [`Event`]: crate::events::Event

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::events::bump_transaction::AnchorDescriptor as nativeAnchorDescriptorImport;
pub(crate) type nativeAnchorDescriptor = nativeAnchorDescriptorImport;

/// A descriptor used to sign for a commitment transaction's anchor output.
#[must_use]
#[repr(C)]
pub struct AnchorDescriptor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeAnchorDescriptor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for AnchorDescriptor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeAnchorDescriptor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the AnchorDescriptor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_free(this_obj: AnchorDescriptor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorDescriptor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeAnchorDescriptor) };
}
#[allow(unused)]
impl AnchorDescriptor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeAnchorDescriptor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeAnchorDescriptor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeAnchorDescriptor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The parameters required to derive the signer for the anchor input.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_get_channel_derivation_parameters(this_ptr: &AnchorDescriptor) -> crate::lightning::sign::ChannelDerivationParameters {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_derivation_parameters;
	crate::lightning::sign::ChannelDerivationParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::sign::ChannelDerivationParameters<>) as *mut _) }, is_owned: false }
}
/// The parameters required to derive the signer for the anchor input.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_set_channel_derivation_parameters(this_ptr: &mut AnchorDescriptor, mut val: crate::lightning::sign::ChannelDerivationParameters) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_derivation_parameters = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The transaction input's outpoint corresponding to the commitment transaction's anchor
/// output.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_get_outpoint(this_ptr: &AnchorDescriptor) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The transaction input's outpoint corresponding to the commitment transaction's anchor
/// output.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_set_outpoint(this_ptr: &mut AnchorDescriptor, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// Constructs a new AnchorDescriptor given each field
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_new(mut channel_derivation_parameters_arg: crate::lightning::sign::ChannelDerivationParameters, mut outpoint_arg: crate::lightning::chain::transaction::OutPoint) -> AnchorDescriptor {
	AnchorDescriptor { inner: ObjOps::heap_alloc(nativeAnchorDescriptor {
		channel_derivation_parameters: *unsafe { Box::from_raw(channel_derivation_parameters_arg.take_inner()) },
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
	}), is_owned: true }
}
impl Clone for AnchorDescriptor {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeAnchorDescriptor>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn AnchorDescriptor_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeAnchorDescriptor)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the AnchorDescriptor
pub extern "C" fn AnchorDescriptor_clone(orig: &AnchorDescriptor) -> AnchorDescriptor {
	orig.clone()
}
/// Checks if two AnchorDescriptors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn AnchorDescriptor_eq(a: &AnchorDescriptor, b: &AnchorDescriptor) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns the UTXO to be spent by the anchor input, which can be obtained via
/// [`Self::unsigned_tx_input`].
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_previous_utxo(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor) -> crate::c_types::TxOut {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.previous_utxo();
	crate::c_types::TxOut::from_rust(&ret)
}

/// Returns the unsigned transaction input spending the anchor output in the commitment
/// transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_unsigned_tx_input(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor) -> crate::c_types::TxIn {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.unsigned_tx_input();
	crate::c_types::TxIn::from_rust(&ret)
}

/// Returns the witness script of the anchor output in the commitment transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_witness_script(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor) -> crate::c_types::derived::CVec_u8Z {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.witness_script();
	ret.into_bytes().into()
}

/// Returns the fully signed witness required to spend the anchor output in the commitment
/// transaction.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_tx_input_witness(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor, mut signature: crate::c_types::ECDSASignature) -> crate::c_types::Witness {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.tx_input_witness(&signature.into_rust());
	crate::c_types::Witness::from_bitcoin(&ret)
}

/// Derives the channel signer required to sign the anchor input.
#[must_use]
#[no_mangle]
pub extern "C" fn AnchorDescriptor_derive_channel_signer(this_arg: &crate::lightning::events::bump_transaction::AnchorDescriptor, signer_provider: &crate::lightning::sign::SignerProvider) -> crate::lightning::sign::WriteableEcdsaChannelSigner {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.derive_channel_signer(signer_provider);
	Into::into(ret)
}

/// Represents the different types of transactions, originating from LDK, to be bumped.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum BumpTransactionEvent {
	/// Indicates that a channel featuring anchor outputs is to be closed by broadcasting the local
	/// commitment transaction. Since commitment transactions have a static feerate pre-agreed upon,
	/// they may need additional fees to be attached through a child transaction using the popular
	/// [Child-Pays-For-Parent](https://bitcoinops.org/en/topics/cpfp) fee bumping technique. This
	/// child transaction must include the anchor input described within `anchor_descriptor` along
	/// with additional inputs to meet the target feerate. Failure to meet the target feerate
	/// decreases the confirmation odds of the transaction package (which includes the commitment
	/// and child anchor transactions), possibly resulting in a loss of funds. Once the transaction
	/// is constructed, it must be fully signed for and broadcast by the consumer of the event
	/// along with the `commitment_tx` enclosed. Note that the `commitment_tx` must always be
	/// broadcast first, as the child anchor transaction depends on it.
	///
	/// The consumer should be able to sign for any of the additional inputs included within the
	/// child anchor transaction. To sign its anchor input, an [`EcdsaChannelSigner`] should be
	/// re-derived through [`AnchorDescriptor::derive_channel_signer`]. The anchor input signature
	/// can be computed with [`EcdsaChannelSigner::sign_holder_anchor_input`], which can then be
	/// provided to [`build_anchor_input_witness`] along with the `funding_pubkey` to obtain the
	/// full witness required to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid child anchor
	/// transaction is never broadcast or is but not with a sufficient fee to be mined. Care should
	/// be taken by the consumer of the event to ensure any future iterations of the child anchor
	/// transaction adhere to the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if they are no longer
	/// able to commit external confirmed funds to the child anchor transaction.
	///
	/// The set of `pending_htlcs` on the commitment transaction to be broadcast can be inspected to
	/// determine whether a significant portion of the channel's funds are allocated to HTLCs,
	/// enabling users to make their own decisions regarding the importance of the commitment
	/// transaction's confirmation. Note that this is not required, but simply exists as an option
	/// for users to override LDK's behavior. On commitments with no HTLCs (indicated by those with
	/// an empty `pending_htlcs`), confirmation of the commitment transaction can be considered to
	/// be not urgent.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_anchor_input`]: crate::sign::EcdsaChannelSigner::sign_holder_anchor_input
	/// [`build_anchor_input_witness`]: crate::ln::chan_utils::build_anchor_input_witness
	ChannelClose {
		/// The unique identifier for the claim of the anchor output in the commitment transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: crate::c_types::ThirtyTwoBytes,
		/// The target feerate that the transaction package, which consists of the commitment
		/// transaction and the to-be-crafted child anchor transaction, must meet.
		package_target_feerate_sat_per_1000_weight: u32,
		/// The channel's commitment transaction to bump the fee of. This transaction should be
		/// broadcast along with the anchor transaction constructed as a result of consuming this
		/// event.
		commitment_tx: crate::c_types::Transaction,
		/// The absolute fee in satoshis of the commitment transaction. This can be used along the
		/// with weight of the commitment transaction to determine its feerate.
		commitment_tx_fee_satoshis: u64,
		/// The descriptor to sign the anchor input of the anchor transaction constructed as a
		/// result of consuming this event.
		anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor,
		/// The set of pending HTLCs on the commitment transaction that need to be resolved once the
		/// commitment transaction confirms.
		pending_htlcs: crate::c_types::derived::CVec_HTLCOutputInCommitmentZ,
	},
	/// Indicates that a channel featuring anchor outputs has unilaterally closed on-chain by a
	/// holder commitment transaction and its HTLC(s) need to be resolved on-chain. With the
	/// zero-HTLC-transaction-fee variant of anchor outputs, the pre-signed HTLC
	/// transactions have a zero fee, thus requiring additional inputs and/or outputs to be attached
	/// for a timely confirmation within the chain. These additional inputs and/or outputs must be
	/// appended to the resulting HTLC transaction to meet the target feerate. Failure to meet the
	/// target feerate decreases the confirmation odds of the transaction, possibly resulting in a
	/// loss of funds. Once the transaction meets the target feerate, it must be signed for and
	/// broadcast by the consumer of the event.
	///
	/// The consumer should be able to sign for any of the non-HTLC inputs added to the resulting
	/// HTLC transaction. To sign HTLC inputs, an [`EcdsaChannelSigner`] should be re-derived
	/// through [`HTLCDescriptor::derive_channel_signer`]. Each HTLC input's signature can be
	/// computed with [`EcdsaChannelSigner::sign_holder_htlc_transaction`], which can then be
	/// provided to [`HTLCDescriptor::tx_input_witness`] to obtain the fully signed witness required
	/// to spend.
	///
	/// It is possible to receive more than one instance of this event if a valid HTLC transaction
	/// is never broadcast or is but not with a sufficient fee to be mined. Care should be taken by
	/// the consumer of the event to ensure any future iterations of the HTLC transaction adhere to
	/// the [Replace-By-Fee
	/// rules](https://github.com/bitcoin/bitcoin/blob/master/doc/policy/mempool-replacements.md)
	/// for fee bumps to be accepted into the mempool, and eventually the chain. As the frequency of
	/// these events is not user-controlled, users may ignore/drop the event if either they are no
	/// longer able to commit external confirmed funds to the HTLC transaction or the fee committed
	/// to the HTLC transaction is greater in value than the HTLCs being claimed.
	///
	/// [`EcdsaChannelSigner`]: crate::sign::EcdsaChannelSigner
	/// [`EcdsaChannelSigner::sign_holder_htlc_transaction`]: crate::sign::EcdsaChannelSigner::sign_holder_htlc_transaction
	HTLCResolution {
		/// The unique identifier for the claim of the HTLCs in the confirmed commitment
		/// transaction.
		///
		/// The identifier must map to the set of external UTXOs assigned to the claim, such that
		/// they can be reused when a new claim with the same identifier needs to be made, resulting
		/// in a fee-bumping attempt.
		claim_id: crate::c_types::ThirtyTwoBytes,
		/// The target feerate that the resulting HTLC transaction must meet.
		target_feerate_sat_per_1000_weight: u32,
		/// The set of pending HTLCs on the confirmed commitment that need to be claimed, preferably
		/// by the same transaction.
		htlc_descriptors: crate::c_types::derived::CVec_HTLCDescriptorZ,
		/// The locktime required for the resulting HTLC transaction.
		tx_lock_time: u32,
	},
}
use lightning::events::bump_transaction::BumpTransactionEvent as BumpTransactionEventImport;
pub(crate) type nativeBumpTransactionEvent = BumpTransactionEventImport;

impl BumpTransactionEvent {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeBumpTransactionEvent {
		match self {
			BumpTransactionEvent::ChannelClose {ref claim_id, ref package_target_feerate_sat_per_1000_weight, ref commitment_tx, ref commitment_tx_fee_satoshis, ref anchor_descriptor, ref pending_htlcs, } => {
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut package_target_feerate_sat_per_1000_weight_nonref = Clone::clone(package_target_feerate_sat_per_1000_weight);
				let mut commitment_tx_nonref = Clone::clone(commitment_tx);
				let mut commitment_tx_fee_satoshis_nonref = Clone::clone(commitment_tx_fee_satoshis);
				let mut anchor_descriptor_nonref = Clone::clone(anchor_descriptor);
				let mut pending_htlcs_nonref = Clone::clone(pending_htlcs);
				let mut local_pending_htlcs_nonref = Vec::new(); for mut item in pending_htlcs_nonref.into_rust().drain(..) { local_pending_htlcs_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::ChannelClose {
					claim_id: ::lightning::chain::ClaimId(claim_id_nonref.data),
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight_nonref,
					commitment_tx: commitment_tx_nonref.into_bitcoin(),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis_nonref,
					anchor_descriptor: *unsafe { Box::from_raw(anchor_descriptor_nonref.take_inner()) },
					pending_htlcs: local_pending_htlcs_nonref,
				}
			},
			BumpTransactionEvent::HTLCResolution {ref claim_id, ref target_feerate_sat_per_1000_weight, ref htlc_descriptors, ref tx_lock_time, } => {
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut target_feerate_sat_per_1000_weight_nonref = Clone::clone(target_feerate_sat_per_1000_weight);
				let mut htlc_descriptors_nonref = Clone::clone(htlc_descriptors);
				let mut local_htlc_descriptors_nonref = Vec::new(); for mut item in htlc_descriptors_nonref.into_rust().drain(..) { local_htlc_descriptors_nonref.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				let mut tx_lock_time_nonref = Clone::clone(tx_lock_time);
				nativeBumpTransactionEvent::HTLCResolution {
					claim_id: ::lightning::chain::ClaimId(claim_id_nonref.data),
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight_nonref,
					htlc_descriptors: local_htlc_descriptors_nonref,
					tx_lock_time: ::bitcoin::PackedLockTime(tx_lock_time_nonref),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeBumpTransactionEvent {
		match self {
			BumpTransactionEvent::ChannelClose {mut claim_id, mut package_target_feerate_sat_per_1000_weight, mut commitment_tx, mut commitment_tx_fee_satoshis, mut anchor_descriptor, mut pending_htlcs, } => {
				let mut local_pending_htlcs = Vec::new(); for mut item in pending_htlcs.into_rust().drain(..) { local_pending_htlcs.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::ChannelClose {
					claim_id: ::lightning::chain::ClaimId(claim_id.data),
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight,
					commitment_tx: commitment_tx.into_bitcoin(),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis,
					anchor_descriptor: *unsafe { Box::from_raw(anchor_descriptor.take_inner()) },
					pending_htlcs: local_pending_htlcs,
				}
			},
			BumpTransactionEvent::HTLCResolution {mut claim_id, mut target_feerate_sat_per_1000_weight, mut htlc_descriptors, mut tx_lock_time, } => {
				let mut local_htlc_descriptors = Vec::new(); for mut item in htlc_descriptors.into_rust().drain(..) { local_htlc_descriptors.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
				nativeBumpTransactionEvent::HTLCResolution {
					claim_id: ::lightning::chain::ClaimId(claim_id.data),
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight,
					htlc_descriptors: local_htlc_descriptors,
					tx_lock_time: ::bitcoin::PackedLockTime(tx_lock_time),
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeBumpTransactionEvent) -> Self {
		match native {
			nativeBumpTransactionEvent::ChannelClose {ref claim_id, ref package_target_feerate_sat_per_1000_weight, ref commitment_tx, ref commitment_tx_fee_satoshis, ref anchor_descriptor, ref pending_htlcs, } => {
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut package_target_feerate_sat_per_1000_weight_nonref = Clone::clone(package_target_feerate_sat_per_1000_weight);
				let mut commitment_tx_nonref = Clone::clone(commitment_tx);
				let mut commitment_tx_fee_satoshis_nonref = Clone::clone(commitment_tx_fee_satoshis);
				let mut anchor_descriptor_nonref = Clone::clone(anchor_descriptor);
				let mut pending_htlcs_nonref = Clone::clone(pending_htlcs);
				let mut local_pending_htlcs_nonref = Vec::new(); for mut item in pending_htlcs_nonref.drain(..) { local_pending_htlcs_nonref.push( { crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::ChannelClose {
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id_nonref.0 },
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight_nonref,
					commitment_tx: crate::c_types::Transaction::from_bitcoin(&commitment_tx_nonref),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis_nonref,
					anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor { inner: ObjOps::heap_alloc(anchor_descriptor_nonref), is_owned: true },
					pending_htlcs: local_pending_htlcs_nonref.into(),
				}
			},
			nativeBumpTransactionEvent::HTLCResolution {ref claim_id, ref target_feerate_sat_per_1000_weight, ref htlc_descriptors, ref tx_lock_time, } => {
				let mut claim_id_nonref = Clone::clone(claim_id);
				let mut target_feerate_sat_per_1000_weight_nonref = Clone::clone(target_feerate_sat_per_1000_weight);
				let mut htlc_descriptors_nonref = Clone::clone(htlc_descriptors);
				let mut local_htlc_descriptors_nonref = Vec::new(); for mut item in htlc_descriptors_nonref.drain(..) { local_htlc_descriptors_nonref.push( { crate::lightning::sign::HTLCDescriptor { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				let mut tx_lock_time_nonref = Clone::clone(tx_lock_time);
				BumpTransactionEvent::HTLCResolution {
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id_nonref.0 },
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight_nonref,
					htlc_descriptors: local_htlc_descriptors_nonref.into(),
					tx_lock_time: tx_lock_time_nonref.0,
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeBumpTransactionEvent) -> Self {
		match native {
			nativeBumpTransactionEvent::ChannelClose {mut claim_id, mut package_target_feerate_sat_per_1000_weight, mut commitment_tx, mut commitment_tx_fee_satoshis, mut anchor_descriptor, mut pending_htlcs, } => {
				let mut local_pending_htlcs = Vec::new(); for mut item in pending_htlcs.drain(..) { local_pending_htlcs.push( { crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::ChannelClose {
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id.0 },
					package_target_feerate_sat_per_1000_weight: package_target_feerate_sat_per_1000_weight,
					commitment_tx: crate::c_types::Transaction::from_bitcoin(&commitment_tx),
					commitment_tx_fee_satoshis: commitment_tx_fee_satoshis,
					anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor { inner: ObjOps::heap_alloc(anchor_descriptor), is_owned: true },
					pending_htlcs: local_pending_htlcs.into(),
				}
			},
			nativeBumpTransactionEvent::HTLCResolution {mut claim_id, mut target_feerate_sat_per_1000_weight, mut htlc_descriptors, mut tx_lock_time, } => {
				let mut local_htlc_descriptors = Vec::new(); for mut item in htlc_descriptors.drain(..) { local_htlc_descriptors.push( { crate::lightning::sign::HTLCDescriptor { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
				BumpTransactionEvent::HTLCResolution {
					claim_id: crate::c_types::ThirtyTwoBytes { data: claim_id.0 },
					target_feerate_sat_per_1000_weight: target_feerate_sat_per_1000_weight,
					htlc_descriptors: local_htlc_descriptors.into(),
					tx_lock_time: tx_lock_time.0,
				}
			},
		}
	}
}
/// Frees any resources used by the BumpTransactionEvent
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_free(this_ptr: BumpTransactionEvent) { }
/// Creates a copy of the BumpTransactionEvent
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_clone(orig: &BumpTransactionEvent) -> BumpTransactionEvent {
	orig.clone()
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEvent_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const BumpTransactionEvent)).clone() })) as *mut c_void
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEvent_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut BumpTransactionEvent) };
}
#[no_mangle]
/// Utility method to constructs a new ChannelClose-variant BumpTransactionEvent
pub extern "C" fn BumpTransactionEvent_channel_close(claim_id: crate::c_types::ThirtyTwoBytes, package_target_feerate_sat_per_1000_weight: u32, commitment_tx: crate::c_types::Transaction, commitment_tx_fee_satoshis: u64, anchor_descriptor: crate::lightning::events::bump_transaction::AnchorDescriptor, pending_htlcs: crate::c_types::derived::CVec_HTLCOutputInCommitmentZ) -> BumpTransactionEvent {
	BumpTransactionEvent::ChannelClose {
		claim_id,
		package_target_feerate_sat_per_1000_weight,
		commitment_tx,
		commitment_tx_fee_satoshis,
		anchor_descriptor,
		pending_htlcs,
	}
}
#[no_mangle]
/// Utility method to constructs a new HTLCResolution-variant BumpTransactionEvent
pub extern "C" fn BumpTransactionEvent_htlcresolution(claim_id: crate::c_types::ThirtyTwoBytes, target_feerate_sat_per_1000_weight: u32, htlc_descriptors: crate::c_types::derived::CVec_HTLCDescriptorZ, tx_lock_time: u32) -> BumpTransactionEvent {
	BumpTransactionEvent::HTLCResolution {
		claim_id,
		target_feerate_sat_per_1000_weight,
		htlc_descriptors,
		tx_lock_time,
	}
}
/// Checks if two BumpTransactionEvents contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn BumpTransactionEvent_eq(a: &BumpTransactionEvent, b: &BumpTransactionEvent) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}

use lightning::events::bump_transaction::Input as nativeInputImport;
pub(crate) type nativeInput = nativeInputImport;

/// An input that must be included in a transaction when performing coin selection through
/// [`CoinSelectionSource::select_confirmed_utxos`]. It is guaranteed to be a SegWit input, so it
/// must have an empty [`TxIn::script_sig`] when spent.
#[must_use]
#[repr(C)]
pub struct Input {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInput,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Input {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInput>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Input, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Input_free(this_obj: Input) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Input_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInput) };
}
#[allow(unused)]
impl Input {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInput {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInput {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInput {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The unique identifier of the input.
#[no_mangle]
pub extern "C" fn Input_get_outpoint(this_ptr: &Input) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The unique identifier of the input.
#[no_mangle]
pub extern "C" fn Input_set_outpoint(this_ptr: &mut Input, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// The UTXO being spent by the input.
#[no_mangle]
pub extern "C" fn Input_get_previous_utxo(this_ptr: &Input) -> crate::c_types::TxOut {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().previous_utxo;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The UTXO being spent by the input.
#[no_mangle]
pub extern "C" fn Input_set_previous_utxo(this_ptr: &mut Input, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.previous_utxo = val.into_rust();
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
/// script.
#[no_mangle]
pub extern "C" fn Input_get_satisfaction_weight(this_ptr: &Input) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().satisfaction_weight;
	*inner_val
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and
/// [`TxIn::witness`], each with their lengths included, required to satisfy the output's
/// script.
#[no_mangle]
pub extern "C" fn Input_set_satisfaction_weight(this_ptr: &mut Input, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.satisfaction_weight = val;
}
/// Constructs a new Input given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Input_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut previous_utxo_arg: crate::c_types::TxOut, mut satisfaction_weight_arg: u64) -> Input {
	Input { inner: ObjOps::heap_alloc(nativeInput {
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
		previous_utxo: previous_utxo_arg.into_rust(),
		satisfaction_weight: satisfaction_weight_arg,
	}), is_owned: true }
}
impl Clone for Input {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInput>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Input_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeInput)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Input
pub extern "C" fn Input_clone(orig: &Input) -> Input {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Input.
#[no_mangle]
pub extern "C" fn Input_hash(o: &Input) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Inputs contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Input_eq(a: &Input, b: &Input) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}

use lightning::events::bump_transaction::Utxo as nativeUtxoImport;
pub(crate) type nativeUtxo = nativeUtxoImport;

/// An unspent transaction output that is available to spend resulting from a successful
/// [`CoinSelection`] attempt.
#[must_use]
#[repr(C)]
pub struct Utxo {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeUtxo,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Utxo {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeUtxo>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Utxo, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Utxo_free(this_obj: Utxo) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Utxo_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeUtxo) };
}
#[allow(unused)]
impl Utxo {
	pub(crate) fn get_native_ref(&self) -> &'static nativeUtxo {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeUtxo {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeUtxo {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The unique identifier of the output.
#[no_mangle]
pub extern "C" fn Utxo_get_outpoint(this_ptr: &Utxo) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::c_types::bitcoin_to_C_outpoint(inner_val)
}
/// The unique identifier of the output.
#[no_mangle]
pub extern "C" fn Utxo_set_outpoint(this_ptr: &mut Utxo, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = crate::c_types::C_to_bitcoin_outpoint(val);
}
/// The output to spend.
#[no_mangle]
pub extern "C" fn Utxo_get_output(this_ptr: &Utxo) -> crate::c_types::TxOut {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().output;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The output to spend.
#[no_mangle]
pub extern "C" fn Utxo_set_output(this_ptr: &mut Utxo, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.output = val.into_rust();
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and [`TxIn::witness`], each
/// with their lengths included, required to satisfy the output's script. The weight consumed by
/// the input's `script_sig` must account for [`WITNESS_SCALE_FACTOR`].
#[no_mangle]
pub extern "C" fn Utxo_get_satisfaction_weight(this_ptr: &Utxo) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().satisfaction_weight;
	*inner_val
}
/// The upper-bound weight consumed by the input's full [`TxIn::script_sig`] and [`TxIn::witness`], each
/// with their lengths included, required to satisfy the output's script. The weight consumed by
/// the input's `script_sig` must account for [`WITNESS_SCALE_FACTOR`].
#[no_mangle]
pub extern "C" fn Utxo_set_satisfaction_weight(this_ptr: &mut Utxo, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.satisfaction_weight = val;
}
/// Constructs a new Utxo given each field
#[must_use]
#[no_mangle]
pub extern "C" fn Utxo_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut output_arg: crate::c_types::TxOut, mut satisfaction_weight_arg: u64) -> Utxo {
	Utxo { inner: ObjOps::heap_alloc(nativeUtxo {
		outpoint: crate::c_types::C_to_bitcoin_outpoint(outpoint_arg),
		output: output_arg.into_rust(),
		satisfaction_weight: satisfaction_weight_arg,
	}), is_owned: true }
}
impl Clone for Utxo {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeUtxo>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Utxo_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeUtxo)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Utxo
pub extern "C" fn Utxo_clone(orig: &Utxo) -> Utxo {
	orig.clone()
}
/// Generates a non-cryptographic 64-bit hash of the Utxo.
#[no_mangle]
pub extern "C" fn Utxo_hash(o: &Utxo) -> u64 {
	if o.inner.is_null() { return 0; }
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(o.get_native_ref(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Checks if two Utxos contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn Utxo_eq(a: &Utxo, b: &Utxo) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
/// Returns a `Utxo` with the `satisfaction_weight` estimate for a legacy P2PKH output.
#[must_use]
#[no_mangle]
pub extern "C" fn Utxo_new_p2pkh(mut outpoint: crate::lightning::chain::transaction::OutPoint, mut value: u64, pubkey_hash: *const [u8; 20]) -> crate::lightning::events::bump_transaction::Utxo {
	let mut ret = lightning::events::bump_transaction::Utxo::new_p2pkh(crate::c_types::C_to_bitcoin_outpoint(outpoint), value, &bitcoin::hash_types::PubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner(unsafe { *pubkey_hash }.clone())));
	crate::lightning::events::bump_transaction::Utxo { inner: ObjOps::heap_alloc(ret), is_owned: true }
}


use lightning::events::bump_transaction::CoinSelection as nativeCoinSelectionImport;
pub(crate) type nativeCoinSelection = nativeCoinSelectionImport;

/// The result of a successful coin selection attempt for a transaction requiring additional UTXOs
/// to cover its fees.
#[must_use]
#[repr(C)]
pub struct CoinSelection {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeCoinSelection,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for CoinSelection {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeCoinSelection>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the CoinSelection, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn CoinSelection_free(this_obj: CoinSelection) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CoinSelection_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeCoinSelection) };
}
#[allow(unused)]
impl CoinSelection {
	pub(crate) fn get_native_ref(&self) -> &'static nativeCoinSelection {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeCoinSelection {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeCoinSelection {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
/// requiring additional fees.
#[no_mangle]
pub extern "C" fn CoinSelection_get_confirmed_utxos(this_ptr: &CoinSelection) -> crate::c_types::derived::CVec_UtxoZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().confirmed_utxos;
	let mut local_inner_val = Vec::new(); for item in inner_val.iter() { local_inner_val.push( { crate::lightning::events::bump_transaction::Utxo { inner: unsafe { ObjOps::nonnull_ptr_to_inner((item as *const lightning::events::bump_transaction::Utxo<>) as *mut _) }, is_owned: false } }); };
	local_inner_val.into()
}
/// The set of UTXOs (with at least 1 confirmation) to spend and use within a transaction
/// requiring additional fees.
#[no_mangle]
pub extern "C" fn CoinSelection_set_confirmed_utxos(this_ptr: &mut CoinSelection, mut val: crate::c_types::derived::CVec_UtxoZ) {
	let mut local_val = Vec::new(); for mut item in val.into_rust().drain(..) { local_val.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.confirmed_utxos = local_val;
}
/// An additional output tracking whether any change remained after coin selection. This output
/// should always have a value above dust for its given `script_pubkey`. It should not be
/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
/// not met. This implies no other party should be able to spend it except us.
#[no_mangle]
pub extern "C" fn CoinSelection_get_change_output(this_ptr: &CoinSelection) -> crate::c_types::derived::COption_TxOutZ {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().change_output;
	let mut local_inner_val = if inner_val.is_none() { crate::c_types::derived::COption_TxOutZ::None } else { crate::c_types::derived::COption_TxOutZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::TxOut::from_rust(&(*inner_val.as_ref().unwrap()).clone()) }) };
	local_inner_val
}
/// An additional output tracking whether any change remained after coin selection. This output
/// should always have a value above dust for its given `script_pubkey`. It should not be
/// spent until the transaction it belongs to confirms to ensure mempool descendant limits are
/// not met. This implies no other party should be able to spend it except us.
#[no_mangle]
pub extern "C" fn CoinSelection_set_change_output(this_ptr: &mut CoinSelection, mut val: crate::c_types::derived::COption_TxOutZ) {
	let mut local_val = { /*val*/ let val_opt = val; if val_opt.is_none() { None } else { Some({ { { val_opt.take() }.into_rust() }})} };
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.change_output = local_val;
}
/// Constructs a new CoinSelection given each field
#[must_use]
#[no_mangle]
pub extern "C" fn CoinSelection_new(mut confirmed_utxos_arg: crate::c_types::derived::CVec_UtxoZ, mut change_output_arg: crate::c_types::derived::COption_TxOutZ) -> CoinSelection {
	let mut local_confirmed_utxos_arg = Vec::new(); for mut item in confirmed_utxos_arg.into_rust().drain(..) { local_confirmed_utxos_arg.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_change_output_arg = { /*change_output_arg*/ let change_output_arg_opt = change_output_arg; if change_output_arg_opt.is_none() { None } else { Some({ { { change_output_arg_opt.take() }.into_rust() }})} };
	CoinSelection { inner: ObjOps::heap_alloc(nativeCoinSelection {
		confirmed_utxos: local_confirmed_utxos_arg,
		change_output: local_change_output_arg,
	}), is_owned: true }
}
impl Clone for CoinSelection {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeCoinSelection>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn CoinSelection_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *const nativeCoinSelection)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the CoinSelection
pub extern "C" fn CoinSelection_clone(orig: &CoinSelection) -> CoinSelection {
	orig.clone()
}
/// An abstraction over a bitcoin wallet that can perform coin selection over a set of UTXOs and can
/// sign for them. The coin selection method aims to mimic Bitcoin Core's `fundrawtransaction` RPC,
/// which most wallets should be able to satisfy. Otherwise, consider implementing [`WalletSource`],
/// which can provide a default implementation of this trait when used with [`Wallet`].
#[repr(C)]
pub struct CoinSelectionSource {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Performs coin selection of a set of UTXOs, with at least 1 confirmation each, that are
	/// available to spend. Implementations are free to pick their coin selection algorithm of
	/// choice, as long as the following requirements are met:
	///
	/// 1. `must_spend` contains a set of [`Input`]s that must be included in the transaction
	///    throughout coin selection, but must not be returned as part of the result.
	/// 2. `must_pay_to` contains a set of [`TxOut`]s that must be included in the transaction
	///    throughout coin selection. In some cases, like when funding an anchor transaction, this
	///    set is empty. Implementations should ensure they handle this correctly on their end,
	///    e.g., Bitcoin Core's `fundrawtransaction` RPC requires at least one output to be
	///    provided, in which case a zero-value empty OP_RETURN output can be used instead.
	/// 3. Enough inputs must be selected/contributed for the resulting transaction (including the
	///    inputs and outputs noted above) to meet `target_feerate_sat_per_1000_weight`.
	///
	/// Implementations must take note that [`Input::satisfaction_weight`] only tracks the weight of
	/// the input's `script_sig` and `witness`. Some wallets, like Bitcoin Core's, may require
	/// providing the full input weight. Failing to do so may lead to underestimating fee bumps and
	/// delaying block inclusion.
	///
	/// The `claim_id` must map to the set of external UTXOs assigned to the claim, such that they
	/// can be re-used within new fee-bumped iterations of the original claiming transaction,
	/// ensuring that claims don't double spend each other. If a specific `claim_id` has never had a
	/// transaction associated with it, and all of the available UTXOs have already been assigned to
	/// other claims, implementations must be willing to double spend their UTXOs. The choice of
	/// which UTXOs to double spend is left to the implementation, but it must strive to keep the
	/// set of other claims being double spent to a minimum.
	pub select_confirmed_utxos: extern "C" fn (this_arg: *const c_void, claim_id: crate::c_types::ThirtyTwoBytes, must_spend: crate::c_types::derived::CVec_InputZ, must_pay_to: crate::c_types::derived::CVec_TxOutZ, target_feerate_sat_per_1000_weight: u32) -> crate::c_types::derived::CResult_CoinSelectionNoneZ,
	/// Signs and provides the full witness for all inputs within the transaction known to the
	/// trait (i.e., any provided via [`CoinSelectionSource::select_confirmed_utxos`]).
	pub sign_tx: extern "C" fn (this_arg: *const c_void, tx: crate::c_types::Transaction) -> crate::c_types::derived::CResult_TransactionNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for CoinSelectionSource {}
unsafe impl Sync for CoinSelectionSource {}
#[allow(unused)]
pub(crate) fn CoinSelectionSource_clone_fields(orig: &CoinSelectionSource) -> CoinSelectionSource {
	CoinSelectionSource {
		this_arg: orig.this_arg,
		select_confirmed_utxos: Clone::clone(&orig.select_confirmed_utxos),
		sign_tx: Clone::clone(&orig.sign_tx),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::bump_transaction::CoinSelectionSource as rustCoinSelectionSource;
impl rustCoinSelectionSource for CoinSelectionSource {
	fn select_confirmed_utxos(&self, mut claim_id: lightning::chain::ClaimId, mut must_spend: Vec<lightning::events::bump_transaction::Input>, mut must_pay_to: &[bitcoin::TxOut], mut target_feerate_sat_per_1000_weight: u32) -> Result<lightning::events::bump_transaction::CoinSelection, ()> {
		let mut local_must_spend = Vec::new(); for mut item in must_spend.drain(..) { local_must_spend.push( { crate::lightning::events::bump_transaction::Input { inner: ObjOps::heap_alloc(item), is_owned: true } }); };
		let mut local_must_pay_to_clone = Vec::new(); local_must_pay_to_clone.extend_from_slice(must_pay_to); let mut must_pay_to = local_must_pay_to_clone; let mut local_must_pay_to = Vec::new(); for mut item in must_pay_to.drain(..) { local_must_pay_to.push( { crate::c_types::TxOut::from_rust(&item) }); };
		let mut ret = (self.select_confirmed_utxos)(self.this_arg, crate::c_types::ThirtyTwoBytes { data: claim_id.0 }, local_must_spend.into(), local_must_pay_to.into(), target_feerate_sat_per_1000_weight);
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_tx(&self, mut tx: bitcoin::Transaction) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.sign_tx)(self.this_arg, crate::c_types::Transaction::from_bitcoin(&tx));
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for CoinSelectionSource {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for CoinSelectionSource {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn CoinSelectionSource_free(this_ptr: CoinSelectionSource) { }
impl Drop for CoinSelectionSource {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// An alternative to [`CoinSelectionSource`] that can be implemented and used along [`Wallet`] to
/// provide a default implementation to [`CoinSelectionSource`].
#[repr(C)]
pub struct WalletSource {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns all UTXOs, with at least 1 confirmation each, that are available to spend.
	pub list_confirmed_utxos: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_CVec_UtxoZNoneZ,
	/// Returns a script to use for change above dust resulting from a successful coin selection
	/// attempt.
	pub get_change_script: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_CVec_u8ZNoneZ,
	/// Signs and provides the full [`TxIn::script_sig`] and [`TxIn::witness`] for all inputs within
	/// the transaction known to the wallet (i.e., any provided via
	/// [`WalletSource::list_confirmed_utxos`]).
	pub sign_tx: extern "C" fn (this_arg: *const c_void, tx: crate::c_types::Transaction) -> crate::c_types::derived::CResult_TransactionNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for WalletSource {}
unsafe impl Sync for WalletSource {}
#[allow(unused)]
pub(crate) fn WalletSource_clone_fields(orig: &WalletSource) -> WalletSource {
	WalletSource {
		this_arg: orig.this_arg,
		list_confirmed_utxos: Clone::clone(&orig.list_confirmed_utxos),
		get_change_script: Clone::clone(&orig.get_change_script),
		sign_tx: Clone::clone(&orig.sign_tx),
		free: Clone::clone(&orig.free),
	}
}

use lightning::events::bump_transaction::WalletSource as rustWalletSource;
impl rustWalletSource for WalletSource {
	fn list_confirmed_utxos(&self) -> Result<Vec<lightning::events::bump_transaction::Utxo>, ()> {
		let mut ret = (self.list_confirmed_utxos)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { let mut local_ret_0 = Vec::new(); for mut item in (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust().drain(..) { local_ret_0.push( { *unsafe { Box::from_raw(item.take_inner()) } }); }; local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn get_change_script(&self) -> Result<bitcoin::Script, ()> {
		let mut ret = (self.get_change_script)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { ::bitcoin::blockdata::script::Script::from((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust()) }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_tx(&self, mut tx: bitcoin::Transaction) -> Result<bitcoin::Transaction, ()> {
		let mut ret = (self.sign_tx)(self.this_arg, crate::c_types::Transaction::from_bitcoin(&tx));
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_bitcoin() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for WalletSource {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for WalletSource {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn WalletSource_free(this_ptr: WalletSource) { }
impl Drop for WalletSource {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::events::bump_transaction::Wallet as nativeWalletImport;
pub(crate) type nativeWallet = nativeWalletImport<crate::lightning::events::bump_transaction::WalletSource, crate::lightning::util::logger::Logger>;

/// A wrapper over [`WalletSource`] that implements [`CoinSelection`] by preferring UTXOs that would
/// avoid conflicting double spends. If not enough UTXOs are available to do so, conflicting double
/// spends may happen.
#[must_use]
#[repr(C)]
pub struct Wallet {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeWallet,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Wallet {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeWallet>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Wallet, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Wallet_free(this_obj: Wallet) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Wallet_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeWallet) };
}
#[allow(unused)]
impl Wallet {
	pub(crate) fn get_native_ref(&self) -> &'static nativeWallet {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeWallet {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeWallet {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Returns a new instance backed by the given [`WalletSource`] that serves as an implementation
/// of [`CoinSelectionSource`].
#[must_use]
#[no_mangle]
pub extern "C" fn Wallet_new(mut source: crate::lightning::events::bump_transaction::WalletSource, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::events::bump_transaction::Wallet {
	let mut ret = lightning::events::bump_transaction::Wallet::new(source, logger);
	crate::lightning::events::bump_transaction::Wallet { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

impl From<nativeWallet> for crate::lightning::events::bump_transaction::CoinSelectionSource {
	fn from(obj: nativeWallet) -> Self {
		let rust_obj = crate::lightning::events::bump_transaction::Wallet { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = Wallet_as_CoinSelectionSource(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so forget it and set ret's free() fn
		core::mem::forget(rust_obj);
		ret.free = Some(Wallet_free_void);
		ret
	}
}
/// Constructs a new CoinSelectionSource which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned CoinSelectionSource must be freed before this_arg is
#[no_mangle]
pub extern "C" fn Wallet_as_CoinSelectionSource(this_arg: &Wallet) -> crate::lightning::events::bump_transaction::CoinSelectionSource {
	crate::lightning::events::bump_transaction::CoinSelectionSource {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		select_confirmed_utxos: Wallet_CoinSelectionSource_select_confirmed_utxos,
		sign_tx: Wallet_CoinSelectionSource_sign_tx,
	}
}

#[must_use]
extern "C" fn Wallet_CoinSelectionSource_select_confirmed_utxos(this_arg: *const c_void, mut claim_id: crate::c_types::ThirtyTwoBytes, mut must_spend: crate::c_types::derived::CVec_InputZ, mut must_pay_to: crate::c_types::derived::CVec_TxOutZ, mut target_feerate_sat_per_1000_weight: u32) -> crate::c_types::derived::CResult_CoinSelectionNoneZ {
	let mut local_must_spend = Vec::new(); for mut item in must_spend.into_rust().drain(..) { local_must_spend.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut local_must_pay_to = Vec::new(); for mut item in must_pay_to.into_rust().drain(..) { local_must_pay_to.push( { item.into_rust() }); };
	let mut ret = <nativeWallet as lightning::events::bump_transaction::CoinSelectionSource<>>::select_confirmed_utxos(unsafe { &mut *(this_arg as *mut nativeWallet) }, ::lightning::chain::ClaimId(claim_id.data), local_must_spend, &local_must_pay_to[..], target_feerate_sat_per_1000_weight);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::events::bump_transaction::CoinSelection { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn Wallet_CoinSelectionSource_sign_tx(this_arg: *const c_void, mut tx: crate::c_types::Transaction) -> crate::c_types::derived::CResult_TransactionNoneZ {
	let mut ret = <nativeWallet as lightning::events::bump_transaction::CoinSelectionSource<>>::sign_tx(unsafe { &mut *(this_arg as *mut nativeWallet) }, tx.into_bitcoin());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Transaction::from_bitcoin(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::events::bump_transaction::BumpTransactionEventHandler as nativeBumpTransactionEventHandlerImport;
pub(crate) type nativeBumpTransactionEventHandler = nativeBumpTransactionEventHandlerImport<crate::lightning::chain::chaininterface::BroadcasterInterface, crate::lightning::events::bump_transaction::CoinSelectionSource, crate::lightning::sign::SignerProvider, crate::lightning::util::logger::Logger>;

/// A handler for [`Event::BumpTransaction`] events that sources confirmed UTXOs from a
/// [`CoinSelectionSource`] to fee bump transactions via Child-Pays-For-Parent (CPFP) or
/// Replace-By-Fee (RBF).
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
#[must_use]
#[repr(C)]
pub struct BumpTransactionEventHandler {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeBumpTransactionEventHandler,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for BumpTransactionEventHandler {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeBumpTransactionEventHandler>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the BumpTransactionEventHandler, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandler_free(this_obj: BumpTransactionEventHandler) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn BumpTransactionEventHandler_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeBumpTransactionEventHandler) };
}
#[allow(unused)]
impl BumpTransactionEventHandler {
	pub(crate) fn get_native_ref(&self) -> &'static nativeBumpTransactionEventHandler {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeBumpTransactionEventHandler {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeBumpTransactionEventHandler {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Returns a new instance capable of handling [`Event::BumpTransaction`] events.
///
/// [`Event::BumpTransaction`]: crate::events::Event::BumpTransaction
#[must_use]
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandler_new(mut broadcaster: crate::lightning::chain::chaininterface::BroadcasterInterface, mut utxo_source: crate::lightning::events::bump_transaction::CoinSelectionSource, mut signer_provider: crate::lightning::sign::SignerProvider, mut logger: crate::lightning::util::logger::Logger) -> crate::lightning::events::bump_transaction::BumpTransactionEventHandler {
	let mut ret = lightning::events::bump_transaction::BumpTransactionEventHandler::new(broadcaster, utxo_source, signer_provider, logger);
	crate::lightning::events::bump_transaction::BumpTransactionEventHandler { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Handles all variants of [`BumpTransactionEvent`].
#[no_mangle]
pub extern "C" fn BumpTransactionEventHandler_handle_event(this_arg: &crate::lightning::events::bump_transaction::BumpTransactionEventHandler, event: &crate::lightning::events::bump_transaction::BumpTransactionEvent) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.handle_event(&event.to_native())
}

