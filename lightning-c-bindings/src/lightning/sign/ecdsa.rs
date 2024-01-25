// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Defines ECDSA-specific signer types.

use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// A trait to sign Lightning channel transactions as described in
/// [BOLT 3](https://github.com/lightning/bolts/blob/master/03-transactions.md).
///
/// Signing services could be implemented on a hardware wallet and should implement signing
/// policies in order to be secure. Please refer to the [VLS Policy
/// Controls](https://gitlab.com/lightning-signer/validating-lightning-signer/-/blob/main/docs/policy-controls.md)
/// for an example of such policies.
#[repr(C)]
pub struct EcdsaChannelSigner {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Create a signature for a counterparty's commitment transaction and associated HTLC transactions.
	///
	/// Note that if signing fails or is rejected, the channel will be force-closed.
	///
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outbound and inbound HTLCs that were fulfilled since the last commitment
	/// are provided. A validating signer should ensure that an outbound HTLC output is removed
	/// only when the matching preimage is provided and after the corresponding inbound HTLC has
	/// been removed for forwarded payments.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	pub sign_counterparty_commitment: extern "C" fn (this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::CommitmentTransaction, inbound_htlc_preimages: crate::c_types::derived::CVec_ThirtyTwoBytesZ, outbound_htlc_preimages: crate::c_types::derived::CVec_ThirtyTwoBytesZ) -> crate::c_types::derived::CResult_C2Tuple_ECDSASignatureCVec_ECDSASignatureZZNoneZ,
	/// Creates a signature for a holder's commitment transaction.
	///
	/// This will be called
	/// - with a non-revoked `commitment_tx`.
	/// - with the latest `commitment_tx` when we initiate a force-close.
	///
	/// This may be called multiple times for the same transaction.
	///
	/// An external signer implementation should check that the commitment has not been revoked.
	pub sign_holder_commitment: extern "C" fn (this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Create a signature for the given input in a transaction spending an HTLC transaction output
	/// or a commitment transaction `to_local` output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// Amount is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder `revocation_secret` to do
	/// so).
	pub sign_justice_revoked_output: extern "C" fn (this_arg: *const c_void, justice_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_key: *const [u8; 32]) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Create a signature for the given input in a transaction spending a commitment transaction
	/// HTLC output when our counterparty broadcasts an old state.
	///
	/// A justice transaction may claim multiple outputs at the same time if timelocks are
	/// similar, but only a signature for the input at index `input` should be signed for here.
	/// It may be called multiple times for same output(s) if a fee-bump is needed with regards
	/// to an upcoming timelock expiration.
	///
	/// `amount` is the value of the output spent by this input, committed to in the BIP 143
	/// signature.
	///
	/// `per_commitment_key` is revocation secret which was provided by our counterparty when they
	/// revoked the state which they eventually broadcast. It's not a _holder_ secret key and does
	/// not allow the spending of any funds by itself (you need our holder revocation_secret to do
	/// so).
	///
	/// `htlc` holds HTLC elements (hash, timelock), thus changing the format of the witness script
	/// (which is committed to in the BIP 143 signatures).
	pub sign_justice_revoked_htlc: extern "C" fn (this_arg: *const c_void, justice_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_key: *const [u8; 32], htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Computes the signature for a commitment transaction's HTLC output used as an input within
	/// `htlc_tx`, which spends the commitment transaction at index `input`. The signature returned
	/// must be be computed using [`EcdsaSighashType::All`].
	///
	/// Note that this may be called for HTLCs in the penultimate commitment transaction if a
	/// [`ChannelMonitor`] [replica](https://github.com/lightningdevkit/rust-lightning/blob/main/GLOSSARY.md#monitor-replicas)
	/// broadcasts it before receiving the update for the latest commitment transaction.
	///
	/// [`EcdsaSighashType::All`]: bitcoin::sighash::EcdsaSighashType::All
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	pub sign_holder_htlc_transaction: extern "C" fn (this_arg: *const c_void, htlc_tx: crate::c_types::Transaction, input: usize, htlc_descriptor: &crate::lightning::sign::HTLCDescriptor) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Create a signature for a claiming transaction for a HTLC output on a counterparty's commitment
	/// transaction, either offered or received.
	///
	/// Such a transaction may claim multiples offered outputs at same time if we know the
	/// preimage for each when we create it, but only the input at index `input` should be
	/// signed for here. It may be called multiple times for same output(s) if a fee-bump is
	/// needed with regards to an upcoming timelock expiration.
	///
	/// `witness_script` is either an offered or received script as defined in BOLT3 for HTLC
	/// outputs.
	///
	/// `amount` is value of the output spent by this input, committed to in the BIP 143 signature.
	///
	/// `per_commitment_point` is the dynamic point corresponding to the channel state
	/// detected onchain. It has been generated by our counterparty and is used to derive
	/// channel state keys, which are then included in the witness script and committed to in the
	/// BIP 143 signature.
	pub sign_counterparty_htlc_transaction: extern "C" fn (this_arg: *const c_void, htlc_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_point: crate::c_types::PublicKey, htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one \"missing\" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	pub sign_closing_transaction: extern "C" fn (this_arg: *const c_void, closing_tx: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Computes the signature for a commitment transaction's anchor output used as an
	/// input within `anchor_tx`, which spends the commitment transaction, at index `input`.
	pub sign_holder_anchor_input: extern "C" fn (this_arg: *const c_void, anchor_tx: crate::c_types::Transaction, input: usize) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Signs a channel announcement message with our funding key proving it comes from one of the
	/// channel participants.
	///
	/// Channel announcements also require a signature from each node's network key. Our node
	/// signature is computed through [`NodeSigner::sign_gossip_message`].
	///
	/// Note that if this fails or is rejected, the channel will not be publicly announced and
	/// our counterparty may (though likely will not) close the channel on us for violating the
	/// protocol.
	///
	/// [`NodeSigner::sign_gossip_message`]: crate::sign::NodeSigner::sign_gossip_message
	pub sign_channel_announcement_with_funding_key: extern "C" fn (this_arg: *const c_void, msg: &crate::lightning::ln::msgs::UnsignedChannelAnnouncement) -> crate::c_types::derived::CResult_ECDSASignatureNoneZ,
	/// Implementation of ChannelSigner for this object.
	pub ChannelSigner: crate::lightning::sign::ChannelSigner,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EcdsaChannelSigner {}
unsafe impl Sync for EcdsaChannelSigner {}
#[allow(unused)]
pub(crate) fn EcdsaChannelSigner_clone_fields(orig: &EcdsaChannelSigner) -> EcdsaChannelSigner {
	EcdsaChannelSigner {
		this_arg: orig.this_arg,
		sign_counterparty_commitment: Clone::clone(&orig.sign_counterparty_commitment),
		sign_holder_commitment: Clone::clone(&orig.sign_holder_commitment),
		sign_justice_revoked_output: Clone::clone(&orig.sign_justice_revoked_output),
		sign_justice_revoked_htlc: Clone::clone(&orig.sign_justice_revoked_htlc),
		sign_holder_htlc_transaction: Clone::clone(&orig.sign_holder_htlc_transaction),
		sign_counterparty_htlc_transaction: Clone::clone(&orig.sign_counterparty_htlc_transaction),
		sign_closing_transaction: Clone::clone(&orig.sign_closing_transaction),
		sign_holder_anchor_input: Clone::clone(&orig.sign_holder_anchor_input),
		sign_channel_announcement_with_funding_key: Clone::clone(&orig.sign_channel_announcement_with_funding_key),
		ChannelSigner: crate::lightning::sign::ChannelSigner_clone_fields(&orig.ChannelSigner),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::sign::ChannelSigner for EcdsaChannelSigner {
	fn get_per_commitment_point(&self, mut idx: u64, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> bitcoin::secp256k1::PublicKey {
		let mut ret = (self.ChannelSigner.get_per_commitment_point)(self.ChannelSigner.this_arg, idx);
		ret.into_rust()
	}
	fn release_commitment_secret(&self, mut idx: u64) -> [u8; 32] {
		let mut ret = (self.ChannelSigner.release_commitment_secret)(self.ChannelSigner.this_arg, idx);
		ret.data
	}
	fn validate_holder_commitment(&self, mut holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut outbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>) -> Result<(), ()> {
		let mut local_outbound_htlc_preimages = Vec::new(); for mut item in outbound_htlc_preimages.drain(..) { local_outbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.ChannelSigner.validate_holder_commitment)(self.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((holder_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false }, local_outbound_htlc_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn validate_counterparty_revocation(&self, mut idx: u64, mut secret: &bitcoin::secp256k1::SecretKey) -> Result<(), ()> {
		let mut ret = (self.ChannelSigner.validate_counterparty_revocation)(self.ChannelSigner.this_arg, idx, secret.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
		if let Some(f) = self.ChannelSigner.set_pubkeys {
			(f)(&self.ChannelSigner);
		}
		unsafe { &*self.ChannelSigner.pubkeys.get() }.get_native_ref()
	}
	fn channel_keys_id(&self) -> [u8; 32] {
		let mut ret = (self.ChannelSigner.channel_keys_id)(self.ChannelSigner.this_arg);
		ret.data
	}
	fn provide_channel_parameters(&mut self, mut channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters) {
		(self.ChannelSigner.provide_channel_parameters)(self.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::ChannelTransactionParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((channel_parameters as *const lightning::ln::chan_utils::ChannelTransactionParameters<>) as *mut _) }, is_owned: false })
	}
}

use lightning::sign::ecdsa::EcdsaChannelSigner as rustEcdsaChannelSigner;
impl rustEcdsaChannelSigner for EcdsaChannelSigner {
	fn sign_counterparty_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, mut inbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>, mut outbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut local_inbound_htlc_preimages = Vec::new(); for mut item in inbound_htlc_preimages.drain(..) { local_inbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut local_outbound_htlc_preimages = Vec::new(); for mut item in outbound_htlc_preimages.drain(..) { local_outbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.sign_counterparty_commitment)(self.this_arg, &crate::lightning::ln::chan_utils::CommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::CommitmentTransaction<>) as *mut _) }, is_owned: false }, local_inbound_htlc_preimages.into(), local_outbound_htlc_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_holder_commitment)(self.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_justice_revoked_output(&self, mut justice_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_key: &bitcoin::secp256k1::SecretKey, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_justice_revoked_output)(self.this_arg, crate::c_types::Transaction::from_bitcoin(justice_tx), input, amount, per_commitment_key.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_justice_revoked_htlc(&self, mut justice_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_key: &bitcoin::secp256k1::SecretKey, mut htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_justice_revoked_htlc)(self.this_arg, crate::c_types::Transaction::from_bitcoin(justice_tx), input, amount, per_commitment_key.as_ref(), &crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc as *const lightning::ln::chan_utils::HTLCOutputInCommitment<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut htlc_descriptor: &lightning::sign::HTLCDescriptor, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_holder_htlc_transaction)(self.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, &crate::lightning::sign::HTLCDescriptor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc_descriptor as *const lightning::sign::HTLCDescriptor<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_counterparty_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_point: &bitcoin::secp256k1::PublicKey, mut htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_counterparty_htlc_transaction)(self.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, amount, crate::c_types::PublicKey::from_rust(&per_commitment_point), &crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc as *const lightning::ln::chan_utils::HTLCOutputInCommitment<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_closing_transaction(&self, mut closing_tx: &lightning::ln::chan_utils::ClosingTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_closing_transaction)(self.this_arg, &crate::lightning::ln::chan_utils::ClosingTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((closing_tx as *const lightning::ln::chan_utils::ClosingTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_anchor_input(&self, mut anchor_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_holder_anchor_input)(self.this_arg, crate::c_types::Transaction::from_bitcoin(anchor_tx), input);
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_channel_announcement_with_funding_key(&self, mut msg: &lightning::ln::msgs::UnsignedChannelAnnouncement, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_channel_announcement_with_funding_key)(self.this_arg, &crate::lightning::ln::msgs::UnsignedChannelAnnouncement { inner: unsafe { ObjOps::nonnull_ptr_to_inner((msg as *const lightning::ln::msgs::UnsignedChannelAnnouncement<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for EcdsaChannelSigner {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for EcdsaChannelSigner {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EcdsaChannelSigner_free(this_ptr: EcdsaChannelSigner) { }
impl Drop for EcdsaChannelSigner {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A writeable signer.
///
/// There will always be two instances of a signer per channel, one occupied by the
/// [`ChannelManager`] and another by the channel's [`ChannelMonitor`].
///
/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
#[repr(C)]
pub struct WriteableEcdsaChannelSigner {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Implementation of EcdsaChannelSigner for this object.
	pub EcdsaChannelSigner: crate::lightning::sign::ecdsa::EcdsaChannelSigner,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Called, if set, after this WriteableEcdsaChannelSigner has been cloned into a duplicate object.
	/// The new WriteableEcdsaChannelSigner is provided, and should be mutated as needed to perform a
	/// deep copy of the object pointed to by this_arg or avoid any double-freeing.
	pub cloned: Option<extern "C" fn (new_WriteableEcdsaChannelSigner: &mut WriteableEcdsaChannelSigner)>,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for WriteableEcdsaChannelSigner {}
unsafe impl Sync for WriteableEcdsaChannelSigner {}
#[allow(unused)]
pub(crate) fn WriteableEcdsaChannelSigner_clone_fields(orig: &WriteableEcdsaChannelSigner) -> WriteableEcdsaChannelSigner {
	WriteableEcdsaChannelSigner {
		this_arg: orig.this_arg,
		EcdsaChannelSigner: crate::lightning::sign::ecdsa::EcdsaChannelSigner_clone_fields(&orig.EcdsaChannelSigner),
		write: Clone::clone(&orig.write),
		cloned: Clone::clone(&orig.cloned),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::sign::ecdsa::EcdsaChannelSigner for WriteableEcdsaChannelSigner {
	fn sign_counterparty_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, mut inbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>, mut outbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut local_inbound_htlc_preimages = Vec::new(); for mut item in inbound_htlc_preimages.drain(..) { local_inbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut local_outbound_htlc_preimages = Vec::new(); for mut item in outbound_htlc_preimages.drain(..) { local_outbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.EcdsaChannelSigner.sign_counterparty_commitment)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::chan_utils::CommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::CommitmentTransaction<>) as *mut _) }, is_owned: false }, local_inbound_htlc_preimages.into(), local_outbound_htlc_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_holder_commitment)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_justice_revoked_output(&self, mut justice_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_key: &bitcoin::secp256k1::SecretKey, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_justice_revoked_output)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(justice_tx), input, amount, per_commitment_key.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_justice_revoked_htlc(&self, mut justice_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_key: &bitcoin::secp256k1::SecretKey, mut htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_justice_revoked_htlc)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(justice_tx), input, amount, per_commitment_key.as_ref(), &crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc as *const lightning::ln::chan_utils::HTLCOutputInCommitment<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut htlc_descriptor: &lightning::sign::HTLCDescriptor, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_holder_htlc_transaction)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, &crate::lightning::sign::HTLCDescriptor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc_descriptor as *const lightning::sign::HTLCDescriptor<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_counterparty_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut amount: u64, mut per_commitment_point: &bitcoin::secp256k1::PublicKey, mut htlc: &lightning::ln::chan_utils::HTLCOutputInCommitment, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_counterparty_htlc_transaction)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, amount, crate::c_types::PublicKey::from_rust(&per_commitment_point), &crate::lightning::ln::chan_utils::HTLCOutputInCommitment { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc as *const lightning::ln::chan_utils::HTLCOutputInCommitment<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_closing_transaction(&self, mut closing_tx: &lightning::ln::chan_utils::ClosingTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_closing_transaction)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::chan_utils::ClosingTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((closing_tx as *const lightning::ln::chan_utils::ClosingTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_anchor_input(&self, mut anchor_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_holder_anchor_input)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(anchor_tx), input);
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_channel_announcement_with_funding_key(&self, mut msg: &lightning::ln::msgs::UnsignedChannelAnnouncement, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_channel_announcement_with_funding_key)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::msgs::UnsignedChannelAnnouncement { inner: unsafe { ObjOps::nonnull_ptr_to_inner((msg as *const lightning::ln::msgs::UnsignedChannelAnnouncement<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}
impl lightning::sign::ChannelSigner for WriteableEcdsaChannelSigner {
	fn get_per_commitment_point(&self, mut idx: u64, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> bitcoin::secp256k1::PublicKey {
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.get_per_commitment_point)(self.EcdsaChannelSigner.ChannelSigner.this_arg, idx);
		ret.into_rust()
	}
	fn release_commitment_secret(&self, mut idx: u64) -> [u8; 32] {
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.release_commitment_secret)(self.EcdsaChannelSigner.ChannelSigner.this_arg, idx);
		ret.data
	}
	fn validate_holder_commitment(&self, mut holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut outbound_htlc_preimages: Vec<lightning::ln::PaymentPreimage>) -> Result<(), ()> {
		let mut local_outbound_htlc_preimages = Vec::new(); for mut item in outbound_htlc_preimages.drain(..) { local_outbound_htlc_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.validate_holder_commitment)(self.EcdsaChannelSigner.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((holder_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false }, local_outbound_htlc_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn validate_counterparty_revocation(&self, mut idx: u64, mut secret: &bitcoin::secp256k1::SecretKey) -> Result<(), ()> {
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.validate_counterparty_revocation)(self.EcdsaChannelSigner.ChannelSigner.this_arg, idx, secret.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
		if let Some(f) = self.EcdsaChannelSigner.ChannelSigner.set_pubkeys {
			(f)(&self.EcdsaChannelSigner.ChannelSigner);
		}
		unsafe { &*self.EcdsaChannelSigner.ChannelSigner.pubkeys.get() }.get_native_ref()
	}
	fn channel_keys_id(&self) -> [u8; 32] {
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.channel_keys_id)(self.EcdsaChannelSigner.ChannelSigner.this_arg);
		ret.data
	}
	fn provide_channel_parameters(&mut self, mut channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters) {
		(self.EcdsaChannelSigner.ChannelSigner.provide_channel_parameters)(self.EcdsaChannelSigner.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::ChannelTransactionParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((channel_parameters as *const lightning::ln::chan_utils::ChannelTransactionParameters<>) as *mut _) }, is_owned: false })
	}
}
impl lightning::util::ser::Writeable for WriteableEcdsaChannelSigner {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}
#[no_mangle]
/// Creates a copy of a WriteableEcdsaChannelSigner
pub extern "C" fn WriteableEcdsaChannelSigner_clone(orig: &WriteableEcdsaChannelSigner) -> WriteableEcdsaChannelSigner {
	let mut res = WriteableEcdsaChannelSigner_clone_fields(orig);
	if let Some(f) = orig.cloned { (f)(&mut res) };
	res
}
impl Clone for WriteableEcdsaChannelSigner {
	fn clone(&self) -> Self {
		WriteableEcdsaChannelSigner_clone(self)
	}
}

use lightning::sign::ecdsa::WriteableEcdsaChannelSigner as rustWriteableEcdsaChannelSigner;
impl rustWriteableEcdsaChannelSigner for WriteableEcdsaChannelSigner {
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for WriteableEcdsaChannelSigner {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
impl core::ops::DerefMut for WriteableEcdsaChannelSigner {
	fn deref_mut(&mut self) -> &mut Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn WriteableEcdsaChannelSigner_free(this_ptr: WriteableEcdsaChannelSigner) { }
impl Drop for WriteableEcdsaChannelSigner {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
