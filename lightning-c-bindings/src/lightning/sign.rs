// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Provides keys to LDK and defines some useful objects describing spendable on-chain outputs.
//!
//! The provided output descriptors follow a custom LDK data format and are currently not fully
//! compatible with Bitcoin Core output descriptors.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};


use lightning::sign::DelayedPaymentOutputDescriptor as nativeDelayedPaymentOutputDescriptorImport;
pub(crate) type nativeDelayedPaymentOutputDescriptor = nativeDelayedPaymentOutputDescriptorImport;

/// Information about a spendable output to a P2WSH script.
///
/// See [`SpendableOutputDescriptor::DelayedPaymentOutput`] for more details on how to spend this.
#[must_use]
#[repr(C)]
pub struct DelayedPaymentOutputDescriptor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeDelayedPaymentOutputDescriptor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for DelayedPaymentOutputDescriptor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeDelayedPaymentOutputDescriptor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the DelayedPaymentOutputDescriptor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_free(this_obj: DelayedPaymentOutputDescriptor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentOutputDescriptor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeDelayedPaymentOutputDescriptor) };
}
#[allow(unused)]
impl DelayedPaymentOutputDescriptor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeDelayedPaymentOutputDescriptor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeDelayedPaymentOutputDescriptor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeDelayedPaymentOutputDescriptor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The outpoint which is spendable.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_outpoint(this_ptr: &DelayedPaymentOutputDescriptor) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::lightning::chain::transaction::OutPoint { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::chain::transaction::OutPoint<>) as *mut _) }, is_owned: false }
}
/// The outpoint which is spendable.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_outpoint(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = *unsafe { Box::from_raw(val.take_inner()) };
}
/// Per commitment point to derive the delayed payment key by key holder.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_per_commitment_point(this_ptr: &DelayedPaymentOutputDescriptor) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().per_commitment_point;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// Per commitment point to derive the delayed payment key by key holder.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_per_commitment_point(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.per_commitment_point = val.into_rust();
}
/// The `nSequence` value which must be set in the spending input to satisfy the `OP_CSV` in
/// the witness_script.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_to_self_delay(this_ptr: &DelayedPaymentOutputDescriptor) -> u16 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().to_self_delay;
	*inner_val
}
/// The `nSequence` value which must be set in the spending input to satisfy the `OP_CSV` in
/// the witness_script.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_to_self_delay(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: u16) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.to_self_delay = val;
}
/// The output which is referenced by the given outpoint.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_output(this_ptr: &DelayedPaymentOutputDescriptor) -> crate::c_types::TxOut {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().output;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The output which is referenced by the given outpoint.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_output(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.output = val.into_rust();
}
/// The revocation point specific to the commitment transaction which was broadcast. Used to
/// derive the witnessScript for this output.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_revocation_pubkey(this_ptr: &DelayedPaymentOutputDescriptor) -> crate::c_types::PublicKey {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().revocation_pubkey;
	crate::c_types::PublicKey::from_rust(&inner_val)
}
/// The revocation point specific to the commitment transaction which was broadcast. Used to
/// derive the witnessScript for this output.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_revocation_pubkey(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: crate::c_types::PublicKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.revocation_pubkey = val.into_rust();
}
/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
/// This may be useful in re-deriving keys used in the channel to spend the output.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_channel_keys_id(this_ptr: &DelayedPaymentOutputDescriptor) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_keys_id;
	inner_val
}
/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
/// This may be useful in re-deriving keys used in the channel to spend the output.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_channel_keys_id(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_keys_id = val.data;
}
/// The value of the channel which this output originated from, possibly indirectly.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_get_channel_value_satoshis(this_ptr: &DelayedPaymentOutputDescriptor) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_value_satoshis;
	*inner_val
}
/// The value of the channel which this output originated from, possibly indirectly.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_set_channel_value_satoshis(this_ptr: &mut DelayedPaymentOutputDescriptor, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_value_satoshis = val;
}
/// Constructs a new DelayedPaymentOutputDescriptor given each field
#[must_use]
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut per_commitment_point_arg: crate::c_types::PublicKey, mut to_self_delay_arg: u16, mut output_arg: crate::c_types::TxOut, mut revocation_pubkey_arg: crate::c_types::PublicKey, mut channel_keys_id_arg: crate::c_types::ThirtyTwoBytes, mut channel_value_satoshis_arg: u64) -> DelayedPaymentOutputDescriptor {
	DelayedPaymentOutputDescriptor { inner: ObjOps::heap_alloc(nativeDelayedPaymentOutputDescriptor {
		outpoint: *unsafe { Box::from_raw(outpoint_arg.take_inner()) },
		per_commitment_point: per_commitment_point_arg.into_rust(),
		to_self_delay: to_self_delay_arg,
		output: output_arg.into_rust(),
		revocation_pubkey: revocation_pubkey_arg.into_rust(),
		channel_keys_id: channel_keys_id_arg.data,
		channel_value_satoshis: channel_value_satoshis_arg,
	}), is_owned: true }
}
impl Clone for DelayedPaymentOutputDescriptor {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeDelayedPaymentOutputDescriptor>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn DelayedPaymentOutputDescriptor_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeDelayedPaymentOutputDescriptor)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the DelayedPaymentOutputDescriptor
pub extern "C" fn DelayedPaymentOutputDescriptor_clone(orig: &DelayedPaymentOutputDescriptor) -> DelayedPaymentOutputDescriptor {
	orig.clone()
}
/// Checks if two DelayedPaymentOutputDescriptors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn DelayedPaymentOutputDescriptor_eq(a: &DelayedPaymentOutputDescriptor, b: &DelayedPaymentOutputDescriptor) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the DelayedPaymentOutputDescriptor object into a byte array which can be read by DelayedPaymentOutputDescriptor_read
pub extern "C" fn DelayedPaymentOutputDescriptor_write(obj: &crate::lightning::sign::DelayedPaymentOutputDescriptor) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn DelayedPaymentOutputDescriptor_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeDelayedPaymentOutputDescriptor) })
}
#[no_mangle]
/// Read a DelayedPaymentOutputDescriptor from a byte array, created by DelayedPaymentOutputDescriptor_write
pub extern "C" fn DelayedPaymentOutputDescriptor_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	let res: Result<lightning::sign::DelayedPaymentOutputDescriptor, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::sign::DelayedPaymentOutputDescriptor { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::sign::StaticPaymentOutputDescriptor as nativeStaticPaymentOutputDescriptorImport;
pub(crate) type nativeStaticPaymentOutputDescriptor = nativeStaticPaymentOutputDescriptorImport;

/// Information about a spendable output to our \"payment key\".
///
/// See [`SpendableOutputDescriptor::StaticPaymentOutput`] for more details on how to spend this.
#[must_use]
#[repr(C)]
pub struct StaticPaymentOutputDescriptor {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeStaticPaymentOutputDescriptor,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for StaticPaymentOutputDescriptor {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeStaticPaymentOutputDescriptor>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the StaticPaymentOutputDescriptor, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_free(this_obj: StaticPaymentOutputDescriptor) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticPaymentOutputDescriptor_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeStaticPaymentOutputDescriptor) };
}
#[allow(unused)]
impl StaticPaymentOutputDescriptor {
	pub(crate) fn get_native_ref(&self) -> &'static nativeStaticPaymentOutputDescriptor {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeStaticPaymentOutputDescriptor {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeStaticPaymentOutputDescriptor {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The outpoint which is spendable.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_get_outpoint(this_ptr: &StaticPaymentOutputDescriptor) -> crate::lightning::chain::transaction::OutPoint {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().outpoint;
	crate::lightning::chain::transaction::OutPoint { inner: unsafe { ObjOps::nonnull_ptr_to_inner((inner_val as *const lightning::chain::transaction::OutPoint<>) as *mut _) }, is_owned: false }
}
/// The outpoint which is spendable.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_set_outpoint(this_ptr: &mut StaticPaymentOutputDescriptor, mut val: crate::lightning::chain::transaction::OutPoint) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.outpoint = *unsafe { Box::from_raw(val.take_inner()) };
}
/// The output which is referenced by the given outpoint.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_get_output(this_ptr: &StaticPaymentOutputDescriptor) -> crate::c_types::TxOut {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().output;
	crate::c_types::TxOut::from_rust(inner_val)
}
/// The output which is referenced by the given outpoint.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_set_output(this_ptr: &mut StaticPaymentOutputDescriptor, mut val: crate::c_types::TxOut) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.output = val.into_rust();
}
/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
/// This may be useful in re-deriving keys used in the channel to spend the output.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_get_channel_keys_id(this_ptr: &StaticPaymentOutputDescriptor) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_keys_id;
	inner_val
}
/// Arbitrary identification information returned by a call to [`ChannelSigner::channel_keys_id`].
/// This may be useful in re-deriving keys used in the channel to spend the output.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_set_channel_keys_id(this_ptr: &mut StaticPaymentOutputDescriptor, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_keys_id = val.data;
}
/// The value of the channel which this transactions spends.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_get_channel_value_satoshis(this_ptr: &StaticPaymentOutputDescriptor) -> u64 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().channel_value_satoshis;
	*inner_val
}
/// The value of the channel which this transactions spends.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_set_channel_value_satoshis(this_ptr: &mut StaticPaymentOutputDescriptor, mut val: u64) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.channel_value_satoshis = val;
}
/// Constructs a new StaticPaymentOutputDescriptor given each field
#[must_use]
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_new(mut outpoint_arg: crate::lightning::chain::transaction::OutPoint, mut output_arg: crate::c_types::TxOut, mut channel_keys_id_arg: crate::c_types::ThirtyTwoBytes, mut channel_value_satoshis_arg: u64) -> StaticPaymentOutputDescriptor {
	StaticPaymentOutputDescriptor { inner: ObjOps::heap_alloc(nativeStaticPaymentOutputDescriptor {
		outpoint: *unsafe { Box::from_raw(outpoint_arg.take_inner()) },
		output: output_arg.into_rust(),
		channel_keys_id: channel_keys_id_arg.data,
		channel_value_satoshis: channel_value_satoshis_arg,
	}), is_owned: true }
}
impl Clone for StaticPaymentOutputDescriptor {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeStaticPaymentOutputDescriptor>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn StaticPaymentOutputDescriptor_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeStaticPaymentOutputDescriptor)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the StaticPaymentOutputDescriptor
pub extern "C" fn StaticPaymentOutputDescriptor_clone(orig: &StaticPaymentOutputDescriptor) -> StaticPaymentOutputDescriptor {
	orig.clone()
}
/// Checks if two StaticPaymentOutputDescriptors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
/// Two objects with NULL inner values will be considered "equal" here.
#[no_mangle]
pub extern "C" fn StaticPaymentOutputDescriptor_eq(a: &StaticPaymentOutputDescriptor, b: &StaticPaymentOutputDescriptor) -> bool {
	if a.inner == b.inner { return true; }
	if a.inner.is_null() || b.inner.is_null() { return false; }
	if a.get_native_ref() == b.get_native_ref() { true } else { false }
}
#[no_mangle]
/// Serialize the StaticPaymentOutputDescriptor object into a byte array which can be read by StaticPaymentOutputDescriptor_read
pub extern "C" fn StaticPaymentOutputDescriptor_write(obj: &crate::lightning::sign::StaticPaymentOutputDescriptor) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn StaticPaymentOutputDescriptor_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeStaticPaymentOutputDescriptor) })
}
#[no_mangle]
/// Read a StaticPaymentOutputDescriptor from a byte array, created by StaticPaymentOutputDescriptor_write
pub extern "C" fn StaticPaymentOutputDescriptor_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	let res: Result<lightning::sign::StaticPaymentOutputDescriptor, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::sign::StaticPaymentOutputDescriptor { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Describes the necessary information to spend a spendable output.
///
/// When on-chain outputs are created by LDK (which our counterparty is not able to claim at any
/// point in the future) a [`SpendableOutputs`] event is generated which you must track and be able
/// to spend on-chain. The information needed to do this is provided in this enum, including the
/// outpoint describing which `txid` and output `index` is available, the full output which exists
/// at that `txid`/`index`, and any keys or other information required to sign.
///
/// [`SpendableOutputs`]: crate::events::Event::SpendableOutputs
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum SpendableOutputDescriptor {
	/// An output to a script which was provided via [`SignerProvider`] directly, either from
	/// [`get_destination_script`] or [`get_shutdown_scriptpubkey`], thus you should already
	/// know how to spend it. No secret keys are provided as LDK was never given any key.
	/// These may include outputs from a transaction punishing our counterparty or claiming an HTLC
	/// on-chain using the payment preimage or after it has timed out.
	///
	/// [`get_shutdown_scriptpubkey`]: SignerProvider::get_shutdown_scriptpubkey
	/// [`get_destination_script`]: SignerProvider::get_shutdown_scriptpubkey
	StaticOutput {
		/// The outpoint which is spendable.
		outpoint: crate::lightning::chain::transaction::OutPoint,
		/// The output which is referenced by the given outpoint.
		output: crate::c_types::TxOut,
	},
	/// An output to a P2WSH script which can be spent with a single signature after an `OP_CSV`
	/// delay.
	///
	/// The witness in the spending input should be:
	/// ```bitcoin
	/// <BIP 143 signature> <empty vector> (MINIMALIF standard rule) <provided witnessScript>
	/// ```
	///
	/// Note that the `nSequence` field in the spending input must be set to
	/// [`DelayedPaymentOutputDescriptor::to_self_delay`] (which means the transaction is not
	/// broadcastable until at least [`DelayedPaymentOutputDescriptor::to_self_delay`] blocks after
	/// the outpoint confirms, see [BIP
	/// 68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)). Also note that LDK
	/// won't generate a [`SpendableOutputDescriptor`] until the corresponding block height
	/// is reached.
	///
	/// These are generally the result of a \"revocable\" output to us, spendable only by us unless
	/// it is an output from an old state which we broadcast (which should never happen).
	///
	/// To derive the delayed payment key which is used to sign this input, you must pass the
	/// holder [`InMemorySigner::delayed_payment_base_key`] (i.e., the private key which corresponds to the
	/// [`ChannelPublicKeys::delayed_payment_basepoint`] in [`ChannelSigner::pubkeys`]) and the provided
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to [`chan_utils::derive_private_key`]. The public key can be
	/// generated without the secret key using [`chan_utils::derive_public_key`] and only the
	/// [`ChannelPublicKeys::delayed_payment_basepoint`] which appears in [`ChannelSigner::pubkeys`].
	///
	/// To derive the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] provided here (which is
	/// used in the witness script generation), you must pass the counterparty
	/// [`ChannelPublicKeys::revocation_basepoint`] (which appears in the call to
	/// [`ChannelSigner::provide_channel_parameters`]) and the provided
	/// [`DelayedPaymentOutputDescriptor::per_commitment_point`] to
	/// [`chan_utils::derive_public_revocation_key`].
	///
	/// The witness script which is hashed and included in the output `script_pubkey` may be
	/// regenerated by passing the [`DelayedPaymentOutputDescriptor::revocation_pubkey`] (derived
	/// as explained above), our delayed payment pubkey (derived as explained above), and the
	/// [`DelayedPaymentOutputDescriptor::to_self_delay`] contained here to
	/// [`chan_utils::get_revokeable_redeemscript`].
	DelayedPaymentOutput(
		crate::lightning::sign::DelayedPaymentOutputDescriptor),
	/// An output to a P2WPKH, spendable exclusively by our payment key (i.e., the private key
	/// which corresponds to the `payment_point` in [`ChannelSigner::pubkeys`]). The witness
	/// in the spending input is, thus, simply:
	/// ```bitcoin
	/// <BIP 143 signature> <payment key>
	/// ```
	///
	/// These are generally the result of our counterparty having broadcast the current state,
	/// allowing us to claim the non-HTLC-encumbered outputs immediately.
	StaticPaymentOutput(
		crate::lightning::sign::StaticPaymentOutputDescriptor),
}
use lightning::sign::SpendableOutputDescriptor as SpendableOutputDescriptorImport;
pub(crate) type nativeSpendableOutputDescriptor = SpendableOutputDescriptorImport;

impl SpendableOutputDescriptor {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeSpendableOutputDescriptor {
		match self {
			SpendableOutputDescriptor::StaticOutput {ref outpoint, ref output, } => {
				let mut outpoint_nonref = Clone::clone(outpoint);
				let mut output_nonref = Clone::clone(output);
				nativeSpendableOutputDescriptor::StaticOutput {
					outpoint: *unsafe { Box::from_raw(outpoint_nonref.take_inner()) },
					output: output_nonref.into_rust(),
				}
			},
			SpendableOutputDescriptor::DelayedPaymentOutput (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSpendableOutputDescriptor::DelayedPaymentOutput (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			SpendableOutputDescriptor::StaticPaymentOutput (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				nativeSpendableOutputDescriptor::StaticPaymentOutput (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeSpendableOutputDescriptor {
		match self {
			SpendableOutputDescriptor::StaticOutput {mut outpoint, mut output, } => {
				nativeSpendableOutputDescriptor::StaticOutput {
					outpoint: *unsafe { Box::from_raw(outpoint.take_inner()) },
					output: output.into_rust(),
				}
			},
			SpendableOutputDescriptor::DelayedPaymentOutput (mut a, ) => {
				nativeSpendableOutputDescriptor::DelayedPaymentOutput (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			SpendableOutputDescriptor::StaticPaymentOutput (mut a, ) => {
				nativeSpendableOutputDescriptor::StaticPaymentOutput (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeSpendableOutputDescriptor) -> Self {
		match native {
			nativeSpendableOutputDescriptor::StaticOutput {ref outpoint, ref output, } => {
				let mut outpoint_nonref = Clone::clone(outpoint);
				let mut output_nonref = Clone::clone(output);
				SpendableOutputDescriptor::StaticOutput {
					outpoint: crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(outpoint_nonref), is_owned: true },
					output: crate::c_types::TxOut::from_rust(&output_nonref),
				}
			},
			nativeSpendableOutputDescriptor::DelayedPaymentOutput (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SpendableOutputDescriptor::DelayedPaymentOutput (
					crate::lightning::sign::DelayedPaymentOutputDescriptor { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeSpendableOutputDescriptor::StaticPaymentOutput (ref a, ) => {
				let mut a_nonref = Clone::clone(a);
				SpendableOutputDescriptor::StaticPaymentOutput (
					crate::lightning::sign::StaticPaymentOutputDescriptor { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeSpendableOutputDescriptor) -> Self {
		match native {
			nativeSpendableOutputDescriptor::StaticOutput {mut outpoint, mut output, } => {
				SpendableOutputDescriptor::StaticOutput {
					outpoint: crate::lightning::chain::transaction::OutPoint { inner: ObjOps::heap_alloc(outpoint), is_owned: true },
					output: crate::c_types::TxOut::from_rust(&output),
				}
			},
			nativeSpendableOutputDescriptor::DelayedPaymentOutput (mut a, ) => {
				SpendableOutputDescriptor::DelayedPaymentOutput (
					crate::lightning::sign::DelayedPaymentOutputDescriptor { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeSpendableOutputDescriptor::StaticPaymentOutput (mut a, ) => {
				SpendableOutputDescriptor::StaticPaymentOutput (
					crate::lightning::sign::StaticPaymentOutputDescriptor { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the SpendableOutputDescriptor
#[no_mangle]
pub extern "C" fn SpendableOutputDescriptor_free(this_ptr: SpendableOutputDescriptor) { }
/// Creates a copy of the SpendableOutputDescriptor
#[no_mangle]
pub extern "C" fn SpendableOutputDescriptor_clone(orig: &SpendableOutputDescriptor) -> SpendableOutputDescriptor {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new StaticOutput-variant SpendableOutputDescriptor
pub extern "C" fn SpendableOutputDescriptor_static_output(outpoint: crate::lightning::chain::transaction::OutPoint, output: crate::c_types::TxOut) -> SpendableOutputDescriptor {
	SpendableOutputDescriptor::StaticOutput {
		outpoint,
		output,
	}
}
#[no_mangle]
/// Utility method to constructs a new DelayedPaymentOutput-variant SpendableOutputDescriptor
pub extern "C" fn SpendableOutputDescriptor_delayed_payment_output(a: crate::lightning::sign::DelayedPaymentOutputDescriptor) -> SpendableOutputDescriptor {
	SpendableOutputDescriptor::DelayedPaymentOutput(a, )
}
#[no_mangle]
/// Utility method to constructs a new StaticPaymentOutput-variant SpendableOutputDescriptor
pub extern "C" fn SpendableOutputDescriptor_static_payment_output(a: crate::lightning::sign::StaticPaymentOutputDescriptor) -> SpendableOutputDescriptor {
	SpendableOutputDescriptor::StaticPaymentOutput(a, )
}
/// Checks if two SpendableOutputDescriptors contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn SpendableOutputDescriptor_eq(a: &SpendableOutputDescriptor, b: &SpendableOutputDescriptor) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
#[no_mangle]
/// Serialize the SpendableOutputDescriptor object into a byte array which can be read by SpendableOutputDescriptor_read
pub extern "C" fn SpendableOutputDescriptor_write(obj: &crate::lightning::sign::SpendableOutputDescriptor) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(&unsafe { &*obj }.to_native())
}
#[no_mangle]
/// Read a SpendableOutputDescriptor from a byte array, created by SpendableOutputDescriptor_write
pub extern "C" fn SpendableOutputDescriptor_read(ser: crate::c_types::u8slice) -> crate::c_types::derived::CResult_SpendableOutputDescriptorDecodeErrorZ {
	let res: Result<lightning::sign::SpendableOutputDescriptor, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj(ser);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::sign::SpendableOutputDescriptor::native_into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}
/// Creates an unsigned [`PartiallySignedTransaction`] which spends the given descriptors to
/// the given outputs, plus an output to the given change destination (if sufficient
/// change value remains). The PSBT will have a feerate, at least, of the given value.
///
/// The `locktime` argument is used to set the transaction's locktime. If `None`, the
/// transaction will have a locktime of 0. It it recommended to set this to the current block
/// height to avoid fee sniping, unless you have some specific reason to use a different
/// locktime.
///
/// Returns the PSBT and expected max transaction weight.
///
/// Returns `Err(())` if the output value is greater than the input value minus required fee,
/// if a descriptor was duplicated, or if an output descriptor `script_pubkey`
/// does not match the one we can spend.
///
/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
#[must_use]
#[no_mangle]
pub extern "C" fn SpendableOutputDescriptor_create_spendable_outputs_psbt(mut descriptors: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, mut outputs: crate::c_types::derived::CVec_TxOutZ, mut change_destination_script: crate::c_types::derived::CVec_u8Z, mut feerate_sat_per_1000_weight: u32, mut locktime: crate::c_types::derived::COption_PackedLockTimeZ) -> crate::c_types::derived::CResult_C2Tuple_PartiallySignedTransactionusizeZNoneZ {
	let mut local_descriptors = Vec::new(); for mut item in descriptors.into_rust().drain(..) { local_descriptors.push( { item.into_native() }); };
	let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_rust() }); };
	let mut local_locktime = { /*locktime*/ let locktime_opt = locktime; if locktime_opt.is_none() { None } else { Some({ { ::bitcoin::PackedLockTime({ locktime_opt.take() }) }})} };
	let mut ret = lightning::sign::SpendableOutputDescriptor::create_spendable_outputs_psbt(&local_descriptors.iter().collect::<Vec<_>>()[..], local_outputs, ::bitcoin::blockdata::script::Script::from(change_destination_script.into_rust()), feerate_sat_per_1000_weight, local_locktime);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_ret_0 = (::bitcoin::consensus::encode::serialize(&orig_ret_0_0).into(), orig_ret_0_1).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// A trait to handle Lightning channel key material without concretizing the channel type or
/// the signature mechanism.
#[repr(C)]
pub struct ChannelSigner {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets the per-commitment point for a specific commitment number
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	pub get_per_commitment_point: extern "C" fn (this_arg: *const c_void, idx: u64) -> crate::c_types::PublicKey,
	/// Gets the commitment secret for a specific commitment number as part of the revocation process
	///
	/// An external signer implementation should error here if the commitment was already signed
	/// and should refuse to sign it in the future.
	///
	/// May be called more than once for the same index.
	///
	/// Note that the commitment number starts at `(1 << 48) - 1` and counts backwards.
	pub release_commitment_secret: extern "C" fn (this_arg: *const c_void, idx: u64) -> crate::c_types::ThirtyTwoBytes,
	/// Validate the counterparty's signatures on the holder commitment transaction and HTLCs.
	///
	/// This is required in order for the signer to make sure that releasing a commitment
	/// secret won't leave us without a broadcastable holder transaction.
	/// Policy checks should be implemented in this function, including checking the amount
	/// sent to us and checking the HTLCs.
	///
	/// The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	/// A validating signer should ensure that an HTLC output is removed only when the matching
	/// preimage is provided, or when the value to holder is restored.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	pub validate_holder_commitment: extern "C" fn (this_arg: *const c_void, holder_tx: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction, preimages: crate::c_types::derived::CVec_PaymentPreimageZ) -> crate::c_types::derived::CResult_NoneNoneZ,
	/// Returns the holder's channel public keys and basepoints.
	pub pubkeys: core::cell::UnsafeCell<crate::lightning::ln::chan_utils::ChannelPublicKeys>,
	/// Fill in the pubkeys field as a reference to it will be given to Rust after this returns
	/// Note that this takes a pointer to this object, not the this_ptr like other methods do
	/// This function pointer may be NULL if pubkeys is filled in when this object is created and never needs updating.
	pub set_pubkeys: Option<extern "C" fn(&ChannelSigner)>,
	/// Returns an arbitrary identifier describing the set of keys which are provided back to you in
	/// some [`SpendableOutputDescriptor`] types. This should be sufficient to identify this
	/// [`EcdsaChannelSigner`] object uniquely and lookup or re-derive its keys.
	pub channel_keys_id: extern "C" fn (this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes,
	/// Set the counterparty static channel data, including basepoints,
	/// `counterparty_selected`/`holder_selected_contest_delay` and funding outpoint.
	///
	/// This data is static, and will never change for a channel once set. For a given [`ChannelSigner`]
	/// instance, LDK will call this method exactly once - either immediately after construction
	/// (not including if done via [`SignerProvider::read_chan_signer`]) or when the funding
	/// information has been generated.
	///
	/// channel_parameters.is_populated() MUST be true.
	pub provide_channel_parameters: extern "C" fn (this_arg: *mut c_void, channel_parameters: &crate::lightning::ln::chan_utils::ChannelTransactionParameters),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for ChannelSigner {}
unsafe impl Sync for ChannelSigner {}
#[no_mangle]
pub(crate) extern "C" fn ChannelSigner_clone_fields(orig: &ChannelSigner) -> ChannelSigner {
	ChannelSigner {
		this_arg: orig.this_arg,
		get_per_commitment_point: Clone::clone(&orig.get_per_commitment_point),
		release_commitment_secret: Clone::clone(&orig.release_commitment_secret),
		validate_holder_commitment: Clone::clone(&orig.validate_holder_commitment),
		pubkeys: Clone::clone(unsafe { &*core::cell::UnsafeCell::get(&orig.pubkeys)}).into(),
		set_pubkeys: Clone::clone(&orig.set_pubkeys),
		channel_keys_id: Clone::clone(&orig.channel_keys_id),
		provide_channel_parameters: Clone::clone(&orig.provide_channel_parameters),
		free: Clone::clone(&orig.free),
	}
}

use lightning::sign::ChannelSigner as rustChannelSigner;
impl rustChannelSigner for ChannelSigner {
	fn get_per_commitment_point(&self, mut idx: u64, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> bitcoin::secp256k1::PublicKey {
		let mut ret = (self.get_per_commitment_point)(self.this_arg, idx);
		ret.into_rust()
	}
	fn release_commitment_secret(&self, mut idx: u64) -> [u8; 32] {
		let mut ret = (self.release_commitment_secret)(self.this_arg, idx);
		ret.data
	}
	fn validate_holder_commitment(&self, mut holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut preimages: Vec<lightning::ln::PaymentPreimage>) -> Result<(), ()> {
		let mut local_preimages = Vec::new(); for mut item in preimages.drain(..) { local_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.validate_holder_commitment)(self.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((holder_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false }, local_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn pubkeys(&self) -> &lightning::ln::chan_utils::ChannelPublicKeys {
		if let Some(f) = self.set_pubkeys {
			(f)(&self);
		}
		unsafe { &*self.pubkeys.get() }.get_native_ref()
	}
	fn channel_keys_id(&self) -> [u8; 32] {
		let mut ret = (self.channel_keys_id)(self.this_arg);
		ret.data
	}
	fn provide_channel_parameters(&mut self, mut channel_parameters: &lightning::ln::chan_utils::ChannelTransactionParameters) {
		(self.provide_channel_parameters)(self.this_arg, &crate::lightning::ln::chan_utils::ChannelTransactionParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((channel_parameters as *const lightning::ln::chan_utils::ChannelTransactionParameters<>) as *mut _) }, is_owned: false })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for ChannelSigner {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn ChannelSigner_free(this_ptr: ChannelSigner) { }
impl Drop for ChannelSigner {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
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
	/// The preimages of outgoing HTLCs that were fulfilled since the last commitment are provided.
	/// A validating signer should ensure that an HTLC output is removed only when the matching
	/// preimage is provided, or when the value to holder is restored.
	///
	/// Note that all the relevant preimages will be provided, but there may also be additional
	/// irrelevant or duplicate preimages.
	pub sign_counterparty_commitment: extern "C" fn (this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::CommitmentTransaction, preimages: crate::c_types::derived::CVec_PaymentPreimageZ) -> crate::c_types::derived::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ,
	/// Validate the counterparty's revocation.
	///
	/// This is required in order for the signer to make sure that the state has moved
	/// forward and it is safe to sign the next counterparty commitment.
	pub validate_counterparty_revocation: extern "C" fn (this_arg: *const c_void, idx: u64, secret: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneNoneZ,
	/// Creates a signature for a holder's commitment transaction and its claiming HTLC transactions.
	///
	/// This will be called
	/// - with a non-revoked `commitment_tx`.
	/// - with the latest `commitment_tx` when we initiate a force-close.
	/// - with the previous `commitment_tx`, just to get claiming HTLC
	///   signatures, if we are reacting to a [`ChannelMonitor`]
	///   [replica](https://github.com/lightningdevkit/rust-lightning/blob/main/GLOSSARY.md#monitor-replicas)
	///   that decided to broadcast before it had been updated to the latest `commitment_tx`.
	///
	/// This may be called multiple times for the same transaction.
	///
	/// An external signer implementation should check that the commitment has not been revoked.
	///
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	pub sign_holder_commitment_and_htlcs: extern "C" fn (this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction) -> crate::c_types::derived::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ,
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
	pub sign_justice_revoked_output: extern "C" fn (this_arg: *const c_void, justice_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_key: *const [u8; 32]) -> crate::c_types::derived::CResult_SignatureNoneZ,
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
	pub sign_justice_revoked_htlc: extern "C" fn (this_arg: *const c_void, justice_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_key: *const [u8; 32], htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Computes the signature for a commitment transaction's HTLC output used as an input within
	/// `htlc_tx`, which spends the commitment transaction at index `input`. The signature returned
	/// must be be computed using [`EcdsaSighashType::All`]. Note that this should only be used to
	/// sign HTLC transactions from channels supporting anchor outputs after all additional
	/// inputs/outputs have been added to the transaction.
	///
	/// [`EcdsaSighashType::All`]: bitcoin::blockdata::transaction::EcdsaSighashType::All
	pub sign_holder_htlc_transaction: extern "C" fn (this_arg: *const c_void, htlc_tx: crate::c_types::Transaction, input: usize, htlc_descriptor: &crate::lightning::events::bump_transaction::HTLCDescriptor) -> crate::c_types::derived::CResult_SignatureNoneZ,
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
	pub sign_counterparty_htlc_transaction: extern "C" fn (this_arg: *const c_void, htlc_tx: crate::c_types::Transaction, input: usize, amount: u64, per_commitment_point: crate::c_types::PublicKey, htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Create a signature for a (proposed) closing transaction.
	///
	/// Note that, due to rounding, there may be one \"missing\" satoshi, and either party may have
	/// chosen to forgo their output as dust.
	pub sign_closing_transaction: extern "C" fn (this_arg: *const c_void, closing_tx: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Computes the signature for a commitment transaction's anchor output used as an
	/// input within `anchor_tx`, which spends the commitment transaction, at index `input`.
	pub sign_holder_anchor_input: extern "C" fn (this_arg: *const c_void, anchor_tx: crate::c_types::Transaction, input: usize) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Signs a channel announcement message with our funding key proving it comes from one of the
	/// channel participants.
	///
	/// Channel announcements also require a signature from each node's network key. Our node
	/// signature is computed through [`NodeSigner::sign_gossip_message`].
	///
	/// Note that if this fails or is rejected, the channel will not be publicly announced and
	/// our counterparty may (though likely will not) close the channel on us for violating the
	/// protocol.
	pub sign_channel_announcement_with_funding_key: extern "C" fn (this_arg: *const c_void, msg: &crate::lightning::ln::msgs::UnsignedChannelAnnouncement) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Implementation of ChannelSigner for this object.
	pub ChannelSigner: crate::lightning::sign::ChannelSigner,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EcdsaChannelSigner {}
unsafe impl Sync for EcdsaChannelSigner {}
#[no_mangle]
pub(crate) extern "C" fn EcdsaChannelSigner_clone_fields(orig: &EcdsaChannelSigner) -> EcdsaChannelSigner {
	EcdsaChannelSigner {
		this_arg: orig.this_arg,
		sign_counterparty_commitment: Clone::clone(&orig.sign_counterparty_commitment),
		validate_counterparty_revocation: Clone::clone(&orig.validate_counterparty_revocation),
		sign_holder_commitment_and_htlcs: Clone::clone(&orig.sign_holder_commitment_and_htlcs),
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
	fn validate_holder_commitment(&self, mut holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut preimages: Vec<lightning::ln::PaymentPreimage>) -> Result<(), ()> {
		let mut local_preimages = Vec::new(); for mut item in preimages.drain(..) { local_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.ChannelSigner.validate_holder_commitment)(self.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((holder_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false }, local_preimages.into());
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

use lightning::sign::EcdsaChannelSigner as rustEcdsaChannelSigner;
impl rustEcdsaChannelSigner for EcdsaChannelSigner {
	fn sign_counterparty_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, mut preimages: Vec<lightning::ln::PaymentPreimage>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut local_preimages = Vec::new(); for mut item in preimages.drain(..) { local_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.sign_counterparty_commitment)(self.this_arg, &crate::lightning::ln::chan_utils::CommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::CommitmentTransaction<>) as *mut _) }, is_owned: false }, local_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn validate_counterparty_revocation(&self, mut idx: u64, mut secret: &bitcoin::secp256k1::SecretKey) -> Result<(), ()> {
		let mut ret = (self.validate_counterparty_revocation)(self.this_arg, idx, secret.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_commitment_and_htlcs(&self, mut commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut ret = (self.sign_holder_commitment_and_htlcs)(self.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
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
	fn sign_holder_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut htlc_descriptor: &lightning::events::bump_transaction::HTLCDescriptor, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_holder_htlc_transaction)(self.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, &crate::lightning::events::bump_transaction::HTLCDescriptor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc_descriptor as *const lightning::events::bump_transaction::HTLCDescriptor<>) as *mut _) }, is_owned: false });
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
	pub EcdsaChannelSigner: crate::lightning::sign::EcdsaChannelSigner,
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for WriteableEcdsaChannelSigner {}
unsafe impl Sync for WriteableEcdsaChannelSigner {}
#[no_mangle]
pub(crate) extern "C" fn WriteableEcdsaChannelSigner_clone_fields(orig: &WriteableEcdsaChannelSigner) -> WriteableEcdsaChannelSigner {
	WriteableEcdsaChannelSigner {
		this_arg: orig.this_arg,
		EcdsaChannelSigner: crate::lightning::sign::EcdsaChannelSigner_clone_fields(&orig.EcdsaChannelSigner),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::sign::EcdsaChannelSigner for WriteableEcdsaChannelSigner {
	fn sign_counterparty_commitment(&self, mut commitment_tx: &lightning::ln::chan_utils::CommitmentTransaction, mut preimages: Vec<lightning::ln::PaymentPreimage>, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut local_preimages = Vec::new(); for mut item in preimages.drain(..) { local_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.EcdsaChannelSigner.sign_counterparty_commitment)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::chan_utils::CommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::CommitmentTransaction<>) as *mut _) }, is_owned: false }, local_preimages.into());
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn validate_counterparty_revocation(&self, mut idx: u64, mut secret: &bitcoin::secp256k1::SecretKey) -> Result<(), ()> {
		let mut ret = (self.EcdsaChannelSigner.validate_counterparty_revocation)(self.EcdsaChannelSigner.this_arg, idx, secret.as_ref());
		let mut local_ret = match ret.result_ok { true => Ok( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) })*/ }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_holder_commitment_and_htlcs(&self, mut commitment_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<(bitcoin::secp256k1::ecdsa::Signature, Vec<bitcoin::secp256k1::ecdsa::Signature>), ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_holder_commitment_and_htlcs)(self.EcdsaChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((commitment_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false });
		let mut local_ret = match ret.result_ok { true => Ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).to_rust(); let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.into_rust().drain(..) { local_orig_ret_0_1.push( { item.into_rust() }); }; let mut local_ret_0 = (orig_ret_0_0.into_rust(), local_orig_ret_0_1); local_ret_0 }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
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
	fn sign_holder_htlc_transaction(&self, mut htlc_tx: &bitcoin::blockdata::transaction::Transaction, mut input: usize, mut htlc_descriptor: &lightning::events::bump_transaction::HTLCDescriptor, mut _secp_ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.EcdsaChannelSigner.sign_holder_htlc_transaction)(self.EcdsaChannelSigner.this_arg, crate::c_types::Transaction::from_bitcoin(htlc_tx), input, &crate::lightning::events::bump_transaction::HTLCDescriptor { inner: unsafe { ObjOps::nonnull_ptr_to_inner((htlc_descriptor as *const lightning::events::bump_transaction::HTLCDescriptor<>) as *mut _) }, is_owned: false });
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
	fn validate_holder_commitment(&self, mut holder_tx: &lightning::ln::chan_utils::HolderCommitmentTransaction, mut preimages: Vec<lightning::ln::PaymentPreimage>) -> Result<(), ()> {
		let mut local_preimages = Vec::new(); for mut item in preimages.drain(..) { local_preimages.push( { crate::c_types::ThirtyTwoBytes { data: item.0 } }); };
		let mut ret = (self.EcdsaChannelSigner.ChannelSigner.validate_holder_commitment)(self.EcdsaChannelSigner.ChannelSigner.this_arg, &crate::lightning::ln::chan_utils::HolderCommitmentTransaction { inner: unsafe { ObjOps::nonnull_ptr_to_inner((holder_tx as *const lightning::ln::chan_utils::HolderCommitmentTransaction<>) as *mut _) }, is_owned: false }, local_preimages.into());
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

use lightning::sign::WriteableEcdsaChannelSigner as rustWriteableEcdsaChannelSigner;
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
/// Specifies the recipient of an invoice.
///
/// This indicates to [`NodeSigner::sign_invoice`] what node secret key should be used to sign
/// the invoice.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Recipient {
	/// The invoice should be signed with the local node secret key.
	Node,
	/// The invoice should be signed with the phantom node secret key. This secret key must be the
	/// same for all nodes participating in the [phantom node payment].
	///
	/// [phantom node payment]: PhantomKeysManager
	PhantomNode,
}
use lightning::sign::Recipient as RecipientImport;
pub(crate) type nativeRecipient = RecipientImport;

impl Recipient {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeRecipient {
		match self {
			Recipient::Node => nativeRecipient::Node,
			Recipient::PhantomNode => nativeRecipient::PhantomNode,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeRecipient {
		match self {
			Recipient::Node => nativeRecipient::Node,
			Recipient::PhantomNode => nativeRecipient::PhantomNode,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeRecipient) -> Self {
		match native {
			nativeRecipient::Node => Recipient::Node,
			nativeRecipient::PhantomNode => Recipient::PhantomNode,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeRecipient) -> Self {
		match native {
			nativeRecipient::Node => Recipient::Node,
			nativeRecipient::PhantomNode => Recipient::PhantomNode,
		}
	}
}
/// Creates a copy of the Recipient
#[no_mangle]
pub extern "C" fn Recipient_clone(orig: &Recipient) -> Recipient {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Node-variant Recipient
pub extern "C" fn Recipient_node() -> Recipient {
	Recipient::Node}
#[no_mangle]
/// Utility method to constructs a new PhantomNode-variant Recipient
pub extern "C" fn Recipient_phantom_node() -> Recipient {
	Recipient::PhantomNode}
/// A trait that describes a source of entropy.
#[repr(C)]
pub struct EntropySource {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Gets a unique, cryptographically-secure, random 32-byte value. This method must return a
	/// different value each time it is called.
	pub get_secure_random_bytes: extern "C" fn (this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for EntropySource {}
unsafe impl Sync for EntropySource {}
#[no_mangle]
pub(crate) extern "C" fn EntropySource_clone_fields(orig: &EntropySource) -> EntropySource {
	EntropySource {
		this_arg: orig.this_arg,
		get_secure_random_bytes: Clone::clone(&orig.get_secure_random_bytes),
		free: Clone::clone(&orig.free),
	}
}

use lightning::sign::EntropySource as rustEntropySource;
impl rustEntropySource for EntropySource {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut ret = (self.get_secure_random_bytes)(self.this_arg);
		ret.data
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for EntropySource {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn EntropySource_free(this_ptr: EntropySource) { }
impl Drop for EntropySource {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait that can handle cryptographic operations at the scope level of a node.
#[repr(C)]
pub struct NodeSigner {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Get secret key material as bytes for use in encrypting and decrypting inbound payment data.
	///
	/// If the implementor of this trait supports [phantom node payments], then every node that is
	/// intended to be included in the phantom invoice route hints must return the same value from
	/// this method.
	///
	/// This method must return the same value each time it is called.
	///
	/// [phantom node payments]: PhantomKeysManager
	pub get_inbound_payment_key_material: extern "C" fn (this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes,
	/// Get node id based on the provided [`Recipient`].
	///
	/// This method must return the same value each time it is called with a given [`Recipient`]
	/// parameter.
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	pub get_node_id: extern "C" fn (this_arg: *const c_void, recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_PublicKeyNoneZ,
	/// Gets the ECDH shared secret of our node secret and `other_key`, multiplying by `tweak` if
	/// one is provided. Note that this tweak can be applied to `other_key` instead of our node
	/// secret, though this is less efficient.
	///
	/// Note that if this fails while attempting to forward an HTLC, LDK will panic. The error
	/// should be resolved to allow LDK to resume forwarding HTLCs.
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	pub ecdh: extern "C" fn (this_arg: *const c_void, recipient: crate::lightning::sign::Recipient, other_key: crate::c_types::PublicKey, tweak: crate::c_types::derived::COption_ScalarZ) -> crate::c_types::derived::CResult_SharedSecretNoneZ,
	/// Sign an invoice.
	///
	/// By parameterizing by the raw invoice bytes instead of the hash, we allow implementors of
	/// this trait to parse the invoice and make sure they're signing what they expect, rather than
	/// blindly signing the hash.
	///
	/// The `hrp_bytes` are ASCII bytes, while the `invoice_data` is base32.
	///
	/// The secret key used to sign the invoice is dependent on the [`Recipient`].
	///
	/// Errors if the [`Recipient`] variant is not supported by the implementation.
	pub sign_invoice: extern "C" fn (this_arg: *const c_void, hrp_bytes: crate::c_types::u8slice, invoice_data: crate::c_types::derived::CVec_U5Z, recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_RecoverableSignatureNoneZ,
	/// Sign a gossip message.
	///
	/// Note that if this fails, LDK may panic and the message will not be broadcast to the network
	/// or a possible channel counterparty. If LDK panics, the error should be resolved to allow the
	/// message to be broadcast, as otherwise it may prevent one from receiving funds over the
	/// corresponding channel.
	pub sign_gossip_message: extern "C" fn (this_arg: *const c_void, msg: crate::lightning::ln::msgs::UnsignedGossipMessage) -> crate::c_types::derived::CResult_SignatureNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for NodeSigner {}
unsafe impl Sync for NodeSigner {}
#[no_mangle]
pub(crate) extern "C" fn NodeSigner_clone_fields(orig: &NodeSigner) -> NodeSigner {
	NodeSigner {
		this_arg: orig.this_arg,
		get_inbound_payment_key_material: Clone::clone(&orig.get_inbound_payment_key_material),
		get_node_id: Clone::clone(&orig.get_node_id),
		ecdh: Clone::clone(&orig.ecdh),
		sign_invoice: Clone::clone(&orig.sign_invoice),
		sign_gossip_message: Clone::clone(&orig.sign_gossip_message),
		free: Clone::clone(&orig.free),
	}
}

use lightning::sign::NodeSigner as rustNodeSigner;
impl rustNodeSigner for NodeSigner {
	fn get_inbound_payment_key_material(&self) -> lightning::sign::KeyMaterial {
		let mut ret = (self.get_inbound_payment_key_material)(self.this_arg);
		::lightning::sign::KeyMaterial(ret.data)
	}
	fn get_node_id(&self, mut recipient: lightning::sign::Recipient) -> Result<bitcoin::secp256k1::PublicKey, ()> {
		let mut ret = (self.get_node_id)(self.this_arg, crate::lightning::sign::Recipient::native_into(recipient));
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn ecdh(&self, mut recipient: lightning::sign::Recipient, mut other_key: &bitcoin::secp256k1::PublicKey, mut tweak: Option<&bitcoin::secp256k1::Scalar>) -> Result<bitcoin::secp256k1::ecdh::SharedSecret, ()> {
		let mut local_tweak = if tweak.is_none() { crate::c_types::derived::COption_ScalarZ::None } else { crate::c_types::derived::COption_ScalarZ::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */ { crate::c_types::BigEndianScalar::from_rust(&(*tweak.as_ref().unwrap()).clone()) }) };
		let mut ret = (self.ecdh)(self.this_arg, crate::lightning::sign::Recipient::native_into(recipient), crate::c_types::PublicKey::from_rust(&other_key), local_tweak);
		let mut local_ret = match ret.result_ok { true => Ok( { ::bitcoin::secp256k1::ecdh::SharedSecret::from_bytes((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).data) }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_invoice(&self, mut hrp_bytes: &[u8], mut invoice_data: &[bitcoin::bech32::u5], mut recipient: lightning::sign::Recipient) -> Result<bitcoin::secp256k1::ecdsa::RecoverableSignature, ()> {
		let mut local_hrp_bytes = crate::c_types::u8slice::from_slice(hrp_bytes);
		let mut local_invoice_data_clone = Vec::new(); local_invoice_data_clone.extend_from_slice(invoice_data); let mut invoice_data = local_invoice_data_clone; let mut local_invoice_data = Vec::new(); for mut item in invoice_data.drain(..) { local_invoice_data.push( { item.into() }); };
		let mut ret = (self.sign_invoice)(self.this_arg, local_hrp_bytes, local_invoice_data.into(), crate::lightning::sign::Recipient::native_into(recipient));
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn sign_gossip_message(&self, mut msg: lightning::ln::msgs::UnsignedGossipMessage) -> Result<bitcoin::secp256k1::ecdsa::Signature, ()> {
		let mut ret = (self.sign_gossip_message)(self.this_arg, crate::lightning::ln::msgs::UnsignedGossipMessage::native_into(msg));
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust() }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for NodeSigner {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn NodeSigner_free(this_ptr: NodeSigner) { }
impl Drop for NodeSigner {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
/// A trait that can return signer instances for individual channels.
#[repr(C)]
pub struct SignerProvider {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Generates a unique `channel_keys_id` that can be used to obtain a [`Self::Signer`] through
	/// [`SignerProvider::derive_channel_signer`]. The `user_channel_id` is provided to allow
	/// implementations of [`SignerProvider`] to maintain a mapping between itself and the generated
	/// `channel_keys_id`.
	///
	/// This method must return a different value each time it is called.
	pub generate_channel_keys_id: extern "C" fn (this_arg: *const c_void, inbound: bool, channel_value_satoshis: u64, user_channel_id: crate::c_types::U128) -> crate::c_types::ThirtyTwoBytes,
	/// Derives the private key material backing a `Signer`.
	///
	/// To derive a new `Signer`, a fresh `channel_keys_id` should be obtained through
	/// [`SignerProvider::generate_channel_keys_id`]. Otherwise, an existing `Signer` can be
	/// re-derived from its `channel_keys_id`, which can be obtained through its trait method
	/// [`ChannelSigner::channel_keys_id`].
	pub derive_channel_signer: extern "C" fn (this_arg: *const c_void, channel_value_satoshis: u64, channel_keys_id: crate::c_types::ThirtyTwoBytes) -> crate::lightning::sign::WriteableEcdsaChannelSigner,
	/// Reads a [`Signer`] for this [`SignerProvider`] from the given input stream.
	/// This is only called during deserialization of other objects which contain
	/// [`WriteableEcdsaChannelSigner`]-implementing objects (i.e., [`ChannelMonitor`]s and [`ChannelManager`]s).
	/// The bytes are exactly those which `<Self::Signer as Writeable>::write()` writes, and
	/// contain no versioning scheme. You may wish to include your own version prefix and ensure
	/// you've read all of the provided bytes to ensure no corruption occurred.
	///
	/// This method is slowly being phased out -- it will only be called when reading objects
	/// written by LDK versions prior to 0.0.113.
	///
	/// [`Signer`]: Self::Signer
	/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
	/// [`ChannelManager`]: crate::ln::channelmanager::ChannelManager
	pub read_chan_signer: extern "C" fn (this_arg: *const c_void, reader: crate::c_types::u8slice) -> crate::c_types::derived::CResult_WriteableEcdsaChannelSignerDecodeErrorZ,
	/// Get a script pubkey which we send funds to when claiming on-chain contestable outputs.
	///
	/// If this function returns an error, this will result in a channel failing to open.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	pub get_destination_script: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_ScriptNoneZ,
	/// Get a script pubkey which we will send funds to when closing a channel.
	///
	/// If this function returns an error, this will result in a channel failing to open or close.
	/// In the event of a failure when the counterparty is initiating a close, this can result in a
	/// channel force close.
	///
	/// This method should return a different value each time it is called, to avoid linking
	/// on-chain funds across channels as controlled to the same user.
	pub get_shutdown_scriptpubkey: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CResult_ShutdownScriptNoneZ,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for SignerProvider {}
unsafe impl Sync for SignerProvider {}
#[no_mangle]
pub(crate) extern "C" fn SignerProvider_clone_fields(orig: &SignerProvider) -> SignerProvider {
	SignerProvider {
		this_arg: orig.this_arg,
		generate_channel_keys_id: Clone::clone(&orig.generate_channel_keys_id),
		derive_channel_signer: Clone::clone(&orig.derive_channel_signer),
		read_chan_signer: Clone::clone(&orig.read_chan_signer),
		get_destination_script: Clone::clone(&orig.get_destination_script),
		get_shutdown_scriptpubkey: Clone::clone(&orig.get_shutdown_scriptpubkey),
		free: Clone::clone(&orig.free),
	}
}

use lightning::sign::SignerProvider as rustSignerProvider;
impl rustSignerProvider for SignerProvider {
	type Signer = crate::lightning::sign::WriteableEcdsaChannelSigner;
	fn generate_channel_keys_id(&self, mut inbound: bool, mut channel_value_satoshis: u64, mut user_channel_id: u128) -> [u8; 32] {
		let mut ret = (self.generate_channel_keys_id)(self.this_arg, inbound, channel_value_satoshis, user_channel_id.into());
		ret.data
	}
	fn derive_channel_signer(&self, mut channel_value_satoshis: u64, mut channel_keys_id: [u8; 32]) -> crate::lightning::sign::WriteableEcdsaChannelSigner {
		let mut ret = (self.derive_channel_signer)(self.this_arg, channel_value_satoshis, crate::c_types::ThirtyTwoBytes { data: channel_keys_id });
		ret
	}
	fn read_chan_signer(&self, mut reader: &[u8]) -> Result<crate::lightning::sign::WriteableEcdsaChannelSigner, lightning::ln::msgs::DecodeError> {
		let mut local_reader = crate::c_types::u8slice::from_slice(reader);
		let mut ret = (self.read_chan_signer)(self.this_arg, local_reader);
		let mut local_ret = match ret.result_ok { true => Ok( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }) }), false => Err( { (*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) }).into_native() })};
		local_ret
	}
	fn get_destination_script(&self) -> Result<bitcoin::blockdata::script::Script, ()> {
		let mut ret = (self.get_destination_script)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { ::bitcoin::blockdata::script::Script::from((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).into_rust()) }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
	fn get_shutdown_scriptpubkey(&self) -> Result<lightning::ln::script::ShutdownScript, ()> {
		let mut ret = (self.get_shutdown_scriptpubkey)(self.this_arg);
		let mut local_ret = match ret.result_ok { true => Ok( { *unsafe { Box::from_raw((*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.result)) }).take_inner()) } }), false => Err( { () /*(*unsafe { Box::from_raw(<*mut _>::take_ptr(&mut ret.contents.err)) })*/ })};
		local_ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for SignerProvider {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn SignerProvider_free(this_ptr: SignerProvider) { }
impl Drop for SignerProvider {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::sign::InMemorySigner as nativeInMemorySignerImport;
pub(crate) type nativeInMemorySigner = nativeInMemorySignerImport;

/// A simple implementation of [`WriteableEcdsaChannelSigner`] that just keeps the private keys in memory.
///
/// This implementation performs no policy checks and is insufficient by itself as
/// a secure external signer.
#[must_use]
#[repr(C)]
pub struct InMemorySigner {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeInMemorySigner,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for InMemorySigner {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeInMemorySigner>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the InMemorySigner, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn InMemorySigner_free(this_obj: InMemorySigner) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InMemorySigner_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeInMemorySigner) };
}
#[allow(unused)]
impl InMemorySigner {
	pub(crate) fn get_native_ref(&self) -> &'static nativeInMemorySigner {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeInMemorySigner {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeInMemorySigner {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Holder secret key in the 2-of-2 multisig script of a channel. This key also backs the
/// holder's anchor output in a commitment transaction, if one is present.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_funding_key(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().funding_key;
	inner_val.as_ref()
}
/// Holder secret key in the 2-of-2 multisig script of a channel. This key also backs the
/// holder's anchor output in a commitment transaction, if one is present.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_funding_key(this_ptr: &mut InMemorySigner, mut val: crate::c_types::SecretKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.funding_key = val.into_rust();
}
/// Holder secret key for blinded revocation pubkey.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_revocation_base_key(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().revocation_base_key;
	inner_val.as_ref()
}
/// Holder secret key for blinded revocation pubkey.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_revocation_base_key(this_ptr: &mut InMemorySigner, mut val: crate::c_types::SecretKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.revocation_base_key = val.into_rust();
}
/// Holder secret key used for our balance in counterparty-broadcasted commitment transactions.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_payment_key(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().payment_key;
	inner_val.as_ref()
}
/// Holder secret key used for our balance in counterparty-broadcasted commitment transactions.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_payment_key(this_ptr: &mut InMemorySigner, mut val: crate::c_types::SecretKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.payment_key = val.into_rust();
}
/// Holder secret key used in an HTLC transaction.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_delayed_payment_base_key(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().delayed_payment_base_key;
	inner_val.as_ref()
}
/// Holder secret key used in an HTLC transaction.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_delayed_payment_base_key(this_ptr: &mut InMemorySigner, mut val: crate::c_types::SecretKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.delayed_payment_base_key = val.into_rust();
}
/// Holder HTLC secret key used in commitment transaction HTLC outputs.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_htlc_base_key(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().htlc_base_key;
	inner_val.as_ref()
}
/// Holder HTLC secret key used in commitment transaction HTLC outputs.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_htlc_base_key(this_ptr: &mut InMemorySigner, mut val: crate::c_types::SecretKey) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.htlc_base_key = val.into_rust();
}
/// Commitment seed.
#[no_mangle]
pub extern "C" fn InMemorySigner_get_commitment_seed(this_ptr: &InMemorySigner) -> *const [u8; 32] {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().commitment_seed;
	inner_val
}
/// Commitment seed.
#[no_mangle]
pub extern "C" fn InMemorySigner_set_commitment_seed(this_ptr: &mut InMemorySigner, mut val: crate::c_types::ThirtyTwoBytes) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.commitment_seed = val.data;
}
impl Clone for InMemorySigner {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeInMemorySigner>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn InMemorySigner_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeInMemorySigner)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the InMemorySigner
pub extern "C" fn InMemorySigner_clone(orig: &InMemorySigner) -> InMemorySigner {
	orig.clone()
}
/// Creates a new [`InMemorySigner`].
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_new(mut funding_key: crate::c_types::SecretKey, mut revocation_base_key: crate::c_types::SecretKey, mut payment_key: crate::c_types::SecretKey, mut delayed_payment_base_key: crate::c_types::SecretKey, mut htlc_base_key: crate::c_types::SecretKey, mut commitment_seed: crate::c_types::ThirtyTwoBytes, mut channel_value_satoshis: u64, mut channel_keys_id: crate::c_types::ThirtyTwoBytes, mut rand_bytes_unique_start: crate::c_types::ThirtyTwoBytes) -> crate::lightning::sign::InMemorySigner {
	let mut ret = lightning::sign::InMemorySigner::new(secp256k1::global::SECP256K1, funding_key.into_rust(), revocation_base_key.into_rust(), payment_key.into_rust(), delayed_payment_base_key.into_rust(), htlc_base_key.into_rust(), commitment_seed.data, channel_value_satoshis, channel_keys_id.data, rand_bytes_unique_start.data);
	crate::lightning::sign::InMemorySigner { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Returns the counterparty's pubkeys.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_counterparty_pubkeys(this_arg: &crate::lightning::sign::InMemorySigner) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.counterparty_pubkeys();
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}

/// Returns the `contest_delay` value specified by our counterparty and applied on holder-broadcastable
/// transactions, i.e., the amount of time that we have to wait to recover our funds if we
/// broadcast a transaction.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_counterparty_selected_contest_delay(this_arg: &crate::lightning::sign::InMemorySigner) -> u16 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.counterparty_selected_contest_delay();
	ret
}

/// Returns the `contest_delay` value specified by us and applied on transactions broadcastable
/// by our counterparty, i.e., the amount of time that they have to wait to recover their funds
/// if they broadcast a transaction.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_holder_selected_contest_delay(this_arg: &crate::lightning::sign::InMemorySigner) -> u16 {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.holder_selected_contest_delay();
	ret
}

/// Returns whether the holder is the initiator.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_is_outbound(this_arg: &crate::lightning::sign::InMemorySigner) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.is_outbound();
	ret
}

/// Funding outpoint
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_funding_outpoint(this_arg: &crate::lightning::sign::InMemorySigner) -> crate::lightning::chain::transaction::OutPoint {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.funding_outpoint();
	crate::lightning::chain::transaction::OutPoint { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::chain::transaction::OutPoint<>) as *mut _) }, is_owned: false }
}

/// Returns a [`ChannelTransactionParameters`] for this channel, to be used when verifying or
/// building transactions.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_get_channel_parameters(this_arg: &crate::lightning::sign::InMemorySigner) -> crate::lightning::ln::chan_utils::ChannelTransactionParameters {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_channel_parameters();
	crate::lightning::ln::chan_utils::ChannelTransactionParameters { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::ChannelTransactionParameters<>) as *mut _) }, is_owned: false }
}

/// Returns the channel type features of the channel parameters. Should be helpful for
/// determining a channel's category, i. e. legacy/anchors/taproot/etc.
///
/// Will panic if [`ChannelSigner::provide_channel_parameters`] has not been called before.
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_channel_type_features(this_arg: &crate::lightning::sign::InMemorySigner) -> crate::lightning::ln::features::ChannelTypeFeatures {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.channel_type_features();
	crate::lightning::ln::features::ChannelTypeFeatures { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::features::ChannelTypeFeatures<>) as *mut _) }, is_owned: false }
}

/// Sign the single input of `spend_tx` at index `input_idx`, which spends the output described
/// by `descriptor`, returning the witness stack for the input.
///
/// Returns an error if the input at `input_idx` does not exist, has a non-empty `script_sig`,
/// is not spending the outpoint described by [`descriptor.outpoint`],
/// or if an output descriptor `script_pubkey` does not match the one we can spend.
///
/// [`descriptor.outpoint`]: StaticPaymentOutputDescriptor::outpoint
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_sign_counterparty_payment_input(this_arg: &crate::lightning::sign::InMemorySigner, mut spend_tx: crate::c_types::Transaction, mut input_idx: usize, descriptor: &crate::lightning::sign::StaticPaymentOutputDescriptor) -> crate::c_types::derived::CResult_CVec_CVec_u8ZZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign_counterparty_payment_input(&spend_tx.into_bitcoin(), input_idx, descriptor.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let mut local_ret_0_0 = Vec::new(); for mut item in item.drain(..) { local_ret_0_0.push( { item }); }; local_ret_0_0.into() }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Sign the single input of `spend_tx` at index `input_idx` which spends the output
/// described by `descriptor`, returning the witness stack for the input.
///
/// Returns an error if the input at `input_idx` does not exist, has a non-empty `script_sig`,
/// is not spending the outpoint described by [`descriptor.outpoint`], does not have a
/// sequence set to [`descriptor.to_self_delay`], or if an output descriptor
/// `script_pubkey` does not match the one we can spend.
///
/// [`descriptor.outpoint`]: DelayedPaymentOutputDescriptor::outpoint
/// [`descriptor.to_self_delay`]: DelayedPaymentOutputDescriptor::to_self_delay
#[must_use]
#[no_mangle]
pub extern "C" fn InMemorySigner_sign_dynamic_p2wsh_input(this_arg: &crate::lightning::sign::InMemorySigner, mut spend_tx: crate::c_types::Transaction, mut input_idx: usize, descriptor: &crate::lightning::sign::DelayedPaymentOutputDescriptor) -> crate::c_types::derived::CResult_CVec_CVec_u8ZZNoneZ {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign_dynamic_p2wsh_input(&spend_tx.into_bitcoin(), input_idx, descriptor.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let mut local_ret_0 = Vec::new(); for mut item in o.drain(..) { local_ret_0.push( { let mut local_ret_0_0 = Vec::new(); for mut item in item.drain(..) { local_ret_0_0.push( { item }); }; local_ret_0_0.into() }); }; local_ret_0.into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativeInMemorySigner> for crate::lightning::sign::EntropySource {
	fn from(obj: nativeInMemorySigner) -> Self {
		let mut rust_obj = InMemorySigner { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InMemorySigner_as_EntropySource(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(InMemorySigner_free_void);
		ret
	}
}
/// Constructs a new EntropySource which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EntropySource must be freed before this_arg is
#[no_mangle]
pub extern "C" fn InMemorySigner_as_EntropySource(this_arg: &InMemorySigner) -> crate::lightning::sign::EntropySource {
	crate::lightning::sign::EntropySource {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_secure_random_bytes: InMemorySigner_EntropySource_get_secure_random_bytes,
	}
}

#[must_use]
extern "C" fn InMemorySigner_EntropySource_get_secure_random_bytes(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeInMemorySigner as lightning::sign::EntropySource<>>::get_secure_random_bytes(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, );
	crate::c_types::ThirtyTwoBytes { data: ret }
}

impl From<nativeInMemorySigner> for crate::lightning::sign::ChannelSigner {
	fn from(obj: nativeInMemorySigner) -> Self {
		let mut rust_obj = InMemorySigner { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InMemorySigner_as_ChannelSigner(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(InMemorySigner_free_void);
		ret
	}
}
/// Constructs a new ChannelSigner which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned ChannelSigner must be freed before this_arg is
#[no_mangle]
pub extern "C" fn InMemorySigner_as_ChannelSigner(this_arg: &InMemorySigner) -> crate::lightning::sign::ChannelSigner {
	crate::lightning::sign::ChannelSigner {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_per_commitment_point: InMemorySigner_ChannelSigner_get_per_commitment_point,
		release_commitment_secret: InMemorySigner_ChannelSigner_release_commitment_secret,
		validate_holder_commitment: InMemorySigner_ChannelSigner_validate_holder_commitment,

		pubkeys: crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: core::ptr::null_mut(), is_owned: true }.into(),
		set_pubkeys: Some(InMemorySigner_ChannelSigner_set_pubkeys),
		channel_keys_id: InMemorySigner_ChannelSigner_channel_keys_id,
		provide_channel_parameters: InMemorySigner_ChannelSigner_provide_channel_parameters,
	}
}

#[must_use]
extern "C" fn InMemorySigner_ChannelSigner_get_per_commitment_point(this_arg: *const c_void, mut idx: u64) -> crate::c_types::PublicKey {
	let mut ret = <nativeInMemorySigner as lightning::sign::ChannelSigner<>>::get_per_commitment_point(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, idx, secp256k1::global::SECP256K1);
	crate::c_types::PublicKey::from_rust(&ret)
}
#[must_use]
extern "C" fn InMemorySigner_ChannelSigner_release_commitment_secret(this_arg: *const c_void, mut idx: u64) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeInMemorySigner as lightning::sign::ChannelSigner<>>::release_commitment_secret(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, idx);
	crate::c_types::ThirtyTwoBytes { data: ret }
}
#[must_use]
extern "C" fn InMemorySigner_ChannelSigner_validate_holder_commitment(this_arg: *const c_void, holder_tx: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction, mut preimages: crate::c_types::derived::CVec_PaymentPreimageZ) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut local_preimages = Vec::new(); for mut item in preimages.into_rust().drain(..) { local_preimages.push( { ::lightning::ln::PaymentPreimage(item.data) }); };
	let mut ret = <nativeInMemorySigner as lightning::sign::ChannelSigner<>>::validate_holder_commitment(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, holder_tx.get_native_ref(), local_preimages);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_ChannelSigner_pubkeys(this_arg: *const c_void) -> crate::lightning::ln::chan_utils::ChannelPublicKeys {
	let mut ret = <nativeInMemorySigner as lightning::sign::ChannelSigner<>>::pubkeys(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, );
	crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: unsafe { ObjOps::nonnull_ptr_to_inner((ret as *const lightning::ln::chan_utils::ChannelPublicKeys<>) as *mut _) }, is_owned: false }
}
extern "C" fn InMemorySigner_ChannelSigner_set_pubkeys(trait_self_arg: &ChannelSigner) {
	// This is a bit race-y in the general case, but for our specific use-cases today, we're safe
	// Specifically, we must ensure that the first time we're called it can never be in parallel
	if unsafe { &*trait_self_arg.pubkeys.get() }.inner.is_null() {
		*unsafe { &mut *(&*(trait_self_arg as *const ChannelSigner)).pubkeys.get() } = InMemorySigner_ChannelSigner_pubkeys(trait_self_arg.this_arg).into();
	}
}
#[must_use]
extern "C" fn InMemorySigner_ChannelSigner_channel_keys_id(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeInMemorySigner as lightning::sign::ChannelSigner<>>::channel_keys_id(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, );
	crate::c_types::ThirtyTwoBytes { data: ret }
}
extern "C" fn InMemorySigner_ChannelSigner_provide_channel_parameters(this_arg: *mut c_void, channel_parameters: &crate::lightning::ln::chan_utils::ChannelTransactionParameters) {
	<nativeInMemorySigner as lightning::sign::ChannelSigner<>>::provide_channel_parameters(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, channel_parameters.get_native_ref())
}

impl From<nativeInMemorySigner> for crate::lightning::sign::EcdsaChannelSigner {
	fn from(obj: nativeInMemorySigner) -> Self {
		let mut rust_obj = InMemorySigner { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InMemorySigner_as_EcdsaChannelSigner(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(InMemorySigner_free_void);
		ret
	}
}
/// Constructs a new EcdsaChannelSigner which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EcdsaChannelSigner must be freed before this_arg is
#[no_mangle]
pub extern "C" fn InMemorySigner_as_EcdsaChannelSigner(this_arg: &InMemorySigner) -> crate::lightning::sign::EcdsaChannelSigner {
	crate::lightning::sign::EcdsaChannelSigner {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		sign_counterparty_commitment: InMemorySigner_EcdsaChannelSigner_sign_counterparty_commitment,
		validate_counterparty_revocation: InMemorySigner_EcdsaChannelSigner_validate_counterparty_revocation,
		sign_holder_commitment_and_htlcs: InMemorySigner_EcdsaChannelSigner_sign_holder_commitment_and_htlcs,
		sign_justice_revoked_output: InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_output,
		sign_justice_revoked_htlc: InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_htlc,
		sign_holder_htlc_transaction: InMemorySigner_EcdsaChannelSigner_sign_holder_htlc_transaction,
		sign_counterparty_htlc_transaction: InMemorySigner_EcdsaChannelSigner_sign_counterparty_htlc_transaction,
		sign_closing_transaction: InMemorySigner_EcdsaChannelSigner_sign_closing_transaction,
		sign_holder_anchor_input: InMemorySigner_EcdsaChannelSigner_sign_holder_anchor_input,
		sign_channel_announcement_with_funding_key: InMemorySigner_EcdsaChannelSigner_sign_channel_announcement_with_funding_key,
		ChannelSigner: crate::lightning::sign::ChannelSigner {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			get_per_commitment_point: InMemorySigner_ChannelSigner_get_per_commitment_point,
			release_commitment_secret: InMemorySigner_ChannelSigner_release_commitment_secret,
			validate_holder_commitment: InMemorySigner_ChannelSigner_validate_holder_commitment,

			pubkeys: crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: core::ptr::null_mut(), is_owned: true }.into(),
			set_pubkeys: Some(InMemorySigner_ChannelSigner_set_pubkeys),
			channel_keys_id: InMemorySigner_ChannelSigner_channel_keys_id,
			provide_channel_parameters: InMemorySigner_ChannelSigner_provide_channel_parameters,
		},
	}
}

#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_counterparty_commitment(this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::CommitmentTransaction, mut preimages: crate::c_types::derived::CVec_PaymentPreimageZ) -> crate::c_types::derived::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	let mut local_preimages = Vec::new(); for mut item in preimages.into_rust().drain(..) { local_preimages.push( { ::lightning::ln::PaymentPreimage(item.data) }); };
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_counterparty_commitment(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, commitment_tx.get_native_ref(), local_preimages, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.drain(..) { local_orig_ret_0_1.push( { crate::c_types::Signature::from_rust(&item) }); }; let mut local_ret_0 = (crate::c_types::Signature::from_rust(&orig_ret_0_0), local_orig_ret_0_1.into()).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_validate_counterparty_revocation(this_arg: *const c_void, mut idx: u64, secret: *const [u8; 32]) -> crate::c_types::derived::CResult_NoneNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::validate_counterparty_revocation(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, idx, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *secret}[..]).unwrap());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { () /*o*/ }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_holder_commitment_and_htlcs(this_arg: *const c_void, commitment_tx: &crate::lightning::ln::chan_utils::HolderCommitmentTransaction) -> crate::c_types::derived::CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_holder_commitment_and_htlcs(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, commitment_tx.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { let (mut orig_ret_0_0, mut orig_ret_0_1) = o; let mut local_orig_ret_0_1 = Vec::new(); for mut item in orig_ret_0_1.drain(..) { local_orig_ret_0_1.push( { crate::c_types::Signature::from_rust(&item) }); }; let mut local_ret_0 = (crate::c_types::Signature::from_rust(&orig_ret_0_0), local_orig_ret_0_1.into()).into(); local_ret_0 }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_output(this_arg: *const c_void, mut justice_tx: crate::c_types::Transaction, mut input: usize, mut amount: u64, per_commitment_key: *const [u8; 32]) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_justice_revoked_output(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, &justice_tx.into_bitcoin(), input, amount, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *per_commitment_key}[..]).unwrap(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_htlc(this_arg: *const c_void, mut justice_tx: crate::c_types::Transaction, mut input: usize, mut amount: u64, per_commitment_key: *const [u8; 32], htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_justice_revoked_htlc(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, &justice_tx.into_bitcoin(), input, amount, &::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *per_commitment_key}[..]).unwrap(), htlc.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_holder_htlc_transaction(this_arg: *const c_void, mut htlc_tx: crate::c_types::Transaction, mut input: usize, htlc_descriptor: &crate::lightning::events::bump_transaction::HTLCDescriptor) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_holder_htlc_transaction(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, &htlc_tx.into_bitcoin(), input, htlc_descriptor.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_counterparty_htlc_transaction(this_arg: *const c_void, mut htlc_tx: crate::c_types::Transaction, mut input: usize, mut amount: u64, mut per_commitment_point: crate::c_types::PublicKey, htlc: &crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_counterparty_htlc_transaction(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, &htlc_tx.into_bitcoin(), input, amount, &per_commitment_point.into_rust(), htlc.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_closing_transaction(this_arg: *const c_void, closing_tx: &crate::lightning::ln::chan_utils::ClosingTransaction) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_closing_transaction(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, closing_tx.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_holder_anchor_input(this_arg: *const c_void, mut anchor_tx: crate::c_types::Transaction, mut input: usize) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_holder_anchor_input(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, &anchor_tx.into_bitcoin(), input, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn InMemorySigner_EcdsaChannelSigner_sign_channel_announcement_with_funding_key(this_arg: *const c_void, msg: &crate::lightning::ln::msgs::UnsignedChannelAnnouncement) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeInMemorySigner as lightning::sign::EcdsaChannelSigner<>>::sign_channel_announcement_with_funding_key(unsafe { &mut *(this_arg as *mut nativeInMemorySigner) }, msg.get_native_ref(), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativeInMemorySigner> for crate::lightning::sign::WriteableEcdsaChannelSigner {
	fn from(obj: nativeInMemorySigner) -> Self {
		let mut rust_obj = InMemorySigner { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = InMemorySigner_as_WriteableEcdsaChannelSigner(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(InMemorySigner_free_void);
		ret
	}
}
/// Constructs a new WriteableEcdsaChannelSigner which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned WriteableEcdsaChannelSigner must be freed before this_arg is
#[no_mangle]
pub extern "C" fn InMemorySigner_as_WriteableEcdsaChannelSigner(this_arg: &InMemorySigner) -> crate::lightning::sign::WriteableEcdsaChannelSigner {
	crate::lightning::sign::WriteableEcdsaChannelSigner {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		EcdsaChannelSigner: crate::lightning::sign::EcdsaChannelSigner {
			this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
			free: None,
			sign_counterparty_commitment: InMemorySigner_EcdsaChannelSigner_sign_counterparty_commitment,
			validate_counterparty_revocation: InMemorySigner_EcdsaChannelSigner_validate_counterparty_revocation,
			sign_holder_commitment_and_htlcs: InMemorySigner_EcdsaChannelSigner_sign_holder_commitment_and_htlcs,
			sign_justice_revoked_output: InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_output,
			sign_justice_revoked_htlc: InMemorySigner_EcdsaChannelSigner_sign_justice_revoked_htlc,
			sign_holder_htlc_transaction: InMemorySigner_EcdsaChannelSigner_sign_holder_htlc_transaction,
			sign_counterparty_htlc_transaction: InMemorySigner_EcdsaChannelSigner_sign_counterparty_htlc_transaction,
			sign_closing_transaction: InMemorySigner_EcdsaChannelSigner_sign_closing_transaction,
			sign_holder_anchor_input: InMemorySigner_EcdsaChannelSigner_sign_holder_anchor_input,
			sign_channel_announcement_with_funding_key: InMemorySigner_EcdsaChannelSigner_sign_channel_announcement_with_funding_key,
			ChannelSigner: crate::lightning::sign::ChannelSigner {
				this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
				free: None,
				get_per_commitment_point: InMemorySigner_ChannelSigner_get_per_commitment_point,
				release_commitment_secret: InMemorySigner_ChannelSigner_release_commitment_secret,
				validate_holder_commitment: InMemorySigner_ChannelSigner_validate_holder_commitment,

				pubkeys: crate::lightning::ln::chan_utils::ChannelPublicKeys { inner: core::ptr::null_mut(), is_owned: true }.into(),
				set_pubkeys: Some(InMemorySigner_ChannelSigner_set_pubkeys),
				channel_keys_id: InMemorySigner_ChannelSigner_channel_keys_id,
				provide_channel_parameters: InMemorySigner_ChannelSigner_provide_channel_parameters,
			},
		},
		write: InMemorySigner_write_void,
	}
}


#[no_mangle]
/// Serialize the InMemorySigner object into a byte array which can be read by InMemorySigner_read
pub extern "C" fn InMemorySigner_write(obj: &crate::lightning::sign::InMemorySigner) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn InMemorySigner_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeInMemorySigner) })
}
#[no_mangle]
/// Read a InMemorySigner from a byte array, created by InMemorySigner_write
pub extern "C" fn InMemorySigner_read(ser: crate::c_types::u8slice, arg: crate::lightning::sign::EntropySource) -> crate::c_types::derived::CResult_InMemorySignerDecodeErrorZ {
	let arg_conv = arg;
	let res: Result<lightning::sign::InMemorySigner, lightning::ln::msgs::DecodeError> = crate::c_types::deserialize_obj_arg(ser, arg_conv);
	let mut local_res = match res { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::sign::InMemorySigner { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_res
}

use lightning::sign::KeysManager as nativeKeysManagerImport;
pub(crate) type nativeKeysManager = nativeKeysManagerImport;

/// Simple implementation of [`EntropySource`], [`NodeSigner`], and [`SignerProvider`] that takes a
/// 32-byte seed for use as a BIP 32 extended key and derives keys from that.
///
/// Your `node_id` is seed/0'.
/// Unilateral closes may use seed/1'.
/// Cooperative closes may use seed/2'.
/// The two close keys may be needed to claim on-chain funds!
///
/// This struct cannot be used for nodes that wish to support receiving phantom payments;
/// [`PhantomKeysManager`] must be used instead.
///
/// Note that switching between this struct and [`PhantomKeysManager`] will invalidate any
/// previously issued invoices and attempts to pay previous invoices will fail.
#[must_use]
#[repr(C)]
pub struct KeysManager {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeKeysManager,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for KeysManager {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeKeysManager>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the KeysManager, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn KeysManager_free(this_obj: KeysManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn KeysManager_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeKeysManager) };
}
#[allow(unused)]
impl KeysManager {
	pub(crate) fn get_native_ref(&self) -> &'static nativeKeysManager {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeKeysManager {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeKeysManager {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a [`KeysManager`] from a 32-byte seed. If the seed is in some way biased (e.g.,
/// your CSRNG is busted) this may panic (but more importantly, you will possibly lose funds).
/// `starting_time` isn't strictly required to actually be a time, but it must absolutely,
/// without a doubt, be unique to this instance. ie if you start multiple times with the same
/// `seed`, `starting_time` must be unique to each run. Thus, the easiest way to achieve this
/// is to simply use the current time (with very high precision).
///
/// The `seed` MUST be backed up safely prior to use so that the keys can be re-created, however,
/// obviously, `starting_time` should be unique every time you reload the library - it is only
/// used to generate new ephemeral key data (which will be stored by the individual channel if
/// necessary).
///
/// Note that the seed is required to recover certain on-chain funds independent of
/// [`ChannelMonitor`] data, though a current copy of [`ChannelMonitor`] data is also required
/// for any channel, and some on-chain during-closing funds.
///
/// [`ChannelMonitor`]: crate::chain::channelmonitor::ChannelMonitor
#[must_use]
#[no_mangle]
pub extern "C" fn KeysManager_new(seed: *const [u8; 32], mut starting_time_secs: u64, mut starting_time_nanos: u32) -> crate::lightning::sign::KeysManager {
	let mut ret = lightning::sign::KeysManager::new(unsafe { &*seed}, starting_time_secs, starting_time_nanos);
	crate::lightning::sign::KeysManager { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Gets the \"node_id\" secret key used to sign gossip announcements, decode onion data, etc.
#[must_use]
#[no_mangle]
pub extern "C" fn KeysManager_get_node_secret_key(this_arg: &crate::lightning::sign::KeysManager) -> crate::c_types::SecretKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_node_secret_key();
	crate::c_types::SecretKey::from_rust(ret)
}

/// Derive an old [`WriteableEcdsaChannelSigner`] containing per-channel secrets based on a key derivation parameters.
#[must_use]
#[no_mangle]
pub extern "C" fn KeysManager_derive_channel_keys(this_arg: &crate::lightning::sign::KeysManager, mut channel_value_satoshis: u64, params: *const [u8; 32]) -> crate::lightning::sign::InMemorySigner {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.derive_channel_keys(channel_value_satoshis, unsafe { &*params});
	crate::lightning::sign::InMemorySigner { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Signs the given [`PartiallySignedTransaction`] which spends the given [`SpendableOutputDescriptor`]s.
/// The resulting inputs will be finalized and the PSBT will be ready for broadcast if there
/// are no other inputs that need signing.
///
/// Returns `Err(())` if the PSBT is missing a descriptor or if we fail to sign.
///
/// May panic if the [`SpendableOutputDescriptor`]s were not generated by channels which used
/// this [`KeysManager`] or one of the [`InMemorySigner`] created by this [`KeysManager`].
#[must_use]
#[no_mangle]
pub extern "C" fn KeysManager_sign_spendable_outputs_psbt(this_arg: &crate::lightning::sign::KeysManager, mut descriptors: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, mut psbt: crate::c_types::derived::CVec_u8Z) -> crate::c_types::derived::CResult_PartiallySignedTransactionNoneZ {
	let mut local_descriptors = Vec::new(); for mut item in descriptors.into_rust().drain(..) { local_descriptors.push( { item.into_native() }); };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.sign_spendable_outputs_psbt(&local_descriptors.iter().collect::<Vec<_>>()[..], ::bitcoin::consensus::encode::deserialize(psbt.as_slice()).expect("Invalid PSBT format"), secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { ::bitcoin::consensus::encode::serialize(&o).into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Creates a [`Transaction`] which spends the given descriptors to the given outputs, plus an
/// output to the given change destination (if sufficient change value remains). The
/// transaction will have a feerate, at least, of the given value.
///
/// The `locktime` argument is used to set the transaction's locktime. If `None`, the
/// transaction will have a locktime of 0. It it recommended to set this to the current block
/// height to avoid fee sniping, unless you have some specific reason to use a different
/// locktime.
///
/// Returns `Err(())` if the output value is greater than the input value minus required fee,
/// if a descriptor was duplicated, or if an output descriptor `script_pubkey`
/// does not match the one we can spend.
///
/// We do not enforce that outputs meet the dust limit or that any output scripts are standard.
///
/// May panic if the [`SpendableOutputDescriptor`]s were not generated by channels which used
/// this [`KeysManager`] or one of the [`InMemorySigner`] created by this [`KeysManager`].
#[must_use]
#[no_mangle]
pub extern "C" fn KeysManager_spend_spendable_outputs(this_arg: &crate::lightning::sign::KeysManager, mut descriptors: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, mut outputs: crate::c_types::derived::CVec_TxOutZ, mut change_destination_script: crate::c_types::derived::CVec_u8Z, mut feerate_sat_per_1000_weight: u32, mut locktime: crate::c_types::derived::COption_PackedLockTimeZ) -> crate::c_types::derived::CResult_TransactionNoneZ {
	let mut local_descriptors = Vec::new(); for mut item in descriptors.into_rust().drain(..) { local_descriptors.push( { item.into_native() }); };
	let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_rust() }); };
	let mut local_locktime = { /*locktime*/ let locktime_opt = locktime; if locktime_opt.is_none() { None } else { Some({ { ::bitcoin::PackedLockTime({ locktime_opt.take() }) }})} };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.spend_spendable_outputs(&local_descriptors.iter().collect::<Vec<_>>()[..], local_outputs, ::bitcoin::blockdata::script::Script::from(change_destination_script.into_rust()), feerate_sat_per_1000_weight, local_locktime, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Transaction::from_bitcoin(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativeKeysManager> for crate::lightning::sign::EntropySource {
	fn from(obj: nativeKeysManager) -> Self {
		let mut rust_obj = KeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = KeysManager_as_EntropySource(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(KeysManager_free_void);
		ret
	}
}
/// Constructs a new EntropySource which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EntropySource must be freed before this_arg is
#[no_mangle]
pub extern "C" fn KeysManager_as_EntropySource(this_arg: &KeysManager) -> crate::lightning::sign::EntropySource {
	crate::lightning::sign::EntropySource {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_secure_random_bytes: KeysManager_EntropySource_get_secure_random_bytes,
	}
}

#[must_use]
extern "C" fn KeysManager_EntropySource_get_secure_random_bytes(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeKeysManager as lightning::sign::EntropySource<>>::get_secure_random_bytes(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, );
	crate::c_types::ThirtyTwoBytes { data: ret }
}

impl From<nativeKeysManager> for crate::lightning::sign::NodeSigner {
	fn from(obj: nativeKeysManager) -> Self {
		let mut rust_obj = KeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = KeysManager_as_NodeSigner(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(KeysManager_free_void);
		ret
	}
}
/// Constructs a new NodeSigner which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned NodeSigner must be freed before this_arg is
#[no_mangle]
pub extern "C" fn KeysManager_as_NodeSigner(this_arg: &KeysManager) -> crate::lightning::sign::NodeSigner {
	crate::lightning::sign::NodeSigner {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_inbound_payment_key_material: KeysManager_NodeSigner_get_inbound_payment_key_material,
		get_node_id: KeysManager_NodeSigner_get_node_id,
		ecdh: KeysManager_NodeSigner_ecdh,
		sign_invoice: KeysManager_NodeSigner_sign_invoice,
		sign_gossip_message: KeysManager_NodeSigner_sign_gossip_message,
	}
}

#[must_use]
extern "C" fn KeysManager_NodeSigner_get_inbound_payment_key_material(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeKeysManager as lightning::sign::NodeSigner<>>::get_inbound_payment_key_material(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, );
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}
#[must_use]
extern "C" fn KeysManager_NodeSigner_get_node_id(this_arg: *const c_void, mut recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_PublicKeyNoneZ {
	let mut ret = <nativeKeysManager as lightning::sign::NodeSigner<>>::get_node_id(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, recipient.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::PublicKey::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn KeysManager_NodeSigner_ecdh(this_arg: *const c_void, mut recipient: crate::lightning::sign::Recipient, mut other_key: crate::c_types::PublicKey, mut tweak: crate::c_types::derived::COption_ScalarZ) -> crate::c_types::derived::CResult_SharedSecretNoneZ {
	let mut local_tweak_base = { /*tweak*/ let tweak_opt = tweak; if tweak_opt.is_none() { None } else { Some({ { { tweak_opt.take() }.into_rust() }})} }; let mut local_tweak = local_tweak_base.as_ref();
	let mut ret = <nativeKeysManager as lightning::sign::NodeSigner<>>::ecdh(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, recipient.into_native(), &other_key.into_rust(), local_tweak);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.secret_bytes() } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn KeysManager_NodeSigner_sign_invoice(this_arg: *const c_void, mut hrp_bytes: crate::c_types::u8slice, mut invoice_data: crate::c_types::derived::CVec_U5Z, mut recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_RecoverableSignatureNoneZ {
	let mut local_invoice_data = Vec::new(); for mut item in invoice_data.into_rust().drain(..) { local_invoice_data.push( { item.into() }); };
	let mut ret = <nativeKeysManager as lightning::sign::NodeSigner<>>::sign_invoice(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, hrp_bytes.to_slice(), &local_invoice_data[..], recipient.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::RecoverableSignature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn KeysManager_NodeSigner_sign_gossip_message(this_arg: *const c_void, mut msg: crate::lightning::ln::msgs::UnsignedGossipMessage) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativeKeysManager as lightning::sign::NodeSigner<>>::sign_gossip_message(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, msg.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativeKeysManager> for crate::lightning::sign::SignerProvider {
	fn from(obj: nativeKeysManager) -> Self {
		let mut rust_obj = KeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = KeysManager_as_SignerProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(KeysManager_free_void);
		ret
	}
}
/// Constructs a new SignerProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned SignerProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn KeysManager_as_SignerProvider(this_arg: &KeysManager) -> crate::lightning::sign::SignerProvider {
	crate::lightning::sign::SignerProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		generate_channel_keys_id: KeysManager_SignerProvider_generate_channel_keys_id,
		derive_channel_signer: KeysManager_SignerProvider_derive_channel_signer,
		read_chan_signer: KeysManager_SignerProvider_read_chan_signer,
		get_destination_script: KeysManager_SignerProvider_get_destination_script,
		get_shutdown_scriptpubkey: KeysManager_SignerProvider_get_shutdown_scriptpubkey,
	}
}

#[must_use]
extern "C" fn KeysManager_SignerProvider_generate_channel_keys_id(this_arg: *const c_void, mut inbound: bool, mut channel_value_satoshis: u64, mut user_channel_id: crate::c_types::U128) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativeKeysManager as lightning::sign::SignerProvider<>>::generate_channel_keys_id(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, inbound, channel_value_satoshis, user_channel_id.into());
	crate::c_types::ThirtyTwoBytes { data: ret }
}
#[must_use]
extern "C" fn KeysManager_SignerProvider_derive_channel_signer(this_arg: *const c_void, mut channel_value_satoshis: u64, mut channel_keys_id: crate::c_types::ThirtyTwoBytes) -> crate::lightning::sign::WriteableEcdsaChannelSigner {
	let mut ret = <nativeKeysManager as lightning::sign::SignerProvider<>>::derive_channel_signer(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, channel_value_satoshis, channel_keys_id.data);
	Into::into(ret)
}
#[must_use]
extern "C" fn KeysManager_SignerProvider_read_chan_signer(this_arg: *const c_void, mut reader: crate::c_types::u8slice) -> crate::c_types::derived::CResult_WriteableEcdsaChannelSignerDecodeErrorZ {
	let mut ret = <nativeKeysManager as lightning::sign::SignerProvider<>>::read_chan_signer(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, reader.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { Into::into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn KeysManager_SignerProvider_get_destination_script(this_arg: *const c_void) -> crate::c_types::derived::CResult_ScriptNoneZ {
	let mut ret = <nativeKeysManager as lightning::sign::SignerProvider<>>::get_destination_script(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, );
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o.into_bytes().into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn KeysManager_SignerProvider_get_shutdown_scriptpubkey(this_arg: *const c_void) -> crate::c_types::derived::CResult_ShutdownScriptNoneZ {
	let mut ret = <nativeKeysManager as lightning::sign::SignerProvider<>>::get_shutdown_scriptpubkey(unsafe { &mut *(this_arg as *mut nativeKeysManager) }, );
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}


use lightning::sign::PhantomKeysManager as nativePhantomKeysManagerImport;
pub(crate) type nativePhantomKeysManager = nativePhantomKeysManagerImport;

/// Similar to [`KeysManager`], but allows the node using this struct to receive phantom node
/// payments.
///
/// A phantom node payment is a payment made to a phantom invoice, which is an invoice that can be
/// paid to one of multiple nodes. This works because we encode the invoice route hints such that
/// LDK will recognize an incoming payment as destined for a phantom node, and collect the payment
/// itself without ever needing to forward to this fake node.
///
/// Phantom node payments are useful for load balancing between multiple LDK nodes. They also
/// provide some fault tolerance, because payers will automatically retry paying other provided
/// nodes in the case that one node goes down.
///
/// Note that multi-path payments are not supported in phantom invoices for security reasons.
/// Switching between this struct and [`KeysManager`] will invalidate any previously issued
/// invoices and attempts to pay previous invoices will fail.
#[must_use]
#[repr(C)]
pub struct PhantomKeysManager {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativePhantomKeysManager,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for PhantomKeysManager {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativePhantomKeysManager>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the PhantomKeysManager, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn PhantomKeysManager_free(this_obj: PhantomKeysManager) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn PhantomKeysManager_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativePhantomKeysManager) };
}
#[allow(unused)]
impl PhantomKeysManager {
	pub(crate) fn get_native_ref(&self) -> &'static nativePhantomKeysManager {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativePhantomKeysManager {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativePhantomKeysManager {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl From<nativePhantomKeysManager> for crate::lightning::sign::EntropySource {
	fn from(obj: nativePhantomKeysManager) -> Self {
		let mut rust_obj = PhantomKeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = PhantomKeysManager_as_EntropySource(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(PhantomKeysManager_free_void);
		ret
	}
}
/// Constructs a new EntropySource which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned EntropySource must be freed before this_arg is
#[no_mangle]
pub extern "C" fn PhantomKeysManager_as_EntropySource(this_arg: &PhantomKeysManager) -> crate::lightning::sign::EntropySource {
	crate::lightning::sign::EntropySource {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_secure_random_bytes: PhantomKeysManager_EntropySource_get_secure_random_bytes,
	}
}

#[must_use]
extern "C" fn PhantomKeysManager_EntropySource_get_secure_random_bytes(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativePhantomKeysManager as lightning::sign::EntropySource<>>::get_secure_random_bytes(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, );
	crate::c_types::ThirtyTwoBytes { data: ret }
}

impl From<nativePhantomKeysManager> for crate::lightning::sign::NodeSigner {
	fn from(obj: nativePhantomKeysManager) -> Self {
		let mut rust_obj = PhantomKeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = PhantomKeysManager_as_NodeSigner(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(PhantomKeysManager_free_void);
		ret
	}
}
/// Constructs a new NodeSigner which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned NodeSigner must be freed before this_arg is
#[no_mangle]
pub extern "C" fn PhantomKeysManager_as_NodeSigner(this_arg: &PhantomKeysManager) -> crate::lightning::sign::NodeSigner {
	crate::lightning::sign::NodeSigner {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		get_inbound_payment_key_material: PhantomKeysManager_NodeSigner_get_inbound_payment_key_material,
		get_node_id: PhantomKeysManager_NodeSigner_get_node_id,
		ecdh: PhantomKeysManager_NodeSigner_ecdh,
		sign_invoice: PhantomKeysManager_NodeSigner_sign_invoice,
		sign_gossip_message: PhantomKeysManager_NodeSigner_sign_gossip_message,
	}
}

#[must_use]
extern "C" fn PhantomKeysManager_NodeSigner_get_inbound_payment_key_material(this_arg: *const c_void) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativePhantomKeysManager as lightning::sign::NodeSigner<>>::get_inbound_payment_key_material(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, );
	crate::c_types::ThirtyTwoBytes { data: ret.0 }
}
#[must_use]
extern "C" fn PhantomKeysManager_NodeSigner_get_node_id(this_arg: *const c_void, mut recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_PublicKeyNoneZ {
	let mut ret = <nativePhantomKeysManager as lightning::sign::NodeSigner<>>::get_node_id(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, recipient.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::PublicKey::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn PhantomKeysManager_NodeSigner_ecdh(this_arg: *const c_void, mut recipient: crate::lightning::sign::Recipient, mut other_key: crate::c_types::PublicKey, mut tweak: crate::c_types::derived::COption_ScalarZ) -> crate::c_types::derived::CResult_SharedSecretNoneZ {
	let mut local_tweak_base = { /*tweak*/ let tweak_opt = tweak; if tweak_opt.is_none() { None } else { Some({ { { tweak_opt.take() }.into_rust() }})} }; let mut local_tweak = local_tweak_base.as_ref();
	let mut ret = <nativePhantomKeysManager as lightning::sign::NodeSigner<>>::ecdh(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, recipient.into_native(), &other_key.into_rust(), local_tweak);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::ThirtyTwoBytes { data: o.secret_bytes() } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn PhantomKeysManager_NodeSigner_sign_invoice(this_arg: *const c_void, mut hrp_bytes: crate::c_types::u8slice, mut invoice_data: crate::c_types::derived::CVec_U5Z, mut recipient: crate::lightning::sign::Recipient) -> crate::c_types::derived::CResult_RecoverableSignatureNoneZ {
	let mut local_invoice_data = Vec::new(); for mut item in invoice_data.into_rust().drain(..) { local_invoice_data.push( { item.into() }); };
	let mut ret = <nativePhantomKeysManager as lightning::sign::NodeSigner<>>::sign_invoice(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, hrp_bytes.to_slice(), &local_invoice_data[..], recipient.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::RecoverableSignature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn PhantomKeysManager_NodeSigner_sign_gossip_message(this_arg: *const c_void, mut msg: crate::lightning::ln::msgs::UnsignedGossipMessage) -> crate::c_types::derived::CResult_SignatureNoneZ {
	let mut ret = <nativePhantomKeysManager as lightning::sign::NodeSigner<>>::sign_gossip_message(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, msg.into_native());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Signature::from_rust(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

impl From<nativePhantomKeysManager> for crate::lightning::sign::SignerProvider {
	fn from(obj: nativePhantomKeysManager) -> Self {
		let mut rust_obj = PhantomKeysManager { inner: ObjOps::heap_alloc(obj), is_owned: true };
		let mut ret = PhantomKeysManager_as_SignerProvider(&rust_obj);
		// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn
		rust_obj.inner = core::ptr::null_mut();
		ret.free = Some(PhantomKeysManager_free_void);
		ret
	}
}
/// Constructs a new SignerProvider which calls the relevant methods on this_arg.
/// This copies the `inner` pointer in this_arg and thus the returned SignerProvider must be freed before this_arg is
#[no_mangle]
pub extern "C" fn PhantomKeysManager_as_SignerProvider(this_arg: &PhantomKeysManager) -> crate::lightning::sign::SignerProvider {
	crate::lightning::sign::SignerProvider {
		this_arg: unsafe { ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void },
		free: None,
		generate_channel_keys_id: PhantomKeysManager_SignerProvider_generate_channel_keys_id,
		derive_channel_signer: PhantomKeysManager_SignerProvider_derive_channel_signer,
		read_chan_signer: PhantomKeysManager_SignerProvider_read_chan_signer,
		get_destination_script: PhantomKeysManager_SignerProvider_get_destination_script,
		get_shutdown_scriptpubkey: PhantomKeysManager_SignerProvider_get_shutdown_scriptpubkey,
	}
}

#[must_use]
extern "C" fn PhantomKeysManager_SignerProvider_generate_channel_keys_id(this_arg: *const c_void, mut inbound: bool, mut channel_value_satoshis: u64, mut user_channel_id: crate::c_types::U128) -> crate::c_types::ThirtyTwoBytes {
	let mut ret = <nativePhantomKeysManager as lightning::sign::SignerProvider<>>::generate_channel_keys_id(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, inbound, channel_value_satoshis, user_channel_id.into());
	crate::c_types::ThirtyTwoBytes { data: ret }
}
#[must_use]
extern "C" fn PhantomKeysManager_SignerProvider_derive_channel_signer(this_arg: *const c_void, mut channel_value_satoshis: u64, mut channel_keys_id: crate::c_types::ThirtyTwoBytes) -> crate::lightning::sign::WriteableEcdsaChannelSigner {
	let mut ret = <nativePhantomKeysManager as lightning::sign::SignerProvider<>>::derive_channel_signer(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, channel_value_satoshis, channel_keys_id.data);
	Into::into(ret)
}
#[must_use]
extern "C" fn PhantomKeysManager_SignerProvider_read_chan_signer(this_arg: *const c_void, mut reader: crate::c_types::u8slice) -> crate::c_types::derived::CResult_WriteableEcdsaChannelSignerDecodeErrorZ {
	let mut ret = <nativePhantomKeysManager as lightning::sign::SignerProvider<>>::read_chan_signer(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, reader.to_slice());
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { Into::into(o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { crate::lightning::ln::msgs::DecodeError::native_into(e) }).into() };
	local_ret
}
#[must_use]
extern "C" fn PhantomKeysManager_SignerProvider_get_destination_script(this_arg: *const c_void) -> crate::c_types::derived::CResult_ScriptNoneZ {
	let mut ret = <nativePhantomKeysManager as lightning::sign::SignerProvider<>>::get_destination_script(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, );
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { o.into_bytes().into() }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}
#[must_use]
extern "C" fn PhantomKeysManager_SignerProvider_get_shutdown_scriptpubkey(this_arg: *const c_void) -> crate::c_types::derived::CResult_ShutdownScriptNoneZ {
	let mut ret = <nativePhantomKeysManager as lightning::sign::SignerProvider<>>::get_shutdown_scriptpubkey(unsafe { &mut *(this_arg as *mut nativePhantomKeysManager) }, );
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(o), is_owned: true } }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// Constructs a [`PhantomKeysManager`] given a 32-byte seed and an additional `cross_node_seed`
/// that is shared across all nodes that intend to participate in [phantom node payments]
/// together.
///
/// See [`KeysManager::new`] for more information on `seed`, `starting_time_secs`, and
/// `starting_time_nanos`.
///
/// `cross_node_seed` must be the same across all phantom payment-receiving nodes and also the
/// same across restarts, or else inbound payments may fail.
///
/// [phantom node payments]: PhantomKeysManager
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomKeysManager_new(seed: *const [u8; 32], mut starting_time_secs: u64, mut starting_time_nanos: u32, cross_node_seed: *const [u8; 32]) -> crate::lightning::sign::PhantomKeysManager {
	let mut ret = lightning::sign::PhantomKeysManager::new(unsafe { &*seed}, starting_time_secs, starting_time_nanos, unsafe { &*cross_node_seed});
	crate::lightning::sign::PhantomKeysManager { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// See [`KeysManager::spend_spendable_outputs`] for documentation on this method.
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomKeysManager_spend_spendable_outputs(this_arg: &crate::lightning::sign::PhantomKeysManager, mut descriptors: crate::c_types::derived::CVec_SpendableOutputDescriptorZ, mut outputs: crate::c_types::derived::CVec_TxOutZ, mut change_destination_script: crate::c_types::derived::CVec_u8Z, mut feerate_sat_per_1000_weight: u32, mut locktime: crate::c_types::derived::COption_PackedLockTimeZ) -> crate::c_types::derived::CResult_TransactionNoneZ {
	let mut local_descriptors = Vec::new(); for mut item in descriptors.into_rust().drain(..) { local_descriptors.push( { item.into_native() }); };
	let mut local_outputs = Vec::new(); for mut item in outputs.into_rust().drain(..) { local_outputs.push( { item.into_rust() }); };
	let mut local_locktime = { /*locktime*/ let locktime_opt = locktime; if locktime_opt.is_none() { None } else { Some({ { ::bitcoin::PackedLockTime({ locktime_opt.take() }) }})} };
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.spend_spendable_outputs(&local_descriptors.iter().collect::<Vec<_>>()[..], local_outputs, ::bitcoin::blockdata::script::Script::from(change_destination_script.into_rust()), feerate_sat_per_1000_weight, local_locktime, secp256k1::global::SECP256K1);
	let mut local_ret = match ret { Ok(mut o) => crate::c_types::CResultTempl::ok( { crate::c_types::Transaction::from_bitcoin(&o) }).into(), Err(mut e) => crate::c_types::CResultTempl::err( { () /*e*/ }).into() };
	local_ret
}

/// See [`KeysManager::derive_channel_keys`] for documentation on this method.
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomKeysManager_derive_channel_keys(this_arg: &crate::lightning::sign::PhantomKeysManager, mut channel_value_satoshis: u64, params: *const [u8; 32]) -> crate::lightning::sign::InMemorySigner {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.derive_channel_keys(channel_value_satoshis, unsafe { &*params});
	crate::lightning::sign::InMemorySigner { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Gets the \"node_id\" secret key used to sign gossip announcements, decode onion data, etc.
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomKeysManager_get_node_secret_key(this_arg: &crate::lightning::sign::PhantomKeysManager) -> crate::c_types::SecretKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_node_secret_key();
	crate::c_types::SecretKey::from_rust(ret)
}

/// Gets the \"node_id\" secret key of the phantom node used to sign invoices, decode the
/// last-hop onion data, etc.
#[must_use]
#[no_mangle]
pub extern "C" fn PhantomKeysManager_get_phantom_node_secret_key(this_arg: &crate::lightning::sign::PhantomKeysManager) -> crate::c_types::SecretKey {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.get_phantom_node_secret_key();
	crate::c_types::SecretKey::from_rust(ret)
}

