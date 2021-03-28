pub mod derived;

use bitcoin::Script as BitcoinScript;
use bitcoin::Transaction as BitcoinTransaction;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::key::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::key::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::Signature as SecpSignature;
use bitcoin::secp256k1::Error as SecpError;

use std::convert::TryInto; // Bindings need at least rustc 1.34

#[derive(Clone)]
#[repr(C)]
pub struct PublicKey {
	pub compressed_form: [u8; 33],
}
impl PublicKey {
	pub(crate) fn from_rust(pk: &SecpPublicKey) -> Self {
		Self {
			compressed_form: pk.serialize(),
		}
	}
	pub(crate) fn into_rust(&self) -> SecpPublicKey {
		SecpPublicKey::from_slice(&self.compressed_form).unwrap()
	}
	pub(crate) fn is_null(&self) -> bool { self.compressed_form[..] == [0; 33][..] }
	pub(crate) fn null() -> Self { Self { compressed_form: [0; 33] } }
}

#[repr(C)]
pub struct SecretKey {
	pub bytes: [u8; 32],
}
impl SecretKey {
	// from_rust isn't implemented for a ref since we just return byte array refs directly
	pub(crate) fn from_rust(sk: SecpSecretKey) -> Self {
		let mut bytes = [0; 32];
		bytes.copy_from_slice(&sk[..]);
		Self { bytes }
	}
	pub(crate) fn into_rust(&self) -> SecpSecretKey {
		SecpSecretKey::from_slice(&self.bytes).unwrap()
	}
}

#[repr(C)]
#[derive(Clone)]
pub struct Signature {
	pub compact_form: [u8; 64],
}
impl Signature {
	pub(crate) fn from_rust(pk: &SecpSignature) -> Self {
		Self {
			compact_form: pk.serialize_compact(),
		}
	}
	pub(crate) fn into_rust(&self) -> SecpSignature {
		SecpSignature::from_compact(&self.compact_form).unwrap()
	}
	// The following are used for Option<Signature> which we support, but don't use anymore
	#[allow(unused)] pub(crate) fn is_null(&self) -> bool { self.compact_form[..] == [0; 64][..] }
	#[allow(unused)] pub(crate) fn null() -> Self { Self { compact_form: [0; 64] } }
}

#[repr(C)]
pub enum Secp256k1Error {
	IncorrectSignature,
	InvalidMessage,
	InvalidPublicKey,
	InvalidSignature,
	InvalidSecretKey,
	InvalidRecoveryId,
	InvalidTweak,
	TweakCheckFailed,
	NotEnoughMemory,
}
impl Secp256k1Error {
	pub(crate) fn from_rust(err: SecpError) -> Self {
		match err {
			SecpError::IncorrectSignature => Secp256k1Error::IncorrectSignature,
			SecpError::InvalidMessage => Secp256k1Error::InvalidMessage,
			SecpError::InvalidPublicKey => Secp256k1Error::InvalidPublicKey,
			SecpError::InvalidSignature => Secp256k1Error::InvalidSignature,
			SecpError::InvalidSecretKey => Secp256k1Error::InvalidSecretKey,
			SecpError::InvalidRecoveryId => Secp256k1Error::InvalidRecoveryId,
			SecpError::InvalidTweak => Secp256k1Error::InvalidTweak,
			SecpError::TweakCheckFailed => Secp256k1Error::TweakCheckFailed,
			SecpError::NotEnoughMemory => Secp256k1Error::NotEnoughMemory,
		}
	}
}

#[repr(C)]
/// A serialized transaction, in (pointer, length) form.
///
/// This type optionally owns its own memory, and thus the semantics around access change based on
/// the `data_is_owned` flag. If `data_is_owned` is set, you must call `Transaction_free` to free
/// the underlying buffer before the object goes out of scope. If `data_is_owned` is not set, any
/// access to the buffer after the scope in which the object was provided to you is invalid. eg,
/// access after you return from the call in which a `!data_is_owned` `Transaction` is provided to
/// you would be invalid.
///
/// Note that, while it may change in the future, because transactions on the Rust side are stored
/// in a deserialized form, all `Transaction`s generated on the Rust side will have `data_is_owned`
/// set. Similarly, while it may change in the future, all `Transaction`s you pass to Rust may have
/// `data_is_owned` either set or unset at your discretion.
pub struct Transaction {
	/// This is non-const for your convenience, an object passed to Rust is never written to.
	pub data: *mut u8,
	pub datalen: usize,
	pub data_is_owned: bool,
}
impl Transaction {
	pub(crate) fn into_bitcoin(&self) -> BitcoinTransaction {
		if self.datalen == 0 { panic!("0-length buffer can never represent a valid Transaction"); }
		::bitcoin::consensus::encode::deserialize(unsafe { std::slice::from_raw_parts(self.data, self.datalen) }).unwrap()
	}
	pub(crate) fn from_vec(v: Vec<u8>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self {
			data: unsafe { (*data).as_mut_ptr() },
			datalen,
			data_is_owned: true,
		}
	}
}
impl Drop for Transaction {
	fn drop(&mut self) {
		if self.data_is_owned && self.datalen != 0 {
			let _ = derived::CVec_u8Z { data: self.data as *mut u8, datalen: self.datalen };
		}
	}
}
#[no_mangle]
pub extern "C" fn Transaction_free(_res: Transaction) { }

pub(crate) fn bitcoin_to_C_outpoint(outpoint: ::bitcoin::blockdata::transaction::OutPoint) -> crate::chain::transaction::OutPoint {
	crate::chain::transaction::OutPoint_new(ThirtyTwoBytes { data: outpoint.txid.into_inner() }, outpoint.vout.try_into().unwrap())
}

#[repr(C)]
#[derive(Clone)]
/// A transaction output including a scriptPubKey and value.
/// This type *does* own its own memory, so must be free'd appropriately.
pub struct TxOut {
	pub script_pubkey: derived::CVec_u8Z,
	pub value: u64,
}

impl TxOut {
	pub(crate) fn into_rust(mut self) -> ::bitcoin::blockdata::transaction::TxOut {
		::bitcoin::blockdata::transaction::TxOut {
			script_pubkey: self.script_pubkey.into_rust().into(),
			value: self.value,
		}
	}
	pub(crate) fn from_rust(txout: ::bitcoin::blockdata::transaction::TxOut) -> Self {
		Self {
			script_pubkey: derived::CVec_u8Z::from(txout.script_pubkey.into_bytes()),
			value: txout.value
		}
	}
}
#[no_mangle]
pub extern "C" fn TxOut_free(_res: TxOut) { }
#[no_mangle]
pub extern "C" fn TxOut_clone(orig: &TxOut) -> TxOut { orig.clone() }

#[repr(C)]
pub struct u8slice {
	pub data: *const u8,
	pub datalen: usize
}
impl u8slice {
	pub(crate) fn from_slice(s: &[u8]) -> Self {
		Self {
			data: s.as_ptr(),
			datalen: s.len(),
		}
	}
	pub(crate) fn to_slice(&self) -> &[u8] {
		if self.datalen == 0 { return &[]; }
		unsafe { std::slice::from_raw_parts(self.data, self.datalen) }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Arbitrary 32 bytes, which could represent one of a few different things. You probably want to
/// look up the corresponding function in rust-lightning's docs.
pub struct ThirtyTwoBytes {
	pub data: [u8; 32],
}
impl ThirtyTwoBytes {
	pub(crate) fn null() -> Self {
		Self { data: [0; 32] }
	}
}

#[repr(C)]
pub struct ThreeBytes { pub data: [u8; 3], }
#[derive(Clone)]
#[repr(C)]
pub struct FourBytes { pub data: [u8; 4], }
#[derive(Clone)]
#[repr(C)]
pub struct TenBytes { pub data: [u8; 10], }
#[derive(Clone)]
#[repr(C)]
pub struct SixteenBytes { pub data: [u8; 16], }

#[repr(C)]
pub struct u64Option {
	pub value: u64,
	pub is_set: bool,
}
#[repr(C)]
pub struct u32Option {
	pub value: u32,
	pub is_set: bool,
}

pub(crate) struct VecWriter(pub Vec<u8>);
impl lightning::util::ser::Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
	}
	fn size_hint(&mut self, size: usize) {
		self.0.reserve_exact(size);
	}
}
pub(crate) fn serialize_obj<I: lightning::util::ser::Writeable>(i: &I) -> derived::CVec_u8Z {
	let mut out = VecWriter(Vec::new());
	i.write(&mut out).unwrap();
	derived::CVec_u8Z::from(out.0)
}
pub(crate) fn deserialize_obj<I: lightning::util::ser::Readable>(s: u8slice) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice())
}
pub(crate) fn deserialize_obj_arg<A, I: lightning::util::ser::ReadableArgs<A>>(s: u8slice, args: A) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice(), args)
}

#[repr(C)]
#[derive(Copy, Clone)]
/// A Rust str object, ie a reference to a UTF8-valid string.
/// This is *not* null-terminated so cannot be used directly as a C string!
pub struct Str {
	pub chars: *const u8,
	pub len: usize
}
impl Into<Str> for &'static str {
	fn into(self) -> Str {
		Str { chars: self.as_ptr(), len: self.len() }
	}
}
impl Into<&'static str> for Str {
	fn into(self) -> &'static str {
		if self.len == 0 { return ""; }
		std::str::from_utf8(unsafe { std::slice::from_raw_parts(self.chars, self.len) }).unwrap()
	}
}

// Note that the C++ headers memset(0) all the Templ types to avoid deallocation!
// Thus, they must gracefully handle being completely null in _free.

// TODO: Integer/bool primitives should avoid the pointer indirection for underlying types
// everywhere in the containers.

#[repr(C)]
pub(crate) union CResultPtr<O, E> {
	pub(crate) result: *mut O,
	pub(crate) err: *mut E,
}
#[repr(C)]
pub(crate) struct CResultTempl<O, E> {
	pub(crate) contents: CResultPtr<O, E>,
	pub(crate) result_ok: bool,
}
impl<O, E> CResultTempl<O, E> {
	pub(crate) extern "C" fn ok(o: O) -> Self {
		CResultTempl {
			contents: CResultPtr {
				result: Box::into_raw(Box::new(o)),
			},
			result_ok: true,
		}
	}
	pub(crate) extern "C" fn err(e: E) -> Self {
		CResultTempl {
			contents: CResultPtr {
				err: Box::into_raw(Box::new(e)),
			},
			result_ok: false,
		}
	}
}
impl<O, E> Drop for CResultTempl<O, E> {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !self.contents.result.is_null() } {
				unsafe { Box::from_raw(self.contents.result) };
			}
		} else if unsafe { !self.contents.err.is_null() } {
			unsafe { Box::from_raw(self.contents.err) };
		}
	}
}

/// Utility to make it easy to set a pointer to null and get its original value in line.
pub(crate) trait TakePointer<T> {
	fn take_ptr(&mut self) -> T;
}
impl<T> TakePointer<*const T> for *const T {
	fn take_ptr(&mut self) -> *const T {
		let ret = *self;
		*self = std::ptr::null();
		ret
	}
}
impl<T> TakePointer<*mut T> for *mut T {
	fn take_ptr(&mut self) -> *mut T {
		let ret = *self;
		*self = std::ptr::null_mut();
		ret
	}
}
