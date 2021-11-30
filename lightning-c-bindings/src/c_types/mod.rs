//! This module contains standard C-mapped types for types not in the original crate.

/// Auto-generated C-mapped types for templated containers
pub mod derived;

use bitcoin::Transaction as BitcoinTransaction;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::key::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::key::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::Signature as SecpSignature;
use bitcoin::secp256k1::Error as SecpError;
use bitcoin::secp256k1::recovery::RecoveryId;
use bitcoin::secp256k1::recovery::RecoverableSignature as SecpRecoverableSignature;
use bitcoin::bech32;

use std::convert::TryInto; // Bindings need at least rustc 1.34
use core::ffi::c_void;
use std::io::{Cursor, Read}; // TODO: We should use core2 here when we support no_std

#[repr(C)]
/// A dummy struct of which an instance must never exist.
/// This corresponds to the Rust type `Infallible`, or, in unstable rust, `!`
pub struct NotConstructable {
	_priv_thing: core::convert::Infallible,
}
impl From<core::convert::Infallible> for NotConstructable {
	fn from(_: core::convert::Infallible) -> Self { unreachable!(); }
}

/// Integer in the range `0..32`
#[derive(PartialEq, Eq, Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct u5(u8);

impl From<bech32::u5> for u5 {
	fn from(o: bech32::u5) -> Self { Self(o.to_u8()) }
}
impl Into<bech32::u5> for u5 {
	fn into(self) -> bech32::u5 { bech32::u5::try_from_u8(self.0).expect("u5 objects must be in the range 0..32") }
}

#[derive(Clone)]
#[repr(C)]
/// Represents a valid secp256k1 public key serialized in "compressed form" as a 33 byte array.
pub struct PublicKey {
	/// The bytes of the public key
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
/// Represents a valid secp256k1 secret key serialized as a 32 byte array.
pub struct SecretKey {
	/// The bytes of the secret key
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
/// Represents a secp256k1 signature serialized as two 32-byte numbers
pub struct Signature {
	/// The bytes of the signature in "compact" form
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
#[derive(Clone)]
/// Represents a secp256k1 signature serialized as two 32-byte numbers as well as a tag which
/// allows recovering the exact public key which created the signature given the message.
pub struct RecoverableSignature {
	/// The bytes of the signature in "compact" form plus a "Recovery ID" which allows for
	/// recovery.
	pub serialized_form: [u8; 68],
}
impl RecoverableSignature {
	pub(crate) fn from_rust(pk: &SecpRecoverableSignature) -> Self {
		let (id, compact_form) = pk.serialize_compact();
		let mut serialized_form = [0; 68];
		serialized_form[0..64].copy_from_slice(&compact_form[..]);
		serialized_form[64..].copy_from_slice(&id.to_i32().to_le_bytes());
		Self { serialized_form }
	}
	pub(crate) fn into_rust(&self) -> SecpRecoverableSignature {
		let mut id = [0; 4];
		id.copy_from_slice(&self.serialized_form[64..]);
		SecpRecoverableSignature::from_compact(&self.serialized_form[0..64],
				RecoveryId::from_i32(i32::from_le_bytes(id)).expect("Invalid Recovery ID"))
			.unwrap()
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents an error returned from libsecp256k1 during validation of some secp256k1 data
pub enum Secp256k1Error {
	/// Signature failed verification
	IncorrectSignature,
	/// Badly sized message ("messages" are actually fixed-sized digests; see the MESSAGE_SIZE constant)
	InvalidMessage,
	/// Bad public key
	InvalidPublicKey,
	/// Bad signature
	InvalidSignature,
	/// Bad secret key
	InvalidSecretKey,
	/// Bad recovery id
	InvalidRecoveryId,
	/// Invalid tweak for add_assign or mul_assign
	InvalidTweak,
	/// tweak_add_check failed on an xonly public key
	TweakCheckFailed,
	/// Didn't pass enough memory to context creation with preallocated memory
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
#[allow(missing_docs)] // If there's no docs upstream, that's good enough for us
#[derive(Clone, Copy, PartialEq)]
/// Represents an IO Error. Note that some information is lost in the conversion from Rust.
pub enum IOError {
	NotFound,
	PermissionDenied,
	ConnectionRefused,
	ConnectionReset,
	ConnectionAborted,
	NotConnected,
	AddrInUse,
	AddrNotAvailable,
	BrokenPipe,
	AlreadyExists,
	WouldBlock,
	InvalidInput,
	InvalidData,
	TimedOut,
	WriteZero,
	Interrupted,
	Other,
	UnexpectedEof,
}
impl IOError {
	pub(crate) fn from_rust(err: std::io::Error) -> Self {
		match err.kind() {
			std::io::ErrorKind::NotFound => IOError::NotFound,
			std::io::ErrorKind::PermissionDenied => IOError::PermissionDenied,
			std::io::ErrorKind::ConnectionRefused => IOError::ConnectionRefused,
			std::io::ErrorKind::ConnectionReset => IOError::ConnectionReset,
			std::io::ErrorKind::ConnectionAborted => IOError::ConnectionAborted,
			std::io::ErrorKind::NotConnected => IOError::NotConnected,
			std::io::ErrorKind::AddrInUse => IOError::AddrInUse,
			std::io::ErrorKind::AddrNotAvailable => IOError::AddrNotAvailable,
			std::io::ErrorKind::BrokenPipe => IOError::BrokenPipe,
			std::io::ErrorKind::AlreadyExists => IOError::AlreadyExists,
			std::io::ErrorKind::WouldBlock => IOError::WouldBlock,
			std::io::ErrorKind::InvalidInput => IOError::InvalidInput,
			std::io::ErrorKind::InvalidData => IOError::InvalidData,
			std::io::ErrorKind::TimedOut => IOError::TimedOut,
			std::io::ErrorKind::WriteZero => IOError::WriteZero,
			std::io::ErrorKind::Interrupted => IOError::Interrupted,
			std::io::ErrorKind::Other => IOError::Other,
			std::io::ErrorKind::UnexpectedEof => IOError::UnexpectedEof,
			_ => IOError::Other,
		}
	}
	pub(crate) fn to_rust(&self) -> std::io::Error {
		std::io::Error::new(match self {
			IOError::NotFound => std::io::ErrorKind::NotFound,
			IOError::PermissionDenied => std::io::ErrorKind::PermissionDenied,
			IOError::ConnectionRefused => std::io::ErrorKind::ConnectionRefused,
			IOError::ConnectionReset => std::io::ErrorKind::ConnectionReset,
			IOError::ConnectionAborted => std::io::ErrorKind::ConnectionAborted,
			IOError::NotConnected => std::io::ErrorKind::NotConnected,
			IOError::AddrInUse => std::io::ErrorKind::AddrInUse,
			IOError::AddrNotAvailable => std::io::ErrorKind::AddrNotAvailable,
			IOError::BrokenPipe => std::io::ErrorKind::BrokenPipe,
			IOError::AlreadyExists => std::io::ErrorKind::AlreadyExists,
			IOError::WouldBlock => std::io::ErrorKind::WouldBlock,
			IOError::InvalidInput => std::io::ErrorKind::InvalidInput,
			IOError::InvalidData => std::io::ErrorKind::InvalidData,
			IOError::TimedOut => std::io::ErrorKind::TimedOut,
			IOError::WriteZero => std::io::ErrorKind::WriteZero,
			IOError::Interrupted => std::io::ErrorKind::Interrupted,
			IOError::Other => std::io::ErrorKind::Other,
			IOError::UnexpectedEof => std::io::ErrorKind::UnexpectedEof,
		}, "")
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
	/// The serialized transaction data.
	///
	/// This is non-const for your convenience, an object passed to Rust is never written to.
	pub data: *mut u8,
	/// The length of the serialized transaction
	pub datalen: usize,
	/// Whether the data pointed to by `data` should be freed or not.
	pub data_is_owned: bool,
}
impl Transaction {
	fn from_vec(vec: Vec<u8>) -> Self {
		let datalen = vec.len();
		let data = Box::into_raw(vec.into_boxed_slice());
		Self {
			data: unsafe { (*data).as_mut_ptr() },
			datalen,
			data_is_owned: true,
		}
	}
	pub(crate) fn into_bitcoin(&self) -> BitcoinTransaction {
		if self.datalen == 0 { panic!("0-length buffer can never represent a valid Transaction"); }
		::bitcoin::consensus::encode::deserialize(unsafe { std::slice::from_raw_parts(self.data, self.datalen) }).unwrap()
	}
	pub(crate) fn from_bitcoin(btc: &BitcoinTransaction) -> Self {
		let vec = ::bitcoin::consensus::encode::serialize(btc);
		Self::from_vec(vec)
	}
}
impl Drop for Transaction {
	fn drop(&mut self) {
		if self.data_is_owned && self.datalen != 0 {
			let _ = derived::CVec_u8Z { data: self.data as *mut u8, datalen: self.datalen };
		}
	}
}
impl Clone for Transaction {
	fn clone(&self) -> Self {
		let sl = unsafe { std::slice::from_raw_parts(self.data, self.datalen) };
		let mut v = Vec::new();
		v.extend_from_slice(&sl);
		Self::from_vec(v)
	}
}
#[no_mangle]
/// Frees the data buffer, if data_is_owned is set and datalen > 0.
pub extern "C" fn Transaction_free(_res: Transaction) { }

pub(crate) fn bitcoin_to_C_outpoint(outpoint: ::bitcoin::blockdata::transaction::OutPoint) -> crate::lightning::chain::transaction::OutPoint {
	crate::lightning::chain::transaction::OutPoint_new(ThirtyTwoBytes { data: outpoint.txid.into_inner() }, outpoint.vout.try_into().unwrap())
}
pub(crate) fn C_to_bitcoin_outpoint(outpoint: crate::lightning::chain::transaction::OutPoint) -> ::bitcoin::blockdata::transaction::OutPoint {
	unsafe {
		::bitcoin::blockdata::transaction::OutPoint {
			txid: (*outpoint.inner).txid, vout: (*outpoint.inner).index as u32
		}
	}
}

#[repr(C)]
#[derive(Clone)]
/// A transaction output including a scriptPubKey and value.
/// This type *does* own its own memory, so must be free'd appropriately.
pub struct TxOut {
	/// The script_pubkey in this output
	pub script_pubkey: derived::CVec_u8Z,
	/// The value, in satoshis, of this output
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
/// Convenience function for constructing a new TxOut
pub extern "C" fn TxOut_new(script_pubkey: derived::CVec_u8Z, value: u64) -> TxOut {
	TxOut { script_pubkey, value }
}
#[no_mangle]
/// Frees the data pointed to by script_pubkey.
pub extern "C" fn TxOut_free(_res: TxOut) { }
#[no_mangle]
/// Creates a new TxOut which has the same data as `orig` but with a new script buffer.
pub extern "C" fn TxOut_clone(orig: &TxOut) -> TxOut { orig.clone() }

#[repr(C)]
/// A "slice" referencing some byte array. This is simply a length-tagged pointer which does not
/// own the memory pointed to by data.
pub struct u8slice {
	/// A pointer to the byte buffer
	pub data: *const u8,
	/// The number of bytes pointed to by `data`.
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
	pub(crate) fn to_reader<'a>(&'a self) -> Cursor<&'a [u8]> {
		let sl = self.to_slice();
		Cursor::new(sl)
	}
	pub(crate) fn from_vec(v: &derived::CVec_u8Z) -> u8slice {
		Self::from_slice(v.as_slice())
	}
}
pub(crate) fn reader_to_vec<R: Read>(r: &mut R) -> derived::CVec_u8Z {
	let mut res = Vec::new();
	r.read_to_end(&mut res).unwrap();
	derived::CVec_u8Z::from(res)
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Arbitrary 32 bytes, which could represent one of a few different things. You probably want to
/// look up the corresponding function in rust-lightning's docs.
pub struct ThirtyTwoBytes {
	/// The thirty-two bytes
	pub data: [u8; 32],
}
impl ThirtyTwoBytes {
	pub(crate) fn null() -> Self {
		Self { data: [0; 32] }
	}
}

#[repr(C)]
/// A 3-byte byte array.
pub struct ThreeBytes { /** The three bytes */ pub data: [u8; 3], }
#[derive(Clone)]
#[repr(C)]
/// A 4-byte byte array.
pub struct FourBytes { /** The four bytes */ pub data: [u8; 4], }
#[derive(Clone)]
#[repr(C)]
/// A 10-byte byte array.
pub struct TenBytes { /** The ten bytes */ pub data: [u8; 10], }
#[derive(Clone)]
#[repr(C)]
/// A 16-byte byte array.
pub struct SixteenBytes { /** The sixteen bytes */ pub data: [u8; 16], }
#[derive(Clone)]
#[repr(C)]
/// A 20-byte byte array.
pub struct TwentyBytes { /** The twenty bytes */ pub data: [u8; 20], }

pub(crate) struct VecWriter(pub Vec<u8>);
impl lightning::util::ser::Writer for VecWriter {
	fn write_all(&mut self, buf: &[u8]) -> Result<(), ::std::io::Error> {
		self.0.extend_from_slice(buf);
		Ok(())
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
pub(crate) fn maybe_deserialize_obj<I: lightning::util::ser::MaybeReadable>(s: u8slice) -> Result<Option<I>, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice())
}
pub(crate) fn deserialize_obj_arg<A, I: lightning::util::ser::ReadableArgs<A>>(s: u8slice, args: A) -> Result<I, lightning::ln::msgs::DecodeError> {
	I::read(&mut s.to_slice(), args)
}

#[repr(C)]
/// A Rust str object, ie a reference to a UTF8-valid string.
/// This is *not* null-terminated so cannot be used directly as a C string!
pub struct Str {
	/// A pointer to the string's bytes, in UTF8 encoding
	pub chars: *const u8,
	/// The number of bytes (not characters!) pointed to by `chars`
	pub len: usize,
	/// Whether the data pointed to by `chars` should be freed or not.
	pub chars_is_owned: bool,
}
impl Into<Str> for &'static str {
	fn into(self) -> Str {
		Str { chars: self.as_ptr(), len: self.len(), chars_is_owned: false }
	}
}
impl Into<Str> for &mut &'static str {
	fn into(self) -> Str {
		let us: &'static str = *self;
		us.into()
	}
}

impl Str {
	pub(crate) fn into_str(&self) -> &'static str {
		if self.len == 0 { return ""; }
		std::str::from_utf8(unsafe { std::slice::from_raw_parts(self.chars, self.len) }).unwrap()
	}
	pub(crate) fn into_string(mut self) -> String {
		let bytes = if self.len == 0 {
			Vec::new()
		} else if self.chars_is_owned {
			let ret = unsafe {
				Box::from_raw(std::slice::from_raw_parts_mut(unsafe { self.chars as *mut u8 }, self.len))
			}.into();
			self.chars_is_owned = false;
			ret
		} else {
			let mut ret = Vec::with_capacity(self.len);
			ret.extend_from_slice(unsafe { std::slice::from_raw_parts(self.chars, self.len) });
			ret
		};
		String::from_utf8(bytes).unwrap()
	}
}
impl Into<Str> for String {
	fn into(self) -> Str {
		let s = Box::leak(self.into_boxed_str());
		Str { chars: s.as_ptr(), len: s.len(), chars_is_owned: true }
	}
}
impl Clone for Str {
	fn clone(&self) -> Self {
		self.into_str().clone().into()
	}
}

impl Drop for Str {
	fn drop(&mut self) {
		if self.chars_is_owned && self.len != 0 {
			let _ = derived::CVec_u8Z { data: self.chars as *mut u8, datalen: self.len };
		}
	}
}
#[no_mangle]
/// Frees the data buffer, if chars_is_owned is set and len > 0.
pub extern "C" fn Str_free(_res: Str) { }

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


pub(crate) mod ObjOps {
	#[inline]
	#[must_use = "returns new dangling pointer"]
	pub(crate) fn heap_alloc<T>(obj: T) -> *mut T {
		let ptr = Box::into_raw(Box::new(obj));
		nonnull_ptr_to_inner(ptr)
	}
	#[inline]
	pub(crate) fn nonnull_ptr_to_inner<T>(ptr: *const T) -> *mut T {
		if core::mem::size_of::<T>() == 0 {
			// We map `None::<T>` as `T { inner: null, .. }` which works great for all
			// non-Zero-Sized-Types `T`.
			// For ZSTs, we need to differentiate between null implying `None` and null implying
			// `Some` with no allocation.
			// Thus, for ZSTs, we add one (usually) page here, which should always be aligned.
			// Note that this relies on undefined behavior! A pointer to NULL may be valid, but a
			// pointer to NULL + 4096 is almost certainly not. That said, Rust's existing use of
			// `(*mut T)1` for the pointer we're adding to is also not defined, so we should be
			// fine.
			// Note that we add 4095 here as at least the Java client assumes that the low bit on
			// any heap pointer is 0, which is generally provided by malloc, but which is not true
			// for ZSTs "allocated" by `Box::new`.
			debug_assert_eq!(ptr as usize, 1);
			unsafe { (ptr as *mut T).cast::<u8>().add(4096 - 1).cast::<T>() }
		} else {
			// In order to get better test coverage, also increment non-ZST pointers with
			// --cfg=test_mod_pointers, which is set in genbindings.sh for debug builds.
			#[cfg(test_mod_pointers)]
			unsafe { (ptr as *mut T).cast::<u8>().add(4096).cast::<T>() }
			#[cfg(not(test_mod_pointers))]
			unsafe { ptr as *mut T }
		}
	}
	#[inline]
	/// Invert nonnull_ptr_to_inner
	pub(crate) fn untweak_ptr<T>(ptr: *mut T) -> *mut T {
		if core::mem::size_of::<T>() == 0 {
			unsafe { ptr.cast::<u8>().sub(4096 - 1).cast::<T>() }
		} else {
			#[cfg(test_mod_pointers)]
			unsafe { ptr.cast::<u8>().sub(4096).cast::<T>() }
			#[cfg(not(test_mod_pointers))]
			ptr
		}
	}
}

#[cfg(test_mod_pointers)]
#[no_mangle]
/// This function exists for memory safety testing purposes. It should never be used in production
/// code
pub extern "C" fn __unmangle_inner_ptr(ptr: *const c_void) -> *const c_void {
	if ptr as usize == 1 {
		core::ptr::null()
	} else {
		unsafe { ptr.cast::<u8>().sub(4096).cast::<c_void>() }
	}
}

pub(crate) struct SmartPtr<T> {
	ptr: *mut T,
}
impl<T> SmartPtr<T> {
	pub(crate) fn from_obj(o: T) -> Self {
		Self { ptr: Box::into_raw(Box::new(o)) }
	}
	pub(crate) fn null() -> Self {
		Self { ptr: std::ptr::null_mut() }
	}
}
impl<T> Drop for SmartPtr<T> {
	fn drop(&mut self) {
		if self.ptr != std::ptr::null_mut() {
			unsafe { Box::from_raw(self.ptr); }
		}
	}
}
impl<T> std::ops::Deref for SmartPtr<T> {
	type Target = *mut T;
	fn deref(&self) -> &*mut T {
		&self.ptr
	}
}
