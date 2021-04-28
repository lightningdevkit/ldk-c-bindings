/// Map a type from C
pub trait FromC<T: Sized> {
	/// Do the mapping
	fn from_c(from: T) -> Self;
}

impl FromC<u64> for std::time::Duration {
	fn from_c(from: u64) -> Self {
		std::time::Duration::from_secs(from)
	}
}
impl FromC<u64> for std::time::SystemTime {
	fn from_c(from: u64) -> Self {
		::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(from)
	}
}
impl FromC<crate::c_types::u5> for bitcoin::bech32::u5 {
	fn from_c(from: crate::c_types::u5) -> Self {
		from.into()
	}
}

impl FromC<crate::c_types::derived::CVec_u8Z> for String {
	fn from_c(mut from: crate::c_types::derived::CVec_u8Z) -> Self {
		String::from_utf8(from.into_rust()).unwrap()
	}
}
impl FromC<crate::c_types::Str> for &'static str {
	fn from_c(from: crate::c_types::Str) -> Self {
		from.into()
	}
}

macro_rules! into_rust_from_c {
	($from:ty, $to:ty, $method_name:ident) => {
		impl FromC<$from> for $to {
			fn from_c(mut from: $from) -> Self {
				from.$method_name()
			}
		}
	};

	($from:ty, $to:ty) => {
		into_rust_from_c!($from, $to, into_rust);
	};
}
into_rust_from_c!(crate::c_types::PublicKey, bitcoin::secp256k1::key::PublicKey);
into_rust_from_c!(crate::c_types::SecretKey, bitcoin::secp256k1::key::SecretKey);
into_rust_from_c!(crate::c_types::Signature, bitcoin::secp256k1::Signature);
into_rust_from_c!(crate::c_types::TxOut, bitcoin::blockdata::transaction::TxOut);

into_rust_from_c!(crate::c_types::Transaction, bitcoin::blockdata::transaction::Transaction, into_bitcoin);
into_rust_from_c!(crate::c_types::Network, bitcoin::network::constants::Network, into_bitcoin);

impl FromC<*const [u8; 32]> for ::bitcoin::secp256k1::key::SecretKey {
	fn from_c(from: *const [u8; 32]) -> Self {
		::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *from }[..]).unwrap()
	}
}
impl FromC<*const [u8; 32]> for ::bitcoin::hash_types::Txid {
	fn from_c(from: *const [u8; 32]) -> Self {
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::Txid::from_slice(&unsafe { *from }[..]).unwrap()
	}
}
impl FromC<crate::c_types::ThirtyTwoBytes> for ::bitcoin::hash_types::Txid {
	fn from_c(from: crate::c_types::ThirtyTwoBytes) -> Self {
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::Txid::from_slice(&from.data[..]).unwrap()
	}
}
impl FromC<crate::c_types::ThirtyTwoBytes> for ::bitcoin::hash_types::BlockHash {
	fn from_c(from: crate::c_types::ThirtyTwoBytes) -> Self {
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::BlockHash::from_slice(&from.data[..]).unwrap()
	}
}

macro_rules! thirty_two_bytes_ldk_types {
	($ty:ty) => {
		impl FromC<*const [u8; 32]> for $ty {
			fn from_c(from: *const [u8; 32]) -> Self {
				Self(unsafe { *from })
			}
		}
		impl FromC<crate::c_types::ThirtyTwoBytes> for $ty {
			fn from_c(from: crate::c_types::ThirtyTwoBytes) -> Self {
				Self(from.data)
			}
		}
	};
}
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentHash);
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentPreimage);
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentSecret);

impl FromC<*const [u8; 80]> for bitcoin::blockdata::block::BlockHeader {
	fn from_c(from: *const [u8; 80]) -> Self {
		::bitcoin::consensus::encode::deserialize(unsafe { &*from }).unwrap()
	}
}
impl FromC<crate::c_types::u8slice> for bitcoin::blockdata::block::Block {
	fn from_c(from: crate::c_types::u8slice) -> Self {
		::bitcoin::consensus::encode::deserialize(from.to_slice()).unwrap()
	}
}

macro_rules! owned_u8_arr_from_c {
	($from:ty, $to:ty) => {
		impl FromC<$from> for $to {
			fn from_c(from: $from) -> Self {
				from.data
			}
		}
	}
}
macro_rules! ref_u8_arr_from_c {
	($arr_ty:ty) => {
		impl FromC<*const $arr_ty> for &$arr_ty {
			fn from_c(from: *const $arr_ty) -> Self {
				unsafe { &*from }
			}
		}
	}
}
owned_u8_arr_from_c!(crate::c_types::ThirtyTwoBytes, [u8; 32]);
owned_u8_arr_from_c!(crate::c_types::TwentyBytes, [u8; 20]);
owned_u8_arr_from_c!(crate::c_types::SixteenBytes, [u8; 16]);
owned_u8_arr_from_c!(crate::c_types::TenBytes, [u8; 10]);
owned_u8_arr_from_c!(crate::c_types::FourBytes, [u8; 4]);
owned_u8_arr_from_c!(crate::c_types::ThreeBytes, [u8; 3]);
ref_u8_arr_from_c!([u8; 32]);

macro_rules! ref_slice_from_c {
	($from:ty, $to:ty) => {
		impl<'a> FromC<&'a $from> for &'a [$to] {
			fn from_c(from: &'a $from) -> Self {
				from.to_slice()
			}
		}
	}
}
ref_slice_from_c!(crate::c_types::u8slice, u8);

impl FromC<crate::c_types::derived::CVec_u8Z> for bitcoin::blockdata::script::Script {
	fn from_c(mut from: crate::c_types::derived::CVec_u8Z) -> Self {
		bitcoin::blockdata::script::Script::from(from.into_rust())
	}
}
impl FromC<crate::c_types::u8slice> for bitcoin::blockdata::script::Script {
	fn from_c(from: crate::c_types::u8slice) -> Self {
		bitcoin::blockdata::script::Script::from(Vec::from(from.to_slice()))
	}
}
