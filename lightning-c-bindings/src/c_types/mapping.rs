#![allow(missing_docs)]

pub trait FromC<T: Sized> {
	fn from_c(from: T) -> Self;
}

pub trait IntoRust<T: Sized> {
	fn into_rust_owned(self) -> T;
}
pub trait IntoRustRef<'lft_in, 'lft_out, T: Sized> {
	fn into_rust_ref(&'lft_in self) -> &'lft_out T;
}
pub trait IntoRustRefMut<'lft_in, 'lft_out, T: Sized> {
	fn into_rust_ref_mut(&'lft_in self) -> &'lft_out mut T;
}

// impl<U, T: FromC<U>> IntoRust<T> for U {
//	 fn into_rust_owned(self) -> T {
//		 FromC::from_c(self)
//	 }
// }

impl IntoRust<std::time::Duration > for u64 {
	fn into_rust_owned(self) -> std::time::Duration  {
		std::time::Duration::from_secs(self)
	}
}
impl IntoRust<std::time::SystemTime > for u64 {
	fn into_rust_owned(self) -> std::time::SystemTime  {
		::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self)
	}
}
impl IntoRust<bitcoin::bech32::u5> for crate::c_types::u5 {
	fn into_rust_owned(self) -> bitcoin::bech32::u5 {
		self.into()
	}
}

impl IntoRust<String> for  crate::c_types::derived::CVec_u8Z{
	fn into_rust_owned(mut self) -> String {
		String::from_utf8(self.into_rust()).unwrap()
	}
}
impl IntoRust<&'static str> for crate::c_types::Str {
	fn into_rust_owned(self) -> &'static str {
		self.into()
	}
}

macro_rules! into_rust_from_c {
	($from:ty, $to:ty, $method_name:ident) => {
		impl IntoRust<$to> for $from {
			fn into_rust_owned(self) -> $to {
				self.$method_name()
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

impl IntoRust<::bitcoin::secp256k1::key::SecretKey> for *const [u8; 32]{
	fn into_rust_owned(self) -> ::bitcoin::secp256k1::key::SecretKey {
		::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *self }[..]).unwrap()
	}
}
impl IntoRust<::bitcoin::hash_types::Txid> for *const [u8; 32] {
	fn into_rust_owned(self) -> ::bitcoin::hash_types::Txid{
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::Txid::from_slice(&unsafe { *self }[..]).unwrap()
	}
}
impl IntoRust<::bitcoin::hash_types::Txid> for crate::c_types::ThirtyTwoBytes {
	fn into_rust_owned(self) -> ::bitcoin::hash_types::Txid  {
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::Txid::from_slice(&self.data[..]).unwrap()
	}
}
impl IntoRust<::bitcoin::hash_types::BlockHash> for crate::c_types::ThirtyTwoBytes {
	fn into_rust_owned(self) -> ::bitcoin::hash_types::BlockHash  {
		use ::bitcoin::hashes::Hash;
		::bitcoin::hash_types::BlockHash::from_slice(&self.data[..]).unwrap()
	}
}

macro_rules! thirty_two_bytes_ldk_types {
	($($ty:tt)+) => {
		impl IntoRust<$($ty)+> for *const [u8; 32] {
			fn into_rust_owned(self) -> $($ty)+ {
				$($ty)+(unsafe { *self })
			}
		}
		impl IntoRust<$($ty)+> for crate::c_types::ThirtyTwoBytes {
			fn into_rust_owned(self) -> $($ty)+ {
				$($ty)+(self.data)
			}
		}
	};
}
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentHash);
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentPreimage);
thirty_two_bytes_ldk_types!(::lightning::ln::channelmanager::PaymentSecret);

impl IntoRust<bitcoin::blockdata::block::BlockHeader> for *const [u8; 80] {
	fn into_rust_owned(self) -> bitcoin::blockdata::block::BlockHeader {
		::bitcoin::consensus::encode::deserialize(unsafe { &*self }).unwrap()
	}
}
impl IntoRust<bitcoin::blockdata::block::Block> for crate::c_types::u8slice {
	fn into_rust_owned(self) -> bitcoin::blockdata::block::Block {
		::bitcoin::consensus::encode::deserialize(self.to_slice()).unwrap()
	}
}

macro_rules! owned_u8_arr_from_c {
	($from:ty, $to:ty) => {
		impl IntoRust<$to> for $from {
			fn into_rust_owned(self) -> $to {
				self.data
			}
		}
	}
}
macro_rules! ref_u8_arr_from_c {
	($arr_ty:ty) => {
		impl IntoRust<&'static $arr_ty> for *const $arr_ty {
			fn into_rust_owned(self) -> &'static $arr_ty {
				unsafe { &*self }
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
		impl<'a> IntoRust<&'a [$to]> for &'a $from {
			fn into_rust_owned(self) -> &'a [$to] {
				self.to_slice()
			}
		}
	}
}
ref_slice_from_c!(crate::c_types::u8slice, u8);

impl IntoRust<bitcoin::blockdata::script::Script> for crate::c_types::derived::CVec_u8Z {
	fn into_rust_owned(mut self) -> bitcoin::blockdata::script::Script {
		bitcoin::blockdata::script::Script::from(self.into_rust())
	}
}
impl IntoRust<bitcoin::blockdata::script::Script> for crate::c_types::u8slice {
	fn into_rust_owned(self) -> bitcoin::blockdata::script::Script {
		bitcoin::blockdata::script::Script::from(Vec::from(self.to_slice()))
	}
}
