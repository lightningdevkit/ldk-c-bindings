#[repr(C)]
/// The contents of CResult_SecretKeyErrorZ
pub union CResult_SecretKeyErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::SecretKey,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
/// A CResult_SecretKeyErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::SecretKey on success and a crate::c_types::Secp256k1Error on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SecretKeyErrorZ {
	/// The contents of this CResult_SecretKeyErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SecretKeyErrorZPtr,
	/// Whether this CResult_SecretKeyErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SecretKeyErrorZ in the success state.
pub extern "C" fn CResult_SecretKeyErrorZ_ok(o: crate::c_types::SecretKey) -> CResult_SecretKeyErrorZ {
	CResult_SecretKeyErrorZ {
		contents: CResult_SecretKeyErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SecretKeyErrorZ in the error state.
pub extern "C" fn CResult_SecretKeyErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_SecretKeyErrorZ {
	CResult_SecretKeyErrorZ {
		contents: CResult_SecretKeyErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SecretKeyErrorZ_is_ok(o: &CResult_SecretKeyErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SecretKeyErrorZ.
pub extern "C" fn CResult_SecretKeyErrorZ_free(_res: CResult_SecretKeyErrorZ) { }
impl Drop for CResult_SecretKeyErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>> for CResult_SecretKeyErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::SecretKey, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SecretKeyErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SecretKeyErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_PublicKeyErrorZ
pub union CResult_PublicKeyErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::PublicKey,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
/// A CResult_PublicKeyErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::PublicKey on success and a crate::c_types::Secp256k1Error on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PublicKeyErrorZ {
	/// The contents of this CResult_PublicKeyErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PublicKeyErrorZPtr,
	/// Whether this CResult_PublicKeyErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PublicKeyErrorZ in the success state.
pub extern "C" fn CResult_PublicKeyErrorZ_ok(o: crate::c_types::PublicKey) -> CResult_PublicKeyErrorZ {
	CResult_PublicKeyErrorZ {
		contents: CResult_PublicKeyErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PublicKeyErrorZ in the error state.
pub extern "C" fn CResult_PublicKeyErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_PublicKeyErrorZ {
	CResult_PublicKeyErrorZ {
		contents: CResult_PublicKeyErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PublicKeyErrorZ_is_ok(o: &CResult_PublicKeyErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PublicKeyErrorZ.
pub extern "C" fn CResult_PublicKeyErrorZ_free(_res: CResult_PublicKeyErrorZ) { }
impl Drop for CResult_PublicKeyErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>> for CResult_PublicKeyErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::PublicKey, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PublicKeyErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PublicKeyErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PublicKeyErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PublicKeyErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::PublicKey>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PublicKeyErrorZPtr {
				err: Box::into_raw(Box::new(<crate::c_types::Secp256k1Error>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PublicKeyErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PublicKeyErrorZ_clone(orig: &CResult_PublicKeyErrorZ) -> CResult_PublicKeyErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_TxCreationKeysDecodeErrorZ
pub union CResult_TxCreationKeysDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::TxCreationKeys,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_TxCreationKeysDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::TxCreationKeys on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TxCreationKeysDecodeErrorZ {
	/// The contents of this CResult_TxCreationKeysDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TxCreationKeysDecodeErrorZPtr,
	/// Whether this CResult_TxCreationKeysDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysDecodeErrorZ in the success state.
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::TxCreationKeys) -> CResult_TxCreationKeysDecodeErrorZ {
	CResult_TxCreationKeysDecodeErrorZ {
		contents: CResult_TxCreationKeysDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysDecodeErrorZ in the error state.
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_TxCreationKeysDecodeErrorZ {
	CResult_TxCreationKeysDecodeErrorZ {
		contents: CResult_TxCreationKeysDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_is_ok(o: &CResult_TxCreationKeysDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TxCreationKeysDecodeErrorZ.
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_free(_res: CResult_TxCreationKeysDecodeErrorZ) { }
impl Drop for CResult_TxCreationKeysDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TxCreationKeys, crate::lightning::ln::msgs::DecodeError>> for CResult_TxCreationKeysDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TxCreationKeys, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxCreationKeysDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxCreationKeysDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TxCreationKeysDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TxCreationKeysDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::TxCreationKeys>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TxCreationKeysDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_TxCreationKeysDecodeErrorZ_clone(orig: &CResult_TxCreationKeysDecodeErrorZ) -> CResult_TxCreationKeysDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelPublicKeysDecodeErrorZ
pub union CResult_ChannelPublicKeysDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::ChannelPublicKeys,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelPublicKeysDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::ChannelPublicKeys on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelPublicKeysDecodeErrorZ {
	/// The contents of this CResult_ChannelPublicKeysDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelPublicKeysDecodeErrorZPtr,
	/// Whether this CResult_ChannelPublicKeysDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelPublicKeysDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::ChannelPublicKeys) -> CResult_ChannelPublicKeysDecodeErrorZ {
	CResult_ChannelPublicKeysDecodeErrorZ {
		contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelPublicKeysDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelPublicKeysDecodeErrorZ {
	CResult_ChannelPublicKeysDecodeErrorZ {
		contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_is_ok(o: &CResult_ChannelPublicKeysDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelPublicKeysDecodeErrorZ.
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_free(_res: CResult_ChannelPublicKeysDecodeErrorZ) { }
impl Drop for CResult_ChannelPublicKeysDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::ChannelPublicKeys, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelPublicKeysDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::ChannelPublicKeys, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelPublicKeysDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelPublicKeysDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelPublicKeysDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::ChannelPublicKeys>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelPublicKeysDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelPublicKeysDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelPublicKeysDecodeErrorZ_clone(orig: &CResult_ChannelPublicKeysDecodeErrorZ) -> CResult_ChannelPublicKeysDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_TxCreationKeysErrorZ
pub union CResult_TxCreationKeysErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::TxCreationKeys,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
/// A CResult_TxCreationKeysErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::TxCreationKeys on success and a crate::c_types::Secp256k1Error on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TxCreationKeysErrorZ {
	/// The contents of this CResult_TxCreationKeysErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TxCreationKeysErrorZPtr,
	/// Whether this CResult_TxCreationKeysErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysErrorZ in the success state.
pub extern "C" fn CResult_TxCreationKeysErrorZ_ok(o: crate::lightning::ln::chan_utils::TxCreationKeys) -> CResult_TxCreationKeysErrorZ {
	CResult_TxCreationKeysErrorZ {
		contents: CResult_TxCreationKeysErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysErrorZ in the error state.
pub extern "C" fn CResult_TxCreationKeysErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_TxCreationKeysErrorZ {
	CResult_TxCreationKeysErrorZ {
		contents: CResult_TxCreationKeysErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TxCreationKeysErrorZ_is_ok(o: &CResult_TxCreationKeysErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TxCreationKeysErrorZ.
pub extern "C" fn CResult_TxCreationKeysErrorZ_free(_res: CResult_TxCreationKeysErrorZ) { }
impl Drop for CResult_TxCreationKeysErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>> for CResult_TxCreationKeysErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TxCreationKeys, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxCreationKeysErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxCreationKeysErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TxCreationKeysErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TxCreationKeysErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::TxCreationKeys>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TxCreationKeysErrorZPtr {
				err: Box::into_raw(Box::new(<crate::c_types::Secp256k1Error>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_TxCreationKeysErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_TxCreationKeysErrorZ_clone(orig: &CResult_TxCreationKeysErrorZ) -> CResult_TxCreationKeysErrorZ { Clone::clone(&orig) }
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a u32 or not
pub enum COption_u32Z {
	/// When we're in this state, this COption_u32Z contains a u32
	Some(u32),
	/// When we're in this state, this COption_u32Z contains nothing
	None
}
impl COption_u32Z {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> u32 {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_u32Z containing a u32
pub extern "C" fn COption_u32Z_some(o: u32) -> COption_u32Z {
	COption_u32Z::Some(o)
}
#[no_mangle]
/// Constructs a new COption_u32Z containing nothing
pub extern "C" fn COption_u32Z_none() -> COption_u32Z {
	COption_u32Z::None
}
#[no_mangle]
/// Frees any resources associated with the u32, if we are in the Some state
pub extern "C" fn COption_u32Z_free(_res: COption_u32Z) { }
#[no_mangle]
/// Creates a new COption_u32Z which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_u32Z_clone(orig: &COption_u32Z) -> COption_u32Z { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_HTLCOutputInCommitmentDecodeErrorZ
pub union CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::HTLCOutputInCommitment,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_HTLCOutputInCommitmentDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::HTLCOutputInCommitment on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_HTLCOutputInCommitmentDecodeErrorZ {
	/// The contents of this CResult_HTLCOutputInCommitmentDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr,
	/// Whether this CResult_HTLCOutputInCommitmentDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_HTLCOutputInCommitmentDecodeErrorZ in the success state.
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::HTLCOutputInCommitment) -> CResult_HTLCOutputInCommitmentDecodeErrorZ {
	CResult_HTLCOutputInCommitmentDecodeErrorZ {
		contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_HTLCOutputInCommitmentDecodeErrorZ in the error state.
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_HTLCOutputInCommitmentDecodeErrorZ {
	CResult_HTLCOutputInCommitmentDecodeErrorZ {
		contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_is_ok(o: &CResult_HTLCOutputInCommitmentDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_HTLCOutputInCommitmentDecodeErrorZ.
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_free(_res: CResult_HTLCOutputInCommitmentDecodeErrorZ) { }
impl Drop for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::HTLCOutputInCommitment, crate::lightning::ln::msgs::DecodeError>> for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::HTLCOutputInCommitment, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HTLCOutputInCommitmentDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HTLCOutputInCommitmentDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HTLCOutputInCommitmentDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::HTLCOutputInCommitment>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HTLCOutputInCommitmentDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_HTLCOutputInCommitmentDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_HTLCOutputInCommitmentDecodeErrorZ_clone(orig: &CResult_HTLCOutputInCommitmentDecodeErrorZ) -> CResult_HTLCOutputInCommitmentDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// An enum which can either contain a  or not
pub enum COption_NoneZ {
	/// When we're in this state, this COption_NoneZ contains a 
	Some,
	/// When we're in this state, this COption_NoneZ contains nothing
	None
}
impl COption_NoneZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
}
#[no_mangle]
/// Constructs a new COption_NoneZ containing a 
pub extern "C" fn COption_NoneZ_some() -> COption_NoneZ {
	COption_NoneZ::Some
}
#[no_mangle]
/// Constructs a new COption_NoneZ containing nothing
pub extern "C" fn COption_NoneZ_none() -> COption_NoneZ {
	COption_NoneZ::None
}
#[no_mangle]
/// Frees any resources associated with the , if we are in the Some state
pub extern "C" fn COption_NoneZ_free(_res: COption_NoneZ) { }
#[repr(C)]
/// The contents of CResult_CounterpartyChannelTransactionParametersDecodeErrorZ
pub union CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_CounterpartyChannelTransactionParametersDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	/// The contents of this CResult_CounterpartyChannelTransactionParametersDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr,
	/// Whether this CResult_CounterpartyChannelTransactionParametersDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CounterpartyChannelTransactionParametersDecodeErrorZ in the success state.
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
		contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CounterpartyChannelTransactionParametersDecodeErrorZ in the error state.
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
		contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_is_ok(o: &CResult_CounterpartyChannelTransactionParametersDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CounterpartyChannelTransactionParametersDecodeErrorZ.
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_free(_res: CResult_CounterpartyChannelTransactionParametersDecodeErrorZ) { }
impl Drop for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters, crate::lightning::ln::msgs::DecodeError>> for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CounterpartyChannelTransactionParametersDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::CounterpartyChannelTransactionParameters>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CounterpartyChannelTransactionParametersDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CounterpartyChannelTransactionParametersDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CounterpartyChannelTransactionParametersDecodeErrorZ_clone(orig: &CResult_CounterpartyChannelTransactionParametersDecodeErrorZ) -> CResult_CounterpartyChannelTransactionParametersDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelTransactionParametersDecodeErrorZ
pub union CResult_ChannelTransactionParametersDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::ChannelTransactionParameters,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelTransactionParametersDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::ChannelTransactionParameters on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelTransactionParametersDecodeErrorZ {
	/// The contents of this CResult_ChannelTransactionParametersDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelTransactionParametersDecodeErrorZPtr,
	/// Whether this CResult_ChannelTransactionParametersDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelTransactionParametersDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::ChannelTransactionParameters) -> CResult_ChannelTransactionParametersDecodeErrorZ {
	CResult_ChannelTransactionParametersDecodeErrorZ {
		contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelTransactionParametersDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelTransactionParametersDecodeErrorZ {
	CResult_ChannelTransactionParametersDecodeErrorZ {
		contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_is_ok(o: &CResult_ChannelTransactionParametersDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelTransactionParametersDecodeErrorZ.
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_free(_res: CResult_ChannelTransactionParametersDecodeErrorZ) { }
impl Drop for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::ChannelTransactionParameters, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::ChannelTransactionParameters, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelTransactionParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelTransactionParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelTransactionParametersDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::ChannelTransactionParameters>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelTransactionParametersDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelTransactionParametersDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelTransactionParametersDecodeErrorZ_clone(orig: &CResult_ChannelTransactionParametersDecodeErrorZ) -> CResult_ChannelTransactionParametersDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::Signatures of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_SignatureZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::Signature,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_SignatureZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::Signature> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::Signature] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::Signature>> for CVec_SignatureZ {
	fn from(v: Vec<crate::c_types::Signature>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_SignatureZ_free(_res: CVec_SignatureZ) { }
impl Drop for CVec_SignatureZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_SignatureZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_HolderCommitmentTransactionDecodeErrorZ
pub union CResult_HolderCommitmentTransactionDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::HolderCommitmentTransaction,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_HolderCommitmentTransactionDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::HolderCommitmentTransaction on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_HolderCommitmentTransactionDecodeErrorZ {
	/// The contents of this CResult_HolderCommitmentTransactionDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr,
	/// Whether this CResult_HolderCommitmentTransactionDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_HolderCommitmentTransactionDecodeErrorZ in the success state.
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::HolderCommitmentTransaction) -> CResult_HolderCommitmentTransactionDecodeErrorZ {
	CResult_HolderCommitmentTransactionDecodeErrorZ {
		contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_HolderCommitmentTransactionDecodeErrorZ in the error state.
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_HolderCommitmentTransactionDecodeErrorZ {
	CResult_HolderCommitmentTransactionDecodeErrorZ {
		contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_is_ok(o: &CResult_HolderCommitmentTransactionDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_HolderCommitmentTransactionDecodeErrorZ.
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_free(_res: CResult_HolderCommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::HolderCommitmentTransaction, crate::lightning::ln::msgs::DecodeError>> for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::HolderCommitmentTransaction, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HolderCommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HolderCommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HolderCommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::HolderCommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HolderCommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_HolderCommitmentTransactionDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_HolderCommitmentTransactionDecodeErrorZ_clone(orig: &CResult_HolderCommitmentTransactionDecodeErrorZ) -> CResult_HolderCommitmentTransactionDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_BuiltCommitmentTransactionDecodeErrorZ
pub union CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::BuiltCommitmentTransaction,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_BuiltCommitmentTransactionDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::BuiltCommitmentTransaction on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_BuiltCommitmentTransactionDecodeErrorZ {
	/// The contents of this CResult_BuiltCommitmentTransactionDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr,
	/// Whether this CResult_BuiltCommitmentTransactionDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_BuiltCommitmentTransactionDecodeErrorZ in the success state.
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::BuiltCommitmentTransaction) -> CResult_BuiltCommitmentTransactionDecodeErrorZ {
	CResult_BuiltCommitmentTransactionDecodeErrorZ {
		contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_BuiltCommitmentTransactionDecodeErrorZ in the error state.
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_BuiltCommitmentTransactionDecodeErrorZ {
	CResult_BuiltCommitmentTransactionDecodeErrorZ {
		contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_is_ok(o: &CResult_BuiltCommitmentTransactionDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_BuiltCommitmentTransactionDecodeErrorZ.
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_free(_res: CResult_BuiltCommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::BuiltCommitmentTransaction, crate::lightning::ln::msgs::DecodeError>> for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::BuiltCommitmentTransaction, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_BuiltCommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_BuiltCommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_BuiltCommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::BuiltCommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_BuiltCommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_BuiltCommitmentTransactionDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_BuiltCommitmentTransactionDecodeErrorZ_clone(orig: &CResult_BuiltCommitmentTransactionDecodeErrorZ) -> CResult_BuiltCommitmentTransactionDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_TrustedClosingTransactionNoneZ
pub union CResult_TrustedClosingTransactionNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::TrustedClosingTransaction,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_TrustedClosingTransactionNoneZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::TrustedClosingTransaction on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TrustedClosingTransactionNoneZ {
	/// The contents of this CResult_TrustedClosingTransactionNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TrustedClosingTransactionNoneZPtr,
	/// Whether this CResult_TrustedClosingTransactionNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TrustedClosingTransactionNoneZ in the success state.
pub extern "C" fn CResult_TrustedClosingTransactionNoneZ_ok(o: crate::lightning::ln::chan_utils::TrustedClosingTransaction) -> CResult_TrustedClosingTransactionNoneZ {
	CResult_TrustedClosingTransactionNoneZ {
		contents: CResult_TrustedClosingTransactionNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TrustedClosingTransactionNoneZ in the error state.
pub extern "C" fn CResult_TrustedClosingTransactionNoneZ_err() -> CResult_TrustedClosingTransactionNoneZ {
	CResult_TrustedClosingTransactionNoneZ {
		contents: CResult_TrustedClosingTransactionNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TrustedClosingTransactionNoneZ_is_ok(o: &CResult_TrustedClosingTransactionNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TrustedClosingTransactionNoneZ.
pub extern "C" fn CResult_TrustedClosingTransactionNoneZ_free(_res: CResult_TrustedClosingTransactionNoneZ) { }
impl Drop for CResult_TrustedClosingTransactionNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TrustedClosingTransaction, ()>> for CResult_TrustedClosingTransactionNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TrustedClosingTransaction, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TrustedClosingTransactionNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_TrustedClosingTransactionNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_CommitmentTransactionDecodeErrorZ
pub union CResult_CommitmentTransactionDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::CommitmentTransaction,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_CommitmentTransactionDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::CommitmentTransaction on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CommitmentTransactionDecodeErrorZ {
	/// The contents of this CResult_CommitmentTransactionDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CommitmentTransactionDecodeErrorZPtr,
	/// Whether this CResult_CommitmentTransactionDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CommitmentTransactionDecodeErrorZ in the success state.
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_ok(o: crate::lightning::ln::chan_utils::CommitmentTransaction) -> CResult_CommitmentTransactionDecodeErrorZ {
	CResult_CommitmentTransactionDecodeErrorZ {
		contents: CResult_CommitmentTransactionDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CommitmentTransactionDecodeErrorZ in the error state.
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_CommitmentTransactionDecodeErrorZ {
	CResult_CommitmentTransactionDecodeErrorZ {
		contents: CResult_CommitmentTransactionDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_is_ok(o: &CResult_CommitmentTransactionDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CommitmentTransactionDecodeErrorZ.
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_free(_res: CResult_CommitmentTransactionDecodeErrorZ) { }
impl Drop for CResult_CommitmentTransactionDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::CommitmentTransaction, crate::lightning::ln::msgs::DecodeError>> for CResult_CommitmentTransactionDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::CommitmentTransaction, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CommitmentTransactionDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CommitmentTransactionDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CommitmentTransactionDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CommitmentTransactionDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::chan_utils::CommitmentTransaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CommitmentTransactionDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CommitmentTransactionDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CommitmentTransactionDecodeErrorZ_clone(orig: &CResult_CommitmentTransactionDecodeErrorZ) -> CResult_CommitmentTransactionDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_TrustedCommitmentTransactionNoneZ
pub union CResult_TrustedCommitmentTransactionNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::chan_utils::TrustedCommitmentTransaction,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_TrustedCommitmentTransactionNoneZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::chan_utils::TrustedCommitmentTransaction on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TrustedCommitmentTransactionNoneZ {
	/// The contents of this CResult_TrustedCommitmentTransactionNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TrustedCommitmentTransactionNoneZPtr,
	/// Whether this CResult_TrustedCommitmentTransactionNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TrustedCommitmentTransactionNoneZ in the success state.
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_ok(o: crate::lightning::ln::chan_utils::TrustedCommitmentTransaction) -> CResult_TrustedCommitmentTransactionNoneZ {
	CResult_TrustedCommitmentTransactionNoneZ {
		contents: CResult_TrustedCommitmentTransactionNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TrustedCommitmentTransactionNoneZ in the error state.
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_err() -> CResult_TrustedCommitmentTransactionNoneZ {
	CResult_TrustedCommitmentTransactionNoneZ {
		contents: CResult_TrustedCommitmentTransactionNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_is_ok(o: &CResult_TrustedCommitmentTransactionNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TrustedCommitmentTransactionNoneZ.
pub extern "C" fn CResult_TrustedCommitmentTransactionNoneZ_free(_res: CResult_TrustedCommitmentTransactionNoneZ) { }
impl Drop for CResult_TrustedCommitmentTransactionNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TrustedCommitmentTransaction, ()>> for CResult_TrustedCommitmentTransactionNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::chan_utils::TrustedCommitmentTransaction, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TrustedCommitmentTransactionNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_TrustedCommitmentTransactionNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_CVec_SignatureZNoneZ
pub union CResult_CVec_SignatureZNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::CVec_SignatureZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_CVec_SignatureZNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::CVec_SignatureZ on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CVec_SignatureZNoneZ {
	/// The contents of this CResult_CVec_SignatureZNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CVec_SignatureZNoneZPtr,
	/// Whether this CResult_CVec_SignatureZNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CVec_SignatureZNoneZ in the success state.
pub extern "C" fn CResult_CVec_SignatureZNoneZ_ok(o: crate::c_types::derived::CVec_SignatureZ) -> CResult_CVec_SignatureZNoneZ {
	CResult_CVec_SignatureZNoneZ {
		contents: CResult_CVec_SignatureZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_SignatureZNoneZ in the error state.
pub extern "C" fn CResult_CVec_SignatureZNoneZ_err() -> CResult_CVec_SignatureZNoneZ {
	CResult_CVec_SignatureZNoneZ {
		contents: CResult_CVec_SignatureZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CVec_SignatureZNoneZ_is_ok(o: &CResult_CVec_SignatureZNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CVec_SignatureZNoneZ.
pub extern "C" fn CResult_CVec_SignatureZNoneZ_free(_res: CResult_CVec_SignatureZNoneZ) { }
impl Drop for CResult_CVec_SignatureZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_SignatureZ, ()>> for CResult_CVec_SignatureZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_SignatureZ, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_SignatureZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_CVec_SignatureZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_SignatureZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_SignatureZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_SignatureZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_SignatureZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_SignatureZNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CVec_SignatureZNoneZ_clone(orig: &CResult_CVec_SignatureZNoneZ) -> CResult_CVec_SignatureZNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ShutdownScriptDecodeErrorZ
pub union CResult_ShutdownScriptDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::script::ShutdownScript,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ShutdownScriptDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::script::ShutdownScript on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ShutdownScriptDecodeErrorZ {
	/// The contents of this CResult_ShutdownScriptDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ShutdownScriptDecodeErrorZPtr,
	/// Whether this CResult_ShutdownScriptDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptDecodeErrorZ in the success state.
pub extern "C" fn CResult_ShutdownScriptDecodeErrorZ_ok(o: crate::lightning::ln::script::ShutdownScript) -> CResult_ShutdownScriptDecodeErrorZ {
	CResult_ShutdownScriptDecodeErrorZ {
		contents: CResult_ShutdownScriptDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptDecodeErrorZ in the error state.
pub extern "C" fn CResult_ShutdownScriptDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ShutdownScriptDecodeErrorZ {
	CResult_ShutdownScriptDecodeErrorZ {
		contents: CResult_ShutdownScriptDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ShutdownScriptDecodeErrorZ_is_ok(o: &CResult_ShutdownScriptDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ShutdownScriptDecodeErrorZ.
pub extern "C" fn CResult_ShutdownScriptDecodeErrorZ_free(_res: CResult_ShutdownScriptDecodeErrorZ) { }
impl Drop for CResult_ShutdownScriptDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::script::ShutdownScript, crate::lightning::ln::msgs::DecodeError>> for CResult_ShutdownScriptDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::script::ShutdownScript, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ShutdownScriptDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ShutdownScriptDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ShutdownScriptDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ShutdownScriptDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::script::ShutdownScript>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ShutdownScriptDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ShutdownScriptDecodeErrorZ_clone(orig: &CResult_ShutdownScriptDecodeErrorZ) -> CResult_ShutdownScriptDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ShutdownScriptInvalidShutdownScriptZ
pub union CResult_ShutdownScriptInvalidShutdownScriptZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::script::ShutdownScript,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::script::InvalidShutdownScript,
}
#[repr(C)]
/// A CResult_ShutdownScriptInvalidShutdownScriptZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::script::ShutdownScript on success and a crate::lightning::ln::script::InvalidShutdownScript on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ShutdownScriptInvalidShutdownScriptZ {
	/// The contents of this CResult_ShutdownScriptInvalidShutdownScriptZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ShutdownScriptInvalidShutdownScriptZPtr,
	/// Whether this CResult_ShutdownScriptInvalidShutdownScriptZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptInvalidShutdownScriptZ in the success state.
pub extern "C" fn CResult_ShutdownScriptInvalidShutdownScriptZ_ok(o: crate::lightning::ln::script::ShutdownScript) -> CResult_ShutdownScriptInvalidShutdownScriptZ {
	CResult_ShutdownScriptInvalidShutdownScriptZ {
		contents: CResult_ShutdownScriptInvalidShutdownScriptZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptInvalidShutdownScriptZ in the error state.
pub extern "C" fn CResult_ShutdownScriptInvalidShutdownScriptZ_err(e: crate::lightning::ln::script::InvalidShutdownScript) -> CResult_ShutdownScriptInvalidShutdownScriptZ {
	CResult_ShutdownScriptInvalidShutdownScriptZ {
		contents: CResult_ShutdownScriptInvalidShutdownScriptZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ShutdownScriptInvalidShutdownScriptZ_is_ok(o: &CResult_ShutdownScriptInvalidShutdownScriptZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ShutdownScriptInvalidShutdownScriptZ.
pub extern "C" fn CResult_ShutdownScriptInvalidShutdownScriptZ_free(_res: CResult_ShutdownScriptInvalidShutdownScriptZ) { }
impl Drop for CResult_ShutdownScriptInvalidShutdownScriptZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::script::ShutdownScript, crate::lightning::ln::script::InvalidShutdownScript>> for CResult_ShutdownScriptInvalidShutdownScriptZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::script::ShutdownScript, crate::lightning::ln::script::InvalidShutdownScript>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ShutdownScriptInvalidShutdownScriptZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ShutdownScriptInvalidShutdownScriptZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ShutdownScriptInvalidShutdownScriptZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ShutdownScriptInvalidShutdownScriptZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::script::ShutdownScript>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ShutdownScriptInvalidShutdownScriptZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::script::InvalidShutdownScript>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownScriptInvalidShutdownScriptZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ShutdownScriptInvalidShutdownScriptZ_clone(orig: &CResult_ShutdownScriptInvalidShutdownScriptZ) -> CResult_ShutdownScriptInvalidShutdownScriptZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NoneErrorZ
pub union CResult_NoneErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::IOError,
}
#[repr(C)]
/// A CResult_NoneErrorZ represents the result of a fallible operation,
/// containing a () on success and a crate::c_types::IOError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneErrorZ {
	/// The contents of this CResult_NoneErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneErrorZPtr,
	/// Whether this CResult_NoneErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneErrorZ in the success state.
pub extern "C" fn CResult_NoneErrorZ_ok() -> CResult_NoneErrorZ {
	CResult_NoneErrorZ {
		contents: CResult_NoneErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneErrorZ in the error state.
pub extern "C" fn CResult_NoneErrorZ_err(e: crate::c_types::IOError) -> CResult_NoneErrorZ {
	CResult_NoneErrorZ {
		contents: CResult_NoneErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneErrorZ_is_ok(o: &CResult_NoneErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneErrorZ.
pub extern "C" fn CResult_NoneErrorZ_free(_res: CResult_NoneErrorZ) { }
impl Drop for CResult_NoneErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::c_types::IOError>> for CResult_NoneErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::c_types::IOError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneErrorZPtr {
				err: Box::into_raw(Box::new(<crate::c_types::IOError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneErrorZ_clone(orig: &CResult_NoneErrorZ) -> CResult_NoneErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_RouteHopDecodeErrorZ
pub union CResult_RouteHopDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::RouteHop,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RouteHopDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::RouteHop on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteHopDecodeErrorZ {
	/// The contents of this CResult_RouteHopDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteHopDecodeErrorZPtr,
	/// Whether this CResult_RouteHopDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteHopDecodeErrorZ in the success state.
pub extern "C" fn CResult_RouteHopDecodeErrorZ_ok(o: crate::lightning::routing::router::RouteHop) -> CResult_RouteHopDecodeErrorZ {
	CResult_RouteHopDecodeErrorZ {
		contents: CResult_RouteHopDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHopDecodeErrorZ in the error state.
pub extern "C" fn CResult_RouteHopDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RouteHopDecodeErrorZ {
	CResult_RouteHopDecodeErrorZ {
		contents: CResult_RouteHopDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteHopDecodeErrorZ_is_ok(o: &CResult_RouteHopDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteHopDecodeErrorZ.
pub extern "C" fn CResult_RouteHopDecodeErrorZ_free(_res: CResult_RouteHopDecodeErrorZ) { }
impl Drop for CResult_RouteHopDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHop, crate::lightning::ln::msgs::DecodeError>> for CResult_RouteHopDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHop, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteHopDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteHopDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteHopDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteHopDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::RouteHop>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteHopDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHopDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteHopDecodeErrorZ_clone(orig: &CResult_RouteHopDecodeErrorZ) -> CResult_RouteHopDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::routing::router::RouteHops of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_RouteHopZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::routing::router::RouteHop,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_RouteHopZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::routing::router::RouteHop> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::routing::router::RouteHop] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::routing::router::RouteHop>> for CVec_RouteHopZ {
	fn from(v: Vec<crate::lightning::routing::router::RouteHop>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_RouteHopZ_free(_res: CVec_RouteHopZ) { }
impl Drop for CVec_RouteHopZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_RouteHopZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::CVec_RouteHopZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_CVec_RouteHopZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::CVec_RouteHopZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_CVec_RouteHopZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CVec_RouteHopZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CVec_RouteHopZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CVec_RouteHopZ>> for CVec_CVec_RouteHopZZ {
	fn from(v: Vec<crate::c_types::derived::CVec_RouteHopZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_CVec_RouteHopZZ_free(_res: CVec_CVec_RouteHopZZ) { }
impl Drop for CVec_CVec_RouteHopZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CVec_RouteHopZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_RouteDecodeErrorZ
pub union CResult_RouteDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::Route,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RouteDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::Route on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteDecodeErrorZ {
	/// The contents of this CResult_RouteDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteDecodeErrorZPtr,
	/// Whether this CResult_RouteDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteDecodeErrorZ in the success state.
pub extern "C" fn CResult_RouteDecodeErrorZ_ok(o: crate::lightning::routing::router::Route) -> CResult_RouteDecodeErrorZ {
	CResult_RouteDecodeErrorZ {
		contents: CResult_RouteDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteDecodeErrorZ in the error state.
pub extern "C" fn CResult_RouteDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RouteDecodeErrorZ {
	CResult_RouteDecodeErrorZ {
		contents: CResult_RouteDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteDecodeErrorZ_is_ok(o: &CResult_RouteDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteDecodeErrorZ.
pub extern "C" fn CResult_RouteDecodeErrorZ_free(_res: CResult_RouteDecodeErrorZ) { }
impl Drop for CResult_RouteDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::Route, crate::lightning::ln::msgs::DecodeError>> for CResult_RouteDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::Route, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::Route>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteDecodeErrorZ_clone(orig: &CResult_RouteDecodeErrorZ) -> CResult_RouteDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_RouteParametersDecodeErrorZ
pub union CResult_RouteParametersDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::RouteParameters,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RouteParametersDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::RouteParameters on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteParametersDecodeErrorZ {
	/// The contents of this CResult_RouteParametersDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteParametersDecodeErrorZPtr,
	/// Whether this CResult_RouteParametersDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteParametersDecodeErrorZ in the success state.
pub extern "C" fn CResult_RouteParametersDecodeErrorZ_ok(o: crate::lightning::routing::router::RouteParameters) -> CResult_RouteParametersDecodeErrorZ {
	CResult_RouteParametersDecodeErrorZ {
		contents: CResult_RouteParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteParametersDecodeErrorZ in the error state.
pub extern "C" fn CResult_RouteParametersDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RouteParametersDecodeErrorZ {
	CResult_RouteParametersDecodeErrorZ {
		contents: CResult_RouteParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteParametersDecodeErrorZ_is_ok(o: &CResult_RouteParametersDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteParametersDecodeErrorZ.
pub extern "C" fn CResult_RouteParametersDecodeErrorZ_free(_res: CResult_RouteParametersDecodeErrorZ) { }
impl Drop for CResult_RouteParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::RouteParameters, crate::lightning::ln::msgs::DecodeError>> for CResult_RouteParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::RouteParameters, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteParametersDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteParametersDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::RouteParameters>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteParametersDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteParametersDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteParametersDecodeErrorZ_clone(orig: &CResult_RouteParametersDecodeErrorZ) -> CResult_RouteParametersDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::routing::router::RouteHints of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_RouteHintZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::routing::router::RouteHint,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_RouteHintZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::routing::router::RouteHint> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::routing::router::RouteHint] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::routing::router::RouteHint>> for CVec_RouteHintZ {
	fn from(v: Vec<crate::lightning::routing::router::RouteHint>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_RouteHintZ_free(_res: CVec_RouteHintZ) { }
impl Drop for CVec_RouteHintZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_RouteHintZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a u64 or not
pub enum COption_u64Z {
	/// When we're in this state, this COption_u64Z contains a u64
	Some(u64),
	/// When we're in this state, this COption_u64Z contains nothing
	None
}
impl COption_u64Z {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> u64 {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_u64Z containing a u64
pub extern "C" fn COption_u64Z_some(o: u64) -> COption_u64Z {
	COption_u64Z::Some(o)
}
#[no_mangle]
/// Constructs a new COption_u64Z containing nothing
pub extern "C" fn COption_u64Z_none() -> COption_u64Z {
	COption_u64Z::None
}
#[no_mangle]
/// Frees any resources associated with the u64, if we are in the Some state
pub extern "C" fn COption_u64Z_free(_res: COption_u64Z) { }
#[no_mangle]
/// Creates a new COption_u64Z which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_u64Z_clone(orig: &COption_u64Z) -> COption_u64Z { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PayeeDecodeErrorZ
pub union CResult_PayeeDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::Payee,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_PayeeDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::Payee on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PayeeDecodeErrorZ {
	/// The contents of this CResult_PayeeDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PayeeDecodeErrorZPtr,
	/// Whether this CResult_PayeeDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PayeeDecodeErrorZ in the success state.
pub extern "C" fn CResult_PayeeDecodeErrorZ_ok(o: crate::lightning::routing::router::Payee) -> CResult_PayeeDecodeErrorZ {
	CResult_PayeeDecodeErrorZ {
		contents: CResult_PayeeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PayeeDecodeErrorZ in the error state.
pub extern "C" fn CResult_PayeeDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_PayeeDecodeErrorZ {
	CResult_PayeeDecodeErrorZ {
		contents: CResult_PayeeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PayeeDecodeErrorZ_is_ok(o: &CResult_PayeeDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PayeeDecodeErrorZ.
pub extern "C" fn CResult_PayeeDecodeErrorZ_free(_res: CResult_PayeeDecodeErrorZ) { }
impl Drop for CResult_PayeeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::Payee, crate::lightning::ln::msgs::DecodeError>> for CResult_PayeeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::Payee, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PayeeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PayeeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PayeeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PayeeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::Payee>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PayeeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PayeeDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PayeeDecodeErrorZ_clone(orig: &CResult_PayeeDecodeErrorZ) -> CResult_PayeeDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::routing::router::RouteHintHops of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_RouteHintHopZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::routing::router::RouteHintHop,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_RouteHintHopZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::routing::router::RouteHintHop> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::routing::router::RouteHintHop] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::routing::router::RouteHintHop>> for CVec_RouteHintHopZ {
	fn from(v: Vec<crate::lightning::routing::router::RouteHintHop>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_RouteHintHopZ_free(_res: CVec_RouteHintHopZ) { }
impl Drop for CVec_RouteHintHopZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_RouteHintHopZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_RouteHintDecodeErrorZ
pub union CResult_RouteHintDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::RouteHint,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RouteHintDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::RouteHint on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteHintDecodeErrorZ {
	/// The contents of this CResult_RouteHintDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteHintDecodeErrorZPtr,
	/// Whether this CResult_RouteHintDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteHintDecodeErrorZ in the success state.
pub extern "C" fn CResult_RouteHintDecodeErrorZ_ok(o: crate::lightning::routing::router::RouteHint) -> CResult_RouteHintDecodeErrorZ {
	CResult_RouteHintDecodeErrorZ {
		contents: CResult_RouteHintDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHintDecodeErrorZ in the error state.
pub extern "C" fn CResult_RouteHintDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RouteHintDecodeErrorZ {
	CResult_RouteHintDecodeErrorZ {
		contents: CResult_RouteHintDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteHintDecodeErrorZ_is_ok(o: &CResult_RouteHintDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteHintDecodeErrorZ.
pub extern "C" fn CResult_RouteHintDecodeErrorZ_free(_res: CResult_RouteHintDecodeErrorZ) { }
impl Drop for CResult_RouteHintDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHint, crate::lightning::ln::msgs::DecodeError>> for CResult_RouteHintDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHint, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteHintDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteHintDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteHintDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteHintDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::RouteHint>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteHintDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHintDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteHintDecodeErrorZ_clone(orig: &CResult_RouteHintDecodeErrorZ) -> CResult_RouteHintDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_RouteHintHopDecodeErrorZ
pub union CResult_RouteHintHopDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::RouteHintHop,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RouteHintHopDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::RouteHintHop on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteHintHopDecodeErrorZ {
	/// The contents of this CResult_RouteHintHopDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteHintHopDecodeErrorZPtr,
	/// Whether this CResult_RouteHintHopDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteHintHopDecodeErrorZ in the success state.
pub extern "C" fn CResult_RouteHintHopDecodeErrorZ_ok(o: crate::lightning::routing::router::RouteHintHop) -> CResult_RouteHintHopDecodeErrorZ {
	CResult_RouteHintHopDecodeErrorZ {
		contents: CResult_RouteHintHopDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHintHopDecodeErrorZ in the error state.
pub extern "C" fn CResult_RouteHintHopDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RouteHintHopDecodeErrorZ {
	CResult_RouteHintHopDecodeErrorZ {
		contents: CResult_RouteHintHopDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteHintHopDecodeErrorZ_is_ok(o: &CResult_RouteHintHopDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteHintHopDecodeErrorZ.
pub extern "C" fn CResult_RouteHintHopDecodeErrorZ_free(_res: CResult_RouteHintHopDecodeErrorZ) { }
impl Drop for CResult_RouteHintHopDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHintHop, crate::lightning::ln::msgs::DecodeError>> for CResult_RouteHintHopDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::RouteHintHop, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteHintHopDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteHintHopDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteHintHopDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteHintHopDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::RouteHintHop>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteHintHopDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteHintHopDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteHintHopDecodeErrorZ_clone(orig: &CResult_RouteHintHopDecodeErrorZ) -> CResult_RouteHintHopDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::channelmanager::ChannelDetailss of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_ChannelDetailsZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::channelmanager::ChannelDetails,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_ChannelDetailsZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::channelmanager::ChannelDetails> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::channelmanager::ChannelDetails] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::channelmanager::ChannelDetails>> for CVec_ChannelDetailsZ {
	fn from(v: Vec<crate::lightning::ln::channelmanager::ChannelDetails>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_ChannelDetailsZ_free(_res: CVec_ChannelDetailsZ) { }
impl Drop for CVec_ChannelDetailsZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_ChannelDetailsZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_RouteLightningErrorZ
pub union CResult_RouteLightningErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::router::Route,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::LightningError,
}
#[repr(C)]
/// A CResult_RouteLightningErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::router::Route on success and a crate::lightning::ln::msgs::LightningError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RouteLightningErrorZ {
	/// The contents of this CResult_RouteLightningErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RouteLightningErrorZPtr,
	/// Whether this CResult_RouteLightningErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RouteLightningErrorZ in the success state.
pub extern "C" fn CResult_RouteLightningErrorZ_ok(o: crate::lightning::routing::router::Route) -> CResult_RouteLightningErrorZ {
	CResult_RouteLightningErrorZ {
		contents: CResult_RouteLightningErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RouteLightningErrorZ in the error state.
pub extern "C" fn CResult_RouteLightningErrorZ_err(e: crate::lightning::ln::msgs::LightningError) -> CResult_RouteLightningErrorZ {
	CResult_RouteLightningErrorZ {
		contents: CResult_RouteLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RouteLightningErrorZ_is_ok(o: &CResult_RouteLightningErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RouteLightningErrorZ.
pub extern "C" fn CResult_RouteLightningErrorZ_free(_res: CResult_RouteLightningErrorZ) { }
impl Drop for CResult_RouteLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::router::Route, crate::lightning::ln::msgs::LightningError>> for CResult_RouteLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::router::Route, crate::lightning::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RouteLightningErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RouteLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RouteLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RouteLightningErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::router::Route>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RouteLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RouteLightningErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RouteLightningErrorZ_clone(orig: &CResult_RouteLightningErrorZ) -> CResult_RouteLightningErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_TxOutAccessErrorZ
pub union CResult_TxOutAccessErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::TxOut,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::chain::AccessError,
}
#[repr(C)]
/// A CResult_TxOutAccessErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::TxOut on success and a crate::lightning::chain::AccessError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TxOutAccessErrorZ {
	/// The contents of this CResult_TxOutAccessErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TxOutAccessErrorZPtr,
	/// Whether this CResult_TxOutAccessErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TxOutAccessErrorZ in the success state.
pub extern "C" fn CResult_TxOutAccessErrorZ_ok(o: crate::c_types::TxOut) -> CResult_TxOutAccessErrorZ {
	CResult_TxOutAccessErrorZ {
		contents: CResult_TxOutAccessErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TxOutAccessErrorZ in the error state.
pub extern "C" fn CResult_TxOutAccessErrorZ_err(e: crate::lightning::chain::AccessError) -> CResult_TxOutAccessErrorZ {
	CResult_TxOutAccessErrorZ {
		contents: CResult_TxOutAccessErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TxOutAccessErrorZ_is_ok(o: &CResult_TxOutAccessErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TxOutAccessErrorZ.
pub extern "C" fn CResult_TxOutAccessErrorZ_free(_res: CResult_TxOutAccessErrorZ) { }
impl Drop for CResult_TxOutAccessErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::TxOut, crate::lightning::chain::AccessError>> for CResult_TxOutAccessErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::TxOut, crate::lightning::chain::AccessError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TxOutAccessErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_TxOutAccessErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TxOutAccessErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TxOutAccessErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::TxOut>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TxOutAccessErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::chain::AccessError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_TxOutAccessErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_TxOutAccessErrorZ_clone(orig: &CResult_TxOutAccessErrorZ) -> CResult_TxOutAccessErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_usizeTransactionZ {
	/// The element at position 0
	pub a: usize,
	/// The element at position 1
	pub b: crate::c_types::Transaction,
}
impl From<(usize, crate::c_types::Transaction)> for C2Tuple_usizeTransactionZ {
	fn from (tup: (usize, crate::c_types::Transaction)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_usizeTransactionZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (usize, crate::c_types::Transaction) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_usizeTransactionZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_usizeTransactionZ_clone(orig: &C2Tuple_usizeTransactionZ) -> C2Tuple_usizeTransactionZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_usizeTransactionZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_usizeTransactionZ_new(a: usize, b: crate::c_types::Transaction) -> C2Tuple_usizeTransactionZ {
	C2Tuple_usizeTransactionZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_usizeTransactionZ.
pub extern "C" fn C2Tuple_usizeTransactionZ_free(_res: C2Tuple_usizeTransactionZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_usizeTransactionZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_usizeTransactionZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_usizeTransactionZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_usizeTransactionZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_usizeTransactionZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ>> for CVec_C2Tuple_usizeTransactionZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_usizeTransactionZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_usizeTransactionZZ_free(_res: CVec_C2Tuple_usizeTransactionZZ) { }
impl Drop for CVec_C2Tuple_usizeTransactionZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C2Tuple_usizeTransactionZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::ThirtyTwoBytess of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_TxidZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::ThirtyTwoBytes,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_TxidZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::ThirtyTwoBytes> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::ThirtyTwoBytes] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::ThirtyTwoBytes>> for CVec_TxidZ {
	fn from(v: Vec<crate::c_types::ThirtyTwoBytes>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_TxidZ_free(_res: CVec_TxidZ) { }
impl Drop for CVec_TxidZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_TxidZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_NoneChannelMonitorUpdateErrZ
pub union CResult_NoneChannelMonitorUpdateErrZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::chain::ChannelMonitorUpdateErr,
}
#[repr(C)]
/// A CResult_NoneChannelMonitorUpdateErrZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning::chain::ChannelMonitorUpdateErr on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneChannelMonitorUpdateErrZ {
	/// The contents of this CResult_NoneChannelMonitorUpdateErrZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneChannelMonitorUpdateErrZPtr,
	/// Whether this CResult_NoneChannelMonitorUpdateErrZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneChannelMonitorUpdateErrZ in the success state.
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_ok() -> CResult_NoneChannelMonitorUpdateErrZ {
	CResult_NoneChannelMonitorUpdateErrZ {
		contents: CResult_NoneChannelMonitorUpdateErrZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneChannelMonitorUpdateErrZ in the error state.
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_err(e: crate::lightning::chain::ChannelMonitorUpdateErr) -> CResult_NoneChannelMonitorUpdateErrZ {
	CResult_NoneChannelMonitorUpdateErrZ {
		contents: CResult_NoneChannelMonitorUpdateErrZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_is_ok(o: &CResult_NoneChannelMonitorUpdateErrZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneChannelMonitorUpdateErrZ.
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_free(_res: CResult_NoneChannelMonitorUpdateErrZ) { }
impl Drop for CResult_NoneChannelMonitorUpdateErrZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning::chain::ChannelMonitorUpdateErr>> for CResult_NoneChannelMonitorUpdateErrZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning::chain::ChannelMonitorUpdateErr>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneChannelMonitorUpdateErrZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneChannelMonitorUpdateErrZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneChannelMonitorUpdateErrZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneChannelMonitorUpdateErrZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneChannelMonitorUpdateErrZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::chain::ChannelMonitorUpdateErr>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneChannelMonitorUpdateErrZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneChannelMonitorUpdateErrZ_clone(orig: &CResult_NoneChannelMonitorUpdateErrZ) -> CResult_NoneChannelMonitorUpdateErrZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::chain::channelmonitor::MonitorEvents of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_MonitorEventZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::chain::channelmonitor::MonitorEvent,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_MonitorEventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::chain::channelmonitor::MonitorEvent> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::chain::channelmonitor::MonitorEvent] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::chain::channelmonitor::MonitorEvent>> for CVec_MonitorEventZ {
	fn from(v: Vec<crate::lightning::chain::channelmonitor::MonitorEvent>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_MonitorEventZ_free(_res: CVec_MonitorEventZ) { }
impl Drop for CVec_MonitorEventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_MonitorEventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::c_types::derived::C2Tuple_usizeTransactionZ or not
pub enum COption_C2Tuple_usizeTransactionZZ {
	/// When we're in this state, this COption_C2Tuple_usizeTransactionZZ contains a crate::c_types::derived::C2Tuple_usizeTransactionZ
	Some(crate::c_types::derived::C2Tuple_usizeTransactionZ),
	/// When we're in this state, this COption_C2Tuple_usizeTransactionZZ contains nothing
	None
}
impl COption_C2Tuple_usizeTransactionZZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::c_types::derived::C2Tuple_usizeTransactionZ {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_C2Tuple_usizeTransactionZZ containing a crate::c_types::derived::C2Tuple_usizeTransactionZ
pub extern "C" fn COption_C2Tuple_usizeTransactionZZ_some(o: crate::c_types::derived::C2Tuple_usizeTransactionZ) -> COption_C2Tuple_usizeTransactionZZ {
	COption_C2Tuple_usizeTransactionZZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_C2Tuple_usizeTransactionZZ containing nothing
pub extern "C" fn COption_C2Tuple_usizeTransactionZZ_none() -> COption_C2Tuple_usizeTransactionZZ {
	COption_C2Tuple_usizeTransactionZZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::c_types::derived::C2Tuple_usizeTransactionZ, if we are in the Some state
pub extern "C" fn COption_C2Tuple_usizeTransactionZZ_free(_res: COption_C2Tuple_usizeTransactionZZ) { }
#[no_mangle]
/// Creates a new COption_C2Tuple_usizeTransactionZZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_C2Tuple_usizeTransactionZZ_clone(orig: &COption_C2Tuple_usizeTransactionZZ) -> COption_C2Tuple_usizeTransactionZZ { Clone::clone(&orig) }
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::lightning::util::events::ClosureReason or not
pub enum COption_ClosureReasonZ {
	/// When we're in this state, this COption_ClosureReasonZ contains a crate::lightning::util::events::ClosureReason
	Some(crate::lightning::util::events::ClosureReason),
	/// When we're in this state, this COption_ClosureReasonZ contains nothing
	None
}
impl COption_ClosureReasonZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::util::events::ClosureReason {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_ClosureReasonZ containing a crate::lightning::util::events::ClosureReason
pub extern "C" fn COption_ClosureReasonZ_some(o: crate::lightning::util::events::ClosureReason) -> COption_ClosureReasonZ {
	COption_ClosureReasonZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_ClosureReasonZ containing nothing
pub extern "C" fn COption_ClosureReasonZ_none() -> COption_ClosureReasonZ {
	COption_ClosureReasonZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::util::events::ClosureReason, if we are in the Some state
pub extern "C" fn COption_ClosureReasonZ_free(_res: COption_ClosureReasonZ) { }
#[no_mangle]
/// Creates a new COption_ClosureReasonZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_ClosureReasonZ_clone(orig: &COption_ClosureReasonZ) -> COption_ClosureReasonZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_COption_ClosureReasonZDecodeErrorZ
pub union CResult_COption_ClosureReasonZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::COption_ClosureReasonZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_COption_ClosureReasonZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::COption_ClosureReasonZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_COption_ClosureReasonZDecodeErrorZ {
	/// The contents of this CResult_COption_ClosureReasonZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_COption_ClosureReasonZDecodeErrorZPtr,
	/// Whether this CResult_COption_ClosureReasonZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_COption_ClosureReasonZDecodeErrorZ in the success state.
pub extern "C" fn CResult_COption_ClosureReasonZDecodeErrorZ_ok(o: crate::c_types::derived::COption_ClosureReasonZ) -> CResult_COption_ClosureReasonZDecodeErrorZ {
	CResult_COption_ClosureReasonZDecodeErrorZ {
		contents: CResult_COption_ClosureReasonZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_COption_ClosureReasonZDecodeErrorZ in the error state.
pub extern "C" fn CResult_COption_ClosureReasonZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_COption_ClosureReasonZDecodeErrorZ {
	CResult_COption_ClosureReasonZDecodeErrorZ {
		contents: CResult_COption_ClosureReasonZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_COption_ClosureReasonZDecodeErrorZ_is_ok(o: &CResult_COption_ClosureReasonZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_COption_ClosureReasonZDecodeErrorZ.
pub extern "C" fn CResult_COption_ClosureReasonZDecodeErrorZ_free(_res: CResult_COption_ClosureReasonZDecodeErrorZ) { }
impl Drop for CResult_COption_ClosureReasonZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::COption_ClosureReasonZ, crate::lightning::ln::msgs::DecodeError>> for CResult_COption_ClosureReasonZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::COption_ClosureReasonZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_COption_ClosureReasonZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_COption_ClosureReasonZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_COption_ClosureReasonZDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_COption_ClosureReasonZDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::COption_ClosureReasonZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_COption_ClosureReasonZDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_COption_ClosureReasonZDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_COption_ClosureReasonZDecodeErrorZ_clone(orig: &CResult_COption_ClosureReasonZDecodeErrorZ) -> CResult_COption_ClosureReasonZDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::lightning::routing::network_graph::NetworkUpdate or not
pub enum COption_NetworkUpdateZ {
	/// When we're in this state, this COption_NetworkUpdateZ contains a crate::lightning::routing::network_graph::NetworkUpdate
	Some(crate::lightning::routing::network_graph::NetworkUpdate),
	/// When we're in this state, this COption_NetworkUpdateZ contains nothing
	None
}
impl COption_NetworkUpdateZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::routing::network_graph::NetworkUpdate {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_NetworkUpdateZ containing a crate::lightning::routing::network_graph::NetworkUpdate
pub extern "C" fn COption_NetworkUpdateZ_some(o: crate::lightning::routing::network_graph::NetworkUpdate) -> COption_NetworkUpdateZ {
	COption_NetworkUpdateZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_NetworkUpdateZ containing nothing
pub extern "C" fn COption_NetworkUpdateZ_none() -> COption_NetworkUpdateZ {
	COption_NetworkUpdateZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::routing::network_graph::NetworkUpdate, if we are in the Some state
pub extern "C" fn COption_NetworkUpdateZ_free(_res: COption_NetworkUpdateZ) { }
#[no_mangle]
/// Creates a new COption_NetworkUpdateZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_NetworkUpdateZ_clone(orig: &COption_NetworkUpdateZ) -> COption_NetworkUpdateZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::chain::keysinterface::SpendableOutputDescriptors of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_SpendableOutputDescriptorZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::chain::keysinterface::SpendableOutputDescriptor,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_SpendableOutputDescriptorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::chain::keysinterface::SpendableOutputDescriptor> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::chain::keysinterface::SpendableOutputDescriptor] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::chain::keysinterface::SpendableOutputDescriptor>> for CVec_SpendableOutputDescriptorZ {
	fn from(v: Vec<crate::lightning::chain::keysinterface::SpendableOutputDescriptor>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_SpendableOutputDescriptorZ_free(_res: CVec_SpendableOutputDescriptorZ) { }
impl Drop for CVec_SpendableOutputDescriptorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_SpendableOutputDescriptorZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::lightning::util::events::Event or not
pub enum COption_EventZ {
	/// When we're in this state, this COption_EventZ contains a crate::lightning::util::events::Event
	Some(crate::lightning::util::events::Event),
	/// When we're in this state, this COption_EventZ contains nothing
	None
}
impl COption_EventZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::util::events::Event {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_EventZ containing a crate::lightning::util::events::Event
pub extern "C" fn COption_EventZ_some(o: crate::lightning::util::events::Event) -> COption_EventZ {
	COption_EventZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_EventZ containing nothing
pub extern "C" fn COption_EventZ_none() -> COption_EventZ {
	COption_EventZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::util::events::Event, if we are in the Some state
pub extern "C" fn COption_EventZ_free(_res: COption_EventZ) { }
#[no_mangle]
/// Creates a new COption_EventZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_EventZ_clone(orig: &COption_EventZ) -> COption_EventZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_COption_EventZDecodeErrorZ
pub union CResult_COption_EventZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::COption_EventZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_COption_EventZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::COption_EventZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_COption_EventZDecodeErrorZ {
	/// The contents of this CResult_COption_EventZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_COption_EventZDecodeErrorZPtr,
	/// Whether this CResult_COption_EventZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_COption_EventZDecodeErrorZ in the success state.
pub extern "C" fn CResult_COption_EventZDecodeErrorZ_ok(o: crate::c_types::derived::COption_EventZ) -> CResult_COption_EventZDecodeErrorZ {
	CResult_COption_EventZDecodeErrorZ {
		contents: CResult_COption_EventZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_COption_EventZDecodeErrorZ in the error state.
pub extern "C" fn CResult_COption_EventZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_COption_EventZDecodeErrorZ {
	CResult_COption_EventZDecodeErrorZ {
		contents: CResult_COption_EventZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_COption_EventZDecodeErrorZ_is_ok(o: &CResult_COption_EventZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_COption_EventZDecodeErrorZ.
pub extern "C" fn CResult_COption_EventZDecodeErrorZ_free(_res: CResult_COption_EventZDecodeErrorZ) { }
impl Drop for CResult_COption_EventZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::COption_EventZ, crate::lightning::ln::msgs::DecodeError>> for CResult_COption_EventZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::COption_EventZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_COption_EventZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_COption_EventZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_COption_EventZDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_COption_EventZDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::COption_EventZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_COption_EventZDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_COption_EventZDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_COption_EventZDecodeErrorZ_clone(orig: &CResult_COption_EventZDecodeErrorZ) -> CResult_COption_EventZDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::util::events::MessageSendEvents of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_MessageSendEventZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::util::events::MessageSendEvent,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_MessageSendEventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::util::events::MessageSendEvent> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::util::events::MessageSendEvent] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::util::events::MessageSendEvent>> for CVec_MessageSendEventZ {
	fn from(v: Vec<crate::lightning::util::events::MessageSendEvent>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_MessageSendEventZ_free(_res: CVec_MessageSendEventZ) { }
impl Drop for CVec_MessageSendEventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_MessageSendEventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_ScoringParametersDecodeErrorZ
pub union CResult_ScoringParametersDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::scoring::ScoringParameters,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ScoringParametersDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::scoring::ScoringParameters on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ScoringParametersDecodeErrorZ {
	/// The contents of this CResult_ScoringParametersDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ScoringParametersDecodeErrorZPtr,
	/// Whether this CResult_ScoringParametersDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ScoringParametersDecodeErrorZ in the success state.
pub extern "C" fn CResult_ScoringParametersDecodeErrorZ_ok(o: crate::lightning::routing::scoring::ScoringParameters) -> CResult_ScoringParametersDecodeErrorZ {
	CResult_ScoringParametersDecodeErrorZ {
		contents: CResult_ScoringParametersDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ScoringParametersDecodeErrorZ in the error state.
pub extern "C" fn CResult_ScoringParametersDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ScoringParametersDecodeErrorZ {
	CResult_ScoringParametersDecodeErrorZ {
		contents: CResult_ScoringParametersDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ScoringParametersDecodeErrorZ_is_ok(o: &CResult_ScoringParametersDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ScoringParametersDecodeErrorZ.
pub extern "C" fn CResult_ScoringParametersDecodeErrorZ_free(_res: CResult_ScoringParametersDecodeErrorZ) { }
impl Drop for CResult_ScoringParametersDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::scoring::ScoringParameters, crate::lightning::ln::msgs::DecodeError>> for CResult_ScoringParametersDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::scoring::ScoringParameters, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ScoringParametersDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ScoringParametersDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_ScorerDecodeErrorZ
pub union CResult_ScorerDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::scoring::Scorer,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ScorerDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::scoring::Scorer on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ScorerDecodeErrorZ {
	/// The contents of this CResult_ScorerDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ScorerDecodeErrorZPtr,
	/// Whether this CResult_ScorerDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ScorerDecodeErrorZ in the success state.
pub extern "C" fn CResult_ScorerDecodeErrorZ_ok(o: crate::lightning::routing::scoring::Scorer) -> CResult_ScorerDecodeErrorZ {
	CResult_ScorerDecodeErrorZ {
		contents: CResult_ScorerDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ScorerDecodeErrorZ in the error state.
pub extern "C" fn CResult_ScorerDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ScorerDecodeErrorZ {
	CResult_ScorerDecodeErrorZ {
		contents: CResult_ScorerDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ScorerDecodeErrorZ_is_ok(o: &CResult_ScorerDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ScorerDecodeErrorZ.
pub extern "C" fn CResult_ScorerDecodeErrorZ_free(_res: CResult_ScorerDecodeErrorZ) { }
impl Drop for CResult_ScorerDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::scoring::Scorer, crate::lightning::ln::msgs::DecodeError>> for CResult_ScorerDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::scoring::Scorer, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ScorerDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ScorerDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_InitFeaturesDecodeErrorZ
pub union CResult_InitFeaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::features::InitFeatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_InitFeaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::features::InitFeatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InitFeaturesDecodeErrorZ {
	/// The contents of this CResult_InitFeaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InitFeaturesDecodeErrorZPtr,
	/// Whether this CResult_InitFeaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InitFeaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_ok(o: crate::lightning::ln::features::InitFeatures) -> CResult_InitFeaturesDecodeErrorZ {
	CResult_InitFeaturesDecodeErrorZ {
		contents: CResult_InitFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InitFeaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_InitFeaturesDecodeErrorZ {
	CResult_InitFeaturesDecodeErrorZ {
		contents: CResult_InitFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_is_ok(o: &CResult_InitFeaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InitFeaturesDecodeErrorZ.
pub extern "C" fn CResult_InitFeaturesDecodeErrorZ_free(_res: CResult_InitFeaturesDecodeErrorZ) { }
impl Drop for CResult_InitFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::features::InitFeatures, crate::lightning::ln::msgs::DecodeError>> for CResult_InitFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::features::InitFeatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InitFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InitFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_ChannelFeaturesDecodeErrorZ
pub union CResult_ChannelFeaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::features::ChannelFeatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelFeaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::features::ChannelFeatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelFeaturesDecodeErrorZ {
	/// The contents of this CResult_ChannelFeaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelFeaturesDecodeErrorZPtr,
	/// Whether this CResult_ChannelFeaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelFeaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_ok(o: crate::lightning::ln::features::ChannelFeatures) -> CResult_ChannelFeaturesDecodeErrorZ {
	CResult_ChannelFeaturesDecodeErrorZ {
		contents: CResult_ChannelFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelFeaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelFeaturesDecodeErrorZ {
	CResult_ChannelFeaturesDecodeErrorZ {
		contents: CResult_ChannelFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_is_ok(o: &CResult_ChannelFeaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelFeaturesDecodeErrorZ.
pub extern "C" fn CResult_ChannelFeaturesDecodeErrorZ_free(_res: CResult_ChannelFeaturesDecodeErrorZ) { }
impl Drop for CResult_ChannelFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::features::ChannelFeatures, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::features::ChannelFeatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_NodeFeaturesDecodeErrorZ
pub union CResult_NodeFeaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::features::NodeFeatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NodeFeaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::features::NodeFeatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NodeFeaturesDecodeErrorZ {
	/// The contents of this CResult_NodeFeaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NodeFeaturesDecodeErrorZPtr,
	/// Whether this CResult_NodeFeaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NodeFeaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_ok(o: crate::lightning::ln::features::NodeFeatures) -> CResult_NodeFeaturesDecodeErrorZ {
	CResult_NodeFeaturesDecodeErrorZ {
		contents: CResult_NodeFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NodeFeaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NodeFeaturesDecodeErrorZ {
	CResult_NodeFeaturesDecodeErrorZ {
		contents: CResult_NodeFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_is_ok(o: &CResult_NodeFeaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NodeFeaturesDecodeErrorZ.
pub extern "C" fn CResult_NodeFeaturesDecodeErrorZ_free(_res: CResult_NodeFeaturesDecodeErrorZ) { }
impl Drop for CResult_NodeFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::features::NodeFeatures, crate::lightning::ln::msgs::DecodeError>> for CResult_NodeFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::features::NodeFeatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_InvoiceFeaturesDecodeErrorZ
pub union CResult_InvoiceFeaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::features::InvoiceFeatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_InvoiceFeaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::features::InvoiceFeatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InvoiceFeaturesDecodeErrorZ {
	/// The contents of this CResult_InvoiceFeaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InvoiceFeaturesDecodeErrorZPtr,
	/// Whether this CResult_InvoiceFeaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InvoiceFeaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_InvoiceFeaturesDecodeErrorZ_ok(o: crate::lightning::ln::features::InvoiceFeatures) -> CResult_InvoiceFeaturesDecodeErrorZ {
	CResult_InvoiceFeaturesDecodeErrorZ {
		contents: CResult_InvoiceFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceFeaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_InvoiceFeaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_InvoiceFeaturesDecodeErrorZ {
	CResult_InvoiceFeaturesDecodeErrorZ {
		contents: CResult_InvoiceFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InvoiceFeaturesDecodeErrorZ_is_ok(o: &CResult_InvoiceFeaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InvoiceFeaturesDecodeErrorZ.
pub extern "C" fn CResult_InvoiceFeaturesDecodeErrorZ_free(_res: CResult_InvoiceFeaturesDecodeErrorZ) { }
impl Drop for CResult_InvoiceFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::features::InvoiceFeatures, crate::lightning::ln::msgs::DecodeError>> for CResult_InvoiceFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::features::InvoiceFeatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InvoiceFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InvoiceFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_ChannelTypeFeaturesDecodeErrorZ
pub union CResult_ChannelTypeFeaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::features::ChannelTypeFeatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelTypeFeaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::features::ChannelTypeFeatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelTypeFeaturesDecodeErrorZ {
	/// The contents of this CResult_ChannelTypeFeaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelTypeFeaturesDecodeErrorZPtr,
	/// Whether this CResult_ChannelTypeFeaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelTypeFeaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelTypeFeaturesDecodeErrorZ_ok(o: crate::lightning::ln::features::ChannelTypeFeatures) -> CResult_ChannelTypeFeaturesDecodeErrorZ {
	CResult_ChannelTypeFeaturesDecodeErrorZ {
		contents: CResult_ChannelTypeFeaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelTypeFeaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelTypeFeaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelTypeFeaturesDecodeErrorZ {
	CResult_ChannelTypeFeaturesDecodeErrorZ {
		contents: CResult_ChannelTypeFeaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelTypeFeaturesDecodeErrorZ_is_ok(o: &CResult_ChannelTypeFeaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelTypeFeaturesDecodeErrorZ.
pub extern "C" fn CResult_ChannelTypeFeaturesDecodeErrorZ_free(_res: CResult_ChannelTypeFeaturesDecodeErrorZ) { }
impl Drop for CResult_ChannelTypeFeaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::features::ChannelTypeFeatures, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelTypeFeaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::features::ChannelTypeFeatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelTypeFeaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelTypeFeaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_DelayedPaymentOutputDescriptorDecodeErrorZ
pub union CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_DelayedPaymentOutputDescriptorDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	/// The contents of this CResult_DelayedPaymentOutputDescriptorDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr,
	/// Whether this CResult_DelayedPaymentOutputDescriptorDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_DelayedPaymentOutputDescriptorDecodeErrorZ in the success state.
pub extern "C" fn CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_ok(o: crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor) -> CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
		contents: CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_DelayedPaymentOutputDescriptorDecodeErrorZ in the error state.
pub extern "C" fn CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
		contents: CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_is_ok(o: &CResult_DelayedPaymentOutputDescriptorDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_DelayedPaymentOutputDescriptorDecodeErrorZ.
pub extern "C" fn CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_free(_res: CResult_DelayedPaymentOutputDescriptorDecodeErrorZ) { }
impl Drop for CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor, crate::lightning::ln::msgs::DecodeError>> for CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_DelayedPaymentOutputDescriptorDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::keysinterface::DelayedPaymentOutputDescriptor>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_DelayedPaymentOutputDescriptorDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_DelayedPaymentOutputDescriptorDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_DelayedPaymentOutputDescriptorDecodeErrorZ_clone(orig: &CResult_DelayedPaymentOutputDescriptorDecodeErrorZ) -> CResult_DelayedPaymentOutputDescriptorDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_StaticPaymentOutputDescriptorDecodeErrorZ
pub union CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_StaticPaymentOutputDescriptorDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	/// The contents of this CResult_StaticPaymentOutputDescriptorDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr,
	/// Whether this CResult_StaticPaymentOutputDescriptorDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_StaticPaymentOutputDescriptorDecodeErrorZ in the success state.
pub extern "C" fn CResult_StaticPaymentOutputDescriptorDecodeErrorZ_ok(o: crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor) -> CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
		contents: CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_StaticPaymentOutputDescriptorDecodeErrorZ in the error state.
pub extern "C" fn CResult_StaticPaymentOutputDescriptorDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
		contents: CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_StaticPaymentOutputDescriptorDecodeErrorZ_is_ok(o: &CResult_StaticPaymentOutputDescriptorDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_StaticPaymentOutputDescriptorDecodeErrorZ.
pub extern "C" fn CResult_StaticPaymentOutputDescriptorDecodeErrorZ_free(_res: CResult_StaticPaymentOutputDescriptorDecodeErrorZ) { }
impl Drop for CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor, crate::lightning::ln::msgs::DecodeError>> for CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_StaticPaymentOutputDescriptorDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::keysinterface::StaticPaymentOutputDescriptor>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_StaticPaymentOutputDescriptorDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_StaticPaymentOutputDescriptorDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_StaticPaymentOutputDescriptorDecodeErrorZ_clone(orig: &CResult_StaticPaymentOutputDescriptorDecodeErrorZ) -> CResult_StaticPaymentOutputDescriptorDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_SpendableOutputDescriptorDecodeErrorZ
pub union CResult_SpendableOutputDescriptorDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::keysinterface::SpendableOutputDescriptor,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_SpendableOutputDescriptorDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::keysinterface::SpendableOutputDescriptor on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SpendableOutputDescriptorDecodeErrorZ {
	/// The contents of this CResult_SpendableOutputDescriptorDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr,
	/// Whether this CResult_SpendableOutputDescriptorDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SpendableOutputDescriptorDecodeErrorZ in the success state.
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_ok(o: crate::lightning::chain::keysinterface::SpendableOutputDescriptor) -> CResult_SpendableOutputDescriptorDecodeErrorZ {
	CResult_SpendableOutputDescriptorDecodeErrorZ {
		contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SpendableOutputDescriptorDecodeErrorZ in the error state.
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_SpendableOutputDescriptorDecodeErrorZ {
	CResult_SpendableOutputDescriptorDecodeErrorZ {
		contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_is_ok(o: &CResult_SpendableOutputDescriptorDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SpendableOutputDescriptorDecodeErrorZ.
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_free(_res: CResult_SpendableOutputDescriptorDecodeErrorZ) { }
impl Drop for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::SpendableOutputDescriptor, crate::lightning::ln::msgs::DecodeError>> for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::SpendableOutputDescriptor, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SpendableOutputDescriptorDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SpendableOutputDescriptorDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SpendableOutputDescriptorDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::keysinterface::SpendableOutputDescriptor>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SpendableOutputDescriptorDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_SpendableOutputDescriptorDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_SpendableOutputDescriptorDecodeErrorZ_clone(orig: &CResult_SpendableOutputDescriptorDecodeErrorZ) -> CResult_SpendableOutputDescriptorDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NoneNoneZ
pub union CResult_NoneNoneZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_NoneNoneZ represents the result of a fallible operation,
/// containing a () on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneNoneZ {
	/// The contents of this CResult_NoneNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneNoneZPtr,
	/// Whether this CResult_NoneNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneNoneZ in the success state.
pub extern "C" fn CResult_NoneNoneZ_ok() -> CResult_NoneNoneZ {
	CResult_NoneNoneZ {
		contents: CResult_NoneNoneZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneNoneZ in the error state.
pub extern "C" fn CResult_NoneNoneZ_err() -> CResult_NoneNoneZ {
	CResult_NoneNoneZ {
		contents: CResult_NoneNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneNoneZ_is_ok(o: &CResult_NoneNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneNoneZ.
pub extern "C" fn CResult_NoneNoneZ_free(_res: CResult_NoneNoneZ) { }
impl Drop for CResult_NoneNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<(), ()>> for CResult_NoneNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<(), ()>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneNoneZPtr { result: std::ptr::null_mut() }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_NoneNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneNoneZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneNoneZ_clone(orig: &CResult_NoneNoneZ) -> CResult_NoneNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_SignatureCVec_SignatureZZ {
	/// The element at position 0
	pub a: crate::c_types::Signature,
	/// The element at position 1
	pub b: crate::c_types::derived::CVec_SignatureZ,
}
impl From<(crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ)> for C2Tuple_SignatureCVec_SignatureZZ {
	fn from (tup: (crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_SignatureCVec_SignatureZZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::Signature, crate::c_types::derived::CVec_SignatureZ) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_SignatureCVec_SignatureZZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_clone(orig: &C2Tuple_SignatureCVec_SignatureZZ) -> C2Tuple_SignatureCVec_SignatureZZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_SignatureCVec_SignatureZZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_new(a: crate::c_types::Signature, b: crate::c_types::derived::CVec_SignatureZ) -> C2Tuple_SignatureCVec_SignatureZZ {
	C2Tuple_SignatureCVec_SignatureZZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_SignatureCVec_SignatureZZ.
pub extern "C" fn C2Tuple_SignatureCVec_SignatureZZ_free(_res: C2Tuple_SignatureCVec_SignatureZZ) { }
#[repr(C)]
/// The contents of CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ
pub union CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	/// The contents of this CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr,
	/// Whether this CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ in the success state.
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_ok(o: crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ) -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
		contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ in the error state.
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_err() -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
		contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_is_ok(o: &CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ.
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_free(_res: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) { }
impl Drop for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ, ()>> for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::C2Tuple_SignatureCVec_SignatureZZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_C2Tuple_SignatureCVec_SignatureZZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ_clone(orig: &CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ) -> CResult_C2Tuple_SignatureCVec_SignatureZZNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_SignatureNoneZ
pub union CResult_SignatureNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::Signature,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_SignatureNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::Signature on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SignatureNoneZ {
	/// The contents of this CResult_SignatureNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SignatureNoneZPtr,
	/// Whether this CResult_SignatureNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SignatureNoneZ in the success state.
pub extern "C" fn CResult_SignatureNoneZ_ok(o: crate::c_types::Signature) -> CResult_SignatureNoneZ {
	CResult_SignatureNoneZ {
		contents: CResult_SignatureNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SignatureNoneZ in the error state.
pub extern "C" fn CResult_SignatureNoneZ_err() -> CResult_SignatureNoneZ {
	CResult_SignatureNoneZ {
		contents: CResult_SignatureNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SignatureNoneZ_is_ok(o: &CResult_SignatureNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SignatureNoneZ.
pub extern "C" fn CResult_SignatureNoneZ_free(_res: CResult_SignatureNoneZ) { }
impl Drop for CResult_SignatureNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::Signature, ()>> for CResult_SignatureNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::Signature, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SignatureNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_SignatureNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SignatureNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SignatureNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::Signature>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SignatureNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_SignatureNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_SignatureNoneZ_clone(orig: &CResult_SignatureNoneZ) -> CResult_SignatureNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_SignDecodeErrorZ
pub union CResult_SignDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::keysinterface::Sign,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_SignDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::keysinterface::Sign on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SignDecodeErrorZ {
	/// The contents of this CResult_SignDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SignDecodeErrorZPtr,
	/// Whether this CResult_SignDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SignDecodeErrorZ in the success state.
pub extern "C" fn CResult_SignDecodeErrorZ_ok(o: crate::lightning::chain::keysinterface::Sign) -> CResult_SignDecodeErrorZ {
	CResult_SignDecodeErrorZ {
		contents: CResult_SignDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SignDecodeErrorZ in the error state.
pub extern "C" fn CResult_SignDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_SignDecodeErrorZ {
	CResult_SignDecodeErrorZ {
		contents: CResult_SignDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SignDecodeErrorZ_is_ok(o: &CResult_SignDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SignDecodeErrorZ.
pub extern "C" fn CResult_SignDecodeErrorZ_free(_res: CResult_SignDecodeErrorZ) { }
impl Drop for CResult_SignDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::Sign, crate::lightning::ln::msgs::DecodeError>> for CResult_SignDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::Sign, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SignDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_SignDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SignDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SignDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::keysinterface::Sign>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SignDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_SignDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_SignDecodeErrorZ_clone(orig: &CResult_SignDecodeErrorZ) -> CResult_SignDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of u8s of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_u8Z {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut u8,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_u8Z {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<u8> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[u8] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<u8>> for CVec_u8Z {
	fn from(v: Vec<u8>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_u8Z_free(_res: CVec_u8Z) { }
impl Drop for CVec_u8Z {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_u8Z {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_RecoverableSignatureNoneZ
pub union CResult_RecoverableSignatureNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::RecoverableSignature,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_RecoverableSignatureNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::RecoverableSignature on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RecoverableSignatureNoneZ {
	/// The contents of this CResult_RecoverableSignatureNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RecoverableSignatureNoneZPtr,
	/// Whether this CResult_RecoverableSignatureNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RecoverableSignatureNoneZ in the success state.
pub extern "C" fn CResult_RecoverableSignatureNoneZ_ok(o: crate::c_types::RecoverableSignature) -> CResult_RecoverableSignatureNoneZ {
	CResult_RecoverableSignatureNoneZ {
		contents: CResult_RecoverableSignatureNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RecoverableSignatureNoneZ in the error state.
pub extern "C" fn CResult_RecoverableSignatureNoneZ_err() -> CResult_RecoverableSignatureNoneZ {
	CResult_RecoverableSignatureNoneZ {
		contents: CResult_RecoverableSignatureNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RecoverableSignatureNoneZ_is_ok(o: &CResult_RecoverableSignatureNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RecoverableSignatureNoneZ.
pub extern "C" fn CResult_RecoverableSignatureNoneZ_free(_res: CResult_RecoverableSignatureNoneZ) { }
impl Drop for CResult_RecoverableSignatureNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::RecoverableSignature, ()>> for CResult_RecoverableSignatureNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::RecoverableSignature, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RecoverableSignatureNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_RecoverableSignatureNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RecoverableSignatureNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RecoverableSignatureNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::RecoverableSignature>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RecoverableSignatureNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RecoverableSignatureNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RecoverableSignatureNoneZ_clone(orig: &CResult_RecoverableSignatureNoneZ) -> CResult_RecoverableSignatureNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::CVec_u8Zs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_CVec_u8ZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::CVec_u8Z,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_CVec_u8ZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CVec_u8Z> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CVec_u8Z] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CVec_u8Z>> for CVec_CVec_u8ZZ {
	fn from(v: Vec<crate::c_types::derived::CVec_u8Z>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_CVec_u8ZZ_free(_res: CVec_CVec_u8ZZ) { }
impl Drop for CVec_CVec_u8ZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CVec_u8ZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_CVec_CVec_u8ZZNoneZ
pub union CResult_CVec_CVec_u8ZZNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::CVec_CVec_u8ZZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_CVec_CVec_u8ZZNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::CVec_CVec_u8ZZ on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CVec_CVec_u8ZZNoneZ {
	/// The contents of this CResult_CVec_CVec_u8ZZNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CVec_CVec_u8ZZNoneZPtr,
	/// Whether this CResult_CVec_CVec_u8ZZNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CVec_CVec_u8ZZNoneZ in the success state.
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_ok(o: crate::c_types::derived::CVec_CVec_u8ZZ) -> CResult_CVec_CVec_u8ZZNoneZ {
	CResult_CVec_CVec_u8ZZNoneZ {
		contents: CResult_CVec_CVec_u8ZZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_CVec_u8ZZNoneZ in the error state.
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_err() -> CResult_CVec_CVec_u8ZZNoneZ {
	CResult_CVec_CVec_u8ZZNoneZ {
		contents: CResult_CVec_CVec_u8ZZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_is_ok(o: &CResult_CVec_CVec_u8ZZNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CVec_CVec_u8ZZNoneZ.
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_free(_res: CResult_CVec_CVec_u8ZZNoneZ) { }
impl Drop for CResult_CVec_CVec_u8ZZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_CVec_u8ZZ, ()>> for CResult_CVec_CVec_u8ZZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_CVec_u8ZZ, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_CVec_u8ZZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_CVec_CVec_u8ZZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_CVec_u8ZZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_CVec_u8ZZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_CVec_u8ZZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_CVec_u8ZZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_CVec_u8ZZNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CVec_CVec_u8ZZNoneZ_clone(orig: &CResult_CVec_CVec_u8ZZNoneZ) -> CResult_CVec_CVec_u8ZZNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_InMemorySignerDecodeErrorZ
pub union CResult_InMemorySignerDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::keysinterface::InMemorySigner,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_InMemorySignerDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::keysinterface::InMemorySigner on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InMemorySignerDecodeErrorZ {
	/// The contents of this CResult_InMemorySignerDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InMemorySignerDecodeErrorZPtr,
	/// Whether this CResult_InMemorySignerDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InMemorySignerDecodeErrorZ in the success state.
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_ok(o: crate::lightning::chain::keysinterface::InMemorySigner) -> CResult_InMemorySignerDecodeErrorZ {
	CResult_InMemorySignerDecodeErrorZ {
		contents: CResult_InMemorySignerDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InMemorySignerDecodeErrorZ in the error state.
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_InMemorySignerDecodeErrorZ {
	CResult_InMemorySignerDecodeErrorZ {
		contents: CResult_InMemorySignerDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_is_ok(o: &CResult_InMemorySignerDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InMemorySignerDecodeErrorZ.
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_free(_res: CResult_InMemorySignerDecodeErrorZ) { }
impl Drop for CResult_InMemorySignerDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::InMemorySigner, crate::lightning::ln::msgs::DecodeError>> for CResult_InMemorySignerDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::keysinterface::InMemorySigner, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InMemorySignerDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InMemorySignerDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InMemorySignerDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InMemorySignerDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::keysinterface::InMemorySigner>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InMemorySignerDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_InMemorySignerDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_InMemorySignerDecodeErrorZ_clone(orig: &CResult_InMemorySignerDecodeErrorZ) -> CResult_InMemorySignerDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::TxOuts of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_TxOutZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::TxOut,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_TxOutZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::TxOut> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::TxOut] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::TxOut>> for CVec_TxOutZ {
	fn from(v: Vec<crate::c_types::TxOut>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_TxOutZ_free(_res: CVec_TxOutZ) { }
impl Drop for CVec_TxOutZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_TxOutZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_TransactionNoneZ
pub union CResult_TransactionNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::Transaction,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_TransactionNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::Transaction on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_TransactionNoneZ {
	/// The contents of this CResult_TransactionNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_TransactionNoneZPtr,
	/// Whether this CResult_TransactionNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_TransactionNoneZ in the success state.
pub extern "C" fn CResult_TransactionNoneZ_ok(o: crate::c_types::Transaction) -> CResult_TransactionNoneZ {
	CResult_TransactionNoneZ {
		contents: CResult_TransactionNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_TransactionNoneZ in the error state.
pub extern "C" fn CResult_TransactionNoneZ_err() -> CResult_TransactionNoneZ {
	CResult_TransactionNoneZ {
		contents: CResult_TransactionNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_TransactionNoneZ_is_ok(o: &CResult_TransactionNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_TransactionNoneZ.
pub extern "C" fn CResult_TransactionNoneZ_free(_res: CResult_TransactionNoneZ) { }
impl Drop for CResult_TransactionNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::Transaction, ()>> for CResult_TransactionNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::Transaction, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_TransactionNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_TransactionNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_TransactionNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_TransactionNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::Transaction>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_TransactionNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_TransactionNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_TransactionNoneZ_clone(orig: &CResult_TransactionNoneZ) -> CResult_TransactionNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_BlockHashChannelMonitorZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::lightning::chain::channelmonitor::ChannelMonitor,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::lightning::chain::channelmonitor::ChannelMonitor)> for C2Tuple_BlockHashChannelMonitorZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::lightning::chain::channelmonitor::ChannelMonitor)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_BlockHashChannelMonitorZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::lightning::chain::channelmonitor::ChannelMonitor) {
		(self.a, self.b)
	}
}
/// Creates a new C2Tuple_BlockHashChannelMonitorZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelMonitorZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::lightning::chain::channelmonitor::ChannelMonitor) -> C2Tuple_BlockHashChannelMonitorZ {
	C2Tuple_BlockHashChannelMonitorZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_BlockHashChannelMonitorZ.
pub extern "C" fn C2Tuple_BlockHashChannelMonitorZ_free(_res: C2Tuple_BlockHashChannelMonitorZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_BlockHashChannelMonitorZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_BlockHashChannelMonitorZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ>> for CVec_C2Tuple_BlockHashChannelMonitorZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_BlockHashChannelMonitorZZ_free(_res: CVec_C2Tuple_BlockHashChannelMonitorZZ) { }
impl Drop for CVec_C2Tuple_BlockHashChannelMonitorZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
/// The contents of CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ
pub union CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::CVec_C2Tuple_BlockHashChannelMonitorZZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::IOError,
}
#[repr(C)]
/// A CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::CVec_C2Tuple_BlockHashChannelMonitorZZ on success and a crate::c_types::IOError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	/// The contents of this CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr,
	/// Whether this CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ in the success state.
pub extern "C" fn CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_ok(o: crate::c_types::derived::CVec_C2Tuple_BlockHashChannelMonitorZZ) -> CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
		contents: CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ in the error state.
pub extern "C" fn CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_err(e: crate::c_types::IOError) -> CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
		contents: CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_is_ok(o: &CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ.
pub extern "C" fn CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ_free(_res: CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ) { }
impl Drop for CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_C2Tuple_BlockHashChannelMonitorZZ, crate::c_types::IOError>> for CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_C2Tuple_BlockHashChannelMonitorZZ, crate::c_types::IOError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CVec_C2Tuple_BlockHashChannelMonitorZZErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a u16 or not
pub enum COption_u16Z {
	/// When we're in this state, this COption_u16Z contains a u16
	Some(u16),
	/// When we're in this state, this COption_u16Z contains nothing
	None
}
impl COption_u16Z {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> u16 {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_u16Z containing a u16
pub extern "C" fn COption_u16Z_some(o: u16) -> COption_u16Z {
	COption_u16Z::Some(o)
}
#[no_mangle]
/// Constructs a new COption_u16Z containing nothing
pub extern "C" fn COption_u16Z_none() -> COption_u16Z {
	COption_u16Z::None
}
#[no_mangle]
/// Frees any resources associated with the u16, if we are in the Some state
pub extern "C" fn COption_u16Z_free(_res: COption_u16Z) { }
#[no_mangle]
/// Creates a new COption_u16Z which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_u16Z_clone(orig: &COption_u16Z) -> COption_u16Z { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NoneAPIErrorZ
pub union CResult_NoneAPIErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::util::errors::APIError,
}
#[repr(C)]
/// A CResult_NoneAPIErrorZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning::util::errors::APIError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneAPIErrorZ {
	/// The contents of this CResult_NoneAPIErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneAPIErrorZPtr,
	/// Whether this CResult_NoneAPIErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneAPIErrorZ in the success state.
pub extern "C" fn CResult_NoneAPIErrorZ_ok() -> CResult_NoneAPIErrorZ {
	CResult_NoneAPIErrorZ {
		contents: CResult_NoneAPIErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneAPIErrorZ in the error state.
pub extern "C" fn CResult_NoneAPIErrorZ_err(e: crate::lightning::util::errors::APIError) -> CResult_NoneAPIErrorZ {
	CResult_NoneAPIErrorZ {
		contents: CResult_NoneAPIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneAPIErrorZ_is_ok(o: &CResult_NoneAPIErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneAPIErrorZ.
pub extern "C" fn CResult_NoneAPIErrorZ_free(_res: CResult_NoneAPIErrorZ) { }
impl Drop for CResult_NoneAPIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning::util::errors::APIError>> for CResult_NoneAPIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneAPIErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneAPIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneAPIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneAPIErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneAPIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneAPIErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneAPIErrorZ_clone(orig: &CResult_NoneAPIErrorZ) -> CResult_NoneAPIErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::CResult_NoneAPIErrorZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_CResult_NoneAPIErrorZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::CResult_NoneAPIErrorZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_CResult_NoneAPIErrorZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::CResult_NoneAPIErrorZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::CResult_NoneAPIErrorZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::CResult_NoneAPIErrorZ>> for CVec_CResult_NoneAPIErrorZZ {
	fn from(v: Vec<crate::c_types::derived::CResult_NoneAPIErrorZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_CResult_NoneAPIErrorZZ_free(_res: CVec_CResult_NoneAPIErrorZZ) { }
impl Drop for CVec_CResult_NoneAPIErrorZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_CResult_NoneAPIErrorZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::util::errors::APIErrors of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_APIErrorZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::util::errors::APIError,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_APIErrorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::util::errors::APIError> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::util::errors::APIError] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::util::errors::APIError>> for CVec_APIErrorZ {
	fn from(v: Vec<crate::lightning::util::errors::APIError>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_APIErrorZ_free(_res: CVec_APIErrorZ) { }
impl Drop for CVec_APIErrorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_APIErrorZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult__u832APIErrorZ
pub union CResult__u832APIErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::util::errors::APIError,
}
#[repr(C)]
/// A CResult__u832APIErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a crate::lightning::util::errors::APIError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult__u832APIErrorZ {
	/// The contents of this CResult__u832APIErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult__u832APIErrorZPtr,
	/// Whether this CResult__u832APIErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult__u832APIErrorZ in the success state.
pub extern "C" fn CResult__u832APIErrorZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult__u832APIErrorZ {
	CResult__u832APIErrorZ {
		contents: CResult__u832APIErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult__u832APIErrorZ in the error state.
pub extern "C" fn CResult__u832APIErrorZ_err(e: crate::lightning::util::errors::APIError) -> CResult__u832APIErrorZ {
	CResult__u832APIErrorZ {
		contents: CResult__u832APIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult__u832APIErrorZ_is_ok(o: &CResult__u832APIErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult__u832APIErrorZ.
pub extern "C" fn CResult__u832APIErrorZ_free(_res: CResult__u832APIErrorZ) { }
impl Drop for CResult__u832APIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>> for CResult__u832APIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult__u832APIErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult__u832APIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult__u832APIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult__u832APIErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult__u832APIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult__u832APIErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult__u832APIErrorZ_clone(orig: &CResult__u832APIErrorZ) -> CResult__u832APIErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PaymentIdPaymentSendFailureZ
pub union CResult_PaymentIdPaymentSendFailureZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::channelmanager::PaymentSendFailure,
}
#[repr(C)]
/// A CResult_PaymentIdPaymentSendFailureZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a crate::lightning::ln::channelmanager::PaymentSendFailure on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PaymentIdPaymentSendFailureZ {
	/// The contents of this CResult_PaymentIdPaymentSendFailureZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PaymentIdPaymentSendFailureZPtr,
	/// Whether this CResult_PaymentIdPaymentSendFailureZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentSendFailureZ in the success state.
pub extern "C" fn CResult_PaymentIdPaymentSendFailureZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult_PaymentIdPaymentSendFailureZ {
	CResult_PaymentIdPaymentSendFailureZ {
		contents: CResult_PaymentIdPaymentSendFailureZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentSendFailureZ in the error state.
pub extern "C" fn CResult_PaymentIdPaymentSendFailureZ_err(e: crate::lightning::ln::channelmanager::PaymentSendFailure) -> CResult_PaymentIdPaymentSendFailureZ {
	CResult_PaymentIdPaymentSendFailureZ {
		contents: CResult_PaymentIdPaymentSendFailureZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PaymentIdPaymentSendFailureZ_is_ok(o: &CResult_PaymentIdPaymentSendFailureZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PaymentIdPaymentSendFailureZ.
pub extern "C" fn CResult_PaymentIdPaymentSendFailureZ_free(_res: CResult_PaymentIdPaymentSendFailureZ) { }
impl Drop for CResult_PaymentIdPaymentSendFailureZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::ln::channelmanager::PaymentSendFailure>> for CResult_PaymentIdPaymentSendFailureZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::ln::channelmanager::PaymentSendFailure>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PaymentIdPaymentSendFailureZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PaymentIdPaymentSendFailureZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PaymentIdPaymentSendFailureZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PaymentIdPaymentSendFailureZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PaymentIdPaymentSendFailureZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::channelmanager::PaymentSendFailure>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentSendFailureZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PaymentIdPaymentSendFailureZ_clone(orig: &CResult_PaymentIdPaymentSendFailureZ) -> CResult_PaymentIdPaymentSendFailureZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NonePaymentSendFailureZ
pub union CResult_NonePaymentSendFailureZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::channelmanager::PaymentSendFailure,
}
#[repr(C)]
/// A CResult_NonePaymentSendFailureZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning::ln::channelmanager::PaymentSendFailure on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NonePaymentSendFailureZ {
	/// The contents of this CResult_NonePaymentSendFailureZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NonePaymentSendFailureZPtr,
	/// Whether this CResult_NonePaymentSendFailureZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NonePaymentSendFailureZ in the success state.
pub extern "C" fn CResult_NonePaymentSendFailureZ_ok() -> CResult_NonePaymentSendFailureZ {
	CResult_NonePaymentSendFailureZ {
		contents: CResult_NonePaymentSendFailureZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NonePaymentSendFailureZ in the error state.
pub extern "C" fn CResult_NonePaymentSendFailureZ_err(e: crate::lightning::ln::channelmanager::PaymentSendFailure) -> CResult_NonePaymentSendFailureZ {
	CResult_NonePaymentSendFailureZ {
		contents: CResult_NonePaymentSendFailureZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NonePaymentSendFailureZ_is_ok(o: &CResult_NonePaymentSendFailureZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NonePaymentSendFailureZ.
pub extern "C" fn CResult_NonePaymentSendFailureZ_free(_res: CResult_NonePaymentSendFailureZ) { }
impl Drop for CResult_NonePaymentSendFailureZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning::ln::channelmanager::PaymentSendFailure>> for CResult_NonePaymentSendFailureZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning::ln::channelmanager::PaymentSendFailure>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NonePaymentSendFailureZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NonePaymentSendFailureZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NonePaymentSendFailureZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NonePaymentSendFailureZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NonePaymentSendFailureZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::channelmanager::PaymentSendFailure>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NonePaymentSendFailureZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NonePaymentSendFailureZ_clone(orig: &CResult_NonePaymentSendFailureZ) -> CResult_NonePaymentSendFailureZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_PaymentHashPaymentIdZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::c_types::ThirtyTwoBytes,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes)> for C2Tuple_PaymentHashPaymentIdZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_PaymentHashPaymentIdZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_PaymentHashPaymentIdZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_PaymentHashPaymentIdZ_clone(orig: &C2Tuple_PaymentHashPaymentIdZ) -> C2Tuple_PaymentHashPaymentIdZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_PaymentHashPaymentIdZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_PaymentHashPaymentIdZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::ThirtyTwoBytes) -> C2Tuple_PaymentHashPaymentIdZ {
	C2Tuple_PaymentHashPaymentIdZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_PaymentHashPaymentIdZ.
pub extern "C" fn C2Tuple_PaymentHashPaymentIdZ_free(_res: C2Tuple_PaymentHashPaymentIdZ) { }
#[repr(C)]
/// The contents of CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ
pub union CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::channelmanager::PaymentSendFailure,
}
#[repr(C)]
/// A CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ on success and a crate::lightning::ln::channelmanager::PaymentSendFailure on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	/// The contents of this CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr,
	/// Whether this CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ in the success state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_ok(o: crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ) -> CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
		contents: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ in the error state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_err(e: crate::lightning::ln::channelmanager::PaymentSendFailure) -> CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
		contents: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_is_ok(o: &CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_free(_res: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ) { }
impl Drop for CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ, crate::lightning::ln::channelmanager::PaymentSendFailure>> for CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ, crate::lightning::ln::channelmanager::PaymentSendFailure>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::C2Tuple_PaymentHashPaymentIdZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::channelmanager::PaymentSendFailure>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ_clone(orig: &CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ) -> CResult_C2Tuple_PaymentHashPaymentIdZPaymentSendFailureZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::NetAddresss of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_NetAddressZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::NetAddress,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_NetAddressZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::NetAddress> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::NetAddress] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::NetAddress>> for CVec_NetAddressZ {
	fn from(v: Vec<crate::lightning::ln::msgs::NetAddress>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_NetAddressZ_free(_res: CVec_NetAddressZ) { }
impl Drop for CVec_NetAddressZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_NetAddressZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_PaymentHashPaymentSecretZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::c_types::ThirtyTwoBytes,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes)> for C2Tuple_PaymentHashPaymentSecretZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_PaymentHashPaymentSecretZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::c_types::ThirtyTwoBytes) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_PaymentHashPaymentSecretZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_PaymentHashPaymentSecretZ_clone(orig: &C2Tuple_PaymentHashPaymentSecretZ) -> C2Tuple_PaymentHashPaymentSecretZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_PaymentHashPaymentSecretZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_PaymentHashPaymentSecretZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::ThirtyTwoBytes) -> C2Tuple_PaymentHashPaymentSecretZ {
	C2Tuple_PaymentHashPaymentSecretZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_PaymentHashPaymentSecretZ.
pub extern "C" fn C2Tuple_PaymentHashPaymentSecretZ_free(_res: C2Tuple_PaymentHashPaymentSecretZ) { }
#[repr(C)]
/// The contents of CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ
pub union CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	/// The contents of this CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr,
	/// Whether this CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ in the success state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_ok(o: crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ) -> CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
		contents: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ in the error state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_err() -> CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
		contents: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_is_ok(o: &CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_free(_res: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ) { }
impl Drop for CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ, ()>> for CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_C2Tuple_PaymentHashPaymentSecretZNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ_clone(orig: &CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ) -> CResult_C2Tuple_PaymentHashPaymentSecretZNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ
pub union CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::util::errors::APIError,
}
#[repr(C)]
/// A CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ on success and a crate::lightning::util::errors::APIError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	/// The contents of this CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr,
	/// Whether this CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ in the success state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_ok(o: crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ) -> CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
		contents: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ in the error state.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_err(e: crate::lightning::util::errors::APIError) -> CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
		contents: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_is_ok(o: &CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_free(_res: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ) { }
impl Drop for CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ, crate::lightning::util::errors::APIError>> for CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ, crate::lightning::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::C2Tuple_PaymentHashPaymentSecretZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ_clone(orig: &CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ) -> CResult_C2Tuple_PaymentHashPaymentSecretZAPIErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PaymentSecretNoneZ
pub union CResult_PaymentSecretNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_PaymentSecretNoneZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PaymentSecretNoneZ {
	/// The contents of this CResult_PaymentSecretNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PaymentSecretNoneZPtr,
	/// Whether this CResult_PaymentSecretNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretNoneZ in the success state.
pub extern "C" fn CResult_PaymentSecretNoneZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult_PaymentSecretNoneZ {
	CResult_PaymentSecretNoneZ {
		contents: CResult_PaymentSecretNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretNoneZ in the error state.
pub extern "C" fn CResult_PaymentSecretNoneZ_err() -> CResult_PaymentSecretNoneZ {
	CResult_PaymentSecretNoneZ {
		contents: CResult_PaymentSecretNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PaymentSecretNoneZ_is_ok(o: &CResult_PaymentSecretNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PaymentSecretNoneZ.
pub extern "C" fn CResult_PaymentSecretNoneZ_free(_res: CResult_PaymentSecretNoneZ) { }
impl Drop for CResult_PaymentSecretNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, ()>> for CResult_PaymentSecretNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PaymentSecretNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_PaymentSecretNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PaymentSecretNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PaymentSecretNoneZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PaymentSecretNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PaymentSecretNoneZ_clone(orig: &CResult_PaymentSecretNoneZ) -> CResult_PaymentSecretNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PaymentSecretAPIErrorZ
pub union CResult_PaymentSecretAPIErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::util::errors::APIError,
}
#[repr(C)]
/// A CResult_PaymentSecretAPIErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a crate::lightning::util::errors::APIError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PaymentSecretAPIErrorZ {
	/// The contents of this CResult_PaymentSecretAPIErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PaymentSecretAPIErrorZPtr,
	/// Whether this CResult_PaymentSecretAPIErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretAPIErrorZ in the success state.
pub extern "C" fn CResult_PaymentSecretAPIErrorZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult_PaymentSecretAPIErrorZ {
	CResult_PaymentSecretAPIErrorZ {
		contents: CResult_PaymentSecretAPIErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretAPIErrorZ in the error state.
pub extern "C" fn CResult_PaymentSecretAPIErrorZ_err(e: crate::lightning::util::errors::APIError) -> CResult_PaymentSecretAPIErrorZ {
	CResult_PaymentSecretAPIErrorZ {
		contents: CResult_PaymentSecretAPIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PaymentSecretAPIErrorZ_is_ok(o: &CResult_PaymentSecretAPIErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PaymentSecretAPIErrorZ.
pub extern "C" fn CResult_PaymentSecretAPIErrorZ_free(_res: CResult_PaymentSecretAPIErrorZ) { }
impl Drop for CResult_PaymentSecretAPIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>> for CResult_PaymentSecretAPIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PaymentSecretAPIErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PaymentSecretAPIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PaymentSecretAPIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PaymentSecretAPIErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PaymentSecretAPIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentSecretAPIErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PaymentSecretAPIErrorZ_clone(orig: &CResult_PaymentSecretAPIErrorZ) -> CResult_PaymentSecretAPIErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PaymentPreimageAPIErrorZ
pub union CResult_PaymentPreimageAPIErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::util::errors::APIError,
}
#[repr(C)]
/// A CResult_PaymentPreimageAPIErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a crate::lightning::util::errors::APIError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PaymentPreimageAPIErrorZ {
	/// The contents of this CResult_PaymentPreimageAPIErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PaymentPreimageAPIErrorZPtr,
	/// Whether this CResult_PaymentPreimageAPIErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PaymentPreimageAPIErrorZ in the success state.
pub extern "C" fn CResult_PaymentPreimageAPIErrorZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult_PaymentPreimageAPIErrorZ {
	CResult_PaymentPreimageAPIErrorZ {
		contents: CResult_PaymentPreimageAPIErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentPreimageAPIErrorZ in the error state.
pub extern "C" fn CResult_PaymentPreimageAPIErrorZ_err(e: crate::lightning::util::errors::APIError) -> CResult_PaymentPreimageAPIErrorZ {
	CResult_PaymentPreimageAPIErrorZ {
		contents: CResult_PaymentPreimageAPIErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PaymentPreimageAPIErrorZ_is_ok(o: &CResult_PaymentPreimageAPIErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PaymentPreimageAPIErrorZ.
pub extern "C" fn CResult_PaymentPreimageAPIErrorZ_free(_res: CResult_PaymentPreimageAPIErrorZ) { }
impl Drop for CResult_PaymentPreimageAPIErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>> for CResult_PaymentPreimageAPIErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning::util::errors::APIError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PaymentPreimageAPIErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PaymentPreimageAPIErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PaymentPreimageAPIErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PaymentPreimageAPIErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PaymentPreimageAPIErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::util::errors::APIError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentPreimageAPIErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PaymentPreimageAPIErrorZ_clone(orig: &CResult_PaymentPreimageAPIErrorZ) -> CResult_PaymentPreimageAPIErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::chain::channelmonitor::ChannelMonitors of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_ChannelMonitorZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::chain::channelmonitor::ChannelMonitor,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_ChannelMonitorZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::chain::channelmonitor::ChannelMonitor> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::chain::channelmonitor::ChannelMonitor] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::chain::channelmonitor::ChannelMonitor>> for CVec_ChannelMonitorZ {
	fn from(v: Vec<crate::lightning::chain::channelmonitor::ChannelMonitor>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_ChannelMonitorZ_free(_res: CVec_ChannelMonitorZ) { }
impl Drop for CVec_ChannelMonitorZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_BlockHashChannelManagerZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::lightning::ln::channelmanager::ChannelManager,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::lightning::ln::channelmanager::ChannelManager)> for C2Tuple_BlockHashChannelManagerZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::lightning::ln::channelmanager::ChannelManager)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_BlockHashChannelManagerZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::lightning::ln::channelmanager::ChannelManager) {
		(self.a, self.b)
	}
}
/// Creates a new C2Tuple_BlockHashChannelManagerZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::lightning::ln::channelmanager::ChannelManager) -> C2Tuple_BlockHashChannelManagerZ {
	C2Tuple_BlockHashChannelManagerZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_BlockHashChannelManagerZ.
pub extern "C" fn C2Tuple_BlockHashChannelManagerZ_free(_res: C2Tuple_BlockHashChannelManagerZ) { }
#[repr(C)]
/// The contents of CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ
pub union CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	/// The contents of this CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr,
	/// Whether this CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ in the success state.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_ok(o: crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ) -> CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ in the error state.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_is_ok(o: &CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ_free(_res: CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ) { }
impl Drop for CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ, crate::lightning::ln::msgs::DecodeError>> for CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelManagerZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_BlockHashChannelManagerZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_ChannelConfigDecodeErrorZ
pub union CResult_ChannelConfigDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::util::config::ChannelConfig,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelConfigDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::util::config::ChannelConfig on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelConfigDecodeErrorZ {
	/// The contents of this CResult_ChannelConfigDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelConfigDecodeErrorZPtr,
	/// Whether this CResult_ChannelConfigDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelConfigDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_ok(o: crate::lightning::util::config::ChannelConfig) -> CResult_ChannelConfigDecodeErrorZ {
	CResult_ChannelConfigDecodeErrorZ {
		contents: CResult_ChannelConfigDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelConfigDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelConfigDecodeErrorZ {
	CResult_ChannelConfigDecodeErrorZ {
		contents: CResult_ChannelConfigDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_is_ok(o: &CResult_ChannelConfigDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelConfigDecodeErrorZ.
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_free(_res: CResult_ChannelConfigDecodeErrorZ) { }
impl Drop for CResult_ChannelConfigDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::util::config::ChannelConfig, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelConfigDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::util::config::ChannelConfig, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelConfigDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelConfigDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelConfigDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelConfigDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::util::config::ChannelConfig>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelConfigDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelConfigDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelConfigDecodeErrorZ_clone(orig: &CResult_ChannelConfigDecodeErrorZ) -> CResult_ChannelConfigDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_OutPointDecodeErrorZ
pub union CResult_OutPointDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::transaction::OutPoint,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_OutPointDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::transaction::OutPoint on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_OutPointDecodeErrorZ {
	/// The contents of this CResult_OutPointDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_OutPointDecodeErrorZPtr,
	/// Whether this CResult_OutPointDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_OutPointDecodeErrorZ in the success state.
pub extern "C" fn CResult_OutPointDecodeErrorZ_ok(o: crate::lightning::chain::transaction::OutPoint) -> CResult_OutPointDecodeErrorZ {
	CResult_OutPointDecodeErrorZ {
		contents: CResult_OutPointDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_OutPointDecodeErrorZ in the error state.
pub extern "C" fn CResult_OutPointDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_OutPointDecodeErrorZ {
	CResult_OutPointDecodeErrorZ {
		contents: CResult_OutPointDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_OutPointDecodeErrorZ_is_ok(o: &CResult_OutPointDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_OutPointDecodeErrorZ.
pub extern "C" fn CResult_OutPointDecodeErrorZ_free(_res: CResult_OutPointDecodeErrorZ) { }
impl Drop for CResult_OutPointDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::transaction::OutPoint, crate::lightning::ln::msgs::DecodeError>> for CResult_OutPointDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::transaction::OutPoint, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_OutPointDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_OutPointDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_OutPointDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_OutPointDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::transaction::OutPoint>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_OutPointDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_OutPointDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_OutPointDecodeErrorZ_clone(orig: &CResult_OutPointDecodeErrorZ) -> CResult_OutPointDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// An enum which can either contain a crate::lightning::ln::wire::Type or not
pub enum COption_TypeZ {
	/// When we're in this state, this COption_TypeZ contains a crate::lightning::ln::wire::Type
	Some(crate::lightning::ln::wire::Type),
	/// When we're in this state, this COption_TypeZ contains nothing
	None
}
impl COption_TypeZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::ln::wire::Type {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_TypeZ containing a crate::lightning::ln::wire::Type
pub extern "C" fn COption_TypeZ_some(o: crate::lightning::ln::wire::Type) -> COption_TypeZ {
	COption_TypeZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_TypeZ containing nothing
pub extern "C" fn COption_TypeZ_none() -> COption_TypeZ {
	COption_TypeZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::ln::wire::Type, if we are in the Some state
pub extern "C" fn COption_TypeZ_free(_res: COption_TypeZ) { }
#[repr(C)]
/// The contents of CResult_COption_TypeZDecodeErrorZ
pub union CResult_COption_TypeZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::COption_TypeZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_COption_TypeZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::COption_TypeZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_COption_TypeZDecodeErrorZ {
	/// The contents of this CResult_COption_TypeZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_COption_TypeZDecodeErrorZPtr,
	/// Whether this CResult_COption_TypeZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_COption_TypeZDecodeErrorZ in the success state.
pub extern "C" fn CResult_COption_TypeZDecodeErrorZ_ok(o: crate::c_types::derived::COption_TypeZ) -> CResult_COption_TypeZDecodeErrorZ {
	CResult_COption_TypeZDecodeErrorZ {
		contents: CResult_COption_TypeZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_COption_TypeZDecodeErrorZ in the error state.
pub extern "C" fn CResult_COption_TypeZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_COption_TypeZDecodeErrorZ {
	CResult_COption_TypeZDecodeErrorZ {
		contents: CResult_COption_TypeZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_COption_TypeZDecodeErrorZ_is_ok(o: &CResult_COption_TypeZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_COption_TypeZDecodeErrorZ.
pub extern "C" fn CResult_COption_TypeZDecodeErrorZ_free(_res: CResult_COption_TypeZDecodeErrorZ) { }
impl Drop for CResult_COption_TypeZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::COption_TypeZ, crate::lightning::ln::msgs::DecodeError>> for CResult_COption_TypeZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::COption_TypeZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_COption_TypeZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_COption_TypeZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_PaymentIdPaymentErrorZ
pub union CResult_PaymentIdPaymentErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::ThirtyTwoBytes,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::payment::PaymentError,
}
#[repr(C)]
/// A CResult_PaymentIdPaymentErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::ThirtyTwoBytes on success and a crate::lightning_invoice::payment::PaymentError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PaymentIdPaymentErrorZ {
	/// The contents of this CResult_PaymentIdPaymentErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PaymentIdPaymentErrorZPtr,
	/// Whether this CResult_PaymentIdPaymentErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentErrorZ in the success state.
pub extern "C" fn CResult_PaymentIdPaymentErrorZ_ok(o: crate::c_types::ThirtyTwoBytes) -> CResult_PaymentIdPaymentErrorZ {
	CResult_PaymentIdPaymentErrorZ {
		contents: CResult_PaymentIdPaymentErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentErrorZ in the error state.
pub extern "C" fn CResult_PaymentIdPaymentErrorZ_err(e: crate::lightning_invoice::payment::PaymentError) -> CResult_PaymentIdPaymentErrorZ {
	CResult_PaymentIdPaymentErrorZ {
		contents: CResult_PaymentIdPaymentErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PaymentIdPaymentErrorZ_is_ok(o: &CResult_PaymentIdPaymentErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PaymentIdPaymentErrorZ.
pub extern "C" fn CResult_PaymentIdPaymentErrorZ_free(_res: CResult_PaymentIdPaymentErrorZ) { }
impl Drop for CResult_PaymentIdPaymentErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning_invoice::payment::PaymentError>> for CResult_PaymentIdPaymentErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::ThirtyTwoBytes, crate::lightning_invoice::payment::PaymentError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PaymentIdPaymentErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PaymentIdPaymentErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PaymentIdPaymentErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PaymentIdPaymentErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::ThirtyTwoBytes>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PaymentIdPaymentErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::payment::PaymentError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PaymentIdPaymentErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PaymentIdPaymentErrorZ_clone(orig: &CResult_PaymentIdPaymentErrorZ) -> CResult_PaymentIdPaymentErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_SiPrefixNoneZ
pub union CResult_SiPrefixNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::SiPrefix,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_SiPrefixNoneZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::SiPrefix on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SiPrefixNoneZ {
	/// The contents of this CResult_SiPrefixNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SiPrefixNoneZPtr,
	/// Whether this CResult_SiPrefixNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SiPrefixNoneZ in the success state.
pub extern "C" fn CResult_SiPrefixNoneZ_ok(o: crate::lightning_invoice::SiPrefix) -> CResult_SiPrefixNoneZ {
	CResult_SiPrefixNoneZ {
		contents: CResult_SiPrefixNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SiPrefixNoneZ in the error state.
pub extern "C" fn CResult_SiPrefixNoneZ_err() -> CResult_SiPrefixNoneZ {
	CResult_SiPrefixNoneZ {
		contents: CResult_SiPrefixNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SiPrefixNoneZ_is_ok(o: &CResult_SiPrefixNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SiPrefixNoneZ.
pub extern "C" fn CResult_SiPrefixNoneZ_free(_res: CResult_SiPrefixNoneZ) { }
impl Drop for CResult_SiPrefixNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::SiPrefix, ()>> for CResult_SiPrefixNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::SiPrefix, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SiPrefixNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_SiPrefixNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SiPrefixNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SiPrefixNoneZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::SiPrefix>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SiPrefixNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_SiPrefixNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_SiPrefixNoneZ_clone(orig: &CResult_SiPrefixNoneZ) -> CResult_SiPrefixNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_InvoiceNoneZ
pub union CResult_InvoiceNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::Invoice,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_InvoiceNoneZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::Invoice on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InvoiceNoneZ {
	/// The contents of this CResult_InvoiceNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InvoiceNoneZPtr,
	/// Whether this CResult_InvoiceNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InvoiceNoneZ in the success state.
pub extern "C" fn CResult_InvoiceNoneZ_ok(o: crate::lightning_invoice::Invoice) -> CResult_InvoiceNoneZ {
	CResult_InvoiceNoneZ {
		contents: CResult_InvoiceNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceNoneZ in the error state.
pub extern "C" fn CResult_InvoiceNoneZ_err() -> CResult_InvoiceNoneZ {
	CResult_InvoiceNoneZ {
		contents: CResult_InvoiceNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InvoiceNoneZ_is_ok(o: &CResult_InvoiceNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InvoiceNoneZ.
pub extern "C" fn CResult_InvoiceNoneZ_free(_res: CResult_InvoiceNoneZ) { }
impl Drop for CResult_InvoiceNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, ()>> for CResult_InvoiceNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InvoiceNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_InvoiceNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InvoiceNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InvoiceNoneZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::Invoice>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InvoiceNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_InvoiceNoneZ_clone(orig: &CResult_InvoiceNoneZ) -> CResult_InvoiceNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_SignedRawInvoiceNoneZ
pub union CResult_SignedRawInvoiceNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::SignedRawInvoice,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_SignedRawInvoiceNoneZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::SignedRawInvoice on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_SignedRawInvoiceNoneZ {
	/// The contents of this CResult_SignedRawInvoiceNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_SignedRawInvoiceNoneZPtr,
	/// Whether this CResult_SignedRawInvoiceNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_SignedRawInvoiceNoneZ in the success state.
pub extern "C" fn CResult_SignedRawInvoiceNoneZ_ok(o: crate::lightning_invoice::SignedRawInvoice) -> CResult_SignedRawInvoiceNoneZ {
	CResult_SignedRawInvoiceNoneZ {
		contents: CResult_SignedRawInvoiceNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_SignedRawInvoiceNoneZ in the error state.
pub extern "C" fn CResult_SignedRawInvoiceNoneZ_err() -> CResult_SignedRawInvoiceNoneZ {
	CResult_SignedRawInvoiceNoneZ {
		contents: CResult_SignedRawInvoiceNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_SignedRawInvoiceNoneZ_is_ok(o: &CResult_SignedRawInvoiceNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_SignedRawInvoiceNoneZ.
pub extern "C" fn CResult_SignedRawInvoiceNoneZ_free(_res: CResult_SignedRawInvoiceNoneZ) { }
impl Drop for CResult_SignedRawInvoiceNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::SignedRawInvoice, ()>> for CResult_SignedRawInvoiceNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::SignedRawInvoice, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_SignedRawInvoiceNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_SignedRawInvoiceNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_SignedRawInvoiceNoneZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_SignedRawInvoiceNoneZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::SignedRawInvoice>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_SignedRawInvoiceNoneZPtr {
				err: std::ptr::null_mut()
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_SignedRawInvoiceNoneZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_SignedRawInvoiceNoneZ_clone(orig: &CResult_SignedRawInvoiceNoneZ) -> CResult_SignedRawInvoiceNoneZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 3 elements. See the individual fields for the types contained.
pub struct C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	/// The element at position 0
	pub a: crate::lightning_invoice::RawInvoice,
	/// The element at position 1
	pub b: crate::c_types::ThirtyTwoBytes,
	/// The element at position 2
	pub c: crate::lightning_invoice::InvoiceSignature,
}
impl From<(crate::lightning_invoice::RawInvoice, crate::c_types::ThirtyTwoBytes, crate::lightning_invoice::InvoiceSignature)> for C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	fn from (tup: (crate::lightning_invoice::RawInvoice, crate::c_types::ThirtyTwoBytes, crate::lightning_invoice::InvoiceSignature)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
			c: tup.2,
		}
	}
}
impl C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::lightning_invoice::RawInvoice, crate::c_types::ThirtyTwoBytes, crate::lightning_invoice::InvoiceSignature) {
		(self.a, self.b, self.c)
	}
}
impl Clone for C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
			c: Clone::clone(&self.c),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C3Tuple_RawInvoice_u832InvoiceSignatureZ_clone(orig: &C3Tuple_RawInvoice_u832InvoiceSignatureZ) -> C3Tuple_RawInvoice_u832InvoiceSignatureZ { Clone::clone(&orig) }
/// Creates a new C3Tuple_RawInvoice_u832InvoiceSignatureZ from the contained elements.
#[no_mangle]
pub extern "C" fn C3Tuple_RawInvoice_u832InvoiceSignatureZ_new(a: crate::lightning_invoice::RawInvoice, b: crate::c_types::ThirtyTwoBytes, c: crate::lightning_invoice::InvoiceSignature) -> C3Tuple_RawInvoice_u832InvoiceSignatureZ {
	C3Tuple_RawInvoice_u832InvoiceSignatureZ { a, b, c, }
}

#[no_mangle]
/// Frees any resources used by the C3Tuple_RawInvoice_u832InvoiceSignatureZ.
pub extern "C" fn C3Tuple_RawInvoice_u832InvoiceSignatureZ_free(_res: C3Tuple_RawInvoice_u832InvoiceSignatureZ) { }
#[repr(C)]
/// The contents of CResult_PayeePubKeyErrorZ
pub union CResult_PayeePubKeyErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::PayeePubKey,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
/// A CResult_PayeePubKeyErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::PayeePubKey on success and a crate::c_types::Secp256k1Error on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PayeePubKeyErrorZ {
	/// The contents of this CResult_PayeePubKeyErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PayeePubKeyErrorZPtr,
	/// Whether this CResult_PayeePubKeyErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PayeePubKeyErrorZ in the success state.
pub extern "C" fn CResult_PayeePubKeyErrorZ_ok(o: crate::lightning_invoice::PayeePubKey) -> CResult_PayeePubKeyErrorZ {
	CResult_PayeePubKeyErrorZ {
		contents: CResult_PayeePubKeyErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PayeePubKeyErrorZ in the error state.
pub extern "C" fn CResult_PayeePubKeyErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_PayeePubKeyErrorZ {
	CResult_PayeePubKeyErrorZ {
		contents: CResult_PayeePubKeyErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PayeePubKeyErrorZ_is_ok(o: &CResult_PayeePubKeyErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PayeePubKeyErrorZ.
pub extern "C" fn CResult_PayeePubKeyErrorZ_free(_res: CResult_PayeePubKeyErrorZ) { }
impl Drop for CResult_PayeePubKeyErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::PayeePubKey, crate::c_types::Secp256k1Error>> for CResult_PayeePubKeyErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::PayeePubKey, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PayeePubKeyErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PayeePubKeyErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PayeePubKeyErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PayeePubKeyErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::PayeePubKey>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PayeePubKeyErrorZPtr {
				err: Box::into_raw(Box::new(<crate::c_types::Secp256k1Error>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PayeePubKeyErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PayeePubKeyErrorZ_clone(orig: &CResult_PayeePubKeyErrorZ) -> CResult_PayeePubKeyErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning_invoice::PrivateRoutes of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_PrivateRouteZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning_invoice::PrivateRoute,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_PrivateRouteZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning_invoice::PrivateRoute> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning_invoice::PrivateRoute] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning_invoice::PrivateRoute>> for CVec_PrivateRouteZ {
	fn from(v: Vec<crate::lightning_invoice::PrivateRoute>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_PrivateRouteZ_free(_res: CVec_PrivateRouteZ) { }
impl Drop for CVec_PrivateRouteZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_PrivateRouteZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_PositiveTimestampCreationErrorZ
pub union CResult_PositiveTimestampCreationErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::PositiveTimestamp,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::CreationError,
}
#[repr(C)]
/// A CResult_PositiveTimestampCreationErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::PositiveTimestamp on success and a crate::lightning_invoice::CreationError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PositiveTimestampCreationErrorZ {
	/// The contents of this CResult_PositiveTimestampCreationErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PositiveTimestampCreationErrorZPtr,
	/// Whether this CResult_PositiveTimestampCreationErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PositiveTimestampCreationErrorZ in the success state.
pub extern "C" fn CResult_PositiveTimestampCreationErrorZ_ok(o: crate::lightning_invoice::PositiveTimestamp) -> CResult_PositiveTimestampCreationErrorZ {
	CResult_PositiveTimestampCreationErrorZ {
		contents: CResult_PositiveTimestampCreationErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PositiveTimestampCreationErrorZ in the error state.
pub extern "C" fn CResult_PositiveTimestampCreationErrorZ_err(e: crate::lightning_invoice::CreationError) -> CResult_PositiveTimestampCreationErrorZ {
	CResult_PositiveTimestampCreationErrorZ {
		contents: CResult_PositiveTimestampCreationErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PositiveTimestampCreationErrorZ_is_ok(o: &CResult_PositiveTimestampCreationErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PositiveTimestampCreationErrorZ.
pub extern "C" fn CResult_PositiveTimestampCreationErrorZ_free(_res: CResult_PositiveTimestampCreationErrorZ) { }
impl Drop for CResult_PositiveTimestampCreationErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::PositiveTimestamp, crate::lightning_invoice::CreationError>> for CResult_PositiveTimestampCreationErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::PositiveTimestamp, crate::lightning_invoice::CreationError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PositiveTimestampCreationErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PositiveTimestampCreationErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PositiveTimestampCreationErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PositiveTimestampCreationErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::PositiveTimestamp>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PositiveTimestampCreationErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::CreationError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PositiveTimestampCreationErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PositiveTimestampCreationErrorZ_clone(orig: &CResult_PositiveTimestampCreationErrorZ) -> CResult_PositiveTimestampCreationErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NoneSemanticErrorZ
pub union CResult_NoneSemanticErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::SemanticError,
}
#[repr(C)]
/// A CResult_NoneSemanticErrorZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning_invoice::SemanticError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneSemanticErrorZ {
	/// The contents of this CResult_NoneSemanticErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneSemanticErrorZPtr,
	/// Whether this CResult_NoneSemanticErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneSemanticErrorZ in the success state.
pub extern "C" fn CResult_NoneSemanticErrorZ_ok() -> CResult_NoneSemanticErrorZ {
	CResult_NoneSemanticErrorZ {
		contents: CResult_NoneSemanticErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneSemanticErrorZ in the error state.
pub extern "C" fn CResult_NoneSemanticErrorZ_err(e: crate::lightning_invoice::SemanticError) -> CResult_NoneSemanticErrorZ {
	CResult_NoneSemanticErrorZ {
		contents: CResult_NoneSemanticErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneSemanticErrorZ_is_ok(o: &CResult_NoneSemanticErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneSemanticErrorZ.
pub extern "C" fn CResult_NoneSemanticErrorZ_free(_res: CResult_NoneSemanticErrorZ) { }
impl Drop for CResult_NoneSemanticErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning_invoice::SemanticError>> for CResult_NoneSemanticErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning_invoice::SemanticError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneSemanticErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneSemanticErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneSemanticErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneSemanticErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneSemanticErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::SemanticError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneSemanticErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneSemanticErrorZ_clone(orig: &CResult_NoneSemanticErrorZ) -> CResult_NoneSemanticErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_InvoiceSemanticErrorZ
pub union CResult_InvoiceSemanticErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::Invoice,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::SemanticError,
}
#[repr(C)]
/// A CResult_InvoiceSemanticErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::Invoice on success and a crate::lightning_invoice::SemanticError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InvoiceSemanticErrorZ {
	/// The contents of this CResult_InvoiceSemanticErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InvoiceSemanticErrorZPtr,
	/// Whether this CResult_InvoiceSemanticErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InvoiceSemanticErrorZ in the success state.
pub extern "C" fn CResult_InvoiceSemanticErrorZ_ok(o: crate::lightning_invoice::Invoice) -> CResult_InvoiceSemanticErrorZ {
	CResult_InvoiceSemanticErrorZ {
		contents: CResult_InvoiceSemanticErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceSemanticErrorZ in the error state.
pub extern "C" fn CResult_InvoiceSemanticErrorZ_err(e: crate::lightning_invoice::SemanticError) -> CResult_InvoiceSemanticErrorZ {
	CResult_InvoiceSemanticErrorZ {
		contents: CResult_InvoiceSemanticErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InvoiceSemanticErrorZ_is_ok(o: &CResult_InvoiceSemanticErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InvoiceSemanticErrorZ.
pub extern "C" fn CResult_InvoiceSemanticErrorZ_free(_res: CResult_InvoiceSemanticErrorZ) { }
impl Drop for CResult_InvoiceSemanticErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, crate::lightning_invoice::SemanticError>> for CResult_InvoiceSemanticErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, crate::lightning_invoice::SemanticError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InvoiceSemanticErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InvoiceSemanticErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InvoiceSemanticErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InvoiceSemanticErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::Invoice>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InvoiceSemanticErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::SemanticError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceSemanticErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_InvoiceSemanticErrorZ_clone(orig: &CResult_InvoiceSemanticErrorZ) -> CResult_InvoiceSemanticErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_DescriptionCreationErrorZ
pub union CResult_DescriptionCreationErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::Description,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::CreationError,
}
#[repr(C)]
/// A CResult_DescriptionCreationErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::Description on success and a crate::lightning_invoice::CreationError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_DescriptionCreationErrorZ {
	/// The contents of this CResult_DescriptionCreationErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_DescriptionCreationErrorZPtr,
	/// Whether this CResult_DescriptionCreationErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_DescriptionCreationErrorZ in the success state.
pub extern "C" fn CResult_DescriptionCreationErrorZ_ok(o: crate::lightning_invoice::Description) -> CResult_DescriptionCreationErrorZ {
	CResult_DescriptionCreationErrorZ {
		contents: CResult_DescriptionCreationErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_DescriptionCreationErrorZ in the error state.
pub extern "C" fn CResult_DescriptionCreationErrorZ_err(e: crate::lightning_invoice::CreationError) -> CResult_DescriptionCreationErrorZ {
	CResult_DescriptionCreationErrorZ {
		contents: CResult_DescriptionCreationErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_DescriptionCreationErrorZ_is_ok(o: &CResult_DescriptionCreationErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_DescriptionCreationErrorZ.
pub extern "C" fn CResult_DescriptionCreationErrorZ_free(_res: CResult_DescriptionCreationErrorZ) { }
impl Drop for CResult_DescriptionCreationErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::Description, crate::lightning_invoice::CreationError>> for CResult_DescriptionCreationErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::Description, crate::lightning_invoice::CreationError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_DescriptionCreationErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_DescriptionCreationErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_DescriptionCreationErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_DescriptionCreationErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::Description>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_DescriptionCreationErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::CreationError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_DescriptionCreationErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_DescriptionCreationErrorZ_clone(orig: &CResult_DescriptionCreationErrorZ) -> CResult_DescriptionCreationErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ExpiryTimeCreationErrorZ
pub union CResult_ExpiryTimeCreationErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::ExpiryTime,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::CreationError,
}
#[repr(C)]
/// A CResult_ExpiryTimeCreationErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::ExpiryTime on success and a crate::lightning_invoice::CreationError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ExpiryTimeCreationErrorZ {
	/// The contents of this CResult_ExpiryTimeCreationErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ExpiryTimeCreationErrorZPtr,
	/// Whether this CResult_ExpiryTimeCreationErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ExpiryTimeCreationErrorZ in the success state.
pub extern "C" fn CResult_ExpiryTimeCreationErrorZ_ok(o: crate::lightning_invoice::ExpiryTime) -> CResult_ExpiryTimeCreationErrorZ {
	CResult_ExpiryTimeCreationErrorZ {
		contents: CResult_ExpiryTimeCreationErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ExpiryTimeCreationErrorZ in the error state.
pub extern "C" fn CResult_ExpiryTimeCreationErrorZ_err(e: crate::lightning_invoice::CreationError) -> CResult_ExpiryTimeCreationErrorZ {
	CResult_ExpiryTimeCreationErrorZ {
		contents: CResult_ExpiryTimeCreationErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ExpiryTimeCreationErrorZ_is_ok(o: &CResult_ExpiryTimeCreationErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ExpiryTimeCreationErrorZ.
pub extern "C" fn CResult_ExpiryTimeCreationErrorZ_free(_res: CResult_ExpiryTimeCreationErrorZ) { }
impl Drop for CResult_ExpiryTimeCreationErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::ExpiryTime, crate::lightning_invoice::CreationError>> for CResult_ExpiryTimeCreationErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::ExpiryTime, crate::lightning_invoice::CreationError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ExpiryTimeCreationErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ExpiryTimeCreationErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ExpiryTimeCreationErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ExpiryTimeCreationErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::ExpiryTime>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ExpiryTimeCreationErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::CreationError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ExpiryTimeCreationErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ExpiryTimeCreationErrorZ_clone(orig: &CResult_ExpiryTimeCreationErrorZ) -> CResult_ExpiryTimeCreationErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PrivateRouteCreationErrorZ
pub union CResult_PrivateRouteCreationErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::PrivateRoute,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::CreationError,
}
#[repr(C)]
/// A CResult_PrivateRouteCreationErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::PrivateRoute on success and a crate::lightning_invoice::CreationError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PrivateRouteCreationErrorZ {
	/// The contents of this CResult_PrivateRouteCreationErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PrivateRouteCreationErrorZPtr,
	/// Whether this CResult_PrivateRouteCreationErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PrivateRouteCreationErrorZ in the success state.
pub extern "C" fn CResult_PrivateRouteCreationErrorZ_ok(o: crate::lightning_invoice::PrivateRoute) -> CResult_PrivateRouteCreationErrorZ {
	CResult_PrivateRouteCreationErrorZ {
		contents: CResult_PrivateRouteCreationErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PrivateRouteCreationErrorZ in the error state.
pub extern "C" fn CResult_PrivateRouteCreationErrorZ_err(e: crate::lightning_invoice::CreationError) -> CResult_PrivateRouteCreationErrorZ {
	CResult_PrivateRouteCreationErrorZ {
		contents: CResult_PrivateRouteCreationErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PrivateRouteCreationErrorZ_is_ok(o: &CResult_PrivateRouteCreationErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PrivateRouteCreationErrorZ.
pub extern "C" fn CResult_PrivateRouteCreationErrorZ_free(_res: CResult_PrivateRouteCreationErrorZ) { }
impl Drop for CResult_PrivateRouteCreationErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::PrivateRoute, crate::lightning_invoice::CreationError>> for CResult_PrivateRouteCreationErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::PrivateRoute, crate::lightning_invoice::CreationError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PrivateRouteCreationErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PrivateRouteCreationErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PrivateRouteCreationErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PrivateRouteCreationErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::PrivateRoute>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PrivateRouteCreationErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::CreationError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PrivateRouteCreationErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PrivateRouteCreationErrorZ_clone(orig: &CResult_PrivateRouteCreationErrorZ) -> CResult_PrivateRouteCreationErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_StringErrorZ
pub union CResult_StringErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::Str,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::c_types::Secp256k1Error,
}
#[repr(C)]
/// A CResult_StringErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::Str on success and a crate::c_types::Secp256k1Error on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_StringErrorZ {
	/// The contents of this CResult_StringErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_StringErrorZPtr,
	/// Whether this CResult_StringErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_StringErrorZ in the success state.
pub extern "C" fn CResult_StringErrorZ_ok(o: crate::c_types::Str) -> CResult_StringErrorZ {
	CResult_StringErrorZ {
		contents: CResult_StringErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_StringErrorZ in the error state.
pub extern "C" fn CResult_StringErrorZ_err(e: crate::c_types::Secp256k1Error) -> CResult_StringErrorZ {
	CResult_StringErrorZ {
		contents: CResult_StringErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_StringErrorZ_is_ok(o: &CResult_StringErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_StringErrorZ.
pub extern "C" fn CResult_StringErrorZ_free(_res: CResult_StringErrorZ) { }
impl Drop for CResult_StringErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::Str, crate::c_types::Secp256k1Error>> for CResult_StringErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::Str, crate::c_types::Secp256k1Error>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_StringErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_StringErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_ChannelMonitorUpdateDecodeErrorZ
pub union CResult_ChannelMonitorUpdateDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::channelmonitor::ChannelMonitorUpdate,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelMonitorUpdateDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::channelmonitor::ChannelMonitorUpdate on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelMonitorUpdateDecodeErrorZ {
	/// The contents of this CResult_ChannelMonitorUpdateDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr,
	/// Whether this CResult_ChannelMonitorUpdateDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelMonitorUpdateDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_ok(o: crate::lightning::chain::channelmonitor::ChannelMonitorUpdate) -> CResult_ChannelMonitorUpdateDecodeErrorZ {
	CResult_ChannelMonitorUpdateDecodeErrorZ {
		contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelMonitorUpdateDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelMonitorUpdateDecodeErrorZ {
	CResult_ChannelMonitorUpdateDecodeErrorZ {
		contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_is_ok(o: &CResult_ChannelMonitorUpdateDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelMonitorUpdateDecodeErrorZ.
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_free(_res: CResult_ChannelMonitorUpdateDecodeErrorZ) { }
impl Drop for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::channelmonitor::ChannelMonitorUpdate, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelMonitorUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelMonitorUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelMonitorUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::channelmonitor::ChannelMonitorUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelMonitorUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelMonitorUpdateDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelMonitorUpdateDecodeErrorZ_clone(orig: &CResult_ChannelMonitorUpdateDecodeErrorZ) -> CResult_ChannelMonitorUpdateDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::lightning::chain::channelmonitor::MonitorEvent or not
pub enum COption_MonitorEventZ {
	/// When we're in this state, this COption_MonitorEventZ contains a crate::lightning::chain::channelmonitor::MonitorEvent
	Some(crate::lightning::chain::channelmonitor::MonitorEvent),
	/// When we're in this state, this COption_MonitorEventZ contains nothing
	None
}
impl COption_MonitorEventZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::chain::channelmonitor::MonitorEvent {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_MonitorEventZ containing a crate::lightning::chain::channelmonitor::MonitorEvent
pub extern "C" fn COption_MonitorEventZ_some(o: crate::lightning::chain::channelmonitor::MonitorEvent) -> COption_MonitorEventZ {
	COption_MonitorEventZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_MonitorEventZ containing nothing
pub extern "C" fn COption_MonitorEventZ_none() -> COption_MonitorEventZ {
	COption_MonitorEventZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::chain::channelmonitor::MonitorEvent, if we are in the Some state
pub extern "C" fn COption_MonitorEventZ_free(_res: COption_MonitorEventZ) { }
#[no_mangle]
/// Creates a new COption_MonitorEventZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_MonitorEventZ_clone(orig: &COption_MonitorEventZ) -> COption_MonitorEventZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_COption_MonitorEventZDecodeErrorZ
pub union CResult_COption_MonitorEventZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::COption_MonitorEventZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_COption_MonitorEventZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::COption_MonitorEventZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_COption_MonitorEventZDecodeErrorZ {
	/// The contents of this CResult_COption_MonitorEventZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_COption_MonitorEventZDecodeErrorZPtr,
	/// Whether this CResult_COption_MonitorEventZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_COption_MonitorEventZDecodeErrorZ in the success state.
pub extern "C" fn CResult_COption_MonitorEventZDecodeErrorZ_ok(o: crate::c_types::derived::COption_MonitorEventZ) -> CResult_COption_MonitorEventZDecodeErrorZ {
	CResult_COption_MonitorEventZDecodeErrorZ {
		contents: CResult_COption_MonitorEventZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_COption_MonitorEventZDecodeErrorZ in the error state.
pub extern "C" fn CResult_COption_MonitorEventZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_COption_MonitorEventZDecodeErrorZ {
	CResult_COption_MonitorEventZDecodeErrorZ {
		contents: CResult_COption_MonitorEventZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_COption_MonitorEventZDecodeErrorZ_is_ok(o: &CResult_COption_MonitorEventZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_COption_MonitorEventZDecodeErrorZ.
pub extern "C" fn CResult_COption_MonitorEventZDecodeErrorZ_free(_res: CResult_COption_MonitorEventZDecodeErrorZ) { }
impl Drop for CResult_COption_MonitorEventZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::COption_MonitorEventZ, crate::lightning::ln::msgs::DecodeError>> for CResult_COption_MonitorEventZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::COption_MonitorEventZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_COption_MonitorEventZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_COption_MonitorEventZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_COption_MonitorEventZDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_COption_MonitorEventZDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::COption_MonitorEventZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_COption_MonitorEventZDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_COption_MonitorEventZDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_COption_MonitorEventZDecodeErrorZ_clone(orig: &CResult_COption_MonitorEventZDecodeErrorZ) -> CResult_COption_MonitorEventZDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_HTLCUpdateDecodeErrorZ
pub union CResult_HTLCUpdateDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::channelmonitor::HTLCUpdate,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_HTLCUpdateDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::channelmonitor::HTLCUpdate on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_HTLCUpdateDecodeErrorZ {
	/// The contents of this CResult_HTLCUpdateDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_HTLCUpdateDecodeErrorZPtr,
	/// Whether this CResult_HTLCUpdateDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_HTLCUpdateDecodeErrorZ in the success state.
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_ok(o: crate::lightning::chain::channelmonitor::HTLCUpdate) -> CResult_HTLCUpdateDecodeErrorZ {
	CResult_HTLCUpdateDecodeErrorZ {
		contents: CResult_HTLCUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_HTLCUpdateDecodeErrorZ in the error state.
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_HTLCUpdateDecodeErrorZ {
	CResult_HTLCUpdateDecodeErrorZ {
		contents: CResult_HTLCUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_is_ok(o: &CResult_HTLCUpdateDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_HTLCUpdateDecodeErrorZ.
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_free(_res: CResult_HTLCUpdateDecodeErrorZ) { }
impl Drop for CResult_HTLCUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::channelmonitor::HTLCUpdate, crate::lightning::ln::msgs::DecodeError>> for CResult_HTLCUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::channelmonitor::HTLCUpdate, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_HTLCUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_HTLCUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_HTLCUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_HTLCUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::chain::channelmonitor::HTLCUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_HTLCUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_HTLCUpdateDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_HTLCUpdateDecodeErrorZ_clone(orig: &CResult_HTLCUpdateDecodeErrorZ) -> CResult_HTLCUpdateDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_OutPointScriptZ {
	/// The element at position 0
	pub a: crate::lightning::chain::transaction::OutPoint,
	/// The element at position 1
	pub b: crate::c_types::derived::CVec_u8Z,
}
impl From<(crate::lightning::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z)> for C2Tuple_OutPointScriptZ {
	fn from (tup: (crate::lightning::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_OutPointScriptZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::lightning::chain::transaction::OutPoint, crate::c_types::derived::CVec_u8Z) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_OutPointScriptZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_OutPointScriptZ_clone(orig: &C2Tuple_OutPointScriptZ) -> C2Tuple_OutPointScriptZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_OutPointScriptZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_OutPointScriptZ_new(a: crate::lightning::chain::transaction::OutPoint, b: crate::c_types::derived::CVec_u8Z) -> C2Tuple_OutPointScriptZ {
	C2Tuple_OutPointScriptZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_OutPointScriptZ.
pub extern "C" fn C2Tuple_OutPointScriptZ_free(_res: C2Tuple_OutPointScriptZ) { }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_u32ScriptZ {
	/// The element at position 0
	pub a: u32,
	/// The element at position 1
	pub b: crate::c_types::derived::CVec_u8Z,
}
impl From<(u32, crate::c_types::derived::CVec_u8Z)> for C2Tuple_u32ScriptZ {
	fn from (tup: (u32, crate::c_types::derived::CVec_u8Z)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_u32ScriptZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (u32, crate::c_types::derived::CVec_u8Z) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_u32ScriptZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_u32ScriptZ_clone(orig: &C2Tuple_u32ScriptZ) -> C2Tuple_u32ScriptZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_u32ScriptZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_u32ScriptZ_new(a: u32, b: crate::c_types::derived::CVec_u8Z) -> C2Tuple_u32ScriptZ {
	C2Tuple_u32ScriptZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_u32ScriptZ.
pub extern "C" fn C2Tuple_u32ScriptZ_free(_res: C2Tuple_u32ScriptZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_u32ScriptZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_u32ScriptZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_u32ScriptZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_u32ScriptZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_u32ScriptZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_u32ScriptZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_u32ScriptZ>> for CVec_C2Tuple_u32ScriptZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_u32ScriptZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_u32ScriptZZ_free(_res: CVec_C2Tuple_u32ScriptZZ) { }
impl Drop for CVec_C2Tuple_u32ScriptZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C2Tuple_u32ScriptZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::c_types::derived::CVec_C2Tuple_u32ScriptZZ,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32ScriptZZ)> for C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32ScriptZZ)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32ScriptZZ) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ_clone(orig: &C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ) -> C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::derived::CVec_C2Tuple_u32ScriptZZ) -> C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ {
	C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ.
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ_free(_res: C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ>> for CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ_free(_res: CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ) { }
impl Drop for CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C2Tuple_TxidCVec_C2Tuple_u32ScriptZZZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::util::events::Events of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_EventZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::util::events::Event,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_EventZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::util::events::Event> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::util::events::Event] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::util::events::Event>> for CVec_EventZ {
	fn from(v: Vec<crate::lightning::util::events::Event>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_EventZ_free(_res: CVec_EventZ) { }
impl Drop for CVec_EventZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_EventZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::Transactions of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_TransactionZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::Transaction,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_TransactionZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::Transaction> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::Transaction] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::Transaction>> for CVec_TransactionZ {
	fn from(v: Vec<crate::c_types::Transaction>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_TransactionZ_free(_res: CVec_TransactionZ) { }
impl Drop for CVec_TransactionZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_TransactionZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_u32TxOutZ {
	/// The element at position 0
	pub a: u32,
	/// The element at position 1
	pub b: crate::c_types::TxOut,
}
impl From<(u32, crate::c_types::TxOut)> for C2Tuple_u32TxOutZ {
	fn from (tup: (u32, crate::c_types::TxOut)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_u32TxOutZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (u32, crate::c_types::TxOut) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_u32TxOutZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_u32TxOutZ_clone(orig: &C2Tuple_u32TxOutZ) -> C2Tuple_u32TxOutZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_u32TxOutZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_u32TxOutZ_new(a: u32, b: crate::c_types::TxOut) -> C2Tuple_u32TxOutZ {
	C2Tuple_u32TxOutZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_u32TxOutZ.
pub extern "C" fn C2Tuple_u32TxOutZ_free(_res: C2Tuple_u32TxOutZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_u32TxOutZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_u32TxOutZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_u32TxOutZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_u32TxOutZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_u32TxOutZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_u32TxOutZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_u32TxOutZ>> for CVec_C2Tuple_u32TxOutZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_u32TxOutZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_u32TxOutZZ_free(_res: CVec_C2Tuple_u32TxOutZZ) { }
impl Drop for CVec_C2Tuple_u32TxOutZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C2Tuple_u32TxOutZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	/// The element at position 0
	pub a: crate::c_types::ThirtyTwoBytes,
	/// The element at position 1
	pub b: crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ,
}
impl From<(crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ)> for C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	fn from (tup: (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::ThirtyTwoBytes, crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ) {
		(self.a, self.b)
	}
}
impl Clone for C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_clone(orig: &C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ) -> C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ { Clone::clone(&orig) }
/// Creates a new C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_new(a: crate::c_types::ThirtyTwoBytes, b: crate::c_types::derived::CVec_C2Tuple_u32TxOutZZ) -> C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ {
	C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ.
pub extern "C" fn C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ_free(_res: C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_TransactionOutputsZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_TransactionOutputsZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ>> for CVec_TransactionOutputsZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_TxidCVec_C2Tuple_u32TxOutZZZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_TransactionOutputsZ_free(_res: CVec_TransactionOutputsZ) { }
impl Drop for CVec_TransactionOutputsZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_TransactionOutputsZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::chain::channelmonitor::Balances of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_BalanceZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::chain::channelmonitor::Balance,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_BalanceZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::chain::channelmonitor::Balance> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::chain::channelmonitor::Balance] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::chain::channelmonitor::Balance>> for CVec_BalanceZ {
	fn from(v: Vec<crate::lightning::chain::channelmonitor::Balance>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_BalanceZ_free(_res: CVec_BalanceZ) { }
impl Drop for CVec_BalanceZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_BalanceZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ
pub union CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	/// The contents of this CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr,
	/// Whether this CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ in the success state.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_ok(o: crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ) -> CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ in the error state.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
		contents: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_is_ok(o: &CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ.
pub extern "C" fn CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ_free(_res: CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ) { }
impl Drop for CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ, crate::lightning::ln::msgs::DecodeError>> for CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::C2Tuple_BlockHashChannelMonitorZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_C2Tuple_BlockHashChannelMonitorZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// The contents of CResult_NoneLightningErrorZ
pub union CResult_NoneLightningErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::LightningError,
}
#[repr(C)]
/// A CResult_NoneLightningErrorZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning::ln::msgs::LightningError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NoneLightningErrorZ {
	/// The contents of this CResult_NoneLightningErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NoneLightningErrorZPtr,
	/// Whether this CResult_NoneLightningErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NoneLightningErrorZ in the success state.
pub extern "C" fn CResult_NoneLightningErrorZ_ok() -> CResult_NoneLightningErrorZ {
	CResult_NoneLightningErrorZ {
		contents: CResult_NoneLightningErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NoneLightningErrorZ in the error state.
pub extern "C" fn CResult_NoneLightningErrorZ_err(e: crate::lightning::ln::msgs::LightningError) -> CResult_NoneLightningErrorZ {
	CResult_NoneLightningErrorZ {
		contents: CResult_NoneLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NoneLightningErrorZ_is_ok(o: &CResult_NoneLightningErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NoneLightningErrorZ.
pub extern "C" fn CResult_NoneLightningErrorZ_free(_res: CResult_NoneLightningErrorZ) { }
impl Drop for CResult_NoneLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning::ln::msgs::LightningError>> for CResult_NoneLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NoneLightningErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NoneLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NoneLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NoneLightningErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NoneLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NoneLightningErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NoneLightningErrorZ_clone(orig: &CResult_NoneLightningErrorZ) -> CResult_NoneLightningErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 2 elements. See the individual fields for the types contained.
pub struct C2Tuple_PublicKeyTypeZ {
	/// The element at position 0
	pub a: crate::c_types::PublicKey,
	/// The element at position 1
	pub b: crate::lightning::ln::wire::Type,
}
impl From<(crate::c_types::PublicKey, crate::lightning::ln::wire::Type)> for C2Tuple_PublicKeyTypeZ {
	fn from (tup: (crate::c_types::PublicKey, crate::lightning::ln::wire::Type)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
		}
	}
}
impl C2Tuple_PublicKeyTypeZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::c_types::PublicKey, crate::lightning::ln::wire::Type) {
		(self.a, self.b)
	}
}
/// Creates a new C2Tuple_PublicKeyTypeZ from the contained elements.
#[no_mangle]
pub extern "C" fn C2Tuple_PublicKeyTypeZ_new(a: crate::c_types::PublicKey, b: crate::lightning::ln::wire::Type) -> C2Tuple_PublicKeyTypeZ {
	C2Tuple_PublicKeyTypeZ { a, b, }
}

#[no_mangle]
/// Frees any resources used by the C2Tuple_PublicKeyTypeZ.
pub extern "C" fn C2Tuple_PublicKeyTypeZ_free(_res: C2Tuple_PublicKeyTypeZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C2Tuple_PublicKeyTypeZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C2Tuple_PublicKeyTypeZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C2Tuple_PublicKeyTypeZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C2Tuple_PublicKeyTypeZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C2Tuple_PublicKeyTypeZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C2Tuple_PublicKeyTypeZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C2Tuple_PublicKeyTypeZ>> for CVec_C2Tuple_PublicKeyTypeZZ {
	fn from(v: Vec<crate::c_types::derived::C2Tuple_PublicKeyTypeZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C2Tuple_PublicKeyTypeZZ_free(_res: CVec_C2Tuple_PublicKeyTypeZZ) { }
impl Drop for CVec_C2Tuple_PublicKeyTypeZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
#[repr(C)]
/// The contents of CResult_boolLightningErrorZ
pub union CResult_boolLightningErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut bool,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::LightningError,
}
#[repr(C)]
/// A CResult_boolLightningErrorZ represents the result of a fallible operation,
/// containing a bool on success and a crate::lightning::ln::msgs::LightningError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_boolLightningErrorZ {
	/// The contents of this CResult_boolLightningErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_boolLightningErrorZPtr,
	/// Whether this CResult_boolLightningErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_boolLightningErrorZ in the success state.
pub extern "C" fn CResult_boolLightningErrorZ_ok(o: bool) -> CResult_boolLightningErrorZ {
	CResult_boolLightningErrorZ {
		contents: CResult_boolLightningErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_boolLightningErrorZ in the error state.
pub extern "C" fn CResult_boolLightningErrorZ_err(e: crate::lightning::ln::msgs::LightningError) -> CResult_boolLightningErrorZ {
	CResult_boolLightningErrorZ {
		contents: CResult_boolLightningErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_boolLightningErrorZ_is_ok(o: &CResult_boolLightningErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_boolLightningErrorZ.
pub extern "C" fn CResult_boolLightningErrorZ_free(_res: CResult_boolLightningErrorZ) { }
impl Drop for CResult_boolLightningErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<bool, crate::lightning::ln::msgs::LightningError>> for CResult_boolLightningErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<bool, crate::lightning::ln::msgs::LightningError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_boolLightningErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_boolLightningErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_boolLightningErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_boolLightningErrorZPtr {
				result: Box::into_raw(Box::new(<bool>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_boolLightningErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::LightningError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_boolLightningErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_boolLightningErrorZ_clone(orig: &CResult_boolLightningErrorZ) -> CResult_boolLightningErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A tuple of 3 elements. See the individual fields for the types contained.
pub struct C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	/// The element at position 0
	pub a: crate::lightning::ln::msgs::ChannelAnnouncement,
	/// The element at position 1
	pub b: crate::lightning::ln::msgs::ChannelUpdate,
	/// The element at position 2
	pub c: crate::lightning::ln::msgs::ChannelUpdate,
}
impl From<(crate::lightning::ln::msgs::ChannelAnnouncement, crate::lightning::ln::msgs::ChannelUpdate, crate::lightning::ln::msgs::ChannelUpdate)> for C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	fn from (tup: (crate::lightning::ln::msgs::ChannelAnnouncement, crate::lightning::ln::msgs::ChannelUpdate, crate::lightning::ln::msgs::ChannelUpdate)) -> Self {
		Self {
			a: tup.0,
			b: tup.1,
			c: tup.2,
		}
	}
}
impl C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	#[allow(unused)] pub(crate) fn to_rust(mut self) -> (crate::lightning::ln::msgs::ChannelAnnouncement, crate::lightning::ln::msgs::ChannelUpdate, crate::lightning::ln::msgs::ChannelUpdate) {
		(self.a, self.b, self.c)
	}
}
impl Clone for C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	fn clone(&self) -> Self {
		Self {
			a: Clone::clone(&self.a),
			b: Clone::clone(&self.b),
			c: Clone::clone(&self.c),
		}
	}
}
#[no_mangle]
/// Creates a new tuple which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_clone(orig: &C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ) -> C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ { Clone::clone(&orig) }
/// Creates a new C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ from the contained elements.
#[no_mangle]
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_new(a: crate::lightning::ln::msgs::ChannelAnnouncement, b: crate::lightning::ln::msgs::ChannelUpdate, c: crate::lightning::ln::msgs::ChannelUpdate) -> C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ {
	C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ { a, b, c, }
}

#[no_mangle]
/// Frees any resources used by the C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ.
pub extern "C" fn C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ_free(_res: C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ) { }
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ>> for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn from(v: Vec<crate::c_types::derived::C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZ>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ_free(_res: CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ) { }
impl Drop for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_C3Tuple_ChannelAnnouncementChannelUpdateChannelUpdateZZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::NodeAnnouncements of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_NodeAnnouncementZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::NodeAnnouncement,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_NodeAnnouncementZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::NodeAnnouncement> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::NodeAnnouncement] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::NodeAnnouncement>> for CVec_NodeAnnouncementZ {
	fn from(v: Vec<crate::lightning::ln::msgs::NodeAnnouncement>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_NodeAnnouncementZ_free(_res: CVec_NodeAnnouncementZ) { }
impl Drop for CVec_NodeAnnouncementZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_NodeAnnouncementZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::c_types::PublicKeys of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_PublicKeyZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::c_types::PublicKey,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_PublicKeyZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::c_types::PublicKey> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::c_types::PublicKey] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::c_types::PublicKey>> for CVec_PublicKeyZ {
	fn from(v: Vec<crate::c_types::PublicKey>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_PublicKeyZ_free(_res: CVec_PublicKeyZ) { }
impl Drop for CVec_PublicKeyZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_PublicKeyZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_CVec_u8ZPeerHandleErrorZ
pub union CResult_CVec_u8ZPeerHandleErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::CVec_u8Z,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
/// A CResult_CVec_u8ZPeerHandleErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::CVec_u8Z on success and a crate::lightning::ln::peer_handler::PeerHandleError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CVec_u8ZPeerHandleErrorZ {
	/// The contents of this CResult_CVec_u8ZPeerHandleErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CVec_u8ZPeerHandleErrorZPtr,
	/// Whether this CResult_CVec_u8ZPeerHandleErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CVec_u8ZPeerHandleErrorZ in the success state.
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_ok(o: crate::c_types::derived::CVec_u8Z) -> CResult_CVec_u8ZPeerHandleErrorZ {
	CResult_CVec_u8ZPeerHandleErrorZ {
		contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_u8ZPeerHandleErrorZ in the error state.
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_err(e: crate::lightning::ln::peer_handler::PeerHandleError) -> CResult_CVec_u8ZPeerHandleErrorZ {
	CResult_CVec_u8ZPeerHandleErrorZ {
		contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_is_ok(o: &CResult_CVec_u8ZPeerHandleErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CVec_u8ZPeerHandleErrorZ.
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_free(_res: CResult_CVec_u8ZPeerHandleErrorZ) { }
impl Drop for CResult_CVec_u8ZPeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::CVec_u8Z, crate::lightning::ln::peer_handler::PeerHandleError>> for CResult_CVec_u8ZPeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::CVec_u8Z, crate::lightning::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CVec_u8ZPeerHandleErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CVec_u8ZPeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CVec_u8ZPeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::CVec_u8Z>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CVec_u8ZPeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CVec_u8ZPeerHandleErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CVec_u8ZPeerHandleErrorZ_clone(orig: &CResult_CVec_u8ZPeerHandleErrorZ) -> CResult_CVec_u8ZPeerHandleErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NonePeerHandleErrorZ
pub union CResult_NonePeerHandleErrorZPtr {
	/// Note that this value is always NULL, as there are no contents in the OK variant
	pub result: *mut std::ffi::c_void,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
/// A CResult_NonePeerHandleErrorZ represents the result of a fallible operation,
/// containing a () on success and a crate::lightning::ln::peer_handler::PeerHandleError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NonePeerHandleErrorZ {
	/// The contents of this CResult_NonePeerHandleErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NonePeerHandleErrorZPtr,
	/// Whether this CResult_NonePeerHandleErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NonePeerHandleErrorZ in the success state.
pub extern "C" fn CResult_NonePeerHandleErrorZ_ok() -> CResult_NonePeerHandleErrorZ {
	CResult_NonePeerHandleErrorZ {
		contents: CResult_NonePeerHandleErrorZPtr {
			result: std::ptr::null_mut(),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NonePeerHandleErrorZ in the error state.
pub extern "C" fn CResult_NonePeerHandleErrorZ_err(e: crate::lightning::ln::peer_handler::PeerHandleError) -> CResult_NonePeerHandleErrorZ {
	CResult_NonePeerHandleErrorZ {
		contents: CResult_NonePeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NonePeerHandleErrorZ_is_ok(o: &CResult_NonePeerHandleErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NonePeerHandleErrorZ.
pub extern "C" fn CResult_NonePeerHandleErrorZ_free(_res: CResult_NonePeerHandleErrorZ) { }
impl Drop for CResult_NonePeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<(), crate::lightning::ln::peer_handler::PeerHandleError>> for CResult_NonePeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<(), crate::lightning::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let _ = unsafe { Box::from_raw(o.contents.result) };
			o.contents.result = std::ptr::null_mut();
			CResult_NonePeerHandleErrorZPtr { result: std::ptr::null_mut() }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NonePeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NonePeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NonePeerHandleErrorZPtr {
				result: std::ptr::null_mut()
			} }
		} else {
			Self { result_ok: false, contents: CResult_NonePeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NonePeerHandleErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NonePeerHandleErrorZ_clone(orig: &CResult_NonePeerHandleErrorZ) -> CResult_NonePeerHandleErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_boolPeerHandleErrorZ
pub union CResult_boolPeerHandleErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut bool,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::peer_handler::PeerHandleError,
}
#[repr(C)]
/// A CResult_boolPeerHandleErrorZ represents the result of a fallible operation,
/// containing a bool on success and a crate::lightning::ln::peer_handler::PeerHandleError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_boolPeerHandleErrorZ {
	/// The contents of this CResult_boolPeerHandleErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_boolPeerHandleErrorZPtr,
	/// Whether this CResult_boolPeerHandleErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_boolPeerHandleErrorZ in the success state.
pub extern "C" fn CResult_boolPeerHandleErrorZ_ok(o: bool) -> CResult_boolPeerHandleErrorZ {
	CResult_boolPeerHandleErrorZ {
		contents: CResult_boolPeerHandleErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_boolPeerHandleErrorZ in the error state.
pub extern "C" fn CResult_boolPeerHandleErrorZ_err(e: crate::lightning::ln::peer_handler::PeerHandleError) -> CResult_boolPeerHandleErrorZ {
	CResult_boolPeerHandleErrorZ {
		contents: CResult_boolPeerHandleErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_boolPeerHandleErrorZ_is_ok(o: &CResult_boolPeerHandleErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_boolPeerHandleErrorZ.
pub extern "C" fn CResult_boolPeerHandleErrorZ_free(_res: CResult_boolPeerHandleErrorZ) { }
impl Drop for CResult_boolPeerHandleErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<bool, crate::lightning::ln::peer_handler::PeerHandleError>> for CResult_boolPeerHandleErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<bool, crate::lightning::ln::peer_handler::PeerHandleError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_boolPeerHandleErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_boolPeerHandleErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_boolPeerHandleErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_boolPeerHandleErrorZPtr {
				result: Box::into_raw(Box::new(<bool>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_boolPeerHandleErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::peer_handler::PeerHandleError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_boolPeerHandleErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_boolPeerHandleErrorZ_clone(orig: &CResult_boolPeerHandleErrorZ) -> CResult_boolPeerHandleErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NodeIdDecodeErrorZ
pub union CResult_NodeIdDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::NodeId,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NodeIdDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::NodeId on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NodeIdDecodeErrorZ {
	/// The contents of this CResult_NodeIdDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NodeIdDecodeErrorZPtr,
	/// Whether this CResult_NodeIdDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NodeIdDecodeErrorZ in the success state.
pub extern "C" fn CResult_NodeIdDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::NodeId) -> CResult_NodeIdDecodeErrorZ {
	CResult_NodeIdDecodeErrorZ {
		contents: CResult_NodeIdDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NodeIdDecodeErrorZ in the error state.
pub extern "C" fn CResult_NodeIdDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NodeIdDecodeErrorZ {
	CResult_NodeIdDecodeErrorZ {
		contents: CResult_NodeIdDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NodeIdDecodeErrorZ_is_ok(o: &CResult_NodeIdDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NodeIdDecodeErrorZ.
pub extern "C" fn CResult_NodeIdDecodeErrorZ_free(_res: CResult_NodeIdDecodeErrorZ) { }
impl Drop for CResult_NodeIdDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeId, crate::lightning::ln::msgs::DecodeError>> for CResult_NodeIdDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeId, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeIdDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeIdDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeIdDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeIdDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::NodeId>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeIdDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NodeIdDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NodeIdDecodeErrorZ_clone(orig: &CResult_NodeIdDecodeErrorZ) -> CResult_NodeIdDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_COption_NetworkUpdateZDecodeErrorZ
pub union CResult_COption_NetworkUpdateZDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::c_types::derived::COption_NetworkUpdateZ,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_COption_NetworkUpdateZDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::c_types::derived::COption_NetworkUpdateZ on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_COption_NetworkUpdateZDecodeErrorZ {
	/// The contents of this CResult_COption_NetworkUpdateZDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_COption_NetworkUpdateZDecodeErrorZPtr,
	/// Whether this CResult_COption_NetworkUpdateZDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_COption_NetworkUpdateZDecodeErrorZ in the success state.
pub extern "C" fn CResult_COption_NetworkUpdateZDecodeErrorZ_ok(o: crate::c_types::derived::COption_NetworkUpdateZ) -> CResult_COption_NetworkUpdateZDecodeErrorZ {
	CResult_COption_NetworkUpdateZDecodeErrorZ {
		contents: CResult_COption_NetworkUpdateZDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_COption_NetworkUpdateZDecodeErrorZ in the error state.
pub extern "C" fn CResult_COption_NetworkUpdateZDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_COption_NetworkUpdateZDecodeErrorZ {
	CResult_COption_NetworkUpdateZDecodeErrorZ {
		contents: CResult_COption_NetworkUpdateZDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_COption_NetworkUpdateZDecodeErrorZ_is_ok(o: &CResult_COption_NetworkUpdateZDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_COption_NetworkUpdateZDecodeErrorZ.
pub extern "C" fn CResult_COption_NetworkUpdateZDecodeErrorZ_free(_res: CResult_COption_NetworkUpdateZDecodeErrorZ) { }
impl Drop for CResult_COption_NetworkUpdateZDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::c_types::derived::COption_NetworkUpdateZ, crate::lightning::ln::msgs::DecodeError>> for CResult_COption_NetworkUpdateZDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::c_types::derived::COption_NetworkUpdateZ, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_COption_NetworkUpdateZDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_COption_NetworkUpdateZDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_COption_NetworkUpdateZDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_COption_NetworkUpdateZDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::c_types::derived::COption_NetworkUpdateZ>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_COption_NetworkUpdateZDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_COption_NetworkUpdateZDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_COption_NetworkUpdateZDecodeErrorZ_clone(orig: &CResult_COption_NetworkUpdateZDecodeErrorZ) -> CResult_COption_NetworkUpdateZDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// An enum which can either contain a crate::lightning::chain::Access or not
pub enum COption_AccessZ {
	/// When we're in this state, this COption_AccessZ contains a crate::lightning::chain::Access
	Some(crate::lightning::chain::Access),
	/// When we're in this state, this COption_AccessZ contains nothing
	None
}
impl COption_AccessZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::chain::Access {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_AccessZ containing a crate::lightning::chain::Access
pub extern "C" fn COption_AccessZ_some(o: crate::lightning::chain::Access) -> COption_AccessZ {
	COption_AccessZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_AccessZ containing nothing
pub extern "C" fn COption_AccessZ_none() -> COption_AccessZ {
	COption_AccessZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::chain::Access, if we are in the Some state
pub extern "C" fn COption_AccessZ_free(_res: COption_AccessZ) { }
#[repr(C)]
/// The contents of CResult_DirectionalChannelInfoDecodeErrorZ
pub union CResult_DirectionalChannelInfoDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::DirectionalChannelInfo,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_DirectionalChannelInfoDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::DirectionalChannelInfo on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_DirectionalChannelInfoDecodeErrorZ {
	/// The contents of this CResult_DirectionalChannelInfoDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_DirectionalChannelInfoDecodeErrorZPtr,
	/// Whether this CResult_DirectionalChannelInfoDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_DirectionalChannelInfoDecodeErrorZ in the success state.
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::DirectionalChannelInfo) -> CResult_DirectionalChannelInfoDecodeErrorZ {
	CResult_DirectionalChannelInfoDecodeErrorZ {
		contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_DirectionalChannelInfoDecodeErrorZ in the error state.
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_DirectionalChannelInfoDecodeErrorZ {
	CResult_DirectionalChannelInfoDecodeErrorZ {
		contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_is_ok(o: &CResult_DirectionalChannelInfoDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_DirectionalChannelInfoDecodeErrorZ.
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_free(_res: CResult_DirectionalChannelInfoDecodeErrorZ) { }
impl Drop for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::DirectionalChannelInfo, crate::lightning::ln::msgs::DecodeError>> for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::DirectionalChannelInfo, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_DirectionalChannelInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_DirectionalChannelInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_DirectionalChannelInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::DirectionalChannelInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_DirectionalChannelInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_DirectionalChannelInfoDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_DirectionalChannelInfoDecodeErrorZ_clone(orig: &CResult_DirectionalChannelInfoDecodeErrorZ) -> CResult_DirectionalChannelInfoDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelInfoDecodeErrorZ
pub union CResult_ChannelInfoDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::ChannelInfo,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelInfoDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::ChannelInfo on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelInfoDecodeErrorZ {
	/// The contents of this CResult_ChannelInfoDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelInfoDecodeErrorZPtr,
	/// Whether this CResult_ChannelInfoDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelInfoDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::ChannelInfo) -> CResult_ChannelInfoDecodeErrorZ {
	CResult_ChannelInfoDecodeErrorZ {
		contents: CResult_ChannelInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelInfoDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelInfoDecodeErrorZ {
	CResult_ChannelInfoDecodeErrorZ {
		contents: CResult_ChannelInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_is_ok(o: &CResult_ChannelInfoDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelInfoDecodeErrorZ.
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_free(_res: CResult_ChannelInfoDecodeErrorZ) { }
impl Drop for CResult_ChannelInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::ChannelInfo, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::ChannelInfo, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::ChannelInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelInfoDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelInfoDecodeErrorZ_clone(orig: &CResult_ChannelInfoDecodeErrorZ) -> CResult_ChannelInfoDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_RoutingFeesDecodeErrorZ
pub union CResult_RoutingFeesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::RoutingFees,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RoutingFeesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::RoutingFees on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RoutingFeesDecodeErrorZ {
	/// The contents of this CResult_RoutingFeesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RoutingFeesDecodeErrorZPtr,
	/// Whether this CResult_RoutingFeesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RoutingFeesDecodeErrorZ in the success state.
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::RoutingFees) -> CResult_RoutingFeesDecodeErrorZ {
	CResult_RoutingFeesDecodeErrorZ {
		contents: CResult_RoutingFeesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RoutingFeesDecodeErrorZ in the error state.
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RoutingFeesDecodeErrorZ {
	CResult_RoutingFeesDecodeErrorZ {
		contents: CResult_RoutingFeesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_is_ok(o: &CResult_RoutingFeesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RoutingFeesDecodeErrorZ.
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_free(_res: CResult_RoutingFeesDecodeErrorZ) { }
impl Drop for CResult_RoutingFeesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::RoutingFees, crate::lightning::ln::msgs::DecodeError>> for CResult_RoutingFeesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::RoutingFees, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RoutingFeesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RoutingFeesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RoutingFeesDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RoutingFeesDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::RoutingFees>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RoutingFeesDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RoutingFeesDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RoutingFeesDecodeErrorZ_clone(orig: &CResult_RoutingFeesDecodeErrorZ) -> CResult_RoutingFeesDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NodeAnnouncementInfoDecodeErrorZ
pub union CResult_NodeAnnouncementInfoDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::NodeAnnouncementInfo,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NodeAnnouncementInfoDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::NodeAnnouncementInfo on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NodeAnnouncementInfoDecodeErrorZ {
	/// The contents of this CResult_NodeAnnouncementInfoDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr,
	/// Whether this CResult_NodeAnnouncementInfoDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementInfoDecodeErrorZ in the success state.
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::NodeAnnouncementInfo) -> CResult_NodeAnnouncementInfoDecodeErrorZ {
	CResult_NodeAnnouncementInfoDecodeErrorZ {
		contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementInfoDecodeErrorZ in the error state.
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NodeAnnouncementInfoDecodeErrorZ {
	CResult_NodeAnnouncementInfoDecodeErrorZ {
		contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_is_ok(o: &CResult_NodeAnnouncementInfoDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NodeAnnouncementInfoDecodeErrorZ.
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_free(_res: CResult_NodeAnnouncementInfoDecodeErrorZ) { }
impl Drop for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeAnnouncementInfo, crate::lightning::ln::msgs::DecodeError>> for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeAnnouncementInfo, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeAnnouncementInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeAnnouncementInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeAnnouncementInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::NodeAnnouncementInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeAnnouncementInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementInfoDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NodeAnnouncementInfoDecodeErrorZ_clone(orig: &CResult_NodeAnnouncementInfoDecodeErrorZ) -> CResult_NodeAnnouncementInfoDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of u64s of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_u64Z {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut u64,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_u64Z {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<u64> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[u64] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<u64>> for CVec_u64Z {
	fn from(v: Vec<u64>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_u64Z_free(_res: CVec_u64Z) { }
impl Drop for CVec_u64Z {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_u64Z {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_NodeInfoDecodeErrorZ
pub union CResult_NodeInfoDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::NodeInfo,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NodeInfoDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::NodeInfo on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NodeInfoDecodeErrorZ {
	/// The contents of this CResult_NodeInfoDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NodeInfoDecodeErrorZPtr,
	/// Whether this CResult_NodeInfoDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NodeInfoDecodeErrorZ in the success state.
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::NodeInfo) -> CResult_NodeInfoDecodeErrorZ {
	CResult_NodeInfoDecodeErrorZ {
		contents: CResult_NodeInfoDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NodeInfoDecodeErrorZ in the error state.
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NodeInfoDecodeErrorZ {
	CResult_NodeInfoDecodeErrorZ {
		contents: CResult_NodeInfoDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_is_ok(o: &CResult_NodeInfoDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NodeInfoDecodeErrorZ.
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_free(_res: CResult_NodeInfoDecodeErrorZ) { }
impl Drop for CResult_NodeInfoDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeInfo, crate::lightning::ln::msgs::DecodeError>> for CResult_NodeInfoDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NodeInfo, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeInfoDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeInfoDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeInfoDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeInfoDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::NodeInfo>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeInfoDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NodeInfoDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NodeInfoDecodeErrorZ_clone(orig: &CResult_NodeInfoDecodeErrorZ) -> CResult_NodeInfoDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NetworkGraphDecodeErrorZ
pub union CResult_NetworkGraphDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::routing::network_graph::NetworkGraph,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NetworkGraphDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::routing::network_graph::NetworkGraph on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NetworkGraphDecodeErrorZ {
	/// The contents of this CResult_NetworkGraphDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NetworkGraphDecodeErrorZPtr,
	/// Whether this CResult_NetworkGraphDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NetworkGraphDecodeErrorZ in the success state.
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_ok(o: crate::lightning::routing::network_graph::NetworkGraph) -> CResult_NetworkGraphDecodeErrorZ {
	CResult_NetworkGraphDecodeErrorZ {
		contents: CResult_NetworkGraphDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NetworkGraphDecodeErrorZ in the error state.
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NetworkGraphDecodeErrorZ {
	CResult_NetworkGraphDecodeErrorZ {
		contents: CResult_NetworkGraphDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_is_ok(o: &CResult_NetworkGraphDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NetworkGraphDecodeErrorZ.
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_free(_res: CResult_NetworkGraphDecodeErrorZ) { }
impl Drop for CResult_NetworkGraphDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NetworkGraph, crate::lightning::ln::msgs::DecodeError>> for CResult_NetworkGraphDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::routing::network_graph::NetworkGraph, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NetworkGraphDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NetworkGraphDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NetworkGraphDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NetworkGraphDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::routing::network_graph::NetworkGraph>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NetworkGraphDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NetworkGraphDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NetworkGraphDecodeErrorZ_clone(orig: &CResult_NetworkGraphDecodeErrorZ) -> CResult_NetworkGraphDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
#[derive(Clone)]
/// An enum which can either contain a crate::c_types::derived::CVec_NetAddressZ or not
pub enum COption_CVec_NetAddressZZ {
	/// When we're in this state, this COption_CVec_NetAddressZZ contains a crate::c_types::derived::CVec_NetAddressZ
	Some(crate::c_types::derived::CVec_NetAddressZ),
	/// When we're in this state, this COption_CVec_NetAddressZZ contains nothing
	None
}
impl COption_CVec_NetAddressZZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::c_types::derived::CVec_NetAddressZ {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_CVec_NetAddressZZ containing a crate::c_types::derived::CVec_NetAddressZ
pub extern "C" fn COption_CVec_NetAddressZZ_some(o: crate::c_types::derived::CVec_NetAddressZ) -> COption_CVec_NetAddressZZ {
	COption_CVec_NetAddressZZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_CVec_NetAddressZZ containing nothing
pub extern "C" fn COption_CVec_NetAddressZZ_none() -> COption_CVec_NetAddressZZ {
	COption_CVec_NetAddressZZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::c_types::derived::CVec_NetAddressZ, if we are in the Some state
pub extern "C" fn COption_CVec_NetAddressZZ_free(_res: COption_CVec_NetAddressZZ) { }
#[no_mangle]
/// Creates a new COption_CVec_NetAddressZZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn COption_CVec_NetAddressZZ_clone(orig: &COption_CVec_NetAddressZZ) -> COption_CVec_NetAddressZZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NetAddressDecodeErrorZ
pub union CResult_NetAddressDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::NetAddress,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NetAddressDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::NetAddress on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NetAddressDecodeErrorZ {
	/// The contents of this CResult_NetAddressDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NetAddressDecodeErrorZPtr,
	/// Whether this CResult_NetAddressDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NetAddressDecodeErrorZ in the success state.
pub extern "C" fn CResult_NetAddressDecodeErrorZ_ok(o: crate::lightning::ln::msgs::NetAddress) -> CResult_NetAddressDecodeErrorZ {
	CResult_NetAddressDecodeErrorZ {
		contents: CResult_NetAddressDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NetAddressDecodeErrorZ in the error state.
pub extern "C" fn CResult_NetAddressDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NetAddressDecodeErrorZ {
	CResult_NetAddressDecodeErrorZ {
		contents: CResult_NetAddressDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NetAddressDecodeErrorZ_is_ok(o: &CResult_NetAddressDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NetAddressDecodeErrorZ.
pub extern "C" fn CResult_NetAddressDecodeErrorZ_free(_res: CResult_NetAddressDecodeErrorZ) { }
impl Drop for CResult_NetAddressDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::NetAddress, crate::lightning::ln::msgs::DecodeError>> for CResult_NetAddressDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::NetAddress, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NetAddressDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NetAddressDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NetAddressDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NetAddressDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::NetAddress>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NetAddressDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NetAddressDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NetAddressDecodeErrorZ_clone(orig: &CResult_NetAddressDecodeErrorZ) -> CResult_NetAddressDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::UpdateAddHTLCs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_UpdateAddHTLCZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::UpdateAddHTLC,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_UpdateAddHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::UpdateAddHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::UpdateAddHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::UpdateAddHTLC>> for CVec_UpdateAddHTLCZ {
	fn from(v: Vec<crate::lightning::ln::msgs::UpdateAddHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_UpdateAddHTLCZ_free(_res: CVec_UpdateAddHTLCZ) { }
impl Drop for CVec_UpdateAddHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateAddHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::UpdateFulfillHTLCs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_UpdateFulfillHTLCZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::UpdateFulfillHTLC,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_UpdateFulfillHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::UpdateFulfillHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::UpdateFulfillHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::UpdateFulfillHTLC>> for CVec_UpdateFulfillHTLCZ {
	fn from(v: Vec<crate::lightning::ln::msgs::UpdateFulfillHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_UpdateFulfillHTLCZ_free(_res: CVec_UpdateFulfillHTLCZ) { }
impl Drop for CVec_UpdateFulfillHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFulfillHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::UpdateFailHTLCs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_UpdateFailHTLCZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::UpdateFailHTLC,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_UpdateFailHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::UpdateFailHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::UpdateFailHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::UpdateFailHTLC>> for CVec_UpdateFailHTLCZ {
	fn from(v: Vec<crate::lightning::ln::msgs::UpdateFailHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_UpdateFailHTLCZ_free(_res: CVec_UpdateFailHTLCZ) { }
impl Drop for CVec_UpdateFailHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFailHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::ln::msgs::UpdateFailMalformedHTLCs of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_UpdateFailMalformedHTLCZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::ln::msgs::UpdateFailMalformedHTLC,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_UpdateFailMalformedHTLCZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::ln::msgs::UpdateFailMalformedHTLC> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::ln::msgs::UpdateFailMalformedHTLC] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::ln::msgs::UpdateFailMalformedHTLC>> for CVec_UpdateFailMalformedHTLCZ {
	fn from(v: Vec<crate::lightning::ln::msgs::UpdateFailMalformedHTLC>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_UpdateFailMalformedHTLCZ_free(_res: CVec_UpdateFailMalformedHTLCZ) { }
impl Drop for CVec_UpdateFailMalformedHTLCZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_UpdateFailMalformedHTLCZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
#[repr(C)]
/// The contents of CResult_AcceptChannelDecodeErrorZ
pub union CResult_AcceptChannelDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::AcceptChannel,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_AcceptChannelDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::AcceptChannel on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_AcceptChannelDecodeErrorZ {
	/// The contents of this CResult_AcceptChannelDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_AcceptChannelDecodeErrorZPtr,
	/// Whether this CResult_AcceptChannelDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_AcceptChannelDecodeErrorZ in the success state.
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_ok(o: crate::lightning::ln::msgs::AcceptChannel) -> CResult_AcceptChannelDecodeErrorZ {
	CResult_AcceptChannelDecodeErrorZ {
		contents: CResult_AcceptChannelDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_AcceptChannelDecodeErrorZ in the error state.
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_AcceptChannelDecodeErrorZ {
	CResult_AcceptChannelDecodeErrorZ {
		contents: CResult_AcceptChannelDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_is_ok(o: &CResult_AcceptChannelDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_AcceptChannelDecodeErrorZ.
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_free(_res: CResult_AcceptChannelDecodeErrorZ) { }
impl Drop for CResult_AcceptChannelDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::AcceptChannel, crate::lightning::ln::msgs::DecodeError>> for CResult_AcceptChannelDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::AcceptChannel, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_AcceptChannelDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_AcceptChannelDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_AcceptChannelDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_AcceptChannelDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::AcceptChannel>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_AcceptChannelDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_AcceptChannelDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_AcceptChannelDecodeErrorZ_clone(orig: &CResult_AcceptChannelDecodeErrorZ) -> CResult_AcceptChannelDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_AnnouncementSignaturesDecodeErrorZ
pub union CResult_AnnouncementSignaturesDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::AnnouncementSignatures,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_AnnouncementSignaturesDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::AnnouncementSignatures on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_AnnouncementSignaturesDecodeErrorZ {
	/// The contents of this CResult_AnnouncementSignaturesDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_AnnouncementSignaturesDecodeErrorZPtr,
	/// Whether this CResult_AnnouncementSignaturesDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_AnnouncementSignaturesDecodeErrorZ in the success state.
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_ok(o: crate::lightning::ln::msgs::AnnouncementSignatures) -> CResult_AnnouncementSignaturesDecodeErrorZ {
	CResult_AnnouncementSignaturesDecodeErrorZ {
		contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_AnnouncementSignaturesDecodeErrorZ in the error state.
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_AnnouncementSignaturesDecodeErrorZ {
	CResult_AnnouncementSignaturesDecodeErrorZ {
		contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_is_ok(o: &CResult_AnnouncementSignaturesDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_AnnouncementSignaturesDecodeErrorZ.
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_free(_res: CResult_AnnouncementSignaturesDecodeErrorZ) { }
impl Drop for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::AnnouncementSignatures, crate::lightning::ln::msgs::DecodeError>> for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::AnnouncementSignatures, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_AnnouncementSignaturesDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_AnnouncementSignaturesDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_AnnouncementSignaturesDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::AnnouncementSignatures>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_AnnouncementSignaturesDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_AnnouncementSignaturesDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_AnnouncementSignaturesDecodeErrorZ_clone(orig: &CResult_AnnouncementSignaturesDecodeErrorZ) -> CResult_AnnouncementSignaturesDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelReestablishDecodeErrorZ
pub union CResult_ChannelReestablishDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ChannelReestablish,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelReestablishDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ChannelReestablish on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelReestablishDecodeErrorZ {
	/// The contents of this CResult_ChannelReestablishDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelReestablishDecodeErrorZPtr,
	/// Whether this CResult_ChannelReestablishDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelReestablishDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ChannelReestablish) -> CResult_ChannelReestablishDecodeErrorZ {
	CResult_ChannelReestablishDecodeErrorZ {
		contents: CResult_ChannelReestablishDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelReestablishDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelReestablishDecodeErrorZ {
	CResult_ChannelReestablishDecodeErrorZ {
		contents: CResult_ChannelReestablishDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_is_ok(o: &CResult_ChannelReestablishDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelReestablishDecodeErrorZ.
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_free(_res: CResult_ChannelReestablishDecodeErrorZ) { }
impl Drop for CResult_ChannelReestablishDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelReestablish, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelReestablishDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelReestablish, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelReestablishDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelReestablishDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelReestablishDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelReestablishDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ChannelReestablish>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelReestablishDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelReestablishDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelReestablishDecodeErrorZ_clone(orig: &CResult_ChannelReestablishDecodeErrorZ) -> CResult_ChannelReestablishDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ClosingSignedDecodeErrorZ
pub union CResult_ClosingSignedDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ClosingSigned,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ClosingSignedDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ClosingSigned on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ClosingSignedDecodeErrorZ {
	/// The contents of this CResult_ClosingSignedDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ClosingSignedDecodeErrorZPtr,
	/// Whether this CResult_ClosingSignedDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedDecodeErrorZ in the success state.
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ClosingSigned) -> CResult_ClosingSignedDecodeErrorZ {
	CResult_ClosingSignedDecodeErrorZ {
		contents: CResult_ClosingSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedDecodeErrorZ in the error state.
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ClosingSignedDecodeErrorZ {
	CResult_ClosingSignedDecodeErrorZ {
		contents: CResult_ClosingSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_is_ok(o: &CResult_ClosingSignedDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ClosingSignedDecodeErrorZ.
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_free(_res: CResult_ClosingSignedDecodeErrorZ) { }
impl Drop for CResult_ClosingSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ClosingSigned, crate::lightning::ln::msgs::DecodeError>> for CResult_ClosingSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ClosingSigned, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ClosingSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ClosingSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ClosingSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ClosingSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ClosingSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ClosingSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ClosingSignedDecodeErrorZ_clone(orig: &CResult_ClosingSignedDecodeErrorZ) -> CResult_ClosingSignedDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ClosingSignedFeeRangeDecodeErrorZ
pub union CResult_ClosingSignedFeeRangeDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ClosingSignedFeeRange,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ClosingSignedFeeRangeDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ClosingSignedFeeRange on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ClosingSignedFeeRangeDecodeErrorZ {
	/// The contents of this CResult_ClosingSignedFeeRangeDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ClosingSignedFeeRangeDecodeErrorZPtr,
	/// Whether this CResult_ClosingSignedFeeRangeDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedFeeRangeDecodeErrorZ in the success state.
pub extern "C" fn CResult_ClosingSignedFeeRangeDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ClosingSignedFeeRange) -> CResult_ClosingSignedFeeRangeDecodeErrorZ {
	CResult_ClosingSignedFeeRangeDecodeErrorZ {
		contents: CResult_ClosingSignedFeeRangeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedFeeRangeDecodeErrorZ in the error state.
pub extern "C" fn CResult_ClosingSignedFeeRangeDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ClosingSignedFeeRangeDecodeErrorZ {
	CResult_ClosingSignedFeeRangeDecodeErrorZ {
		contents: CResult_ClosingSignedFeeRangeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ClosingSignedFeeRangeDecodeErrorZ_is_ok(o: &CResult_ClosingSignedFeeRangeDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ClosingSignedFeeRangeDecodeErrorZ.
pub extern "C" fn CResult_ClosingSignedFeeRangeDecodeErrorZ_free(_res: CResult_ClosingSignedFeeRangeDecodeErrorZ) { }
impl Drop for CResult_ClosingSignedFeeRangeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ClosingSignedFeeRange, crate::lightning::ln::msgs::DecodeError>> for CResult_ClosingSignedFeeRangeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ClosingSignedFeeRange, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ClosingSignedFeeRangeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ClosingSignedFeeRangeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ClosingSignedFeeRangeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ClosingSignedFeeRangeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ClosingSignedFeeRange>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ClosingSignedFeeRangeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ClosingSignedFeeRangeDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ClosingSignedFeeRangeDecodeErrorZ_clone(orig: &CResult_ClosingSignedFeeRangeDecodeErrorZ) -> CResult_ClosingSignedFeeRangeDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_CommitmentSignedDecodeErrorZ
pub union CResult_CommitmentSignedDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::CommitmentSigned,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_CommitmentSignedDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::CommitmentSigned on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_CommitmentSignedDecodeErrorZ {
	/// The contents of this CResult_CommitmentSignedDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_CommitmentSignedDecodeErrorZPtr,
	/// Whether this CResult_CommitmentSignedDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_CommitmentSignedDecodeErrorZ in the success state.
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_ok(o: crate::lightning::ln::msgs::CommitmentSigned) -> CResult_CommitmentSignedDecodeErrorZ {
	CResult_CommitmentSignedDecodeErrorZ {
		contents: CResult_CommitmentSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_CommitmentSignedDecodeErrorZ in the error state.
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_CommitmentSignedDecodeErrorZ {
	CResult_CommitmentSignedDecodeErrorZ {
		contents: CResult_CommitmentSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_is_ok(o: &CResult_CommitmentSignedDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_CommitmentSignedDecodeErrorZ.
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_free(_res: CResult_CommitmentSignedDecodeErrorZ) { }
impl Drop for CResult_CommitmentSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::CommitmentSigned, crate::lightning::ln::msgs::DecodeError>> for CResult_CommitmentSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::CommitmentSigned, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_CommitmentSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_CommitmentSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_CommitmentSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_CommitmentSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::CommitmentSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_CommitmentSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_CommitmentSignedDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_CommitmentSignedDecodeErrorZ_clone(orig: &CResult_CommitmentSignedDecodeErrorZ) -> CResult_CommitmentSignedDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_FundingCreatedDecodeErrorZ
pub union CResult_FundingCreatedDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::FundingCreated,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_FundingCreatedDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::FundingCreated on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_FundingCreatedDecodeErrorZ {
	/// The contents of this CResult_FundingCreatedDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_FundingCreatedDecodeErrorZPtr,
	/// Whether this CResult_FundingCreatedDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_FundingCreatedDecodeErrorZ in the success state.
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_ok(o: crate::lightning::ln::msgs::FundingCreated) -> CResult_FundingCreatedDecodeErrorZ {
	CResult_FundingCreatedDecodeErrorZ {
		contents: CResult_FundingCreatedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_FundingCreatedDecodeErrorZ in the error state.
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_FundingCreatedDecodeErrorZ {
	CResult_FundingCreatedDecodeErrorZ {
		contents: CResult_FundingCreatedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_is_ok(o: &CResult_FundingCreatedDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_FundingCreatedDecodeErrorZ.
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_free(_res: CResult_FundingCreatedDecodeErrorZ) { }
impl Drop for CResult_FundingCreatedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingCreated, crate::lightning::ln::msgs::DecodeError>> for CResult_FundingCreatedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingCreated, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingCreatedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingCreatedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingCreatedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingCreatedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::FundingCreated>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingCreatedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_FundingCreatedDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_FundingCreatedDecodeErrorZ_clone(orig: &CResult_FundingCreatedDecodeErrorZ) -> CResult_FundingCreatedDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_FundingSignedDecodeErrorZ
pub union CResult_FundingSignedDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::FundingSigned,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_FundingSignedDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::FundingSigned on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_FundingSignedDecodeErrorZ {
	/// The contents of this CResult_FundingSignedDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_FundingSignedDecodeErrorZPtr,
	/// Whether this CResult_FundingSignedDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_FundingSignedDecodeErrorZ in the success state.
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_ok(o: crate::lightning::ln::msgs::FundingSigned) -> CResult_FundingSignedDecodeErrorZ {
	CResult_FundingSignedDecodeErrorZ {
		contents: CResult_FundingSignedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_FundingSignedDecodeErrorZ in the error state.
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_FundingSignedDecodeErrorZ {
	CResult_FundingSignedDecodeErrorZ {
		contents: CResult_FundingSignedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_is_ok(o: &CResult_FundingSignedDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_FundingSignedDecodeErrorZ.
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_free(_res: CResult_FundingSignedDecodeErrorZ) { }
impl Drop for CResult_FundingSignedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingSigned, crate::lightning::ln::msgs::DecodeError>> for CResult_FundingSignedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingSigned, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingSignedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingSignedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingSignedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingSignedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::FundingSigned>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingSignedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_FundingSignedDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_FundingSignedDecodeErrorZ_clone(orig: &CResult_FundingSignedDecodeErrorZ) -> CResult_FundingSignedDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_FundingLockedDecodeErrorZ
pub union CResult_FundingLockedDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::FundingLocked,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_FundingLockedDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::FundingLocked on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_FundingLockedDecodeErrorZ {
	/// The contents of this CResult_FundingLockedDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_FundingLockedDecodeErrorZPtr,
	/// Whether this CResult_FundingLockedDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_FundingLockedDecodeErrorZ in the success state.
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_ok(o: crate::lightning::ln::msgs::FundingLocked) -> CResult_FundingLockedDecodeErrorZ {
	CResult_FundingLockedDecodeErrorZ {
		contents: CResult_FundingLockedDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_FundingLockedDecodeErrorZ in the error state.
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_FundingLockedDecodeErrorZ {
	CResult_FundingLockedDecodeErrorZ {
		contents: CResult_FundingLockedDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_is_ok(o: &CResult_FundingLockedDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_FundingLockedDecodeErrorZ.
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_free(_res: CResult_FundingLockedDecodeErrorZ) { }
impl Drop for CResult_FundingLockedDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingLocked, crate::lightning::ln::msgs::DecodeError>> for CResult_FundingLockedDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::FundingLocked, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_FundingLockedDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_FundingLockedDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_FundingLockedDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_FundingLockedDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::FundingLocked>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_FundingLockedDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_FundingLockedDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_FundingLockedDecodeErrorZ_clone(orig: &CResult_FundingLockedDecodeErrorZ) -> CResult_FundingLockedDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_InitDecodeErrorZ
pub union CResult_InitDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::Init,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_InitDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::Init on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InitDecodeErrorZ {
	/// The contents of this CResult_InitDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InitDecodeErrorZPtr,
	/// Whether this CResult_InitDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InitDecodeErrorZ in the success state.
pub extern "C" fn CResult_InitDecodeErrorZ_ok(o: crate::lightning::ln::msgs::Init) -> CResult_InitDecodeErrorZ {
	CResult_InitDecodeErrorZ {
		contents: CResult_InitDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InitDecodeErrorZ in the error state.
pub extern "C" fn CResult_InitDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_InitDecodeErrorZ {
	CResult_InitDecodeErrorZ {
		contents: CResult_InitDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InitDecodeErrorZ_is_ok(o: &CResult_InitDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InitDecodeErrorZ.
pub extern "C" fn CResult_InitDecodeErrorZ_free(_res: CResult_InitDecodeErrorZ) { }
impl Drop for CResult_InitDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::Init, crate::lightning::ln::msgs::DecodeError>> for CResult_InitDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::Init, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InitDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InitDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InitDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InitDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::Init>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InitDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_InitDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_InitDecodeErrorZ_clone(orig: &CResult_InitDecodeErrorZ) -> CResult_InitDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_OpenChannelDecodeErrorZ
pub union CResult_OpenChannelDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::OpenChannel,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_OpenChannelDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::OpenChannel on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_OpenChannelDecodeErrorZ {
	/// The contents of this CResult_OpenChannelDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_OpenChannelDecodeErrorZPtr,
	/// Whether this CResult_OpenChannelDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_OpenChannelDecodeErrorZ in the success state.
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_ok(o: crate::lightning::ln::msgs::OpenChannel) -> CResult_OpenChannelDecodeErrorZ {
	CResult_OpenChannelDecodeErrorZ {
		contents: CResult_OpenChannelDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_OpenChannelDecodeErrorZ in the error state.
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_OpenChannelDecodeErrorZ {
	CResult_OpenChannelDecodeErrorZ {
		contents: CResult_OpenChannelDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_is_ok(o: &CResult_OpenChannelDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_OpenChannelDecodeErrorZ.
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_free(_res: CResult_OpenChannelDecodeErrorZ) { }
impl Drop for CResult_OpenChannelDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::OpenChannel, crate::lightning::ln::msgs::DecodeError>> for CResult_OpenChannelDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::OpenChannel, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_OpenChannelDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_OpenChannelDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_OpenChannelDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_OpenChannelDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::OpenChannel>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_OpenChannelDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_OpenChannelDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_OpenChannelDecodeErrorZ_clone(orig: &CResult_OpenChannelDecodeErrorZ) -> CResult_OpenChannelDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_RevokeAndACKDecodeErrorZ
pub union CResult_RevokeAndACKDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::RevokeAndACK,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_RevokeAndACKDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::RevokeAndACK on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_RevokeAndACKDecodeErrorZ {
	/// The contents of this CResult_RevokeAndACKDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_RevokeAndACKDecodeErrorZPtr,
	/// Whether this CResult_RevokeAndACKDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_RevokeAndACKDecodeErrorZ in the success state.
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_ok(o: crate::lightning::ln::msgs::RevokeAndACK) -> CResult_RevokeAndACKDecodeErrorZ {
	CResult_RevokeAndACKDecodeErrorZ {
		contents: CResult_RevokeAndACKDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_RevokeAndACKDecodeErrorZ in the error state.
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_RevokeAndACKDecodeErrorZ {
	CResult_RevokeAndACKDecodeErrorZ {
		contents: CResult_RevokeAndACKDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_is_ok(o: &CResult_RevokeAndACKDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_RevokeAndACKDecodeErrorZ.
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_free(_res: CResult_RevokeAndACKDecodeErrorZ) { }
impl Drop for CResult_RevokeAndACKDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::RevokeAndACK, crate::lightning::ln::msgs::DecodeError>> for CResult_RevokeAndACKDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::RevokeAndACK, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_RevokeAndACKDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_RevokeAndACKDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_RevokeAndACKDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_RevokeAndACKDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::RevokeAndACK>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_RevokeAndACKDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_RevokeAndACKDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_RevokeAndACKDecodeErrorZ_clone(orig: &CResult_RevokeAndACKDecodeErrorZ) -> CResult_RevokeAndACKDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ShutdownDecodeErrorZ
pub union CResult_ShutdownDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::Shutdown,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ShutdownDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::Shutdown on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ShutdownDecodeErrorZ {
	/// The contents of this CResult_ShutdownDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ShutdownDecodeErrorZPtr,
	/// Whether this CResult_ShutdownDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ShutdownDecodeErrorZ in the success state.
pub extern "C" fn CResult_ShutdownDecodeErrorZ_ok(o: crate::lightning::ln::msgs::Shutdown) -> CResult_ShutdownDecodeErrorZ {
	CResult_ShutdownDecodeErrorZ {
		contents: CResult_ShutdownDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownDecodeErrorZ in the error state.
pub extern "C" fn CResult_ShutdownDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ShutdownDecodeErrorZ {
	CResult_ShutdownDecodeErrorZ {
		contents: CResult_ShutdownDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ShutdownDecodeErrorZ_is_ok(o: &CResult_ShutdownDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ShutdownDecodeErrorZ.
pub extern "C" fn CResult_ShutdownDecodeErrorZ_free(_res: CResult_ShutdownDecodeErrorZ) { }
impl Drop for CResult_ShutdownDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::Shutdown, crate::lightning::ln::msgs::DecodeError>> for CResult_ShutdownDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::Shutdown, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ShutdownDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ShutdownDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ShutdownDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ShutdownDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::Shutdown>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ShutdownDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ShutdownDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ShutdownDecodeErrorZ_clone(orig: &CResult_ShutdownDecodeErrorZ) -> CResult_ShutdownDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UpdateFailHTLCDecodeErrorZ
pub union CResult_UpdateFailHTLCDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UpdateFailHTLC,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UpdateFailHTLCDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UpdateFailHTLC on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UpdateFailHTLCDecodeErrorZ {
	/// The contents of this CResult_UpdateFailHTLCDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UpdateFailHTLCDecodeErrorZPtr,
	/// Whether this CResult_UpdateFailHTLCDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UpdateFailHTLCDecodeErrorZ in the success state.
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UpdateFailHTLC) -> CResult_UpdateFailHTLCDecodeErrorZ {
	CResult_UpdateFailHTLCDecodeErrorZ {
		contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFailHTLCDecodeErrorZ in the error state.
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UpdateFailHTLCDecodeErrorZ {
	CResult_UpdateFailHTLCDecodeErrorZ {
		contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_is_ok(o: &CResult_UpdateFailHTLCDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UpdateFailHTLCDecodeErrorZ.
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_free(_res: CResult_UpdateFailHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFailHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFailHTLC, crate::lightning::ln::msgs::DecodeError>> for CResult_UpdateFailHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFailHTLC, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFailHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFailHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFailHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UpdateFailHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFailHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFailHTLCDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UpdateFailHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFailHTLCDecodeErrorZ) -> CResult_UpdateFailHTLCDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UpdateFailMalformedHTLCDecodeErrorZ
pub union CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UpdateFailMalformedHTLC,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UpdateFailMalformedHTLCDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UpdateFailMalformedHTLC on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	/// The contents of this CResult_UpdateFailMalformedHTLCDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr,
	/// Whether this CResult_UpdateFailMalformedHTLCDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UpdateFailMalformedHTLCDecodeErrorZ in the success state.
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UpdateFailMalformedHTLC) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	CResult_UpdateFailMalformedHTLCDecodeErrorZ {
		contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFailMalformedHTLCDecodeErrorZ in the error state.
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	CResult_UpdateFailMalformedHTLCDecodeErrorZ {
		contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_is_ok(o: &CResult_UpdateFailMalformedHTLCDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UpdateFailMalformedHTLCDecodeErrorZ.
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_free(_res: CResult_UpdateFailMalformedHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFailMalformedHTLC, crate::lightning::ln::msgs::DecodeError>> for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFailMalformedHTLC, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFailMalformedHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFailMalformedHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFailMalformedHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UpdateFailMalformedHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFailMalformedHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFailMalformedHTLCDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UpdateFailMalformedHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFailMalformedHTLCDecodeErrorZ) -> CResult_UpdateFailMalformedHTLCDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UpdateFeeDecodeErrorZ
pub union CResult_UpdateFeeDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UpdateFee,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UpdateFeeDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UpdateFee on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UpdateFeeDecodeErrorZ {
	/// The contents of this CResult_UpdateFeeDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UpdateFeeDecodeErrorZPtr,
	/// Whether this CResult_UpdateFeeDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UpdateFeeDecodeErrorZ in the success state.
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UpdateFee) -> CResult_UpdateFeeDecodeErrorZ {
	CResult_UpdateFeeDecodeErrorZ {
		contents: CResult_UpdateFeeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFeeDecodeErrorZ in the error state.
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UpdateFeeDecodeErrorZ {
	CResult_UpdateFeeDecodeErrorZ {
		contents: CResult_UpdateFeeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_is_ok(o: &CResult_UpdateFeeDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UpdateFeeDecodeErrorZ.
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_free(_res: CResult_UpdateFeeDecodeErrorZ) { }
impl Drop for CResult_UpdateFeeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFee, crate::lightning::ln::msgs::DecodeError>> for CResult_UpdateFeeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFee, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFeeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFeeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFeeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFeeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UpdateFee>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFeeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFeeDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UpdateFeeDecodeErrorZ_clone(orig: &CResult_UpdateFeeDecodeErrorZ) -> CResult_UpdateFeeDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UpdateFulfillHTLCDecodeErrorZ
pub union CResult_UpdateFulfillHTLCDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UpdateFulfillHTLC,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UpdateFulfillHTLCDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UpdateFulfillHTLC on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UpdateFulfillHTLCDecodeErrorZ {
	/// The contents of this CResult_UpdateFulfillHTLCDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr,
	/// Whether this CResult_UpdateFulfillHTLCDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UpdateFulfillHTLCDecodeErrorZ in the success state.
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UpdateFulfillHTLC) -> CResult_UpdateFulfillHTLCDecodeErrorZ {
	CResult_UpdateFulfillHTLCDecodeErrorZ {
		contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFulfillHTLCDecodeErrorZ in the error state.
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UpdateFulfillHTLCDecodeErrorZ {
	CResult_UpdateFulfillHTLCDecodeErrorZ {
		contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_is_ok(o: &CResult_UpdateFulfillHTLCDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UpdateFulfillHTLCDecodeErrorZ.
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_free(_res: CResult_UpdateFulfillHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFulfillHTLC, crate::lightning::ln::msgs::DecodeError>> for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateFulfillHTLC, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateFulfillHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateFulfillHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateFulfillHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UpdateFulfillHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateFulfillHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateFulfillHTLCDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UpdateFulfillHTLCDecodeErrorZ_clone(orig: &CResult_UpdateFulfillHTLCDecodeErrorZ) -> CResult_UpdateFulfillHTLCDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UpdateAddHTLCDecodeErrorZ
pub union CResult_UpdateAddHTLCDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UpdateAddHTLC,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UpdateAddHTLCDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UpdateAddHTLC on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UpdateAddHTLCDecodeErrorZ {
	/// The contents of this CResult_UpdateAddHTLCDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UpdateAddHTLCDecodeErrorZPtr,
	/// Whether this CResult_UpdateAddHTLCDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UpdateAddHTLCDecodeErrorZ in the success state.
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UpdateAddHTLC) -> CResult_UpdateAddHTLCDecodeErrorZ {
	CResult_UpdateAddHTLCDecodeErrorZ {
		contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateAddHTLCDecodeErrorZ in the error state.
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UpdateAddHTLCDecodeErrorZ {
	CResult_UpdateAddHTLCDecodeErrorZ {
		contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_is_ok(o: &CResult_UpdateAddHTLCDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UpdateAddHTLCDecodeErrorZ.
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_free(_res: CResult_UpdateAddHTLCDecodeErrorZ) { }
impl Drop for CResult_UpdateAddHTLCDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateAddHTLC, crate::lightning::ln::msgs::DecodeError>> for CResult_UpdateAddHTLCDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UpdateAddHTLC, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UpdateAddHTLCDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UpdateAddHTLCDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UpdateAddHTLCDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UpdateAddHTLC>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UpdateAddHTLCDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UpdateAddHTLCDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UpdateAddHTLCDecodeErrorZ_clone(orig: &CResult_UpdateAddHTLCDecodeErrorZ) -> CResult_UpdateAddHTLCDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PingDecodeErrorZ
pub union CResult_PingDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::Ping,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_PingDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::Ping on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PingDecodeErrorZ {
	/// The contents of this CResult_PingDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PingDecodeErrorZPtr,
	/// Whether this CResult_PingDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PingDecodeErrorZ in the success state.
pub extern "C" fn CResult_PingDecodeErrorZ_ok(o: crate::lightning::ln::msgs::Ping) -> CResult_PingDecodeErrorZ {
	CResult_PingDecodeErrorZ {
		contents: CResult_PingDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PingDecodeErrorZ in the error state.
pub extern "C" fn CResult_PingDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_PingDecodeErrorZ {
	CResult_PingDecodeErrorZ {
		contents: CResult_PingDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PingDecodeErrorZ_is_ok(o: &CResult_PingDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PingDecodeErrorZ.
pub extern "C" fn CResult_PingDecodeErrorZ_free(_res: CResult_PingDecodeErrorZ) { }
impl Drop for CResult_PingDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::Ping, crate::lightning::ln::msgs::DecodeError>> for CResult_PingDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::Ping, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PingDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PingDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PingDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PingDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::Ping>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PingDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PingDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PingDecodeErrorZ_clone(orig: &CResult_PingDecodeErrorZ) -> CResult_PingDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_PongDecodeErrorZ
pub union CResult_PongDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::Pong,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_PongDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::Pong on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_PongDecodeErrorZ {
	/// The contents of this CResult_PongDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_PongDecodeErrorZPtr,
	/// Whether this CResult_PongDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_PongDecodeErrorZ in the success state.
pub extern "C" fn CResult_PongDecodeErrorZ_ok(o: crate::lightning::ln::msgs::Pong) -> CResult_PongDecodeErrorZ {
	CResult_PongDecodeErrorZ {
		contents: CResult_PongDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_PongDecodeErrorZ in the error state.
pub extern "C" fn CResult_PongDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_PongDecodeErrorZ {
	CResult_PongDecodeErrorZ {
		contents: CResult_PongDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_PongDecodeErrorZ_is_ok(o: &CResult_PongDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_PongDecodeErrorZ.
pub extern "C" fn CResult_PongDecodeErrorZ_free(_res: CResult_PongDecodeErrorZ) { }
impl Drop for CResult_PongDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::Pong, crate::lightning::ln::msgs::DecodeError>> for CResult_PongDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::Pong, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_PongDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_PongDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_PongDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_PongDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::Pong>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_PongDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_PongDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_PongDecodeErrorZ_clone(orig: &CResult_PongDecodeErrorZ) -> CResult_PongDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UnsignedChannelAnnouncementDecodeErrorZ
pub union CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UnsignedChannelAnnouncement,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UnsignedChannelAnnouncementDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UnsignedChannelAnnouncement on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	/// The contents of this CResult_UnsignedChannelAnnouncementDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr,
	/// Whether this CResult_UnsignedChannelAnnouncementDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelAnnouncementDecodeErrorZ in the success state.
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UnsignedChannelAnnouncement) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	CResult_UnsignedChannelAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelAnnouncementDecodeErrorZ in the error state.
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	CResult_UnsignedChannelAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_is_ok(o: &CResult_UnsignedChannelAnnouncementDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UnsignedChannelAnnouncementDecodeErrorZ.
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_free(_res: CResult_UnsignedChannelAnnouncementDecodeErrorZ) { }
impl Drop for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedChannelAnnouncement, crate::lightning::ln::msgs::DecodeError>> for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedChannelAnnouncement, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedChannelAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedChannelAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedChannelAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UnsignedChannelAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedChannelAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelAnnouncementDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UnsignedChannelAnnouncementDecodeErrorZ_clone(orig: &CResult_UnsignedChannelAnnouncementDecodeErrorZ) -> CResult_UnsignedChannelAnnouncementDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelAnnouncementDecodeErrorZ
pub union CResult_ChannelAnnouncementDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ChannelAnnouncement,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelAnnouncementDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ChannelAnnouncement on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelAnnouncementDecodeErrorZ {
	/// The contents of this CResult_ChannelAnnouncementDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelAnnouncementDecodeErrorZPtr,
	/// Whether this CResult_ChannelAnnouncementDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelAnnouncementDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ChannelAnnouncement) -> CResult_ChannelAnnouncementDecodeErrorZ {
	CResult_ChannelAnnouncementDecodeErrorZ {
		contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelAnnouncementDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelAnnouncementDecodeErrorZ {
	CResult_ChannelAnnouncementDecodeErrorZ {
		contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_is_ok(o: &CResult_ChannelAnnouncementDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelAnnouncementDecodeErrorZ.
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_free(_res: CResult_ChannelAnnouncementDecodeErrorZ) { }
impl Drop for CResult_ChannelAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelAnnouncement, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelAnnouncement, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ChannelAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelAnnouncementDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelAnnouncementDecodeErrorZ_clone(orig: &CResult_ChannelAnnouncementDecodeErrorZ) -> CResult_ChannelAnnouncementDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UnsignedChannelUpdateDecodeErrorZ
pub union CResult_UnsignedChannelUpdateDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UnsignedChannelUpdate,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UnsignedChannelUpdateDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UnsignedChannelUpdate on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UnsignedChannelUpdateDecodeErrorZ {
	/// The contents of this CResult_UnsignedChannelUpdateDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr,
	/// Whether this CResult_UnsignedChannelUpdateDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelUpdateDecodeErrorZ in the success state.
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UnsignedChannelUpdate) -> CResult_UnsignedChannelUpdateDecodeErrorZ {
	CResult_UnsignedChannelUpdateDecodeErrorZ {
		contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelUpdateDecodeErrorZ in the error state.
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UnsignedChannelUpdateDecodeErrorZ {
	CResult_UnsignedChannelUpdateDecodeErrorZ {
		contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_is_ok(o: &CResult_UnsignedChannelUpdateDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UnsignedChannelUpdateDecodeErrorZ.
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_free(_res: CResult_UnsignedChannelUpdateDecodeErrorZ) { }
impl Drop for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedChannelUpdate, crate::lightning::ln::msgs::DecodeError>> for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedChannelUpdate, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedChannelUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedChannelUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedChannelUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UnsignedChannelUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedChannelUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedChannelUpdateDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UnsignedChannelUpdateDecodeErrorZ_clone(orig: &CResult_UnsignedChannelUpdateDecodeErrorZ) -> CResult_UnsignedChannelUpdateDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ChannelUpdateDecodeErrorZ
pub union CResult_ChannelUpdateDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ChannelUpdate,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ChannelUpdateDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ChannelUpdate on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ChannelUpdateDecodeErrorZ {
	/// The contents of this CResult_ChannelUpdateDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ChannelUpdateDecodeErrorZPtr,
	/// Whether this CResult_ChannelUpdateDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ChannelUpdateDecodeErrorZ in the success state.
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ChannelUpdate) -> CResult_ChannelUpdateDecodeErrorZ {
	CResult_ChannelUpdateDecodeErrorZ {
		contents: CResult_ChannelUpdateDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelUpdateDecodeErrorZ in the error state.
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ChannelUpdateDecodeErrorZ {
	CResult_ChannelUpdateDecodeErrorZ {
		contents: CResult_ChannelUpdateDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_is_ok(o: &CResult_ChannelUpdateDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ChannelUpdateDecodeErrorZ.
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_free(_res: CResult_ChannelUpdateDecodeErrorZ) { }
impl Drop for CResult_ChannelUpdateDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelUpdate, crate::lightning::ln::msgs::DecodeError>> for CResult_ChannelUpdateDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ChannelUpdate, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ChannelUpdateDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ChannelUpdateDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ChannelUpdateDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ChannelUpdateDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ChannelUpdate>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ChannelUpdateDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ChannelUpdateDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ChannelUpdateDecodeErrorZ_clone(orig: &CResult_ChannelUpdateDecodeErrorZ) -> CResult_ChannelUpdateDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ErrorMessageDecodeErrorZ
pub union CResult_ErrorMessageDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ErrorMessage,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ErrorMessageDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ErrorMessage on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ErrorMessageDecodeErrorZ {
	/// The contents of this CResult_ErrorMessageDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ErrorMessageDecodeErrorZPtr,
	/// Whether this CResult_ErrorMessageDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ErrorMessageDecodeErrorZ in the success state.
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ErrorMessage) -> CResult_ErrorMessageDecodeErrorZ {
	CResult_ErrorMessageDecodeErrorZ {
		contents: CResult_ErrorMessageDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ErrorMessageDecodeErrorZ in the error state.
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ErrorMessageDecodeErrorZ {
	CResult_ErrorMessageDecodeErrorZ {
		contents: CResult_ErrorMessageDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_is_ok(o: &CResult_ErrorMessageDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ErrorMessageDecodeErrorZ.
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_free(_res: CResult_ErrorMessageDecodeErrorZ) { }
impl Drop for CResult_ErrorMessageDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ErrorMessage, crate::lightning::ln::msgs::DecodeError>> for CResult_ErrorMessageDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ErrorMessage, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ErrorMessageDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ErrorMessageDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ErrorMessageDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ErrorMessageDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ErrorMessage>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ErrorMessageDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ErrorMessageDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ErrorMessageDecodeErrorZ_clone(orig: &CResult_ErrorMessageDecodeErrorZ) -> CResult_ErrorMessageDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_UnsignedNodeAnnouncementDecodeErrorZ
pub union CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::UnsignedNodeAnnouncement,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_UnsignedNodeAnnouncementDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::UnsignedNodeAnnouncement on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	/// The contents of this CResult_UnsignedNodeAnnouncementDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr,
	/// Whether this CResult_UnsignedNodeAnnouncementDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_UnsignedNodeAnnouncementDecodeErrorZ in the success state.
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_ok(o: crate::lightning::ln::msgs::UnsignedNodeAnnouncement) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	CResult_UnsignedNodeAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedNodeAnnouncementDecodeErrorZ in the error state.
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	CResult_UnsignedNodeAnnouncementDecodeErrorZ {
		contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_is_ok(o: &CResult_UnsignedNodeAnnouncementDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_UnsignedNodeAnnouncementDecodeErrorZ.
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_free(_res: CResult_UnsignedNodeAnnouncementDecodeErrorZ) { }
impl Drop for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedNodeAnnouncement, crate::lightning::ln::msgs::DecodeError>> for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::UnsignedNodeAnnouncement, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_UnsignedNodeAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_UnsignedNodeAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_UnsignedNodeAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::UnsignedNodeAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_UnsignedNodeAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_UnsignedNodeAnnouncementDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_UnsignedNodeAnnouncementDecodeErrorZ_clone(orig: &CResult_UnsignedNodeAnnouncementDecodeErrorZ) -> CResult_UnsignedNodeAnnouncementDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_NodeAnnouncementDecodeErrorZ
pub union CResult_NodeAnnouncementDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::NodeAnnouncement,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_NodeAnnouncementDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::NodeAnnouncement on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_NodeAnnouncementDecodeErrorZ {
	/// The contents of this CResult_NodeAnnouncementDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_NodeAnnouncementDecodeErrorZPtr,
	/// Whether this CResult_NodeAnnouncementDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementDecodeErrorZ in the success state.
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_ok(o: crate::lightning::ln::msgs::NodeAnnouncement) -> CResult_NodeAnnouncementDecodeErrorZ {
	CResult_NodeAnnouncementDecodeErrorZ {
		contents: CResult_NodeAnnouncementDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementDecodeErrorZ in the error state.
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_NodeAnnouncementDecodeErrorZ {
	CResult_NodeAnnouncementDecodeErrorZ {
		contents: CResult_NodeAnnouncementDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_is_ok(o: &CResult_NodeAnnouncementDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_NodeAnnouncementDecodeErrorZ.
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_free(_res: CResult_NodeAnnouncementDecodeErrorZ) { }
impl Drop for CResult_NodeAnnouncementDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::NodeAnnouncement, crate::lightning::ln::msgs::DecodeError>> for CResult_NodeAnnouncementDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::NodeAnnouncement, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_NodeAnnouncementDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_NodeAnnouncementDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_NodeAnnouncementDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_NodeAnnouncementDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::NodeAnnouncement>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_NodeAnnouncementDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_NodeAnnouncementDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_NodeAnnouncementDecodeErrorZ_clone(orig: &CResult_NodeAnnouncementDecodeErrorZ) -> CResult_NodeAnnouncementDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_QueryShortChannelIdsDecodeErrorZ
pub union CResult_QueryShortChannelIdsDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::QueryShortChannelIds,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_QueryShortChannelIdsDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::QueryShortChannelIds on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_QueryShortChannelIdsDecodeErrorZ {
	/// The contents of this CResult_QueryShortChannelIdsDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_QueryShortChannelIdsDecodeErrorZPtr,
	/// Whether this CResult_QueryShortChannelIdsDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_QueryShortChannelIdsDecodeErrorZ in the success state.
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_ok(o: crate::lightning::ln::msgs::QueryShortChannelIds) -> CResult_QueryShortChannelIdsDecodeErrorZ {
	CResult_QueryShortChannelIdsDecodeErrorZ {
		contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_QueryShortChannelIdsDecodeErrorZ in the error state.
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_QueryShortChannelIdsDecodeErrorZ {
	CResult_QueryShortChannelIdsDecodeErrorZ {
		contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_is_ok(o: &CResult_QueryShortChannelIdsDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_QueryShortChannelIdsDecodeErrorZ.
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_free(_res: CResult_QueryShortChannelIdsDecodeErrorZ) { }
impl Drop for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::QueryShortChannelIds, crate::lightning::ln::msgs::DecodeError>> for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::QueryShortChannelIds, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_QueryShortChannelIdsDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_QueryShortChannelIdsDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_QueryShortChannelIdsDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::QueryShortChannelIds>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_QueryShortChannelIdsDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_QueryShortChannelIdsDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_QueryShortChannelIdsDecodeErrorZ_clone(orig: &CResult_QueryShortChannelIdsDecodeErrorZ) -> CResult_QueryShortChannelIdsDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ReplyShortChannelIdsEndDecodeErrorZ
pub union CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ReplyShortChannelIdsEnd,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ReplyShortChannelIdsEndDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ReplyShortChannelIdsEnd on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	/// The contents of this CResult_ReplyShortChannelIdsEndDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr,
	/// Whether this CResult_ReplyShortChannelIdsEndDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ReplyShortChannelIdsEndDecodeErrorZ in the success state.
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ReplyShortChannelIdsEnd) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	CResult_ReplyShortChannelIdsEndDecodeErrorZ {
		contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ReplyShortChannelIdsEndDecodeErrorZ in the error state.
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	CResult_ReplyShortChannelIdsEndDecodeErrorZ {
		contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_is_ok(o: &CResult_ReplyShortChannelIdsEndDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ReplyShortChannelIdsEndDecodeErrorZ.
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_free(_res: CResult_ReplyShortChannelIdsEndDecodeErrorZ) { }
impl Drop for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ReplyShortChannelIdsEnd, crate::lightning::ln::msgs::DecodeError>> for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ReplyShortChannelIdsEnd, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ReplyShortChannelIdsEndDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ReplyShortChannelIdsEndDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ReplyShortChannelIdsEndDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ReplyShortChannelIdsEnd>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ReplyShortChannelIdsEndDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ReplyShortChannelIdsEndDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ReplyShortChannelIdsEndDecodeErrorZ_clone(orig: &CResult_ReplyShortChannelIdsEndDecodeErrorZ) -> CResult_ReplyShortChannelIdsEndDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_QueryChannelRangeDecodeErrorZ
pub union CResult_QueryChannelRangeDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::QueryChannelRange,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_QueryChannelRangeDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::QueryChannelRange on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_QueryChannelRangeDecodeErrorZ {
	/// The contents of this CResult_QueryChannelRangeDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_QueryChannelRangeDecodeErrorZPtr,
	/// Whether this CResult_QueryChannelRangeDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_QueryChannelRangeDecodeErrorZ in the success state.
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_ok(o: crate::lightning::ln::msgs::QueryChannelRange) -> CResult_QueryChannelRangeDecodeErrorZ {
	CResult_QueryChannelRangeDecodeErrorZ {
		contents: CResult_QueryChannelRangeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_QueryChannelRangeDecodeErrorZ in the error state.
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_QueryChannelRangeDecodeErrorZ {
	CResult_QueryChannelRangeDecodeErrorZ {
		contents: CResult_QueryChannelRangeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_is_ok(o: &CResult_QueryChannelRangeDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_QueryChannelRangeDecodeErrorZ.
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_free(_res: CResult_QueryChannelRangeDecodeErrorZ) { }
impl Drop for CResult_QueryChannelRangeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::QueryChannelRange, crate::lightning::ln::msgs::DecodeError>> for CResult_QueryChannelRangeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::QueryChannelRange, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_QueryChannelRangeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_QueryChannelRangeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_QueryChannelRangeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_QueryChannelRangeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::QueryChannelRange>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_QueryChannelRangeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_QueryChannelRangeDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_QueryChannelRangeDecodeErrorZ_clone(orig: &CResult_QueryChannelRangeDecodeErrorZ) -> CResult_QueryChannelRangeDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_ReplyChannelRangeDecodeErrorZ
pub union CResult_ReplyChannelRangeDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::ReplyChannelRange,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_ReplyChannelRangeDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::ReplyChannelRange on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_ReplyChannelRangeDecodeErrorZ {
	/// The contents of this CResult_ReplyChannelRangeDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_ReplyChannelRangeDecodeErrorZPtr,
	/// Whether this CResult_ReplyChannelRangeDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_ReplyChannelRangeDecodeErrorZ in the success state.
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_ok(o: crate::lightning::ln::msgs::ReplyChannelRange) -> CResult_ReplyChannelRangeDecodeErrorZ {
	CResult_ReplyChannelRangeDecodeErrorZ {
		contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_ReplyChannelRangeDecodeErrorZ in the error state.
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_ReplyChannelRangeDecodeErrorZ {
	CResult_ReplyChannelRangeDecodeErrorZ {
		contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_is_ok(o: &CResult_ReplyChannelRangeDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_ReplyChannelRangeDecodeErrorZ.
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_free(_res: CResult_ReplyChannelRangeDecodeErrorZ) { }
impl Drop for CResult_ReplyChannelRangeDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::ReplyChannelRange, crate::lightning::ln::msgs::DecodeError>> for CResult_ReplyChannelRangeDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::ReplyChannelRange, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_ReplyChannelRangeDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_ReplyChannelRangeDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_ReplyChannelRangeDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::ReplyChannelRange>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_ReplyChannelRangeDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_ReplyChannelRangeDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_ReplyChannelRangeDecodeErrorZ_clone(orig: &CResult_ReplyChannelRangeDecodeErrorZ) -> CResult_ReplyChannelRangeDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_GossipTimestampFilterDecodeErrorZ
pub union CResult_GossipTimestampFilterDecodeErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::ln::msgs::GossipTimestampFilter,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning::ln::msgs::DecodeError,
}
#[repr(C)]
/// A CResult_GossipTimestampFilterDecodeErrorZ represents the result of a fallible operation,
/// containing a crate::lightning::ln::msgs::GossipTimestampFilter on success and a crate::lightning::ln::msgs::DecodeError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_GossipTimestampFilterDecodeErrorZ {
	/// The contents of this CResult_GossipTimestampFilterDecodeErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_GossipTimestampFilterDecodeErrorZPtr,
	/// Whether this CResult_GossipTimestampFilterDecodeErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_GossipTimestampFilterDecodeErrorZ in the success state.
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_ok(o: crate::lightning::ln::msgs::GossipTimestampFilter) -> CResult_GossipTimestampFilterDecodeErrorZ {
	CResult_GossipTimestampFilterDecodeErrorZ {
		contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_GossipTimestampFilterDecodeErrorZ in the error state.
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_err(e: crate::lightning::ln::msgs::DecodeError) -> CResult_GossipTimestampFilterDecodeErrorZ {
	CResult_GossipTimestampFilterDecodeErrorZ {
		contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_is_ok(o: &CResult_GossipTimestampFilterDecodeErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_GossipTimestampFilterDecodeErrorZ.
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_free(_res: CResult_GossipTimestampFilterDecodeErrorZ) { }
impl Drop for CResult_GossipTimestampFilterDecodeErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::ln::msgs::GossipTimestampFilter, crate::lightning::ln::msgs::DecodeError>> for CResult_GossipTimestampFilterDecodeErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::ln::msgs::GossipTimestampFilter, crate::lightning::ln::msgs::DecodeError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_GossipTimestampFilterDecodeErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_GossipTimestampFilterDecodeErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_GossipTimestampFilterDecodeErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning::ln::msgs::GossipTimestampFilter>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_GossipTimestampFilterDecodeErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning::ln::msgs::DecodeError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_GossipTimestampFilterDecodeErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_GossipTimestampFilterDecodeErrorZ_clone(orig: &CResult_GossipTimestampFilterDecodeErrorZ) -> CResult_GossipTimestampFilterDecodeErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// The contents of CResult_InvoiceSignOrCreationErrorZ
pub union CResult_InvoiceSignOrCreationErrorZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning_invoice::Invoice,
	/// A pointer to the contents in the error state.
	/// Reading from this pointer when `result_ok` is set is undefined.
	pub err: *mut crate::lightning_invoice::SignOrCreationError,
}
#[repr(C)]
/// A CResult_InvoiceSignOrCreationErrorZ represents the result of a fallible operation,
/// containing a crate::lightning_invoice::Invoice on success and a crate::lightning_invoice::SignOrCreationError on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_InvoiceSignOrCreationErrorZ {
	/// The contents of this CResult_InvoiceSignOrCreationErrorZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_InvoiceSignOrCreationErrorZPtr,
	/// Whether this CResult_InvoiceSignOrCreationErrorZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_InvoiceSignOrCreationErrorZ in the success state.
pub extern "C" fn CResult_InvoiceSignOrCreationErrorZ_ok(o: crate::lightning_invoice::Invoice) -> CResult_InvoiceSignOrCreationErrorZ {
	CResult_InvoiceSignOrCreationErrorZ {
		contents: CResult_InvoiceSignOrCreationErrorZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceSignOrCreationErrorZ in the error state.
pub extern "C" fn CResult_InvoiceSignOrCreationErrorZ_err(e: crate::lightning_invoice::SignOrCreationError) -> CResult_InvoiceSignOrCreationErrorZ {
	CResult_InvoiceSignOrCreationErrorZ {
		contents: CResult_InvoiceSignOrCreationErrorZPtr {
			err: Box::into_raw(Box::new(e)),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_InvoiceSignOrCreationErrorZ_is_ok(o: &CResult_InvoiceSignOrCreationErrorZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_InvoiceSignOrCreationErrorZ.
pub extern "C" fn CResult_InvoiceSignOrCreationErrorZ_free(_res: CResult_InvoiceSignOrCreationErrorZ) { }
impl Drop for CResult_InvoiceSignOrCreationErrorZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
			if unsafe { !(self.contents.err as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.err) };
			}
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, crate::lightning_invoice::SignOrCreationError>> for CResult_InvoiceSignOrCreationErrorZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning_invoice::Invoice, crate::lightning_invoice::SignOrCreationError>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_InvoiceSignOrCreationErrorZPtr { result }
		} else {
			let err = unsafe { o.contents.err };
			unsafe { o.contents.err = std::ptr::null_mut(); }
			CResult_InvoiceSignOrCreationErrorZPtr { err }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
impl Clone for CResult_InvoiceSignOrCreationErrorZ {
	fn clone(&self) -> Self {
		if self.result_ok {
			Self { result_ok: true, contents: CResult_InvoiceSignOrCreationErrorZPtr {
				result: Box::into_raw(Box::new(<crate::lightning_invoice::Invoice>::clone(unsafe { &*self.contents.result })))
			} }
		} else {
			Self { result_ok: false, contents: CResult_InvoiceSignOrCreationErrorZPtr {
				err: Box::into_raw(Box::new(<crate::lightning_invoice::SignOrCreationError>::clone(unsafe { &*self.contents.err })))
			} }
		}
	}
}
#[no_mangle]
/// Creates a new CResult_InvoiceSignOrCreationErrorZ which has the same data as `orig`
/// but with all dynamically-allocated buffers duplicated in new buffers.
pub extern "C" fn CResult_InvoiceSignOrCreationErrorZ_clone(orig: &CResult_InvoiceSignOrCreationErrorZ) -> CResult_InvoiceSignOrCreationErrorZ { Clone::clone(&orig) }
#[repr(C)]
/// An enum which can either contain a crate::lightning::chain::Filter or not
pub enum COption_FilterZ {
	/// When we're in this state, this COption_FilterZ contains a crate::lightning::chain::Filter
	Some(crate::lightning::chain::Filter),
	/// When we're in this state, this COption_FilterZ contains nothing
	None
}
impl COption_FilterZ {
	#[allow(unused)] pub(crate) fn is_some(&self) -> bool {
		if let Self::None = self { false } else { true }
	}
	#[allow(unused)] pub(crate) fn is_none(&self) -> bool {
		!self.is_some()
	}
	#[allow(unused)] pub(crate) fn take(mut self) -> crate::lightning::chain::Filter {
		if let Self::Some(v) = self { v } else { unreachable!() }
	}
}
#[no_mangle]
/// Constructs a new COption_FilterZ containing a crate::lightning::chain::Filter
pub extern "C" fn COption_FilterZ_some(o: crate::lightning::chain::Filter) -> COption_FilterZ {
	COption_FilterZ::Some(o)
}
#[no_mangle]
/// Constructs a new COption_FilterZ containing nothing
pub extern "C" fn COption_FilterZ_none() -> COption_FilterZ {
	COption_FilterZ::None
}
#[no_mangle]
/// Frees any resources associated with the crate::lightning::chain::Filter, if we are in the Some state
pub extern "C" fn COption_FilterZ_free(_res: COption_FilterZ) { }
#[repr(C)]
/// The contents of CResult_LockedChannelMonitorNoneZ
pub union CResult_LockedChannelMonitorNoneZPtr {
	/// A pointer to the contents in the success state.
	/// Reading from this pointer when `result_ok` is not set is undefined.
	pub result: *mut crate::lightning::chain::chainmonitor::LockedChannelMonitor,
	/// Note that this value is always NULL, as there are no contents in the Err variant
	pub err: *mut std::ffi::c_void,
}
#[repr(C)]
/// A CResult_LockedChannelMonitorNoneZ represents the result of a fallible operation,
/// containing a crate::lightning::chain::chainmonitor::LockedChannelMonitor on success and a () on failure.
/// `result_ok` indicates the overall state, and the contents are provided via `contents`.
pub struct CResult_LockedChannelMonitorNoneZ {
	/// The contents of this CResult_LockedChannelMonitorNoneZ, accessible via either
	/// `err` or `result` depending on the state of `result_ok`.
	pub contents: CResult_LockedChannelMonitorNoneZPtr,
	/// Whether this CResult_LockedChannelMonitorNoneZ represents a success state.
	pub result_ok: bool,
}
#[no_mangle]
/// Creates a new CResult_LockedChannelMonitorNoneZ in the success state.
pub extern "C" fn CResult_LockedChannelMonitorNoneZ_ok(o: crate::lightning::chain::chainmonitor::LockedChannelMonitor) -> CResult_LockedChannelMonitorNoneZ {
	CResult_LockedChannelMonitorNoneZ {
		contents: CResult_LockedChannelMonitorNoneZPtr {
			result: Box::into_raw(Box::new(o)),
		},
		result_ok: true,
	}
}
#[no_mangle]
/// Creates a new CResult_LockedChannelMonitorNoneZ in the error state.
pub extern "C" fn CResult_LockedChannelMonitorNoneZ_err() -> CResult_LockedChannelMonitorNoneZ {
	CResult_LockedChannelMonitorNoneZ {
		contents: CResult_LockedChannelMonitorNoneZPtr {
			err: std::ptr::null_mut(),
		},
		result_ok: false,
	}
}
/// Checks if the given object is currently in the success state
#[no_mangle]
pub extern "C" fn CResult_LockedChannelMonitorNoneZ_is_ok(o: &CResult_LockedChannelMonitorNoneZ) -> bool {
	o.result_ok
}
#[no_mangle]
/// Frees any resources used by the CResult_LockedChannelMonitorNoneZ.
pub extern "C" fn CResult_LockedChannelMonitorNoneZ_free(_res: CResult_LockedChannelMonitorNoneZ) { }
impl Drop for CResult_LockedChannelMonitorNoneZ {
	fn drop(&mut self) {
		if self.result_ok {
			if unsafe { !(self.contents.result as *mut ()).is_null() } {
				let _ = unsafe { Box::from_raw(self.contents.result) };
			}
		} else {
		}
	}
}
impl From<crate::c_types::CResultTempl<crate::lightning::chain::chainmonitor::LockedChannelMonitor, ()>> for CResult_LockedChannelMonitorNoneZ {
	fn from(mut o: crate::c_types::CResultTempl<crate::lightning::chain::chainmonitor::LockedChannelMonitor, ()>) -> Self {
		let contents = if o.result_ok {
			let result = unsafe { o.contents.result };
			unsafe { o.contents.result = std::ptr::null_mut() };
			CResult_LockedChannelMonitorNoneZPtr { result }
		} else {
			let _ = unsafe { Box::from_raw(o.contents.err) };
			o.contents.err = std::ptr::null_mut();
			CResult_LockedChannelMonitorNoneZPtr { err: std::ptr::null_mut() }
		};
		Self {
			contents,
			result_ok: o.result_ok,
		}
	}
}
#[repr(C)]
/// A dynamically-allocated array of crate::lightning::chain::transaction::OutPoints of arbitrary size.
/// This corresponds to std::vector in C++
pub struct CVec_OutPointZ {
	/// The elements in the array.
	/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().
	pub data: *mut crate::lightning::chain::transaction::OutPoint,
	/// The number of elements pointed to by `data`.
	pub datalen: usize
}
impl CVec_OutPointZ {
	#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<crate::lightning::chain::transaction::OutPoint> {
		if self.datalen == 0 { return Vec::new(); }
		let ret = unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }.into();
		self.data = std::ptr::null_mut();
		self.datalen = 0;
		ret
	}
	#[allow(unused)] pub(crate) fn as_slice(&self) -> &[crate::lightning::chain::transaction::OutPoint] {
		unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) }
	}
}
impl From<Vec<crate::lightning::chain::transaction::OutPoint>> for CVec_OutPointZ {
	fn from(v: Vec<crate::lightning::chain::transaction::OutPoint>) -> Self {
		let datalen = v.len();
		let data = Box::into_raw(v.into_boxed_slice());
		Self { datalen, data: unsafe { (*data).as_mut_ptr() } }
	}
}
#[no_mangle]
/// Frees the buffer pointed to by `data` if `datalen` is non-0.
pub extern "C" fn CVec_OutPointZ_free(_res: CVec_OutPointZ) { }
impl Drop for CVec_OutPointZ {
	fn drop(&mut self) {
		if self.datalen == 0 { return; }
		unsafe { Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) };
	}
}
impl Clone for CVec_OutPointZ {
	fn clone(&self) -> Self {
		let mut res = Vec::new();
		if self.datalen == 0 { return Self::from(res); }
		res.extend_from_slice(unsafe { std::slice::from_raw_parts_mut(self.data, self.datalen) });
		Self::from(res)
	}
}
