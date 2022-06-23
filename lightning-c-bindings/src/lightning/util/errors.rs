// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Error types live here.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// Indicates an error on the client's part (usually some variant of attempting to use too-low or
/// too-high values)
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum APIError {
	/// Indicates the API was wholly misused (see err for more). Cases where these can be returned
	/// are documented, but generally indicates some precondition of a function was violated.
	APIMisuseError {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// Due to a high feerate, we were unable to complete the request.
	/// For example, this may be returned if the feerate implies we cannot open a channel at the
	/// requested value, but opening a larger channel would succeed.
	FeeRateTooHigh {
		/// A human-readable error message
		err: crate::c_types::Str,
		/// The feerate which was too high.
		feerate: u32,
	},
	/// A malformed Route was provided (eg overflowed value, node id mismatch, overly-looped route,
	/// too-many-hops, etc).
	RouteError {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// We were unable to complete the request as the Channel required to do so is unable to
	/// complete the request (or was not found). This can take many forms, including disconnected
	/// peer, channel at capacity, channel shutting down, etc.
	ChannelUnavailable {
		/// A human-readable error message
		err: crate::c_types::Str,
	},
	/// An attempt to call watch/update_channel returned an Err (ie you did this!), causing the
	/// attempted action to fail.
	MonitorUpdateFailed,
	/// [`KeysInterface::get_shutdown_scriptpubkey`] returned a shutdown scriptpubkey incompatible
	/// with the channel counterparty as negotiated in [`InitFeatures`].
	///
	/// Using a SegWit v0 script should resolve this issue. If you cannot, you won't be able to open
	/// a channel or cooperatively close one with this peer (and will have to force-close instead).
	///
	/// [`KeysInterface::get_shutdown_scriptpubkey`]: crate::chain::keysinterface::KeysInterface::get_shutdown_scriptpubkey
	/// [`InitFeatures`]: crate::ln::features::InitFeatures
	IncompatibleShutdownScript {
		/// The incompatible shutdown script.
		script: crate::lightning::ln::script::ShutdownScript,
	},
}
use lightning::util::errors::APIError as APIErrorImport;
pub(crate) type nativeAPIError = APIErrorImport;

impl APIError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeAPIError {
		match self {
			APIError::APIMisuseError {ref err, } => {
				let mut err_nonref = (*err).clone();
				nativeAPIError::APIMisuseError {
					err: err_nonref.into_string(),
				}
			},
			APIError::FeeRateTooHigh {ref err, ref feerate, } => {
				let mut err_nonref = (*err).clone();
				let mut feerate_nonref = (*feerate).clone();
				nativeAPIError::FeeRateTooHigh {
					err: err_nonref.into_string(),
					feerate: feerate_nonref,
				}
			},
			APIError::RouteError {ref err, } => {
				let mut err_nonref = (*err).clone();
				nativeAPIError::RouteError {
					err: err_nonref.into_str(),
				}
			},
			APIError::ChannelUnavailable {ref err, } => {
				let mut err_nonref = (*err).clone();
				nativeAPIError::ChannelUnavailable {
					err: err_nonref.into_string(),
				}
			},
			APIError::MonitorUpdateFailed => nativeAPIError::MonitorUpdateFailed,
			APIError::IncompatibleShutdownScript {ref script, } => {
				let mut script_nonref = (*script).clone();
				nativeAPIError::IncompatibleShutdownScript {
					script: *unsafe { Box::from_raw(script_nonref.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeAPIError {
		match self {
			APIError::APIMisuseError {mut err, } => {
				nativeAPIError::APIMisuseError {
					err: err.into_string(),
				}
			},
			APIError::FeeRateTooHigh {mut err, mut feerate, } => {
				nativeAPIError::FeeRateTooHigh {
					err: err.into_string(),
					feerate: feerate,
				}
			},
			APIError::RouteError {mut err, } => {
				nativeAPIError::RouteError {
					err: err.into_str(),
				}
			},
			APIError::ChannelUnavailable {mut err, } => {
				nativeAPIError::ChannelUnavailable {
					err: err.into_string(),
				}
			},
			APIError::MonitorUpdateFailed => nativeAPIError::MonitorUpdateFailed,
			APIError::IncompatibleShutdownScript {mut script, } => {
				nativeAPIError::IncompatibleShutdownScript {
					script: *unsafe { Box::from_raw(script.take_inner()) },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeAPIError) -> Self {
		match native {
			nativeAPIError::APIMisuseError {ref err, } => {
				let mut err_nonref = (*err).clone();
				APIError::APIMisuseError {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::FeeRateTooHigh {ref err, ref feerate, } => {
				let mut err_nonref = (*err).clone();
				let mut feerate_nonref = (*feerate).clone();
				APIError::FeeRateTooHigh {
					err: err_nonref.into(),
					feerate: feerate_nonref,
				}
			},
			nativeAPIError::RouteError {ref err, } => {
				let mut err_nonref = (*err).clone();
				APIError::RouteError {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::ChannelUnavailable {ref err, } => {
				let mut err_nonref = (*err).clone();
				APIError::ChannelUnavailable {
					err: err_nonref.into(),
				}
			},
			nativeAPIError::MonitorUpdateFailed => APIError::MonitorUpdateFailed,
			nativeAPIError::IncompatibleShutdownScript {ref script, } => {
				let mut script_nonref = (*script).clone();
				APIError::IncompatibleShutdownScript {
					script: crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(script_nonref), is_owned: true },
				}
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeAPIError) -> Self {
		match native {
			nativeAPIError::APIMisuseError {mut err, } => {
				APIError::APIMisuseError {
					err: err.into(),
				}
			},
			nativeAPIError::FeeRateTooHigh {mut err, mut feerate, } => {
				APIError::FeeRateTooHigh {
					err: err.into(),
					feerate: feerate,
				}
			},
			nativeAPIError::RouteError {mut err, } => {
				APIError::RouteError {
					err: err.into(),
				}
			},
			nativeAPIError::ChannelUnavailable {mut err, } => {
				APIError::ChannelUnavailable {
					err: err.into(),
				}
			},
			nativeAPIError::MonitorUpdateFailed => APIError::MonitorUpdateFailed,
			nativeAPIError::IncompatibleShutdownScript {mut script, } => {
				APIError::IncompatibleShutdownScript {
					script: crate::lightning::ln::script::ShutdownScript { inner: ObjOps::heap_alloc(script), is_owned: true },
				}
			},
		}
	}
}
/// Frees any resources used by the APIError
#[no_mangle]
pub extern "C" fn APIError_free(this_ptr: APIError) { }
/// Creates a copy of the APIError
#[no_mangle]
pub extern "C" fn APIError_clone(orig: &APIError) -> APIError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new APIMisuseError-variant APIError
pub extern "C" fn APIError_apimisuse_error(err: crate::c_types::Str) -> APIError {
	APIError::APIMisuseError {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new FeeRateTooHigh-variant APIError
pub extern "C" fn APIError_fee_rate_too_high(err: crate::c_types::Str, feerate: u32) -> APIError {
	APIError::FeeRateTooHigh {
		err,
		feerate,
	}
}
#[no_mangle]
/// Utility method to constructs a new RouteError-variant APIError
pub extern "C" fn APIError_route_error(err: crate::c_types::Str) -> APIError {
	APIError::RouteError {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new ChannelUnavailable-variant APIError
pub extern "C" fn APIError_channel_unavailable(err: crate::c_types::Str) -> APIError {
	APIError::ChannelUnavailable {
		err,
	}
}
#[no_mangle]
/// Utility method to constructs a new MonitorUpdateFailed-variant APIError
pub extern "C" fn APIError_monitor_update_failed() -> APIError {
	APIError::MonitorUpdateFailed}
#[no_mangle]
/// Utility method to constructs a new IncompatibleShutdownScript-variant APIError
pub extern "C" fn APIError_incompatible_shutdown_script(script: crate::lightning::ln::script::ShutdownScript) -> APIError {
	APIError::IncompatibleShutdownScript {
		script,
	}
}
