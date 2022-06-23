// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

/// Error types that these functions can return

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// All-encompassing standard error type that processing can return
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum GraphSyncError {
	/// Error trying to read the update data, typically due to an erroneous data length indication
	/// that is greater than the actual amount of data provided
	DecodeError(
		crate::lightning::ln::msgs::DecodeError),
	/// Error applying the patch to the network graph, usually the result of updates that are too
	/// old or missing prerequisite data to the application of updates out of order
	LightningError(
		crate::lightning::ln::msgs::LightningError),
}
use lightning_rapid_gossip_sync::error::GraphSyncError as GraphSyncErrorImport;
pub(crate) type nativeGraphSyncError = GraphSyncErrorImport;

impl GraphSyncError {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeGraphSyncError {
		match self {
			GraphSyncError::DecodeError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativeGraphSyncError::DecodeError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
			GraphSyncError::LightningError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				nativeGraphSyncError::LightningError (
					*unsafe { Box::from_raw(a_nonref.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeGraphSyncError {
		match self {
			GraphSyncError::DecodeError (mut a, ) => {
				nativeGraphSyncError::DecodeError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
			GraphSyncError::LightningError (mut a, ) => {
				nativeGraphSyncError::LightningError (
					*unsafe { Box::from_raw(a.take_inner()) },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeGraphSyncError) -> Self {
		match native {
			nativeGraphSyncError::DecodeError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				GraphSyncError::DecodeError (
					crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
			nativeGraphSyncError::LightningError (ref a, ) => {
				let mut a_nonref = (*a).clone();
				GraphSyncError::LightningError (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a_nonref), is_owned: true },
				)
			},
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeGraphSyncError) -> Self {
		match native {
			nativeGraphSyncError::DecodeError (mut a, ) => {
				GraphSyncError::DecodeError (
					crate::lightning::ln::msgs::DecodeError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
			nativeGraphSyncError::LightningError (mut a, ) => {
				GraphSyncError::LightningError (
					crate::lightning::ln::msgs::LightningError { inner: ObjOps::heap_alloc(a), is_owned: true },
				)
			},
		}
	}
}
/// Frees any resources used by the GraphSyncError
#[no_mangle]
pub extern "C" fn GraphSyncError_free(this_ptr: GraphSyncError) { }
/// Creates a copy of the GraphSyncError
#[no_mangle]
pub extern "C" fn GraphSyncError_clone(orig: &GraphSyncError) -> GraphSyncError {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new DecodeError-variant GraphSyncError
pub extern "C" fn GraphSyncError_decode_error(a: crate::lightning::ln::msgs::DecodeError) -> GraphSyncError {
	GraphSyncError::DecodeError(a, )
}
#[no_mangle]
/// Utility method to constructs a new LightningError-variant GraphSyncError
pub extern "C" fn GraphSyncError_lightning_error(a: crate::lightning::ln::msgs::LightningError) -> GraphSyncError {
	GraphSyncError::LightningError(a, )
}
