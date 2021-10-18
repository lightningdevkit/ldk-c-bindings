// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Structs and impls for receiving messages about the network and storing the topology live here.

use std::str::FromStr;
use std::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;

pub mod network_graph;
pub mod router;
pub mod scorer;
/// An interface used to score payment channels for path finding.
///
///\tScoring is in terms of fees willing to be paid in order to avoid routing through a channel.
#[repr(C)]
pub struct Score {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Returns the fee in msats willing to be paid to avoid routing through the given channel.
	#[must_use]
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64) -> u64,
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Score {}
unsafe impl Sync for Score {}
#[no_mangle]
pub(crate) extern "C" fn Score_clone_fields(orig: &Score) -> Score {
	Score {
		this_arg: orig.this_arg,
		channel_penalty_msat: Clone::clone(&orig.channel_penalty_msat),
		free: Clone::clone(&orig.free),
	}
}

use lightning::routing::Score as rustScore;
impl rustScore for Score {
	fn channel_penalty_msat(&self, mut short_channel_id: u64) -> u64 {
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id);
		ret
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Score {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Score_free(this_ptr: Score) { }
impl Drop for Score {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
