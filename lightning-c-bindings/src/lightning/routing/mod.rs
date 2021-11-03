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
	/// Returns the fee in msats willing to be paid to avoid routing through the given channel
	/// in the direction from `source` to `target`.
	#[must_use]
	pub channel_penalty_msat: extern "C" fn (this_arg: *const c_void, short_channel_id: u64, source: &crate::lightning::routing::network_graph::NodeId, target: &crate::lightning::routing::network_graph::NodeId) -> u64,
	/// Handles updating channel penalties after failing to route through a channel.
	pub payment_path_failed: extern "C" fn (this_arg: *mut c_void, path: crate::c_types::derived::CVec_RouteHopZ, short_channel_id: u64),
	/// Serialize the object into a byte array
	pub write: extern "C" fn (this_arg: *const c_void) -> crate::c_types::derived::CVec_u8Z,
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
		payment_path_failed: Clone::clone(&orig.payment_path_failed),
		write: Clone::clone(&orig.write),
		free: Clone::clone(&orig.free),
	}
}
impl lightning::util::ser::Writeable for Score {
	fn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {
		let vec = (self.write)(self.this_arg);
		w.write_all(vec.as_slice())
	}
}

use lightning::routing::Score as rustScore;
impl rustScore for Score {
	fn channel_penalty_msat(&self, mut short_channel_id: u64, mut source: &lightning::routing::network_graph::NodeId, mut target: &lightning::routing::network_graph::NodeId) -> u64 {
		let mut ret = (self.channel_penalty_msat)(self.this_arg, short_channel_id, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((source as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false }, &crate::lightning::routing::network_graph::NodeId { inner: unsafe { ObjOps::nonnull_ptr_to_inner((target as *const lightning::routing::network_graph::NodeId<>) as *mut _) }, is_owned: false });
		ret
	}
	fn payment_path_failed(&mut self, mut path: &[&lightning::routing::router::RouteHop], mut short_channel_id: u64) {
		let mut local_path = Vec::new(); for item in path.iter() { local_path.push( { crate::lightning::routing::router::RouteHop { inner: unsafe { ObjOps::nonnull_ptr_to_inner(((*item) as *const lightning::routing::router::RouteHop<>) as *mut _) }, is_owned: false } }); };
		(self.payment_path_failed)(self.this_arg, local_path.into(), short_channel_id)
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

use lightning::routing::LockableScore as nativeLockableScoreImport;
pub(crate) type nativeLockableScore = nativeLockableScoreImport<crate::lightning::routing::Score>;

/// A scorer that is accessed under a lock.
///
/// Needed so that calls to [`Score::channel_penalty_msat`] in [`find_route`] can be made while
/// having shared ownership of a scorer but without requiring internal locking in [`Score`]
/// implementations. Internal locking would be detrimental to route finding performance and could
/// result in [`Score::channel_penalty_msat`] returning a different value for the same channel.
///
/// [`find_route`]: crate::routing::router::find_route
#[must_use]
#[repr(C)]
pub struct LockableScore {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeLockableScore,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for LockableScore {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeLockableScore>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the LockableScore, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn LockableScore_free(this_obj: LockableScore) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn LockableScore_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeLockableScore); }
}
#[allow(unused)]
impl LockableScore {
	pub(crate) fn get_native_ref(&self) -> &'static nativeLockableScore {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeLockableScore {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeLockableScore {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = std::ptr::null_mut();
		ret
	}
}
/// Constructs a new LockableScore from a Score
#[must_use]
#[no_mangle]
pub extern "C" fn LockableScore_new(mut score: crate::lightning::routing::Score) -> LockableScore {
	let mut ret = lightning::routing::LockableScore::new(score);
	LockableScore { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

#[no_mangle]
/// Serialize the LockableScore object into a byte array which can be read by LockableScore_read
pub extern "C" fn LockableScore_write(obj: &LockableScore) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*obj }.get_native_ref())
}
#[no_mangle]
pub(crate) extern "C" fn LockableScore_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {
	crate::c_types::serialize_obj(unsafe { &*(obj as *const nativeLockableScore) })
}
