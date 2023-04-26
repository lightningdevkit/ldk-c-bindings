// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Utilities which allow users to block on some future notification from LDK. These are
//! specifically used by [`ChannelManager`] to allow waiting until the [`ChannelManager`] needs to
//! be re-persisted.
//!
//! [`ChannelManager`]: crate::ln::channelmanager::ChannelManager

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// A callback which is called when a [`Future`] completes.
///
/// Note that this MUST NOT call back into LDK directly, it must instead schedule actions to be
/// taken later. Rust users should use the [`std::future::Future`] implementation for [`Future`]
/// instead.
///
/// Note that the [`std::future::Future`] implementation may only work for runtimes which schedule
/// futures when they receive a wake, rather than immediately executing them.
#[repr(C)]
pub struct FutureCallback {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// The method which is called.
	pub call: extern "C" fn (this_arg: *const c_void),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for FutureCallback {}
unsafe impl Sync for FutureCallback {}
#[no_mangle]
pub(crate) extern "C" fn FutureCallback_clone_fields(orig: &FutureCallback) -> FutureCallback {
	FutureCallback {
		this_arg: orig.this_arg,
		call: Clone::clone(&orig.call),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::wakers::FutureCallback as rustFutureCallback;
impl rustFutureCallback for FutureCallback {
	fn call(&self) {
		(self.call)(self.this_arg)
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for FutureCallback {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn FutureCallback_free(this_ptr: FutureCallback) { }
impl Drop for FutureCallback {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}

use lightning::util::wakers::Future as nativeFutureImport;
pub(crate) type nativeFuture = nativeFutureImport;

/// A simple future which can complete once, and calls some callback(s) when it does so.
///
/// Clones can be made and all futures cloned from the same source will complete at the same time.
#[must_use]
#[repr(C)]
pub struct Future {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeFuture,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Future {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeFuture>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Future, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Future_free(this_obj: Future) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Future_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeFuture) };
}
#[allow(unused)]
impl Future {
	pub(crate) fn get_native_ref(&self) -> &'static nativeFuture {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeFuture {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeFuture {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
impl Clone for Future {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeFuture>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Future_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeFuture)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Future
pub extern "C" fn Future_clone(orig: &Future) -> Future {
	orig.clone()
}
/// Registers a callback to be called upon completion of this future. If the future has already
/// completed, the callback will be called immediately.
#[no_mangle]
pub extern "C" fn Future_register_callback_fn(this_arg: &crate::lightning::util::wakers::Future, mut callback: crate::lightning::util::wakers::FutureCallback) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.register_callback_fn(callback)
}

/// Waits until this [`Future`] completes.
#[no_mangle]
pub extern "C" fn Future_wait(mut this_arg: crate::lightning::util::wakers::Future) {
	(*unsafe { Box::from_raw(this_arg.take_inner()) }).wait()
}

/// Waits until this [`Future`] completes or the given amount of time has elapsed.
///
/// Returns true if the [`Future`] completed, false if the time elapsed.
#[must_use]
#[no_mangle]
pub extern "C" fn Future_wait_timeout(mut this_arg: crate::lightning::util::wakers::Future, mut max_wait: u64) -> bool {
	let mut ret = (*unsafe { Box::from_raw(this_arg.take_inner()) }).wait_timeout(core::time::Duration::from_secs(max_wait));
	ret
}


use lightning::util::wakers::Sleeper as nativeSleeperImport;
pub(crate) type nativeSleeper = nativeSleeperImport;

/// A struct which can be used to select across many [`Future`]s at once without relying on a full
/// async context.
#[must_use]
#[repr(C)]
pub struct Sleeper {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeSleeper,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Sleeper {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeSleeper>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Sleeper, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Sleeper_free(this_obj: Sleeper) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Sleeper_free_void(this_ptr: *mut c_void) {
	let _ = unsafe { Box::from_raw(this_ptr as *mut nativeSleeper) };
}
#[allow(unused)]
impl Sleeper {
	pub(crate) fn get_native_ref(&self) -> &'static nativeSleeper {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeSleeper {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeSleeper {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// Constructs a new sleeper from one future, allowing blocking on it.
#[must_use]
#[no_mangle]
pub extern "C" fn Sleeper_from_single_future(mut future: crate::lightning::util::wakers::Future) -> crate::lightning::util::wakers::Sleeper {
	let mut ret = lightning::util::wakers::Sleeper::from_single_future(*unsafe { Box::from_raw(future.take_inner()) });
	crate::lightning::util::wakers::Sleeper { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Constructs a new sleeper from two futures, allowing blocking on both at once.
#[must_use]
#[no_mangle]
pub extern "C" fn Sleeper_from_two_futures(mut fut_a: crate::lightning::util::wakers::Future, mut fut_b: crate::lightning::util::wakers::Future) -> crate::lightning::util::wakers::Sleeper {
	let mut ret = lightning::util::wakers::Sleeper::from_two_futures(*unsafe { Box::from_raw(fut_a.take_inner()) }, *unsafe { Box::from_raw(fut_b.take_inner()) });
	crate::lightning::util::wakers::Sleeper { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Constructs a new sleeper on many futures, allowing blocking on all at once.
#[must_use]
#[no_mangle]
pub extern "C" fn Sleeper_new(mut futures: crate::c_types::derived::CVec_FutureZ) -> crate::lightning::util::wakers::Sleeper {
	let mut local_futures = Vec::new(); for mut item in futures.into_rust().drain(..) { local_futures.push( { *unsafe { Box::from_raw(item.take_inner()) } }); };
	let mut ret = lightning::util::wakers::Sleeper::new(local_futures);
	crate::lightning::util::wakers::Sleeper { inner: ObjOps::heap_alloc(ret), is_owned: true }
}

/// Wait until one of the [`Future`]s registered with this [`Sleeper`] has completed.
#[no_mangle]
pub extern "C" fn Sleeper_wait(this_arg: &crate::lightning::util::wakers::Sleeper) {
	unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.wait()
}

/// Wait until one of the [`Future`]s registered with this [`Sleeper`] has completed or the
/// given amount of time has elapsed. Returns true if a [`Future`] completed, false if the time
/// elapsed.
#[must_use]
#[no_mangle]
pub extern "C" fn Sleeper_wait_timeout(this_arg: &crate::lightning::util::wakers::Sleeper, mut max_wait: u64) -> bool {
	let mut ret = unsafe { &*ObjOps::untweak_ptr(this_arg.inner) }.wait_timeout(core::time::Duration::from_secs(max_wait));
	ret
}

