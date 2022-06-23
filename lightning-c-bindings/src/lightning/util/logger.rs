// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Log traits live here, which are called throughout the library to provide useful information for
//! debugging purposes.
//!
//! There is currently 2 ways to filter log messages. First one, by using compilation features, e.g \"max_level_off\".
//! The second one, client-side by implementing check against Record Level field.
//! Each module may have its own Logger or share one.

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};

/// An enum representing the available verbosity levels of the logger.
#[derive(Clone)]
#[must_use]
#[repr(C)]
pub enum Level {
	/// Designates extremely verbose information, including gossip-induced messages
	Gossip,
	/// Designates very low priority, often extremely verbose, information
	Trace,
	/// Designates lower priority information
	Debug,
	/// Designates useful information
	Info,
	/// Designates hazardous situations
	Warn,
	/// Designates very serious errors
	Error,
}
use lightning::util::logger::Level as LevelImport;
pub(crate) type nativeLevel = LevelImport;

impl Level {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLevel {
		match self {
			Level::Gossip => nativeLevel::Gossip,
			Level::Trace => nativeLevel::Trace,
			Level::Debug => nativeLevel::Debug,
			Level::Info => nativeLevel::Info,
			Level::Warn => nativeLevel::Warn,
			Level::Error => nativeLevel::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn into_native(self) -> nativeLevel {
		match self {
			Level::Gossip => nativeLevel::Gossip,
			Level::Trace => nativeLevel::Trace,
			Level::Debug => nativeLevel::Debug,
			Level::Info => nativeLevel::Info,
			Level::Warn => nativeLevel::Warn,
			Level::Error => nativeLevel::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn from_native(native: &nativeLevel) -> Self {
		match native {
			nativeLevel::Gossip => Level::Gossip,
			nativeLevel::Trace => Level::Trace,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Info => Level::Info,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Error => Level::Error,
		}
	}
	#[allow(unused)]
	pub(crate) fn native_into(native: nativeLevel) -> Self {
		match native {
			nativeLevel::Gossip => Level::Gossip,
			nativeLevel::Trace => Level::Trace,
			nativeLevel::Debug => Level::Debug,
			nativeLevel::Info => Level::Info,
			nativeLevel::Warn => Level::Warn,
			nativeLevel::Error => Level::Error,
		}
	}
}
/// Creates a copy of the Level
#[no_mangle]
pub extern "C" fn Level_clone(orig: &Level) -> Level {
	orig.clone()
}
#[no_mangle]
/// Utility method to constructs a new Gossip-variant Level
pub extern "C" fn Level_gossip() -> Level {
	Level::Gossip}
#[no_mangle]
/// Utility method to constructs a new Trace-variant Level
pub extern "C" fn Level_trace() -> Level {
	Level::Trace}
#[no_mangle]
/// Utility method to constructs a new Debug-variant Level
pub extern "C" fn Level_debug() -> Level {
	Level::Debug}
#[no_mangle]
/// Utility method to constructs a new Info-variant Level
pub extern "C" fn Level_info() -> Level {
	Level::Info}
#[no_mangle]
/// Utility method to constructs a new Warn-variant Level
pub extern "C" fn Level_warn() -> Level {
	Level::Warn}
#[no_mangle]
/// Utility method to constructs a new Error-variant Level
pub extern "C" fn Level_error() -> Level {
	Level::Error}
/// Checks if two Levels contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Level_eq(a: &Level, b: &Level) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Checks if two Levels contain equal inner contents.
#[no_mangle]
pub extern "C" fn Level_hash(o: &Level) -> u64 {
	// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	core::hash::Hash::hash(&o.to_native(), &mut hasher);
	core::hash::Hasher::finish(&hasher)
}
/// Returns the most verbose logging level.
#[must_use]
#[no_mangle]
pub extern "C" fn Level_max() -> crate::lightning::util::logger::Level {
	let mut ret = lightning::util::logger::Level::max();
	crate::lightning::util::logger::Level::native_into(ret)
}


use lightning::util::logger::Record as nativeRecordImport;
pub(crate) type nativeRecord = nativeRecordImport<'static>;

/// A Record, unit of logging output with Metadata to enable filtering
/// Module_path, file, line to inform on log's source
#[must_use]
#[repr(C)]
pub struct Record {
	/// A pointer to the opaque Rust object.

	/// Nearly everywhere, inner must be non-null, however in places where
	/// the Rust equivalent takes an Option, it may be set to null to indicate None.
	pub inner: *mut nativeRecord,
	/// Indicates that this is the only struct which contains the same pointer.

	/// Rust functions which take ownership of an object provided via an argument require
	/// this to be true and invalidate the object pointed to by inner.
	pub is_owned: bool,
}

impl Drop for Record {
	fn drop(&mut self) {
		if self.is_owned && !<*mut nativeRecord>::is_null(self.inner) {
			let _ = unsafe { Box::from_raw(ObjOps::untweak_ptr(self.inner)) };
		}
	}
}
/// Frees any resources used by the Record, if is_owned is set and inner is non-NULL.
#[no_mangle]
pub extern "C" fn Record_free(this_obj: Record) { }
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Record_free_void(this_ptr: *mut c_void) {
	unsafe { let _ = Box::from_raw(this_ptr as *mut nativeRecord); }
}
#[allow(unused)]
impl Record {
	pub(crate) fn get_native_ref(&self) -> &'static nativeRecord {
		unsafe { &*ObjOps::untweak_ptr(self.inner) }
	}
	pub(crate) fn get_native_mut_ref(&self) -> &'static mut nativeRecord {
		unsafe { &mut *ObjOps::untweak_ptr(self.inner) }
	}
	/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy
	pub(crate) fn take_inner(mut self) -> *mut nativeRecord {
		assert!(self.is_owned);
		let ret = ObjOps::untweak_ptr(self.inner);
		self.inner = core::ptr::null_mut();
		ret
	}
}
/// The verbosity level of the message.
#[no_mangle]
pub extern "C" fn Record_get_level(this_ptr: &Record) -> crate::lightning::util::logger::Level {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().level;
	crate::lightning::util::logger::Level::from_native(inner_val)
}
/// The verbosity level of the message.
#[no_mangle]
pub extern "C" fn Record_set_level(this_ptr: &mut Record, mut val: crate::lightning::util::logger::Level) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.level = val.into_native();
}
/// The message body.
#[no_mangle]
pub extern "C" fn Record_get_args(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().args;
	inner_val.as_str().into()
}
/// The message body.
#[no_mangle]
pub extern "C" fn Record_set_args(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.args = val.into_string();
}
/// The module path of the message.
#[no_mangle]
pub extern "C" fn Record_get_module_path(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().module_path;
	inner_val.into()
}
/// The module path of the message.
#[no_mangle]
pub extern "C" fn Record_set_module_path(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.module_path = val.into_str();
}
/// The source file containing the message.
#[no_mangle]
pub extern "C" fn Record_get_file(this_ptr: &Record) -> crate::c_types::Str {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().file;
	inner_val.into()
}
/// The source file containing the message.
#[no_mangle]
pub extern "C" fn Record_set_file(this_ptr: &mut Record, mut val: crate::c_types::Str) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.file = val.into_str();
}
/// The line containing the message.
#[no_mangle]
pub extern "C" fn Record_get_line(this_ptr: &Record) -> u32 {
	let mut inner_val = &mut this_ptr.get_native_mut_ref().line;
	*inner_val
}
/// The line containing the message.
#[no_mangle]
pub extern "C" fn Record_set_line(this_ptr: &mut Record, mut val: u32) {
	unsafe { &mut *ObjOps::untweak_ptr(this_ptr.inner) }.line = val;
}
impl Clone for Record {
	fn clone(&self) -> Self {
		Self {
			inner: if <*mut nativeRecord>::is_null(self.inner) { core::ptr::null_mut() } else {
				ObjOps::heap_alloc(unsafe { &*ObjOps::untweak_ptr(self.inner) }.clone()) },
			is_owned: true,
		}
	}
}
#[allow(unused)]
/// Used only if an object of this type is returned as a trait impl by a method
pub(crate) extern "C" fn Record_clone_void(this_ptr: *const c_void) -> *mut c_void {
	Box::into_raw(Box::new(unsafe { (*(this_ptr as *mut nativeRecord)).clone() })) as *mut c_void
}
#[no_mangle]
/// Creates a copy of the Record
pub extern "C" fn Record_clone(orig: &Record) -> Record {
	orig.clone()
}
/// A trait encapsulating the operations required of a logger
#[repr(C)]
pub struct Logger {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Logs the `Record`
	pub log: extern "C" fn (this_arg: *const c_void, record: &crate::lightning::util::logger::Record),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}
#[no_mangle]
pub(crate) extern "C" fn Logger_clone_fields(orig: &Logger) -> Logger {
	Logger {
		this_arg: orig.this_arg,
		log: Clone::clone(&orig.log),
		free: Clone::clone(&orig.free),
	}
}

use lightning::util::logger::Logger as rustLogger;
impl rustLogger for Logger {
	fn log(&self, mut record: &lightning::util::logger::Record) {
		(self.log)(self.this_arg, &crate::lightning::util::logger::Record { inner: unsafe { ObjOps::nonnull_ptr_to_inner((record as *const lightning::util::logger::Record<'_, >) as *mut _) }, is_owned: false })
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl core::ops::Deref for Logger {
	type Target = Self;
	fn deref(&self) -> &Self {
		self
	}
}
/// Calls the free function if one is set
#[no_mangle]
pub extern "C" fn Logger_free(this_ptr: Logger) { }
impl Drop for Logger {
	fn drop(&mut self) {
		if let Some(f) = self.free {
			f(self.this_arg);
		}
	}
}
