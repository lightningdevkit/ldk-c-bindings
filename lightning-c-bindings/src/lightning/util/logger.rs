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

use std::str::FromStr;
use std::ffi::c_void;
use bitcoin::hashes::Hash;
use crate::c_types::*;

/// An enum representing the available verbosity levels of the logger.
#[must_use]
#[derive(Clone)]
#[repr(C)]
pub enum Level {
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
use lightning::util::logger::Level as nativeLevel;
impl Level {
	#[allow(unused)]
	pub(crate) fn to_native(&self) -> nativeLevel {
		match self {
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
/// Checks if two Levels contain equal inner contents.
/// This ignores pointers and is_owned flags and looks at the values in fields.
#[no_mangle]
pub extern "C" fn Level_eq(a: &Level, b: &Level) -> bool {
	if &a.to_native() == &b.to_native() { true } else { false }
}
/// Checks if two Levels contain equal inner contents.
#[no_mangle]
pub extern "C" fn Level_hash(o: &Level) -> u64 {
	// Note that we'd love to use std::collections::hash_map::DefaultHasher but it's not in core
	#[allow(deprecated)]
	let mut hasher = core::hash::SipHasher::new();
	std::hash::Hash::hash(&o.to_native(), &mut hasher);
	std::hash::Hasher::finish(&hasher)
}
/// Returns the most verbose logging level.
#[must_use]
#[no_mangle]
pub extern "C" fn Level_max() -> crate::lightning::util::logger::Level {
	let mut ret = lightning::util::logger::Level::max();
	crate::lightning::util::logger::Level::native_into(ret)
}

/// A trait encapsulating the operations required of a logger
#[repr(C)]
pub struct Logger {
	/// An opaque pointer which is passed to your function implementations as an argument.
	/// This has no meaning in the LDK, and can be NULL or any other value.
	pub this_arg: *mut c_void,
	/// Logs the `Record`
	pub log: extern "C" fn (this_arg: *const c_void, record: *const std::os::raw::c_char),
	/// Frees any resources associated with this object given its this_arg pointer.
	/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.
	pub free: Option<extern "C" fn(this_arg: *mut c_void)>,
}
unsafe impl Send for Logger {}
unsafe impl Sync for Logger {}

use lightning::util::logger::Logger as rustLogger;
impl rustLogger for Logger {
	fn log(&self, mut record: &lightning::util::logger::Record) {
		let mut local_record = std::ffi::CString::new(format!("{}", record.args)).unwrap();
		(self.log)(self.this_arg, local_record.as_ptr())
	}
}

// We're essentially a pointer already, or at least a set of pointers, so allow us to be used
// directly as a Deref trait in higher-level structs:
impl std::ops::Deref for Logger {
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
