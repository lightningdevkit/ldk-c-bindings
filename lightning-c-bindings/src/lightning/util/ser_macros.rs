// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! Some macros that implement [`Readable`]/[`Writeable`] traits for lightning messages.
//! They also handle serialization and deserialization of TLVs.
//!
//! [`Readable`]: crate::util::ser::Readable
//! [`Writeable`]: crate::util::ser::Writeable

use alloc::str::FromStr;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature="no-std")]
use alloc::{vec::Vec, boxed::Box};
