// This file is Copyright its original authors, visible in version control
// history and in the source files from which this was generated.
//
// This file is licensed under the license available in the LICENSE or LICENSE.md
// file in the root of this repository or, if no such file exists, the same
// license as that which applies to the original source files from which this
// source was automatically generated.

//! C Bindings
#![allow(unknown_lints)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_parens)]
#![allow(unused_unsafe)]
#![allow(unused_braces)]
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(not(any(feature = "std", feature = "no-std")))]
compile_error!("at least one of the `std` or `no-std` features must be enabled");
extern crate alloc;
pub mod version;
pub mod c_types;
pub mod bitcoin;
pub mod lightning;
pub mod lightning_persister;
pub mod lightning_background_processor;
pub mod lightning_invoice;
pub mod lightning_rapid_gossip_sync;
