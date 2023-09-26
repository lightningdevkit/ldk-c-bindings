// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Converts a rust crate into a rust crate containing a number of C-exported wrapper functions and
//! classes (which is exportable using cbindgen).
//! In general, supports convering:
//!  * structs as a pointer to the underlying type (either owned or not owned),
//!  * traits as a void-ptr plus a jump table,
//!  * enums as an equivalent enum with all the inner fields mapped to the mapped types,
//!  * certain containers (tuples, slices, Vecs, Options, and Results currently) to a concrete
//!    version of a defined container template.
//!
//! It also generates relevant memory-management functions and free-standing functions with
//! parameters mapped.

use std::collections::{HashMap, hash_map, HashSet};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::iter::FromIterator;
use std::process;

use proc_macro2::Span;
use quote::format_ident;
use syn::parse_quote;

mod types;
mod blocks;
use types::*;
use blocks::*;

const DEFAULT_IMPORTS: &'static str = "
use alloc::str::FromStr;
use alloc::string::String;
use core::ffi::c_void;
use core::convert::Infallible;
use bitcoin::hashes::Hash;
use crate::c_types::*;
#[cfg(feature=\"no-std\")]
use alloc::{vec::Vec, boxed::Box};
";


/// str.rsplit_once but with an older MSRV
fn rsplit_once<'a>(inp: &'a str, pattern: &str) -> Option<(&'a str, &'a str)> {
	let mut iter = inp.rsplitn(2, pattern);
	let second_entry = iter.next().unwrap();
	Some((iter.next().unwrap(), second_entry))
}

// *************************************
// *** Manually-expanded conversions ***
// *************************************

/// Convert "impl trait_path for for_ty { .. }" for manually-mapped types (ie (de)serialization)
fn maybe_convert_trait_impl<W: std::io::Write>(w: &mut W, trait_path: &syn::Path, for_ty: &syn::Type, types: &mut TypeResolver, generics: &GenericTypes) {
	if let Some(t) = types.maybe_resolve_path(&trait_path, Some(generics)) {
		let for_obj;
		let full_obj_path;
		let mut has_inner = false;
		if let syn::Type::Path(ref p) = for_ty {
			let resolved_path = types.resolve_path(&p.path, Some(generics));
			for_obj = format!("{}", p.path.segments.last().unwrap().ident);
			full_obj_path = format!("crate::{}", resolved_path);
			has_inner = types.c_type_has_inner_from_path(&resolved_path);
		} else {
			// We assume that anything that isn't a Path is somehow a generic that ends up in our
			// derived-types module.
			let mut for_obj_vec = Vec::new();
			types.write_c_type(&mut for_obj_vec, for_ty, Some(generics), false);
			full_obj_path = String::from_utf8(for_obj_vec).unwrap();
			if !full_obj_path.starts_with(TypeResolver::generated_container_path()) { return; }
			for_obj = full_obj_path[TypeResolver::generated_container_path().len() + 2..].into();
		}

		match &t as &str {
			"lightning::util::ser::Writeable" => {
				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "/// Serialize the {} object into a byte array which can be read by {}_read", for_obj, for_obj).unwrap();
				writeln!(w, "pub extern \"C\" fn {}_write(obj: &{}) -> crate::c_types::derived::CVec_u8Z {{", for_obj, full_obj_path).unwrap();

				let ref_type: syn::Type = syn::parse_quote!(&#for_ty);
				assert!(!types.write_from_c_conversion_new_var(w, &format_ident!("obj"), &ref_type, Some(generics)));

				write!(w, "\tcrate::c_types::serialize_obj(").unwrap();
				types.write_from_c_conversion_prefix(w, &ref_type, Some(generics));
				write!(w, "unsafe {{ &*obj }}").unwrap();
				types.write_from_c_conversion_suffix(w, &ref_type, Some(generics));
				writeln!(w, ")").unwrap();

				writeln!(w, "}}").unwrap();
				if has_inner {
					writeln!(w, "#[no_mangle]").unwrap();
					writeln!(w, "pub(crate) extern \"C\" fn {}_write_void(obj: *const c_void) -> crate::c_types::derived::CVec_u8Z {{", for_obj).unwrap();
					writeln!(w, "\tcrate::c_types::serialize_obj(unsafe {{ &*(obj as *const native{}) }})", for_obj).unwrap();
					writeln!(w, "}}").unwrap();
				}
			},
			"lightning::util::ser::Readable"|"lightning::util::ser::ReadableArgs"|"lightning::util::ser::MaybeReadable" => {
				// Create the Result<Object, DecodeError> syn::Type
				let mut res_ty: syn::Type = parse_quote!(Result<#for_ty, lightning::ln::msgs::DecodeError>);

				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "/// Read a {} from a byte array, created by {}_write", for_obj, for_obj).unwrap();
				write!(w, "pub extern \"C\" fn {}_read(ser: crate::c_types::u8slice", for_obj).unwrap();

				let mut arg_conv = Vec::new();
				if t == "lightning::util::ser::ReadableArgs" {
					assert!(trait_path.leading_colon.is_none());
					let args_seg = trait_path.segments.iter().last().unwrap();
					assert_eq!(format!("{}", args_seg.ident), "ReadableArgs");
					if let syn::PathArguments::AngleBracketed(args) = &args_seg.arguments {
						assert_eq!(args.args.len(), 1);
						if let syn::GenericArgument::Type(args_ty) = args.args.iter().next().unwrap() {
							macro_rules! write_arg_conv {
								($ty: expr, $arg_name: expr) => {
									write!(w, ", {}: ", $arg_name).unwrap();
									types.write_c_type(w, $ty, Some(generics), false);

									write!(&mut arg_conv, "\t").unwrap();
									if types.write_from_c_conversion_new_var(&mut arg_conv, &format_ident!("{}", $arg_name), &$ty, Some(generics)) {
										write!(&mut arg_conv, "\n\t").unwrap();
									}

									write!(&mut arg_conv, "let {}_conv = ", $arg_name).unwrap();
									types.write_from_c_conversion_prefix(&mut arg_conv, &$ty, Some(generics));
									write!(&mut arg_conv, "{}", $arg_name).unwrap();
									types.write_from_c_conversion_suffix(&mut arg_conv, &$ty, Some(generics));
									write!(&mut arg_conv, ";\n").unwrap();
								}
							}

							if let syn::Type::Tuple(tup) = args_ty {
								// Crack open tuples and make them separate arguments instead of
								// converting the full tuple. This makes it substantially easier to
								// reason about things like references in the tuple fields.
								let mut arg_conv_res = Vec::new();
								for (idx, elem) in tup.elems.iter().enumerate() {
									let arg_name = format!("arg_{}", ('a' as u8 + idx as u8) as char);
									write_arg_conv!(elem, arg_name);
									write!(&mut arg_conv_res, "{}_conv{}", arg_name, if idx != tup.elems.len() - 1 { ", " } else { "" }).unwrap();
								}
								writeln!(&mut arg_conv, "\tlet arg_conv = ({});", String::from_utf8(arg_conv_res).unwrap()).unwrap();
							} else {
								write_arg_conv!(args_ty, "arg");
							}
						} else { unreachable!(); }
					} else { unreachable!(); }
				} else if t == "lightning::util::ser::MaybeReadable" {
					res_ty = parse_quote!(Result<Option<#for_ty>, lightning::ln::msgs::DecodeError>);
				}
				write!(w, ") -> ").unwrap();
				types.write_c_type(w, &res_ty, Some(generics), false);
				writeln!(w, " {{").unwrap();

				if t == "lightning::util::ser::ReadableArgs" {
					w.write(&arg_conv).unwrap();
				}

				write!(w, "\tlet res: ").unwrap();
				// At least in one case we need type annotations here, so provide them.
				types.write_rust_type(w, Some(generics), &res_ty, false);

				if t == "lightning::util::ser::ReadableArgs" {
					writeln!(w, " = crate::c_types::deserialize_obj_arg(ser, arg_conv);").unwrap();
				} else if t == "lightning::util::ser::MaybeReadable" {
					writeln!(w, " = crate::c_types::maybe_deserialize_obj(ser);").unwrap();
				} else {
					writeln!(w, " = crate::c_types::deserialize_obj(ser);").unwrap();
				}
				write!(w, "\t").unwrap();
				if types.write_to_c_conversion_new_var(w, &format_ident!("res"), &res_ty, Some(generics), false) {
					write!(w, "\n\t").unwrap();
				}
				types.write_to_c_conversion_inline_prefix(w, &res_ty, Some(generics), false);
				write!(w, "res").unwrap();
				types.write_to_c_conversion_inline_suffix(w, &res_ty, Some(generics), false);
				writeln!(w, "\n}}").unwrap();
			},
			_ => {},
		}
	}
}

/// Convert "TraitA : TraitB" to a single function name and return type.
///
/// This is (obviously) somewhat over-specialized and only useful for TraitB's that only require a
/// single function (eg for serialization).
fn convert_trait_impl_field(trait_path: &str) -> (&'static str, String, &'static str) {
	match trait_path {
		"lightning::util::ser::Writeable" => ("Serialize the object into a byte array", "write".to_owned(), "crate::c_types::derived::CVec_u8Z"),
		_ => unimplemented!(),
	}
}

/// Companion to convert_trait_impl_field, write an assignment for the function defined by it for
/// `for_obj` which implements the the trait at `trait_path`.
fn write_trait_impl_field_assign<W: std::io::Write>(w: &mut W, trait_path: &str, for_obj: &syn::Ident) {
	match trait_path {
		"lightning::util::ser::Writeable" => {
			writeln!(w, "\t\twrite: {}_write_void,", for_obj).unwrap();
		},
		_ => unimplemented!(),
	}
}

/// Write out the impl block for a defined trait struct which has a supertrait
fn do_write_impl_trait<W: std::io::Write>(w: &mut W, trait_path: &str, _trait_name: &syn::Ident, for_obj: &str) {
	match trait_path {
		"lightning::util::ser::Writeable" => {
			writeln!(w, "impl {} for {} {{", trait_path, for_obj).unwrap();
			writeln!(w, "\tfn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), crate::c_types::io::Error> {{").unwrap();
			writeln!(w, "\t\tlet vec = (self.write)(self.this_arg);").unwrap();
			writeln!(w, "\t\tw.write_all(vec.as_slice())").unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		_ => panic!(),
	}
}

/// Returns true if an instance of the given type must never exist
fn is_type_unconstructable(path: &str) -> bool {
	path == "core::convert::Infallible" || path == "crate::c_types::NotConstructable"
}

// *******************************
// *** Per-Type Printing Logic ***
// *******************************

macro_rules! walk_supertraits { ($t: expr, $types: expr, ($( $($pat: pat)|* => $e: expr),*) ) => { {
	if $t.colon_token.is_some() {
		for st in $t.supertraits.iter() {
			match st {
				syn::TypeParamBound::Trait(supertrait) => {
					if supertrait.paren_token.is_some() || supertrait.lifetimes.is_some() {
						unimplemented!();
					}
					// First try to resolve path to find in-crate traits, but if that doesn't work
					// assume its a prelude trait (eg Clone, etc) and just use the single ident.
					let types_opt: Option<&TypeResolver> = $types;
					if let Some(types) = types_opt {
						if let Some(path) = types.maybe_resolve_path(&supertrait.path, None) {
							let last_seg = supertrait.path.segments.iter().last().unwrap();
							match (&path as &str, &last_seg.ident, &last_seg.arguments) {
								$( $($pat)|* => $e, )*
							}
							continue;
						}
					}
					if let Some(ident) = supertrait.path.get_ident() {
						match (&format!("{}", ident) as &str, &ident, &syn::PathArguments::None) {
							$( $($pat)|* => $e, )*
						}
					} else if types_opt.is_some() {
						panic!("Supertrait unresolvable and not single-ident");
					}
				},
				syn::TypeParamBound::Lifetime(_) => unimplemented!(),
			}
		}
	}
} } }

macro_rules! get_module_type_resolver {
	($module: expr, $crate_libs: expr, $crate_types: expr) => { {
		let module: &str = &$module;
		let mut module_iter = module.rsplitn(2, "::");
		module_iter.next().unwrap();
		let module = module_iter.next().unwrap();
		let imports = ImportResolver::new(module.splitn(2, "::").next().unwrap(), &$crate_types.lib_ast,
				module, &$crate_types.lib_ast.modules.get(module).unwrap().items);
		TypeResolver::new(module, imports, $crate_types)
	} }
}

/// Prints a C-mapped trait object containing a void pointer and a jump table for each function in
/// the original trait.
/// Implements the native Rust trait and relevant parent traits for the new C-mapped trait.
///
/// Finally, implements Deref<MappedTrait> for MappedTrait which allows its use in types which need
/// a concrete Deref to the Rust trait.
fn writeln_trait<'a, 'b, W: std::io::Write>(w: &mut W, t: &'a syn::ItemTrait, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	let trait_name = format!("{}", t.ident);
	let implementable;
	match export_status(&t.attrs) {
		ExportStatus::Export => { implementable = true; }
		ExportStatus::NotImplementable => { implementable = false; },
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}
	writeln_docs(w, &t.attrs, "");

	let mut gen_types = GenericTypes::new(Some(format!("{}::{}", types.module_path, trait_name)));

	// Add functions which may be required for supertrait implementations.
	// Due to borrow checker limitations, we only support one in-crate supertrait here.
	let supertrait_name;
	let supertrait_resolver;
	walk_supertraits!(t, Some(&types), (
		(s, _i, _) => {
			if let Some(supertrait) = types.crate_types.traits.get(s) {
				supertrait_name = s.to_string();
				supertrait_resolver = get_module_type_resolver!(supertrait_name, types.crate_libs, types.crate_types);
				gen_types.learn_associated_types(&supertrait, &supertrait_resolver);
				break;
			}
		}
	) );

	assert!(gen_types.learn_generics(&t.generics, types));
	gen_types.learn_associated_types(&t, types);

	writeln!(w, "#[repr(C)]\npub struct {} {{", trait_name).unwrap();
	writeln!(w, "\t/// An opaque pointer which is passed to your function implementations as an argument.").unwrap();
	writeln!(w, "\t/// This has no meaning in the LDK, and can be NULL or any other value.").unwrap();
	writeln!(w, "\tpub this_arg: *mut c_void,").unwrap();
	// We store every field's (name, Option<clone_fn>, docs) except this_arg, used in Clone generation
	// docs is only set if its a function which should be callable on the object itself in C++
	let mut generated_fields = Vec::new();
	for item in t.items.iter() {
		match item {
			&syn::TraitItem::Method(ref m) => {
				match export_status(&m.attrs) {
					ExportStatus::NoExport => {
						// NoExport in this context means we'll hit an unimplemented!() at runtime,
						// so bail out.
						unimplemented!();
					},
					ExportStatus::Export => {},
					ExportStatus::TestOnly => continue,
					ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
				}

				let mut meth_gen_types = gen_types.push_ctx();
				assert!(meth_gen_types.learn_generics(&m.sig.generics, types));

				writeln_fn_docs(w, &m.attrs, "\t", types, Some(&meth_gen_types), m.sig.inputs.iter(), &m.sig.output);

				if let syn::ReturnType::Type(_, rtype) = &m.sig.output {
					if let syn::Type::Reference(r) = &**rtype {
						// We have to do quite a dance for trait functions which return references
						// - they ultimately require us to have a native Rust object stored inside
						// our concrete trait to return a reference to. However, users may wish to
						// update the value to be returned each time the function is called (or, to
						// make C copies of Rust impls equivalent, we have to be able to).
						//
						// Thus, we store a copy of the C-mapped type (which is just a pointer to
						// the Rust type and a flag to indicate whether deallocation needs to
						// happen) as well as provide an Option<>al function pointer which is
						// called when the trait method is called which allows updating on the fly.
						write!(w, "\tpub {}: core::cell::UnsafeCell<", m.sig.ident).unwrap();
						generated_fields.push((format!("{}", m.sig.ident), Some(("Clone::clone(unsafe { &*core::cell::UnsafeCell::get(".to_owned(), ")}).into()")), None));
						types.write_c_type(w, &*r.elem, Some(&meth_gen_types), false);
						writeln!(w, ">,").unwrap();
						writeln!(w, "\t/// Fill in the {} field as a reference to it will be given to Rust after this returns", m.sig.ident).unwrap();
						writeln!(w, "\t/// Note that this takes a pointer to this object, not the this_ptr like other methods do").unwrap();
						writeln!(w, "\t/// This function pointer may be NULL if {} is filled in when this object is created and never needs updating.", m.sig.ident).unwrap();
						writeln!(w, "\tpub set_{}: Option<extern \"C\" fn(&{})>,", m.sig.ident, trait_name).unwrap();
						generated_fields.push((format!("set_{}", m.sig.ident), None, None));
						// Note that cbindgen will now generate
						// typedef struct Thing {..., set_thing: (const struct Thing*), ...} Thing;
						// which does not compile since Thing is not defined before it is used.
						writeln!(extra_headers, "struct LDK{};", trait_name).unwrap();
						continue;
					}
				}

				let mut cpp_docs = Vec::new();
				writeln_fn_docs(&mut cpp_docs, &m.attrs, "\t * ", types, Some(&meth_gen_types), m.sig.inputs.iter(), &m.sig.output);
				let docs_string = "\t/**\n".to_owned() + &String::from_utf8(cpp_docs).unwrap().replace("///", "") + "\t */\n";

				write!(w, "\tpub {}: extern \"C\" fn (", m.sig.ident).unwrap();
				generated_fields.push((format!("{}", m.sig.ident), None, Some(docs_string)));
				write_method_params(w, &m.sig, "c_void", types, Some(&meth_gen_types), true, false);
				writeln!(w, ",").unwrap();
			},
			&syn::TraitItem::Type(_) => {},
			_ => unimplemented!(),
		}
	}
	// Add functions which may be required for supertrait implementations.
	walk_supertraits!(t, Some(&types), (
		("Clone", _, _) => {
			writeln!(w, "\t/// Called, if set, after this {} has been cloned into a duplicate object.", trait_name).unwrap();
			writeln!(w, "\t/// The new {} is provided, and should be mutated as needed to perform a", trait_name).unwrap();
			writeln!(w, "\t/// deep copy of the object pointed to by this_arg or avoid any double-freeing.").unwrap();
			writeln!(w, "\tpub cloned: Option<extern \"C\" fn (new_{}: &mut {})>,", trait_name, trait_name).unwrap();
			generated_fields.push(("cloned".to_owned(), None, None));
		},
		("std::cmp::Eq", _, _)|("core::cmp::Eq", _, _) => {
			let eq_docs = "Checks if two objects are equal given this object's this_arg pointer and another object.";
			writeln!(w, "\t/// {}", eq_docs).unwrap();
			writeln!(w, "\tpub eq: extern \"C\" fn (this_arg: *const c_void, other_arg: &{}) -> bool,", trait_name).unwrap();
			generated_fields.push(("eq".to_owned(), None, Some(format!("\t/** {} */\n", eq_docs))));
		},
		("std::hash::Hash", _, _)|("core::hash::Hash", _, _) => {
			let hash_docs_a = "Calculate a succinct non-cryptographic hash for an object given its this_arg pointer.";
			let hash_docs_b = "This is used, for example, for inclusion of this object in a hash map.";
			writeln!(w, "\t/// {}", hash_docs_a).unwrap();
			writeln!(w, "\t/// {}", hash_docs_b).unwrap();
			writeln!(w, "\tpub hash: extern \"C\" fn (this_arg: *const c_void) -> u64,").unwrap();
			generated_fields.push(("hash".to_owned(), None,
				Some(format!("\t/**\n\t * {}\n\t * {}\n\t */\n", hash_docs_a, hash_docs_b))));
		},
		("Send", _, _) => {}, ("Sync", _, _) => {},
		("std::fmt::Debug", _, _)|("core::fmt::Debug", _, _) => {
			let debug_docs = "Return a human-readable \"debug\" string describing this object";
			writeln!(w, "\t/// {}", debug_docs).unwrap();
			writeln!(w, "\tpub debug_str: extern \"C\" fn (this_arg: *const c_void) -> crate::c_types::Str,").unwrap();
			generated_fields.push(("debug_str".to_owned(), None,
				Some(format!("\t/**\n\t * {}\n\t */\n", debug_docs))));
		},
		(s, i, _) => {
			// TODO: Both of the below should expose supertrait methods in C++, but doing so is
			// nontrivial.
			generated_fields.push(if types.crate_types.traits.get(s).is_none() {
				let (docs, name, ret) = convert_trait_impl_field(s);
				writeln!(w, "\t/// {}", docs).unwrap();
				writeln!(w, "\tpub {}: extern \"C\" fn (this_arg: *const c_void) -> {},", name, ret).unwrap();
				(name, None, None) // Assume clonable
			} else {
				// For in-crate supertraits, just store a C-mapped copy of the supertrait as a member.
				writeln!(w, "\t/// Implementation of {} for this object.", i).unwrap();
				let is_clonable = types.is_clonable(s);
				writeln!(w, "\tpub {}: crate::{},", i, s).unwrap();
				(format!("{}", i), if !is_clonable {
					Some((format!("crate::{}_clone_fields(", s), ")"))
				} else { None }, None)
			});
		}
	) );
	writeln!(w, "\t/// Frees any resources associated with this object given its this_arg pointer.").unwrap();
	writeln!(w, "\t/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.").unwrap();
	writeln!(w, "\tpub free: Option<extern \"C\" fn(this_arg: *mut c_void)>,").unwrap();
	generated_fields.push(("free".to_owned(), None, None));
	writeln!(w, "}}").unwrap();

	macro_rules! impl_trait_for_c {
		($t: expr, $impl_accessor: expr, $type_resolver: expr, $generic_impls: expr) => {
			let mut trait_gen_types = gen_types.push_ctx();
			assert!(trait_gen_types.learn_generics_with_impls(&$t.generics, $generic_impls, $type_resolver));
			for item in $t.items.iter() {
				match item {
					syn::TraitItem::Method(m) => {
						if let ExportStatus::TestOnly = export_status(&m.attrs) { continue; }
						if m.sig.constness.is_some() || m.sig.asyncness.is_some() || m.sig.unsafety.is_some() ||
								m.sig.abi.is_some() || m.sig.variadic.is_some() {
							panic!("1");
						}
						let mut meth_gen_types = trait_gen_types.push_ctx();
						assert!(meth_gen_types.learn_generics(&m.sig.generics, $type_resolver));
						// Note that we do *not* use the method generics when printing "native"
						// rust parts - if the method is generic, we need to print a generic
						// method.
						write!(w, "\tfn {}", m.sig.ident).unwrap();
						$type_resolver.write_rust_generic_param(w, Some(&gen_types), m.sig.generics.params.iter());
						write!(w, "(").unwrap();
						for inp in m.sig.inputs.iter() {
							match inp {
								syn::FnArg::Receiver(recv) => {
									if !recv.attrs.is_empty() || recv.reference.is_none() { panic!("2"); }
									write!(w, "&").unwrap();
									if let Some(lft) = &recv.reference.as_ref().unwrap().1 {
										write!(w, "'{} ", lft.ident).unwrap();
									}
									if recv.mutability.is_some() {
										write!(w, "mut self").unwrap();
									} else {
										write!(w, "self").unwrap();
									}
								},
								syn::FnArg::Typed(arg) => {
									if !arg.attrs.is_empty() { panic!("3"); }
									match &*arg.pat {
										syn::Pat::Ident(ident) => {
											if !ident.attrs.is_empty() || ident.by_ref.is_some() ||
													ident.mutability.is_some() || ident.subpat.is_some() {
												panic!("4");
											}
											write!(w, ", mut {}{}: ", if $type_resolver.skip_arg(&*arg.ty, Some(&meth_gen_types)) { "_" } else { "" }, ident.ident).unwrap();
										}
										_ => panic!("5"),
									}
									$type_resolver.write_rust_type(w, Some(&gen_types), &*arg.ty, false);
								}
							}
						}
						write!(w, ")").unwrap();
						match &m.sig.output {
							syn::ReturnType::Type(_, rtype) => {
								write!(w, " -> ").unwrap();
								$type_resolver.write_rust_type(w, Some(&gen_types), &*rtype, false)
							},
							_ => {},
						}
						write!(w, " {{\n\t\t").unwrap();
						match export_status(&m.attrs) {
							ExportStatus::NoExport => {
								panic!("6");
							},
							_ => {},
						}
						if let syn::ReturnType::Type(_, rtype) = &m.sig.output {
							if let syn::Type::Reference(r) = &**rtype {
								assert_eq!(m.sig.inputs.len(), 1); // Must only take self!
								writeln!(w, "if let Some(f) = self{}.set_{} {{", $impl_accessor, m.sig.ident).unwrap();
								writeln!(w, "\t\t\t(f)(&self{});", $impl_accessor).unwrap();
								write!(w, "\t\t}}\n\t\t").unwrap();
								$type_resolver.write_from_c_conversion_to_ref_prefix(w, &*r.elem, Some(&meth_gen_types));
								write!(w, "unsafe {{ &*self{}.{}.get() }}", $impl_accessor, m.sig.ident).unwrap();
								$type_resolver.write_from_c_conversion_to_ref_suffix(w, &*r.elem, Some(&meth_gen_types));
								writeln!(w, "\n\t}}").unwrap();
								continue;
							}
						}
						write_method_var_decl_body(w, &m.sig, "\t", $type_resolver, Some(&meth_gen_types), true);
						write!(w, "(self{}.{})(", $impl_accessor, m.sig.ident).unwrap();
						let mut args = Vec::new();
						write_method_call_params(&mut args, &m.sig, "\t", $type_resolver, Some(&meth_gen_types), "", true);
						w.write_all(String::from_utf8(args).unwrap().replace("self", &format!("self{}", $impl_accessor)).as_bytes()).unwrap();

						writeln!(w, "\n\t}}").unwrap();
					},
					&syn::TraitItem::Type(ref t) => {
						if t.default.is_some() || t.generics.lt_token.is_some() { panic!("10"); }
						let mut bounds_iter = t.bounds.iter();
						loop {
							match bounds_iter.next().unwrap() {
								syn::TypeParamBound::Trait(tr) => {
									writeln!(w, "\ttype {} = crate::{};", t.ident, $type_resolver.resolve_path(&tr.path, Some(&gen_types))).unwrap();
									for bound in bounds_iter {
										if let syn::TypeParamBound::Trait(t) = bound {
											// We only allow for `Sized` here.
											assert_eq!(t.path.segments.len(), 1);
											assert_eq!(format!("{}", t.path.segments[0].ident), "Sized");
										}
									}
									break;
								},
								syn::TypeParamBound::Lifetime(_) => {},
							}
						}
					},
					_ => panic!("12"),
				}
			}
		}
	}

	writeln!(w, "unsafe impl Send for {} {{}}", trait_name).unwrap();
	writeln!(w, "unsafe impl Sync for {} {{}}", trait_name).unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "pub(crate) extern \"C\" fn {}_clone_fields(orig: &{}) -> {} {{", trait_name, trait_name, trait_name).unwrap();
	writeln!(w, "\t{} {{", trait_name).unwrap();
	writeln!(w, "\t\tthis_arg: orig.this_arg,").unwrap();
	for (field, clone_fn, _) in generated_fields.iter() {
		if let Some((pfx, sfx)) = clone_fn {
			// If the field isn't clonable, blindly assume its a trait and hope for the best.
			writeln!(w, "\t\t{}: {}&orig.{}{},", field, pfx, field, sfx).unwrap();
		} else {
			writeln!(w, "\t\t{}: Clone::clone(&orig.{}),", field, field).unwrap();
		}
	}
	writeln!(w, "\t}}\n}}").unwrap();

	// Implement supertraits for the C-mapped struct.
	walk_supertraits!(t, Some(&types), (
		("std::cmp::Eq", _, _)|("core::cmp::Eq", _, _) => {
			writeln!(w, "impl core::cmp::Eq for {} {{}}", trait_name).unwrap();
			writeln!(w, "impl core::cmp::PartialEq for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn eq(&self, o: &Self) -> bool {{ (self.eq)(self.this_arg, o) }}\n}}").unwrap();
		},
		("std::hash::Hash", _, _)|("core::hash::Hash", _, _) => {
			writeln!(w, "impl core::hash::Hash for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn hash<H: core::hash::Hasher>(&self, hasher: &mut H) {{ hasher.write_u64((self.hash)(self.this_arg)) }}\n}}").unwrap();
		},
		("Send", _, _) => {}, ("Sync", _, _) => {},
		("Clone", _, _) => {
			writeln!(w, "#[no_mangle]").unwrap();
			writeln!(w, "/// Creates a copy of a {}", trait_name).unwrap();
			writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", trait_name, trait_name, trait_name).unwrap();
			writeln!(w, "\tlet mut res = {}_clone_fields(orig);", trait_name).unwrap();
			writeln!(w, "\tif let Some(f) = orig.cloned {{ (f)(&mut res) }};").unwrap();
			writeln!(w, "\tres\n}}").unwrap();
			writeln!(w, "impl Clone for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
			writeln!(w, "\t\t{}_clone(self)", trait_name).unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		("std::fmt::Debug", _, _)|("core::fmt::Debug", _, _) => {
			writeln!(w, "impl core::fmt::Debug for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {{").unwrap();
			writeln!(w, "\t\tf.write_str((self.debug_str)(self.this_arg).into_str())").unwrap();
			writeln!(w, "\t}}").unwrap();
			writeln!(w, "}}").unwrap();
		},
		(s, i, generic_args) => {
			if let Some(supertrait) = types.crate_types.traits.get(s) {
				let resolver = get_module_type_resolver!(s, types.crate_libs, types.crate_types);
				macro_rules! impl_supertrait {
					($s: expr, $supertrait: expr, $i: expr, $generic_args: expr) => {
						let resolver = get_module_type_resolver!($s, types.crate_libs, types.crate_types);

						// Blindly assume that the same imports where `supertrait` is defined are also
						// imported here. This will almost certainly break at some point, but it should be
						// a compilation failure when it does so.
						write!(w, "impl").unwrap();
						maybe_write_lifetime_generics(w, &$supertrait.generics, types);
						write!(w, " {}", $s).unwrap();
						maybe_write_generics(w, &$supertrait.generics, $generic_args, types, false);
						writeln!(w, " for {} {{", trait_name).unwrap();

						impl_trait_for_c!($supertrait, format!(".{}", $i), &resolver, $generic_args);
						writeln!(w, "}}").unwrap();
					}
				}
				impl_supertrait!(s, supertrait, i, generic_args);
				walk_supertraits!(supertrait, Some(&resolver), (
					(s, supertrait_i, generic_args) => {
						if let Some(supertrait) = types.crate_types.traits.get(s) {
							impl_supertrait!(s, supertrait, format!("{}.{}", i, supertrait_i), generic_args);
						}
					}
				) );
			} else {
				do_write_impl_trait(w, s, i, &trait_name);
			}
		}
	) );

	// Finally, implement the original Rust trait for the newly created mapped trait.
	writeln!(w, "\nuse {}::{} as rust{};", types.module_path, t.ident, trait_name).unwrap();
	if implementable {
		write!(w, "impl").unwrap();
		maybe_write_lifetime_generics(w, &t.generics, types);
		write!(w, " rust{}", t.ident).unwrap();
		maybe_write_generics(w, &t.generics, &syn::PathArguments::None, types, false);
		writeln!(w, " for {} {{", trait_name).unwrap();
		impl_trait_for_c!(t, "", types, &syn::PathArguments::None);
		writeln!(w, "}}\n").unwrap();
		writeln!(w, "// We're essentially a pointer already, or at least a set of pointers, so allow us to be used").unwrap();
		writeln!(w, "// directly as a Deref trait in higher-level structs:").unwrap();
		writeln!(w, "impl core::ops::Deref for {} {{\n\ttype Target = Self;", trait_name).unwrap();
		writeln!(w, "\tfn deref(&self) -> &Self {{\n\t\tself\n\t}}\n}}").unwrap();
	}

	writeln!(w, "/// Calls the free function if one is set").unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", trait_name, trait_name).unwrap();
	writeln!(w, "impl Drop for {} {{", trait_name).unwrap();
	writeln!(w, "\tfn drop(&mut self) {{").unwrap();
	writeln!(w, "\t\tif let Some(f) = self.free {{").unwrap();
	writeln!(w, "\t\t\tf(self.this_arg);").unwrap();
	writeln!(w, "\t\t}}\n\t}}\n}}").unwrap();

	write_cpp_wrapper(cpp_headers, &trait_name, true, Some(generated_fields.drain(..)
		.filter_map(|(name, _, docs)| if let Some(docs) = docs { Some((name, docs)) } else { None }).collect()));
}

/// Write out a simple "opaque" type (eg structs) which contain a pointer to the native Rust type
/// and a flag to indicate whether Drop'ing the mapped struct drops the underlying Rust type.
///
/// Also writes out a _free function and a C++ wrapper which handles calling _free.
fn writeln_opaque<W: std::io::Write>(w: &mut W, ident: &syn::Ident, struct_name: &str, generics: &syn::Generics, attrs: &[syn::Attribute], types: &TypeResolver, extra_headers: &mut File, cpp_headers: &mut File) {
	// If we directly read the original type by its original name, cbindgen hits
	// https://github.com/eqrion/cbindgen/issues/286 Thus, instead, we import it as a temporary
	// name and then reference it by that name, which works around the issue.
	write!(w, "\nuse {}::{} as native{}Import;\npub(crate) type native{} = native{}Import", types.module_path, ident, ident, ident, ident).unwrap();
	maybe_write_generics(w, &generics, &syn::PathArguments::None, &types, true);
	writeln!(w, ";\n").unwrap();
	writeln!(extra_headers, "struct native{}Opaque;\ntypedef struct native{}Opaque LDKnative{};", ident, ident, ident).unwrap();
	writeln_docs(w, &attrs, "");
	writeln!(w, "#[must_use]\n#[repr(C)]\npub struct {} {{", struct_name).unwrap();
	writeln!(w, "\t/// A pointer to the opaque Rust object.\n").unwrap();
	writeln!(w, "\t/// Nearly everywhere, inner must be non-null, however in places where").unwrap();
	writeln!(w, "\t/// the Rust equivalent takes an Option, it may be set to null to indicate None.").unwrap();
	writeln!(w, "\tpub inner: *mut native{},", ident).unwrap();
	writeln!(w, "\t/// Indicates that this is the only struct which contains the same pointer.\n").unwrap();
	writeln!(w, "\t/// Rust functions which take ownership of an object provided via an argument require").unwrap();
	writeln!(w, "\t/// this to be true and invalidate the object pointed to by inner.").unwrap();
	writeln!(w, "\tpub is_owned: bool,").unwrap();
	writeln!(w, "}}\n").unwrap();
	writeln!(w, "impl Drop for {} {{\n\tfn drop(&mut self) {{", struct_name).unwrap();
	writeln!(w, "\t\tif self.is_owned && !<*mut native{}>::is_null(self.inner) {{", ident).unwrap();
	writeln!(w, "\t\t\tlet _ = unsafe {{ Box::from_raw(ObjOps::untweak_ptr(self.inner)) }};\n\t\t}}\n\t}}\n}}").unwrap();
	writeln!(w, "/// Frees any resources used by the {}, if is_owned is set and inner is non-NULL.", struct_name).unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_obj: {}) {{ }}", struct_name, struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "/// Used only if an object of this type is returned as a trait impl by a method").unwrap();
	writeln!(w, "pub(crate) extern \"C\" fn {}_free_void(this_ptr: *mut c_void) {{", struct_name).unwrap();
	writeln!(w, "\tlet _ = unsafe {{ Box::from_raw(this_ptr as *mut native{}) }};\n}}", struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "impl {} {{", struct_name).unwrap();
	writeln!(w, "\tpub(crate) fn get_native_ref(&self) -> &'static native{} {{", struct_name).unwrap();
	writeln!(w, "\t\tunsafe {{ &*ObjOps::untweak_ptr(self.inner) }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "\tpub(crate) fn get_native_mut_ref(&self) -> &'static mut native{} {{", struct_name).unwrap();
	writeln!(w, "\t\tunsafe {{ &mut *ObjOps::untweak_ptr(self.inner) }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "\t/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy").unwrap();
	writeln!(w, "\tpub(crate) fn take_inner(mut self) -> *mut native{} {{", struct_name).unwrap();
	writeln!(w, "\t\tassert!(self.is_owned);").unwrap();
	writeln!(w, "\t\tlet ret = ObjOps::untweak_ptr(self.inner);").unwrap();
	writeln!(w, "\t\tself.inner = core::ptr::null_mut();").unwrap();
	writeln!(w, "\t\tret").unwrap();
	writeln!(w, "\t}}\n}}").unwrap();

	write_cpp_wrapper(cpp_headers, &format!("{}", ident), true, None);
}

/// Writes out all the relevant mappings for a Rust struct, deferring to writeln_opaque to generate
/// the struct itself, and then writing getters and setters for public, understood-type fields and
/// a constructor if every field is public.
fn writeln_struct<'a, 'b, W: std::io::Write>(w: &mut W, s: &'a syn::ItemStruct, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	if export_status(&s.attrs) != ExportStatus::Export { return; }

	let struct_name = &format!("{}", s.ident);
	writeln_opaque(w, &s.ident, struct_name, &s.generics, &s.attrs, types, extra_headers, cpp_headers);

	let mut self_path_segs = syn::punctuated::Punctuated::new();
	self_path_segs.push(s.ident.clone().into());
	let self_path = syn::Path { leading_colon: None, segments: self_path_segs};
	let mut gen_types = GenericTypes::new(Some(types.resolve_path(&self_path, None)));
	assert!(gen_types.learn_generics(&s.generics, types));

	let mut all_fields_settable = true;
	macro_rules! define_field {
		($new_name: expr, $real_name: expr, $field: expr) => {
			if let syn::Visibility::Public(_) = $field.vis {
				let export = export_status(&$field.attrs);
				match export {
					ExportStatus::Export => {},
					ExportStatus::NoExport|ExportStatus::TestOnly => {
						all_fields_settable = false;
						continue
					},
					ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
				}

				if let Some(ref_type) = types.create_ownable_reference(&$field.ty, Some(&gen_types)) {
					if types.understood_c_type(&ref_type, Some(&gen_types)) {
						writeln_arg_docs(w, &$field.attrs, "", types, Some(&gen_types), vec![].drain(..), Some(&ref_type));
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_get_{}(this_ptr: &{}) -> ", struct_name, $new_name, struct_name).unwrap();
						types.write_c_type(w, &ref_type, Some(&gen_types), true);
						write!(w, " {{\n\tlet mut inner_val = &mut this_ptr.get_native_mut_ref().{};\n\t", $real_name).unwrap();
						let local_var = types.write_to_c_conversion_from_ownable_ref_new_var(w, &format_ident!("inner_val"), &ref_type, Some(&gen_types));
						if local_var { write!(w, "\n\t").unwrap(); }
						types.write_to_c_conversion_inline_prefix(w, &ref_type, Some(&gen_types), true);
						write!(w, "inner_val").unwrap();
						types.write_to_c_conversion_inline_suffix(w, &ref_type, Some(&gen_types), true);
						writeln!(w, "\n}}").unwrap();
					} else {
						// If the type isn't reference-able, but is clonable, export a getter that just clones
						if types.understood_c_type(&$field.ty, Some(&gen_types)) {
							let mut v = Vec::new();
							types.write_c_type(&mut v, &$field.ty, Some(&gen_types), true);
							let s = String::from_utf8(v).unwrap();
							if types.is_clonable(&s) {
								writeln_arg_docs(w, &$field.attrs, "", types, Some(&gen_types), vec![].drain(..), Some(&$field.ty));
								writeln!(w, "///\n/// Returns a copy of the field.").unwrap();
								write!(w, "#[no_mangle]\npub extern \"C\" fn {}_get_{}(this_ptr: &{}) -> {}", struct_name, $new_name, struct_name, s).unwrap();
								write!(w, " {{\n\tlet mut inner_val = this_ptr.get_native_mut_ref().{}.clone();\n\t", $real_name).unwrap();
								let local_var = types.write_to_c_conversion_new_var(w, &format_ident!("inner_val"), &$field.ty, Some(&gen_types), true);
								if local_var { write!(w, "\n\t").unwrap(); }
								types.write_to_c_conversion_inline_prefix(w, &$field.ty, Some(&gen_types), true);
								write!(w, "inner_val").unwrap();
								types.write_to_c_conversion_inline_suffix(w, &$field.ty, Some(&gen_types), true);
								writeln!(w, "\n}}").unwrap();
							}
						}
					}
				}

				if types.understood_c_type(&$field.ty, Some(&gen_types)) {
					writeln_arg_docs(w, &$field.attrs, "", types, Some(&gen_types), vec![("val".to_owned(), &$field.ty)].drain(..), None);
					write!(w, "#[no_mangle]\npub extern \"C\" fn {}_set_{}(this_ptr: &mut {}, mut val: ", struct_name, $new_name, struct_name).unwrap();
					types.write_c_type(w, &$field.ty, Some(&gen_types), false);
					write!(w, ") {{\n\t").unwrap();
					let local_var = types.write_from_c_conversion_new_var(w, &format_ident!("val"), &$field.ty, Some(&gen_types));
					if local_var { write!(w, "\n\t").unwrap(); }
					write!(w, "unsafe {{ &mut *ObjOps::untweak_ptr(this_ptr.inner) }}.{} = ", $real_name).unwrap();
					types.write_from_c_conversion_prefix(w, &$field.ty, Some(&gen_types));
					write!(w, "val").unwrap();
					types.write_from_c_conversion_suffix(w, &$field.ty, Some(&gen_types));
					writeln!(w, ";\n}}").unwrap();
				} else { all_fields_settable = false; }
			} else { all_fields_settable = false; }
		}
	}

	match &s.fields {
		syn::Fields::Named(fields) => {
			for field in fields.named.iter() {
				if let Some(ident) = &field.ident {
					define_field!(ident, ident, field);
				} else { all_fields_settable = false; }
			}
		}
		syn::Fields::Unnamed(fields) => {
			for (idx, field) in fields.unnamed.iter().enumerate() {
				define_field!(('a' as u8 + idx as u8) as char, ('0' as u8 + idx as u8) as char, field);
			}
		}
		syn::Fields::Unit => {},
	}

	if all_fields_settable {
		// Build a constructor!
		writeln!(w, "/// Constructs a new {} given each field", struct_name).unwrap();
		write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_new(", struct_name).unwrap();

		match &s.fields {
			syn::Fields::Named(fields) => {
				for (idx, field) in fields.named.iter().enumerate() {
					if idx != 0 { write!(w, ", ").unwrap(); }
					write!(w, "mut {}_arg: ", field.ident.as_ref().unwrap()).unwrap();
					types.write_c_type(w, &field.ty, Some(&gen_types), false);
				}
			}
			syn::Fields::Unnamed(fields) => {
				for (idx, field) in fields.unnamed.iter().enumerate() {
					if idx != 0 { write!(w, ", ").unwrap(); }
					write!(w, "mut {}_arg: ", ('a' as u8 + idx as u8) as char).unwrap();
					types.write_c_type(w, &field.ty, Some(&gen_types), false);
				}
			}
			syn::Fields::Unit => {},
		}
		write!(w, ") -> {} {{\n\t", struct_name).unwrap();
		match &s.fields {
			syn::Fields::Named(fields) => {
				for field in fields.named.iter() {
					let field_ident = format_ident!("{}_arg", field.ident.as_ref().unwrap());
					if types.write_from_c_conversion_new_var(w, &field_ident, &field.ty, Some(&gen_types)) {
						write!(w, "\n\t").unwrap();
					}
				}
			},
			syn::Fields::Unnamed(fields) => {
				for (idx, field) in fields.unnamed.iter().enumerate() {
					let field_ident = format_ident!("{}_arg", ('a' as u8 + idx as u8) as char);
					if types.write_from_c_conversion_new_var(w, &field_ident, &field.ty, Some(&gen_types)) {
						write!(w, "\n\t").unwrap();
					}
				}
			},
			syn::Fields::Unit => {},
		}
		write!(w, "{} {{ inner: ObjOps::heap_alloc(", struct_name).unwrap();
		match &s.fields {
			syn::Fields::Named(fields) => {
				writeln!(w, "native{} {{", s.ident).unwrap();
				for field in fields.named.iter() {
					write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
					types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
					write!(w, "{}_arg", field.ident.as_ref().unwrap()).unwrap();
					types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
					writeln!(w, ",").unwrap();
				}
				write!(w, "\t}}").unwrap();
			},
			syn::Fields::Unnamed(fields) => {
				assert!(!s.generics.params.iter()
					.any(|gen| if let syn::GenericParam::Lifetime(_) = gen { false } else { true }));
				writeln!(w, "{} (", types.maybe_resolve_ident(&s.ident).unwrap()).unwrap();
				for (idx, field) in fields.unnamed.iter().enumerate() {
					write!(w, "\t\t").unwrap();
					types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
					write!(w, "{}_arg", ('a' as u8 + idx as u8) as char).unwrap();
					types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
					writeln!(w, ",").unwrap();
				}
				write!(w, "\t)").unwrap();
			},
			syn::Fields::Unit => write!(w, "{}::{} {{}}", types.module_path, struct_name).unwrap(),
		}
		writeln!(w, "), is_owned: true }}\n}}").unwrap();
	}
}

/// Prints a relevant conversion for impl *
///
/// For simple impl Struct {}s, this just outputs the wrapper functions as Struct_fn_name() { .. }.
///
/// For impl Trait for Struct{}s, this non-exported generates wrapper functions as
/// Trait_Struct_fn_name and a Struct_as_Trait(&struct) -> Trait function which returns a populated
/// Trait struct containing a pointer to the passed struct's inner field and the wrapper functions.
///
/// A few non-crate Traits are hard-coded including Default.
fn writeln_impl<W: std::io::Write>(w: &mut W, w_uses: &mut HashSet<String, NonRandomHash>, i: &syn::ItemImpl, types: &mut TypeResolver) {
	match export_status(&i.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
		ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
	}

	if let syn::Type::Tuple(_) = &*i.self_ty {
		if types.understood_c_type(&*i.self_ty, None) {
			let mut gen_types = GenericTypes::new(None);
			if !gen_types.learn_generics(&i.generics, types) {
				eprintln!("Not implementing anything for `impl (..)` due to not understood generics");
				return;
			}

			if i.defaultness.is_some() || i.unsafety.is_some() { unimplemented!(); }
			if let Some(trait_path) = i.trait_.as_ref() {
				if trait_path.0.is_some() { unimplemented!(); }
				if types.understood_c_path(&trait_path.1) {
					eprintln!("Not implementing anything for `impl Trait for (..)` - we only support manual defines");
					return;
				} else {
					// Just do a manual implementation:
					maybe_convert_trait_impl(w, &trait_path.1, &*i.self_ty, types, &gen_types);
				}
			} else {
				eprintln!("Not implementing anything for plain `impl (..)` block - we only support `impl Trait for (..)` blocks");
				return;
			}
		}
		return;
	}
	if let &syn::Type::Path(ref p) = &*i.self_ty {
		if p.qself.is_some() { unimplemented!(); }
		let ident = &p.path.segments.last().unwrap().ident;
		if let Some(resolved_path) = types.maybe_resolve_path(&p.path, None) {
			if types.crate_types.opaques.contains_key(&resolved_path) || types.crate_types.mirrored_enums.contains_key(&resolved_path) ||
				// At least for core::infallible::Infallible we need to support mapping an
				// out-of-crate trait implementation.
				(types.understood_c_path(&p.path) && first_seg_is_stdlib(resolved_path.split("::").next().unwrap())) {
				if !types.understood_c_path(&p.path) {
					eprintln!("Not implementing anything for impl {} as the type is not understood (probably C-not exported)", ident);
					return;
				}

				let mut gen_types = GenericTypes::new(Some(resolved_path.clone()));
				if !gen_types.learn_generics(&i.generics, types) {
					eprintln!("Not implementing anything for impl {} due to not understood generics", ident);
					return;
				}

				if i.defaultness.is_some() || i.unsafety.is_some() { unimplemented!(); }
				if let Some(trait_path) = i.trait_.as_ref() {
					if trait_path.0.is_some() { unimplemented!(); }
					let full_trait_path_opt = types.maybe_resolve_path(&trait_path.1, None);
					let trait_obj_opt = full_trait_path_opt.as_ref().and_then(|path| types.crate_types.traits.get(path));
					if types.understood_c_path(&trait_path.1) && trait_obj_opt.is_some() {
						let full_trait_path = full_trait_path_opt.unwrap();
						let trait_obj = *trait_obj_opt.unwrap();

						let supertrait_name;
						let supertrait_resolver;
						walk_supertraits!(trait_obj, Some(&types), (
							(s, _i, _) => {
								if let Some(supertrait) = types.crate_types.traits.get(s) {
									supertrait_name = s.to_string();
									supertrait_resolver = get_module_type_resolver!(supertrait_name, types.crate_libs, types.crate_types);
									gen_types.learn_associated_types(&supertrait, &supertrait_resolver);
									break;
								}
							}
						) );
						// We learn the associated types maping from the original trait object.
						// That's great, except that they are unresolved idents, so if we learn
						// mappings from a trai defined in a different file, we may mis-resolve or
						// fail to resolve the mapped types. Thus, we have to construct a new
						// resolver for the module that the trait was defined in here first.
						let mut trait_resolver = get_module_type_resolver!(full_trait_path, types.crate_libs, types.crate_types);
						gen_types.learn_associated_types(trait_obj, &trait_resolver);
						let mut impl_associated_types = HashMap::new();
						for item in i.items.iter() {
							match item {
								syn::ImplItem::Type(t) => {
									if let syn::Type::Path(p) = &t.ty {
										if let Some(id) = single_ident_generic_path_to_ident(&p.path) {
											impl_associated_types.insert(&t.ident, id);
										}
									}
								},
								_ => {},
							}
						}

						let export = export_status(&trait_obj.attrs);
						match export {
							ExportStatus::Export|ExportStatus::NotImplementable => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => return,
						}

						// For cases where we have a concrete native object which implements a
						// trait and need to return the C-mapped version of the trait, provide a
						// From<> implementation which does all the work to ensure free is handled
						// properly. This way we can call this method from deep in the
						// type-conversion logic without actually knowing the concrete native type.
						if !resolved_path.starts_with(types.module_path) {
							if !first_seg_is_stdlib(resolved_path.split("::").next().unwrap()) {
								w_uses.insert(format!("use crate::{}::native{} as native{};", resolved_path.rsplitn(2, "::").skip(1).next().unwrap(), ident, ident));
								w_uses.insert(format!("use crate::{};", resolved_path));
								w_uses.insert(format!("use crate::{}_free_void;", resolved_path));
							} else {
								w_uses.insert(format!("use {} as native{};", resolved_path, ident));
							}
						}
						writeln!(w, "impl From<native{}> for crate::{} {{", ident, full_trait_path).unwrap();
						writeln!(w, "\tfn from(obj: native{}) -> Self {{", ident).unwrap();
						if is_type_unconstructable(&resolved_path) {
							writeln!(w, "\t\tunreachable!();").unwrap();
						} else {
							writeln!(w, "\t\tlet mut rust_obj = {} {{ inner: ObjOps::heap_alloc(obj), is_owned: true }};", ident).unwrap();
							writeln!(w, "\t\tlet mut ret = {}_as_{}(&rust_obj);", ident, trait_obj.ident).unwrap();
							writeln!(w, "\t\t// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn").unwrap();
							writeln!(w, "\t\trust_obj.inner = core::ptr::null_mut();").unwrap();
							writeln!(w, "\t\tret.free = Some({}_free_void);", ident).unwrap();
							writeln!(w, "\t\tret").unwrap();
						}
						writeln!(w, "\t}}\n}}").unwrap();
						if is_type_unconstructable(&resolved_path) {
							// We don't bother with Struct_as_Trait conversion for types which must
							// never be instantiated, so just return early.
							return;
						}

						writeln!(w, "/// Constructs a new {} which calls the relevant methods on this_arg.", trait_obj.ident).unwrap();
						writeln!(w, "/// This copies the `inner` pointer in this_arg and thus the returned {} must be freed before this_arg is", trait_obj.ident).unwrap();
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_as_{}(this_arg: &{}) -> crate::{} {{\n", ident, trait_obj.ident, ident, full_trait_path).unwrap();
						writeln!(w, "\tcrate::{} {{", full_trait_path).unwrap();
						writeln!(w, "\t\tthis_arg: unsafe {{ ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void }},").unwrap();
						writeln!(w, "\t\tfree: None,").unwrap();

						macro_rules! write_meth {
							($m: expr, $trait: expr, $indent: expr) => {
								let trait_method = $trait.items.iter().filter_map(|item| {
									if let syn::TraitItem::Method(t_m) = item { Some(t_m) } else { None }
								}).find(|trait_meth| trait_meth.sig.ident == $m.sig.ident).unwrap();
								match export_status(&trait_method.attrs) {
									ExportStatus::Export => {},
									ExportStatus::NoExport => {
										write!(w, "{}\t\t//XXX: Need to export {}\n", $indent, $m.sig.ident).unwrap();
										continue;
									},
									ExportStatus::TestOnly => continue,
									ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
								}

								let mut printed = false;
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										write!(w, "\n\t\t{}{}: ", $indent, $m.sig.ident).unwrap();
										types.write_empty_rust_val(Some(&gen_types), w, &*r.elem);
										writeln!(w, ".into(),\n{}\t\tset_{}: Some({}_{}_set_{}),", $indent, $m.sig.ident, ident, $trait.ident, $m.sig.ident).unwrap();
										printed = true;
									}
								}
								if !printed {
									write!(w, "{}\t\t{}: {}_{}_{},\n", $indent, $m.sig.ident, ident, $trait.ident, $m.sig.ident).unwrap();
								}
							}
						}
						for item in trait_obj.items.iter() {
							match item {
								syn::TraitItem::Method(m) => {
									write_meth!(m, trait_obj, "");
								},
								_ => {},
							}
						}
						let mut requires_clone = false;
						walk_supertraits!(trait_obj, Some(&types), (
							("Clone", _, _) => {
								requires_clone = true;
								writeln!(w, "\t\tcloned: Some({}_{}_cloned),", trait_obj.ident, ident).unwrap();
							},
							("Sync", _, _) => {}, ("Send", _, _) => {},
							("std::marker::Sync", _, _) => {}, ("std::marker::Send", _, _) => {},
							("core::fmt::Debug", _, _) => {},
							(s, t, _) => {
								if let Some(supertrait_obj) = types.crate_types.traits.get(s) {
									macro_rules! write_impl_fields {
										($s: expr, $supertrait_obj: expr, $t: expr, $pfx: expr, $resolver: expr) => {
											writeln!(w, "{}\t{}: crate::{} {{", $pfx, $t, $s).unwrap();
											writeln!(w, "{}\t\tthis_arg: unsafe {{ ObjOps::untweak_ptr((*this_arg).inner) as *mut c_void }},", $pfx).unwrap();
											writeln!(w, "{}\t\tfree: None,", $pfx).unwrap();
											for item in $supertrait_obj.items.iter() {
												match item {
													syn::TraitItem::Method(m) => {
														write_meth!(m, $supertrait_obj, $pfx);
													},
													_ => {},
												}
											}
										walk_supertraits!($supertrait_obj, Some(&$resolver), (
											("Clone", _, _) => {
												writeln!(w, "{}\tcloned: Some({}_{}_cloned),", $pfx, $supertrait_obj.ident, ident).unwrap();
											},
											(_, _, _) => {}
										) );
										}
									}
									write_impl_fields!(s, supertrait_obj, t, "\t", types);

									let resolver = get_module_type_resolver!(s, types.crate_libs, types.crate_types);
									walk_supertraits!(supertrait_obj, Some(&resolver), (
										(s, t, _) => {
											if let Some(supertrait_obj) = types.crate_types.traits.get(s) {
												write_impl_fields!(s, supertrait_obj, t, "\t\t", resolver);
												write!(w, "\t\t\t}},\n").unwrap();
											}
										}
									) );
									write!(w, "\t\t}},\n").unwrap();
								} else {
									write_trait_impl_field_assign(w, s, ident);
								}
							}
						) );
						writeln!(w, "\t}}\n}}\n").unwrap();

						macro_rules! impl_meth {
							($m: expr, $trait_meth: expr, $trait_path: expr, $trait: expr, $indent: expr, $types: expr) => {
								let trait_method = $trait.items.iter().filter_map(|item| {
									if let syn::TraitItem::Method(t_m) = item { Some(t_m) } else { None }
								}).find(|trait_meth| trait_meth.sig.ident == $m.sig.ident).unwrap();
								match export_status(&trait_method.attrs) {
									ExportStatus::Export => {},
									ExportStatus::NoExport|ExportStatus::TestOnly => continue,
									ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
								}

								if let syn::ReturnType::Type(_, _) = &$m.sig.output {
									writeln!(w, "#[must_use]").unwrap();
								}
								write!(w, "extern \"C\" fn {}_{}_{}(", ident, $trait.ident, $m.sig.ident).unwrap();
								let mut meth_gen_types = gen_types.push_ctx();
								assert!(meth_gen_types.learn_generics(&$m.sig.generics, $types));
								let mut uncallable_function = false;
								for inp in $m.sig.inputs.iter() {
									match inp {
										syn::FnArg::Typed(arg) => {
											if $types.skip_arg(&*arg.ty, Some(&meth_gen_types)) { continue; }
											let mut c_type = Vec::new();
											$types.write_c_type(&mut c_type, &*arg.ty, Some(&meth_gen_types), false);
											if is_type_unconstructable(&String::from_utf8(c_type).unwrap()) {
												uncallable_function = true;
											}
										}
										_ => {}
									}
								}
								write_method_params(w, &$trait_meth.sig, "c_void", &mut trait_resolver, Some(&meth_gen_types), true, true);
								write!(w, " {{\n\t").unwrap();
								if uncallable_function {
									write!(w, "unreachable!();").unwrap();
								} else {
									write_method_var_decl_body(w, &$trait_meth.sig, "", &mut trait_resolver, Some(&meth_gen_types), false);
									let mut takes_self = false;
									for inp in $m.sig.inputs.iter() {
										if let syn::FnArg::Receiver(_) = inp {
											takes_self = true;
										}
									}

									let mut t_gen_args = String::new();
									for (idx, _) in $trait.generics.params.iter().enumerate() {
										if idx != 0 { t_gen_args += ", " };
										t_gen_args += "_"
									}
									// rustc doesn't like <_> if the _ is actually a lifetime, so
									// if all the parameters are lifetimes just skip it.
									let mut nonlifetime_param = false;
									for param in $trait.generics.params.iter() {
										if let syn::GenericParam::Lifetime(_) = param {}
										else { nonlifetime_param = true; }
									}
									if !nonlifetime_param { t_gen_args = String::new(); }
									if takes_self {
										write!(w, "<native{} as {}<{}>>::{}(unsafe {{ &mut *(this_arg as *mut native{}) }}, ", ident, $trait_path, t_gen_args, $m.sig.ident, ident).unwrap();
									} else {
										write!(w, "<native{} as {}<{}>>::{}(", ident, $trait_path, t_gen_args, $m.sig.ident).unwrap();
									}

									let mut real_type = "".to_string();
									match &$m.sig.output {
										syn::ReturnType::Type(_, rtype) => {
											if let Some(mut remaining_path) = first_seg_self(&*rtype) {
												if let Some(associated_seg) = get_single_remaining_path_seg(&mut remaining_path) {
													real_type = format!("{}", impl_associated_types.get(associated_seg).unwrap());
												}
											}
										},
										_ => {},
									}
									write_method_call_params(w, &$trait_meth.sig, "", &mut trait_resolver, Some(&meth_gen_types), &real_type, false);
								}
								write!(w, "\n}}\n").unwrap();
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										assert_eq!($m.sig.inputs.len(), 1); // Must only take self
										writeln!(w, "extern \"C\" fn {}_{}_set_{}(trait_self_arg: &{}) {{", ident, $trait.ident, $m.sig.ident, $trait.ident).unwrap();
										writeln!(w, "\t// This is a bit race-y in the general case, but for our specific use-cases today, we're safe").unwrap();
										writeln!(w, "\t// Specifically, we must ensure that the first time we're called it can never be in parallel").unwrap();
										write!(w, "\tif ").unwrap();
										$types.write_empty_rust_val_check(Some(&meth_gen_types), w, &*r.elem, &format!("unsafe {{ &*trait_self_arg.{}.get() }}", $m.sig.ident));
										writeln!(w, " {{").unwrap();
										writeln!(w, "\t\t*unsafe {{ &mut *(&*(trait_self_arg as *const {})).{}.get() }} = {}_{}_{}(trait_self_arg.this_arg).into();", $trait.ident, $m.sig.ident, ident, $trait.ident, $m.sig.ident).unwrap();
										writeln!(w, "\t}}").unwrap();
										writeln!(w, "}}").unwrap();
									}
								}
							}
						}

						'impl_item_loop: for trait_item in trait_obj.items.iter() {
							match trait_item {
								syn::TraitItem::Method(meth) => {
									for item in i.items.iter() {
										match item {
											syn::ImplItem::Method(m) => {
												if meth.sig.ident == m.sig.ident {
													impl_meth!(m, meth, full_trait_path, trait_obj, "", types);
													continue 'impl_item_loop;
												}
											},
											syn::ImplItem::Type(_) => {},
											_ => unimplemented!(),
										}
									}
									assert!(meth.default.is_some());
									let old_gen_types = gen_types;
									gen_types = GenericTypes::new(Some(resolved_path.clone()));
									impl_meth!(meth, meth, full_trait_path, trait_obj, "", &mut trait_resolver);
									gen_types = old_gen_types;
								},
								_ => {},
							}
						}
						if requires_clone {
							writeln!(w, "extern \"C\" fn {}_{}_cloned(new_obj: &mut crate::{}) {{", trait_obj.ident, ident, full_trait_path).unwrap();
							writeln!(w, "\tnew_obj.this_arg = {}_clone_void(new_obj.this_arg);", ident).unwrap();
							writeln!(w, "\tnew_obj.free = Some({}_free_void);", ident).unwrap();
							walk_supertraits!(trait_obj, Some(&types), (
								(s, t, _) => {
									if types.crate_types.traits.get(s).is_some() {
										assert!(!types.is_clonable(s)); // We don't currently support cloning with a clonable supertrait
										writeln!(w, "\tnew_obj.{}.this_arg = new_obj.this_arg;", t).unwrap();
										writeln!(w, "\tnew_obj.{}.free = None;", t).unwrap();
									}
								}
							) );
							writeln!(w, "}}").unwrap();
						}
						write!(w, "\n").unwrap();
						return;
					}
					if is_type_unconstructable(&resolved_path) {
						// Don't bother exposing trait implementations for objects which cannot be
						// instantiated.
						return;
					}
					if path_matches_nongeneric(&trait_path.1, &["From"]) {
					} else if path_matches_nongeneric(&trait_path.1, &["Default"]) {
						writeln!(w, "/// Creates a \"default\" {}. See struct and individual field documentaiton for details on which values are used.", ident).unwrap();
						write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_default() -> {} {{\n", ident, ident).unwrap();
						write!(w, "\t{} {{ inner: ObjOps::heap_alloc(Default::default()), is_owned: true }}\n", ident).unwrap();
						write!(w, "}}\n").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["core", "cmp", "PartialEq"]) {
					} else if path_matches_nongeneric(&trait_path.1, &["core", "cmp", "Eq"]) {
						writeln!(w, "/// Checks if two {}s contain equal inner contents.", ident).unwrap();
						writeln!(w, "/// This ignores pointers and is_owned flags and looks at the values in fields.").unwrap();
						if types.c_type_has_inner_from_path(&resolved_path) {
							writeln!(w, "/// Two objects with NULL inner values will be considered \"equal\" here.").unwrap();
						}
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_eq(a: &{}, b: &{}) -> bool {{\n", ident, ident, ident).unwrap();
						if types.c_type_has_inner_from_path(&resolved_path) {
							write!(w, "\tif a.inner == b.inner {{ return true; }}\n").unwrap();
							write!(w, "\tif a.inner.is_null() || b.inner.is_null() {{ return false; }}\n").unwrap();
						}

						let path = &p.path;
						let ref_type: syn::Type = syn::parse_quote!(&#path);
						assert!(!types.write_to_c_conversion_new_var(w, &format_ident!("a"), &*i.self_ty, Some(&gen_types), false), "We don't support new var conversions when comparing equality");

						write!(w, "\tif ").unwrap();
						types.write_from_c_conversion_prefix(w, &ref_type, Some(&gen_types));
						write!(w, "a").unwrap();
						types.write_from_c_conversion_suffix(w, &ref_type, Some(&gen_types));
						write!(w, " == ").unwrap();
						types.write_from_c_conversion_prefix(w, &ref_type, Some(&gen_types));
						write!(w, "b").unwrap();
						types.write_from_c_conversion_suffix(w, &ref_type, Some(&gen_types));

						writeln!(w, " {{ true }} else {{ false }}\n}}").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["core", "hash", "Hash"]) {
						writeln!(w, "/// Generates a non-cryptographic 64-bit hash of the {}.", ident).unwrap();
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_hash(o: &{}) -> u64 {{\n", ident, ident).unwrap();
						if types.c_type_has_inner_from_path(&resolved_path) {
							write!(w, "\tif o.inner.is_null() {{ return 0; }}\n").unwrap();
						}

						let path = &p.path;
						let ref_type: syn::Type = syn::parse_quote!(&#path);
						assert!(!types.write_to_c_conversion_new_var(w, &format_ident!("a"), &*i.self_ty, Some(&gen_types), false), "We don't support new var conversions when comparing equality");

						writeln!(w, "\t// Note that we'd love to use alloc::collections::hash_map::DefaultHasher but it's not in core").unwrap();
						writeln!(w, "\t#[allow(deprecated)]").unwrap();
						writeln!(w, "\tlet mut hasher = core::hash::SipHasher::new();").unwrap();
						write!(w, "\tcore::hash::Hash::hash(").unwrap();
						types.write_from_c_conversion_prefix(w, &ref_type, Some(&gen_types));
						write!(w, "o").unwrap();
						types.write_from_c_conversion_suffix(w, &ref_type, Some(&gen_types));
						writeln!(w, ", &mut hasher);").unwrap();
						writeln!(w, "\tcore::hash::Hasher::finish(&hasher)\n}}").unwrap();
					} else if (path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) || path_matches_nongeneric(&trait_path.1, &["Clone"])) &&
							types.c_type_has_inner_from_path(&resolved_path) {
						writeln!(w, "impl Clone for {} {{", ident).unwrap();
						writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
						writeln!(w, "\t\tSelf {{").unwrap();
						writeln!(w, "\t\t\tinner: if <*mut native{}>::is_null(self.inner) {{ core::ptr::null_mut() }} else {{", ident).unwrap();
						writeln!(w, "\t\t\t\tObjOps::heap_alloc(unsafe {{ &*ObjOps::untweak_ptr(self.inner) }}.clone()) }},").unwrap();
						writeln!(w, "\t\t\tis_owned: true,").unwrap();
						writeln!(w, "\t\t}}\n\t}}\n}}").unwrap();
						writeln!(w, "#[allow(unused)]").unwrap();
						writeln!(w, "/// Used only if an object of this type is returned as a trait impl by a method").unwrap();
						writeln!(w, "pub(crate) extern \"C\" fn {}_clone_void(this_ptr: *const c_void) -> *mut c_void {{", ident).unwrap();
						writeln!(w, "\tBox::into_raw(Box::new(unsafe {{ (*(this_ptr as *mut native{})).clone() }})) as *mut c_void", ident).unwrap();
						writeln!(w, "}}").unwrap();
						writeln!(w, "#[no_mangle]").unwrap();
						writeln!(w, "/// Creates a copy of the {}", ident).unwrap();
						writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", ident, ident, ident).unwrap();
						writeln!(w, "\torig.clone()").unwrap();
						writeln!(w, "}}").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["FromStr"]) {
						let mut err_opt = None;
						for item in i.items.iter() {
							match item {
								syn::ImplItem::Type(ty) if format!("{}", ty.ident) == "Err" => {
									err_opt = Some(&ty.ty);
								},
								_ => {}
							}
						}
						let err_ty = err_opt.unwrap();
						if let Some(container) = types.get_c_mangled_container_type(vec![&*i.self_ty, &err_ty], Some(&gen_types), "Result") {
							writeln!(w, "#[no_mangle]").unwrap();
							writeln!(w, "/// Read a {} object from a string", ident).unwrap();
							writeln!(w, "pub extern \"C\" fn {}_from_str(s: crate::c_types::Str) -> {} {{", ident, container).unwrap();
							writeln!(w, "\tmatch {}::from_str(s.into_str()) {{", resolved_path).unwrap();

							writeln!(w, "\t\tOk(r) => {{").unwrap();
							let new_var = types.write_to_c_conversion_new_var(w, &format_ident!("r"), &*i.self_ty, Some(&gen_types), false);
							write!(w, "\t\t\tcrate::c_types::CResultTempl::ok(\n\t\t\t\t").unwrap();
							types.write_to_c_conversion_inline_prefix(w, &*i.self_ty, Some(&gen_types), false);
							write!(w, "{}r", if new_var { "local_" } else { "" }).unwrap();
							types.write_to_c_conversion_inline_suffix(w, &*i.self_ty, Some(&gen_types), false);
							writeln!(w, "\n\t\t\t)\n\t\t}},").unwrap();

							writeln!(w, "\t\tErr(e) => {{").unwrap();
							let new_var = types.write_to_c_conversion_new_var(w, &format_ident!("e"), &err_ty, Some(&gen_types), false);
							write!(w, "\t\t\tcrate::c_types::CResultTempl::err(\n\t\t\t\t").unwrap();
							types.write_to_c_conversion_inline_prefix(w, &err_ty, Some(&gen_types), false);
							write!(w, "{}e", if new_var { "local_" } else { "" }).unwrap();
							types.write_to_c_conversion_inline_suffix(w, &err_ty, Some(&gen_types), false);
							writeln!(w, "\n\t\t\t)\n\t\t}},").unwrap();

							writeln!(w, "\t}}.into()\n}}").unwrap();
						}
					} else if path_matches_nongeneric(&trait_path.1, &["Display"]) {
						writeln!(w, "#[no_mangle]").unwrap();
						writeln!(w, "/// Get the string representation of a {} object", ident).unwrap();
						writeln!(w, "pub extern \"C\" fn {}_to_str(o: &crate::{}) -> Str {{", ident, resolved_path).unwrap();

						let self_ty = &i.self_ty;
						let ref_type: syn::Type = syn::parse_quote!(&#self_ty);
						let new_var = types.write_from_c_conversion_new_var(w, &format_ident!("o"), &ref_type, Some(&gen_types));
						write!(w, "\talloc::format!(\"{{}}\", ").unwrap();
						types.write_from_c_conversion_prefix(w, &ref_type, Some(&gen_types));
						write!(w, "{}o", if new_var { "local_" } else { "" }).unwrap();
						types.write_from_c_conversion_suffix(w, &ref_type, Some(&gen_types));
						writeln!(w, ").into()").unwrap();

						writeln!(w, "}}").unwrap();
					} else {
						//XXX: implement for other things like ToString
						// If we have no generics, try a manual implementation:
						maybe_convert_trait_impl(w, &trait_path.1, &*i.self_ty, types, &gen_types);
					}
				} else {
					let is_opaque = types.crate_types.opaques.contains_key(&resolved_path);
					let is_mirrored_enum = types.crate_types.mirrored_enums.contains_key(&resolved_path);
					for item in i.items.iter() {
						match item {
							syn::ImplItem::Method(m) => {
								if let syn::Visibility::Public(_) = m.vis {
									match export_status(&m.attrs) {
										ExportStatus::Export => {},
										ExportStatus::NoExport|ExportStatus::TestOnly => continue,
										ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
									}
									if m.sig.asyncness.is_some() { continue; }
									let mut meth_gen_types = gen_types.push_ctx();
									assert!(meth_gen_types.learn_generics(&m.sig.generics, types));
									if m.defaultness.is_some() { unimplemented!(); }
									writeln_fn_docs(w, &m.attrs, "", types, Some(&meth_gen_types), m.sig.inputs.iter(), &m.sig.output);
									if let syn::ReturnType::Type(_, _) = &m.sig.output {
										writeln!(w, "#[must_use]").unwrap();
									}
									write!(w, "#[no_mangle]\npub extern \"C\" fn {}_{}(", ident, m.sig.ident).unwrap();
									let ret_type = format!("crate::{}", resolved_path);
									write_method_params(w, &m.sig, &ret_type, types, Some(&meth_gen_types), false, true);
									write!(w, " {{\n\t").unwrap();
									write_method_var_decl_body(w, &m.sig, "", types, Some(&meth_gen_types), false);
									let mut takes_self = false;
									let mut takes_mut_self = false;
									let mut takes_owned_self = false;
									for inp in m.sig.inputs.iter() {
										if let syn::FnArg::Receiver(r) = inp {
											takes_self = true;
											if r.mutability.is_some() { takes_mut_self = true; }
											if r.reference.is_none() { takes_owned_self = true; }
										}
									}
									if !takes_mut_self && !takes_self {
										write!(w, "{}::{}(", resolved_path, m.sig.ident).unwrap();
									} else {
										if is_mirrored_enum {
											write!(w, "this_arg.to_native().{}(", m.sig.ident).unwrap();
										} else if is_opaque {
											if takes_owned_self {
												write!(w, "(*unsafe {{ Box::from_raw(this_arg.take_inner()) }}).{}(", m.sig.ident).unwrap();
											} else if takes_mut_self {
												write!(w, "unsafe {{ &mut (*ObjOps::untweak_ptr(this_arg.inner as *mut crate::{}::native{})) }}.{}(", rsplit_once(&resolved_path, "::").unwrap().0, ident, m.sig.ident).unwrap();
											} else {
												write!(w, "unsafe {{ &*ObjOps::untweak_ptr(this_arg.inner) }}.{}(", m.sig.ident).unwrap();
											}
										} else {
											unimplemented!();
										}
									}
									write_method_call_params(w, &m.sig, "", types, Some(&meth_gen_types), &ret_type, false);
									writeln!(w, "\n}}\n").unwrap();
								}
							},
							_ => {},
						}
					}
				}
			} else if let Some(resolved_path) = types.maybe_resolve_ident(&ident) {
				create_alias_for_impl(resolved_path, i, types, move |aliased_impl, types| writeln_impl(w, w_uses, &aliased_impl, types));
			} else {
				eprintln!("Not implementing anything for {} due to no-resolve (probably the type isn't pub)", ident);
			}
		}
	}
}

fn create_alias_for_impl<F: FnMut(syn::ItemImpl, &mut TypeResolver)>(resolved_path: String, i: &syn::ItemImpl, types: &mut TypeResolver, mut callback: F) {
	if let Some(aliases) = types.crate_types.reverse_alias_map.get(&resolved_path).cloned() {
		let mut gen_types = Some(GenericTypes::new(Some(resolved_path.clone())));
		if !gen_types.as_mut().unwrap().learn_generics(&i.generics, types) {
			gen_types = None;
		}
		let alias_module = rsplit_once(&resolved_path, "::").unwrap().0;

		'alias_impls: for (alias_resolved, arguments) in aliases {
			let mut new_ty_generics = Vec::new();
			let mut new_ty_bounds = Vec::new();
			let mut need_generics = false;

			let alias_resolver_override;
			let alias_resolver = if alias_module != types.module_path {
				alias_resolver_override = ImportResolver::new(types.types.crate_name, &types.crate_types.lib_ast,
					alias_module, &types.crate_types.lib_ast.modules.get(alias_module).unwrap().items);
				&alias_resolver_override
			} else { &types.types };
			let mut where_clause = syn::WhereClause { where_token: syn::Token![where](Span::call_site()),
				predicates: syn::punctuated::Punctuated::new()
			};
			for (idx, gen) in i.generics.params.iter().enumerate() {
				match gen {
					syn::GenericParam::Type(type_param) => {
						'bounds_check: for bound in type_param.bounds.iter() {
							if let syn::TypeParamBound::Trait(trait_bound) = bound {
								if let syn::PathArguments::AngleBracketed(ref t) = &arguments {
									assert!(idx < t.args.len());
									if let syn::GenericArgument::Type(syn::Type::Path(p)) = &t.args[idx] {
										let generic_bound = types.maybe_resolve_path(&trait_bound.path, None)
											.unwrap_or_else(|| format!("{}::{}", types.module_path, single_ident_generic_path_to_ident(&trait_bound.path).unwrap()));

										if let Some(generic_arg) = alias_resolver.maybe_resolve_path(&p.path, None) {
											new_ty_generics.push((type_param.ident.clone(), syn::Type::Path(p.clone())));
											if let Some(traits_impld) = types.crate_types.trait_impls.get(&generic_arg) {
												for trait_impld in traits_impld {
													if *trait_impld == generic_bound { continue 'bounds_check; }
												}
												eprintln!("struct {}'s generic arg {} didn't match bound {}", alias_resolved, generic_arg, generic_bound);
												continue 'alias_impls;
											} else {
												eprintln!("struct {}'s generic arg {} didn't match bound {}", alias_resolved, generic_arg, generic_bound);
												continue 'alias_impls;
											}
										} else if gen_types.is_some() {
											let resp =  types.maybe_resolve_path(&p.path, gen_types.as_ref());
											if generic_bound == "core::ops::Deref" && resp.is_some() {
												new_ty_bounds.push((type_param.ident.clone(),
													string_path_to_syn_path("core::ops::Deref")));
												let mut bounds = syn::punctuated::Punctuated::new();
												bounds.push(syn::TypeParamBound::Trait(syn::TraitBound {
													paren_token: None,
													modifier: syn::TraitBoundModifier::None,
													lifetimes: None,
													path: string_path_to_syn_path(&types.resolve_path(&p.path, gen_types.as_ref())),
												}));
												let mut path = string_path_to_syn_path(&format!("{}::Target", type_param.ident));
												path.leading_colon = None;
												where_clause.predicates.push(syn::WherePredicate::Type(syn::PredicateType {
													lifetimes: None,
													bounded_ty: syn::Type::Path(syn::TypePath { qself: None, path }),
													colon_token: syn::Token![:](Span::call_site()),
													bounds,
												}));
											} else {
												new_ty_generics.push((type_param.ident.clone(),
													gen_types.as_ref().resolve_type(&syn::Type::Path(p.clone())).clone()));
											}
											need_generics = true;
										} else {
											unimplemented!();
										}
									} else { unimplemented!(); }
								} else { unimplemented!(); }
							} else { unimplemented!(); }
						}
					},
					syn::GenericParam::Lifetime(_) => {},
					syn::GenericParam::Const(_) => unimplemented!(),
				}
			}
			let mut params = syn::punctuated::Punctuated::new();
			let alias = string_path_to_syn_path(&alias_resolved);
			let real_aliased =
				if need_generics {
					let alias_generics = types.crate_types.opaques.get(&alias_resolved).unwrap().1;

					// If we need generics on the alias, create impl generic bounds...
					assert_eq!(new_ty_generics.len() + new_ty_bounds.len(), i.generics.params.len());
					let mut args = syn::punctuated::Punctuated::new();
					for (ident, param) in new_ty_generics.drain(..) {
						// TODO: We blindly assume that generics in the type alias and
						// the aliased type have the same names, which we really shouldn't.
						if alias_generics.params.iter().any(|generic|
							if let syn::GenericParam::Type(t) = generic { t.ident == ident } else { false })
						{
							args.push(parse_quote!(#ident));
						}
						params.push(syn::GenericParam::Type(syn::TypeParam {
							attrs: Vec::new(),
							ident,
							colon_token: None,
							bounds: syn::punctuated::Punctuated::new(),
							eq_token: Some(syn::token::Eq(Span::call_site())),
							default: Some(param),
						}));
					}
					for (ident, param) in new_ty_bounds.drain(..) {
						// TODO: We blindly assume that generics in the type alias and
						// the aliased type have the same names, which we really shouldn't.
						if alias_generics.params.iter().any(|generic|
							if let syn::GenericParam::Type(t) = generic { t.ident == ident } else { false })
						{
							args.push(parse_quote!(#ident));
						}
						params.push(syn::GenericParam::Type(syn::TypeParam {
							attrs: Vec::new(),
							ident,
							colon_token: Some(syn::token::Colon(Span::call_site())),
							bounds: syn::punctuated::Punctuated::from_iter(
								Some(syn::TypeParamBound::Trait(syn::TraitBound {
									path: param, paren_token: None, lifetimes: None,
									modifier: syn::TraitBoundModifier::None,
								}))
							),
							eq_token: None,
							default: None,
						}));
					}
					// ... and swap the last segment of the impl self_ty to use the generic bounds.
					let mut res = alias.clone();
					res.segments.last_mut().unwrap().arguments = syn::PathArguments::AngleBracketed(syn::AngleBracketedGenericArguments {
						colon2_token: None,
						lt_token: syn::token::Lt(Span::call_site()),
						args,
						gt_token: syn::token::Gt(Span::call_site()),
					});
					res
				} else { alias.clone() };
			callback(syn::ItemImpl {
				attrs: i.attrs.clone(),
				brace_token: syn::token::Brace(Span::call_site()),
				defaultness: None,
				generics: syn::Generics {
					lt_token: None,
					params,
					gt_token: None,
					where_clause: Some(where_clause),
				},
				impl_token: syn::Token![impl](Span::call_site()),
				items: i.items.clone(),
				self_ty: Box::new(syn::Type::Path(syn::TypePath { qself: None, path: real_aliased })),
				trait_: i.trait_.clone(),
				unsafety: None,
			}, types);
		}
	} else {
		eprintln!("Not implementing anything for {} due to it being marked not exported", resolved_path);
	}
}

/// Replaces upper case charachters with underscore followed by lower case except the first
/// charachter and repeated upper case characthers (which are only made lower case).
fn camel_to_snake_case(camel: &str) -> String {
	let mut res = "".to_string();
	let mut last_upper = -1;
	for (idx, c) in camel.chars().enumerate() {
		if c.is_uppercase() {
			if last_upper != idx as isize - 1 { res.push('_'); }
			res.push(c.to_lowercase().next().unwrap());
			last_upper = idx as isize;
		} else {
			res.push(c);
		}
	}
	res
}


/// Print a mapping of an enum. If all of the enum's fields are C-mapped in some form (or the enum
/// is unitary), we generate an equivalent enum with all types replaced with their C mapped
/// versions followed by conversion functions which map between the Rust version and the C mapped
/// version.
fn writeln_enum<'a, 'b, W: std::io::Write>(w: &mut W, e: &'a syn::ItemEnum, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	match export_status(&e.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
		ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
	}

	if is_enum_opaque(e) {
		eprintln!("Skipping enum {} as it contains non-unit fields", e.ident);
		writeln_opaque(w, &e.ident, &format!("{}", e.ident), &e.generics, &e.attrs, types, extra_headers, cpp_headers);
		return;
	}
	writeln_docs(w, &e.attrs, "");

	let mut gen_types = GenericTypes::new(None);
	assert!(gen_types.learn_generics(&e.generics, types));

	let mut needs_free = false;
	let mut constr = Vec::new();
	let mut is_clonable = true;

	for var in e.variants.iter() {
		if let syn::Fields::Named(fields) = &var.fields {
			needs_free = true;
			for field in fields.named.iter() {
				if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }

				let mut ty_checks = Vec::new();
				types.write_c_type(&mut ty_checks, &field.ty, Some(&gen_types), false);
				if !types.is_clonable(&String::from_utf8(ty_checks).unwrap()) {
					is_clonable = false;
				}
			}
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			for field in fields.unnamed.iter() {
				let mut ty_checks = Vec::new();
				types.write_c_type(&mut ty_checks, &field.ty, Some(&gen_types), false);
				let ty = String::from_utf8(ty_checks).unwrap();
				if ty != "" && !types.is_clonable(&ty) {
					is_clonable = false;
				}
			}
		}
	}

	if is_clonable {
		writeln!(w, "#[derive(Clone)]").unwrap();
		types.crate_types.set_clonable(format!("{}::{}", types.module_path, e.ident));
	}
	writeln!(w, "#[must_use]\n#[repr(C)]\npub enum {} {{", e.ident).unwrap();
	for var in e.variants.iter() {
		assert_eq!(export_status(&var.attrs), ExportStatus::Export); // We can't partially-export a mirrored enum
		writeln_docs(w, &var.attrs, "\t");
		write!(w, "\t{}", var.ident).unwrap();
		writeln!(&mut constr, "#[no_mangle]\n/// Utility method to constructs a new {}-variant {}", var.ident, e.ident).unwrap();
		let constr_name = camel_to_snake_case(&format!("{}", var.ident));
		write!(&mut constr, "pub extern \"C\" fn {}_{}(", e.ident, constr_name).unwrap();
		let mut empty_tuple_variant = false;
		if let syn::Fields::Named(fields) = &var.fields {
			needs_free = true;
			writeln!(w, " {{").unwrap();
			for (idx, field) in fields.named.iter().enumerate() {
				if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
				writeln_field_docs(w, &field.attrs, "\t\t", types, Some(&gen_types), &field.ty);
				write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
				write!(&mut constr, "{}{}: ", if idx != 0 { ", " } else { "" }, field.ident.as_ref().unwrap()).unwrap();
				types.write_c_type(w, &field.ty, Some(&gen_types), true);
				types.write_c_type(&mut constr, &field.ty, Some(&gen_types), true);
				writeln!(w, ",").unwrap();
			}
			write!(w, "\t}}").unwrap();
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			if fields.unnamed.len() == 1 {
				let mut empty_check = Vec::new();
				types.write_c_type(&mut empty_check, &fields.unnamed[0].ty, Some(&gen_types), true);
				if empty_check.is_empty() {
					empty_tuple_variant = true;
				}
			}
			if !empty_tuple_variant {
				needs_free = true;
				writeln!(w, "(").unwrap();
				for (idx, field) in fields.unnamed.iter().enumerate() {
					if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
					writeln_field_docs(w, &field.attrs, "\t\t", types, Some(&gen_types), &field.ty);
					write!(w, "\t\t").unwrap();
					types.write_c_type(w, &field.ty, Some(&gen_types), true);

					write!(&mut constr, "{}: ", ('a' as u8 + idx as u8) as char).unwrap();
					types.write_c_type(&mut constr, &field.ty, Some(&gen_types), false);
					if idx != fields.unnamed.len() - 1 {
						writeln!(w, ",").unwrap();
						write!(&mut constr, ",").unwrap();
					}
				}
				write!(w, ")").unwrap();
			}
		}
		write!(&mut constr, ") -> {} {{\n\t{}::{}", e.ident, e.ident, var.ident).unwrap();
		if let syn::Fields::Named(fields) = &var.fields {
			writeln!(&mut constr, " {{").unwrap();
			for field in fields.named.iter() {
				writeln!(&mut constr, "\t\t{},", field.ident.as_ref().unwrap()).unwrap();
			}
			writeln!(&mut constr, "\t}}").unwrap();
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			if !empty_tuple_variant {
				write!(&mut constr, "(").unwrap();
				for (idx, field) in fields.unnamed.iter().enumerate() {
					let mut ref_c_ty = Vec::new();
					let mut nonref_c_ty = Vec::new();
					types.write_c_type(&mut ref_c_ty, &field.ty, Some(&gen_types), false);
					types.write_c_type(&mut nonref_c_ty, &field.ty, Some(&gen_types), true);

					if ref_c_ty != nonref_c_ty {
						// We blindly assume references in field types are always opaque types, and
						// print out an opaque reference -> owned reference conversion here.
						write!(&mut constr, "{} {{ inner: {}.inner, is_owned: false }}, ", String::from_utf8(nonref_c_ty).unwrap(), ('a' as u8 + idx as u8) as char).unwrap();
					} else {
						write!(&mut constr, "{}, ", ('a' as u8 + idx as u8) as char).unwrap();
					}
				}
				writeln!(&mut constr, ")").unwrap();
			} else {
				writeln!(&mut constr, "").unwrap();
			}
		}
		writeln!(&mut constr, "}}").unwrap();
		writeln!(w, ",").unwrap();
	}
	writeln!(w, "}}\nuse {}::{} as {}Import;", types.module_path, e.ident, e.ident).unwrap();
	write!(w, "pub(crate) type native{} = {}Import", e.ident, e.ident).unwrap();
	maybe_write_generics(w, &e.generics, &syn::PathArguments::None, &types, true);
	writeln!(w, ";\n\nimpl {} {{", e.ident).unwrap();

	macro_rules! write_conv {
		($fn_sig: expr, $to_c: expr, $ref: expr) => {
			writeln!(w, "\t#[allow(unused)]\n\tpub(crate) fn {} {{\n\t\tmatch {} {{", $fn_sig, if $to_c { "native" } else { "self" }).unwrap();
			for var in e.variants.iter() {
				write!(w, "\t\t\t{}{}::{} ", if $to_c { "native" } else { "" }, e.ident, var.ident).unwrap();
				let mut empty_tuple_variant = false;
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, "{{").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "{}{}, ", if $ref { "ref " } else { "mut " }, field.ident.as_ref().unwrap()).unwrap();
					}
					write!(w, "}} ").unwrap();
				} else if let syn::Fields::Unnamed(fields) = &var.fields {
					if fields.unnamed.len() == 1 {
						let mut empty_check = Vec::new();
						types.write_c_type(&mut empty_check, &fields.unnamed[0].ty, Some(&gen_types), true);
						if empty_check.is_empty() {
							empty_tuple_variant = true;
						}
					}
					if !empty_tuple_variant || $to_c {
						write!(w, "(").unwrap();
						for (idx, field) in fields.unnamed.iter().enumerate() {
							if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
							write!(w, "{}{}, ", if $ref { "ref " } else { "mut " }, ('a' as u8 + idx as u8) as char).unwrap();
						}
						write!(w, ") ").unwrap();
					}
				}
				write!(w, "=>").unwrap();

				macro_rules! handle_field_a {
					($field: expr, $field_ident: expr) => { {
						if export_status(&$field.attrs) == ExportStatus::TestOnly { continue; }
						let mut sink = ::std::io::sink();
						let mut out: &mut dyn std::io::Write = if $ref { &mut sink } else { w };
						let new_var = if $to_c {
							types.write_to_c_conversion_new_var(&mut out, $field_ident, &$field.ty, Some(&gen_types), true)
						} else {
							types.write_from_c_conversion_new_var(&mut out, $field_ident, &$field.ty, Some(&gen_types))
						};
						if $ref || new_var {
							if $ref {
								write!(w, "let mut {}_nonref = Clone::clone({});\n\t\t\t\t", $field_ident, $field_ident).unwrap();
								if new_var {
									let nonref_ident = format_ident!("{}_nonref", $field_ident);
									if $to_c {
										types.write_to_c_conversion_new_var(w, &nonref_ident, &$field.ty, Some(&gen_types), true);
									} else {
										types.write_from_c_conversion_new_var(w, &nonref_ident, &$field.ty, Some(&gen_types));
									}
									write!(w, "\n\t\t\t\t").unwrap();
								}
							} else {
								write!(w, "\n\t\t\t\t").unwrap();
							}
						}
					} }
				}
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, " {{\n\t\t\t\t").unwrap();
					for field in fields.named.iter() {
						handle_field_a!(field, field.ident.as_ref().unwrap());
					}
				} else if let syn::Fields::Unnamed(fields) = &var.fields {
					write!(w, " {{\n\t\t\t\t").unwrap();
					for (idx, field) in fields.unnamed.iter().enumerate() {
						if !empty_tuple_variant {
							handle_field_a!(field, &format_ident!("{}", ('a' as u8 + idx as u8) as char));
						}
					}
				} else { write!(w, " ").unwrap(); }

				write!(w, "{}{}::{}", if $to_c { "" } else { "native" }, e.ident, var.ident).unwrap();

				macro_rules! handle_field_b {
					($field: expr, $field_ident: expr) => { {
						if export_status(&$field.attrs) == ExportStatus::TestOnly { continue; }
						if $to_c {
							types.write_to_c_conversion_inline_prefix(w, &$field.ty, Some(&gen_types), true);
						} else {
							types.write_from_c_conversion_prefix(w, &$field.ty, Some(&gen_types));
						}
						write!(w, "{}{}", $field_ident,
							if $ref { "_nonref" } else { "" }).unwrap();
						if $to_c {
							types.write_to_c_conversion_inline_suffix(w, &$field.ty, Some(&gen_types), true);
						} else {
							types.write_from_c_conversion_suffix(w, &$field.ty, Some(&gen_types));
						}
						write!(w, ",").unwrap();
					} }
				}

				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, " {{").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "\n\t\t\t\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
						handle_field_b!(field, field.ident.as_ref().unwrap());
					}
					writeln!(w, "\n\t\t\t\t}}").unwrap();
					write!(w, "\t\t\t}}").unwrap();
				} else if let syn::Fields::Unnamed(fields) = &var.fields {
					if !empty_tuple_variant || !$to_c {
						write!(w, " (").unwrap();
						for (idx, field) in fields.unnamed.iter().enumerate() {
							write!(w, "\n\t\t\t\t\t").unwrap();
							handle_field_b!(field, &format_ident!("{}", ('a' as u8 + idx as u8) as char));
						}
						writeln!(w, "\n\t\t\t\t)").unwrap();
					}
					write!(w, "\t\t\t}}").unwrap();
				}
				writeln!(w, ",").unwrap();
			}
			writeln!(w, "\t\t}}\n\t}}").unwrap();
		}
	}

	if is_clonable {
		write_conv!(format!("to_native(&self) -> native{}", e.ident), false, true);
	}
	write_conv!(format!("into_native(self) -> native{}", e.ident), false, false);
	if is_clonable {
		write_conv!(format!("from_native(native: &native{}) -> Self", e.ident), true, true);
	}
	write_conv!(format!("native_into(native: native{}) -> Self", e.ident), true, false);
	writeln!(w, "}}").unwrap();

	if needs_free {
		writeln!(w, "/// Frees any resources used by the {}", e.ident).unwrap();
		writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", e.ident, e.ident).unwrap();
	}
	if is_clonable {
		writeln!(w, "/// Creates a copy of the {}", e.ident).unwrap();
		writeln!(w, "#[no_mangle]").unwrap();
		writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", e.ident, e.ident, e.ident).unwrap();
		writeln!(w, "\torig.clone()").unwrap();
		writeln!(w, "}}").unwrap();
	}
	w.write_all(&constr).unwrap();
	write_cpp_wrapper(cpp_headers, &format!("{}", e.ident), needs_free, None);
}

fn writeln_fn<'a, 'b, W: std::io::Write>(w: &mut W, f: &'a syn::ItemFn, types: &mut TypeResolver<'b, 'a>) {
	match export_status(&f.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
		ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
	}
	let mut gen_types = GenericTypes::new(None);
	if !gen_types.learn_generics(&f.sig.generics, types) { return; }

	writeln_fn_docs(w, &f.attrs, "", types, Some(&gen_types), f.sig.inputs.iter(), &f.sig.output);

	write!(w, "#[no_mangle]\npub extern \"C\" fn {}(", f.sig.ident).unwrap();


	write_method_params(w, &f.sig, "", types, Some(&gen_types), false, true);
	write!(w, " {{\n\t").unwrap();
	write_method_var_decl_body(w, &f.sig, "", types, Some(&gen_types), false);
	write!(w, "{}::{}", types.module_path, f.sig.ident).unwrap();

	let mut function_generic_args = Vec::new();
	maybe_write_generics(&mut function_generic_args, &f.sig.generics, &syn::PathArguments::None, types, true);
	if !function_generic_args.is_empty() {
		write!(w, "::{}", String::from_utf8(function_generic_args).unwrap()).unwrap();
	}
	write!(w, "(").unwrap();

	write_method_call_params(w, &f.sig, "", types, Some(&gen_types), "", false);
	writeln!(w, "\n}}\n").unwrap();
}

// ********************************
// *** File/Crate Walking Logic ***
// ********************************

fn convert_priv_mod<'a, 'b: 'a, W: std::io::Write>(w: &mut W, w_uses: &mut HashSet<String, NonRandomHash>, libast: &'b FullLibraryAST, crate_types: &CrateTypes<'b>, out_dir: &str, mod_path: &str, module: &'b syn::ItemMod) {
	// We want to ignore all items declared in this module (as they are not pub), but we still need
	// to give the ImportResolver any use statements, so we copy them here.
	let mut use_items = Vec::new();
	for item in module.content.as_ref().unwrap().1.iter() {
		if let syn::Item::Use(_) = item {
			use_items.push(item);
		}
	}
	let import_resolver = ImportResolver::from_borrowed_items(mod_path.splitn(2, "::").next().unwrap(), libast, mod_path, &use_items);
	let mut types = TypeResolver::new(mod_path, import_resolver, crate_types);

	writeln!(w, "mod {} {{\n{}", module.ident, DEFAULT_IMPORTS).unwrap();
	for item in module.content.as_ref().unwrap().1.iter() {
		match item {
			syn::Item::Mod(m) => convert_priv_mod(w, w_uses, libast, crate_types, out_dir, &format!("{}::{}", mod_path, module.ident), m),
			syn::Item::Impl(i) => {
				writeln_impl(w, w_uses, i, &mut types);
			},
			_ => {},
		}
	}
	writeln!(w, "}}").unwrap();
}

/// Do the Real Work of mapping an original file to C-callable wrappers. Creates a new file at
/// `out_path` and fills it with wrapper structs/functions to allow calling the things in the AST
/// at `module` from C.
fn convert_file<'a, 'b>(libast: &'a FullLibraryAST, crate_types: &CrateTypes<'a>, out_dir: &str, header_file: &mut File, cpp_header_file: &mut File) {
	for (module, astmod) in libast.modules.iter() {
		let orig_crate = module.splitn(2, "::").next().unwrap();
		let ASTModule { ref attrs, ref items, ref submods } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);

		let new_file_path = if submods.is_empty() {
			format!("{}/{}.rs", out_dir, module.replace("::", "/"))
		} else if module != "" {
			format!("{}/{}/mod.rs", out_dir, module.replace("::", "/"))
		} else {
			format!("{}/lib.rs", out_dir)
		};
		let _ = std::fs::create_dir((&new_file_path.as_ref() as &std::path::Path).parent().unwrap());
		let mut out = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
			.open(new_file_path).expect("Unable to open new src file");
		let mut out_uses = HashSet::default();

		writeln!(out, "// This file is Copyright its original authors, visible in version control").unwrap();
		writeln!(out, "// history and in the source files from which this was generated.").unwrap();
		writeln!(out, "//").unwrap();
		writeln!(out, "// This file is licensed under the license available in the LICENSE or LICENSE.md").unwrap();
		writeln!(out, "// file in the root of this repository or, if no such file exists, the same").unwrap();
		writeln!(out, "// license as that which applies to the original source files from which this").unwrap();
		writeln!(out, "// source was automatically generated.").unwrap();
		writeln!(out, "").unwrap();

		writeln_docs(&mut out, &attrs, "");

		if module == "" {
			// Special-case the top-level lib.rs with various lint allows and a pointer to the c_types
			// and bitcoin hand-written modules.
			writeln!(out, "//! C Bindings").unwrap();
			writeln!(out, "#![allow(unknown_lints)]").unwrap();
			writeln!(out, "#![allow(non_camel_case_types)]").unwrap();
			writeln!(out, "#![allow(non_snake_case)]").unwrap();
			writeln!(out, "#![allow(unused_imports)]").unwrap();
			writeln!(out, "#![allow(unused_variables)]").unwrap();
			writeln!(out, "#![allow(unused_mut)]").unwrap();
			writeln!(out, "#![allow(unused_parens)]").unwrap();
			writeln!(out, "#![allow(unused_unsafe)]").unwrap();
			writeln!(out, "#![allow(unused_braces)]").unwrap();
			// TODO: We need to map deny(missing_docs) in the source crate(s)
			//writeln!(out, "#![deny(missing_docs)]").unwrap();

			writeln!(out, "#![cfg_attr(not(feature = \"std\"), no_std)]").unwrap();
			writeln!(out, "#[cfg(not(any(feature = \"std\", feature = \"no-std\")))]").unwrap();
			writeln!(out, "compile_error!(\"at least one of the `std` or `no-std` features must be enabled\");").unwrap();
			writeln!(out, "extern crate alloc;").unwrap();

			writeln!(out, "pub mod version;").unwrap();
			writeln!(out, "pub mod c_types;").unwrap();
			writeln!(out, "pub mod bitcoin;").unwrap();
		} else {
			writeln!(out, "{}", DEFAULT_IMPORTS).unwrap();
		}

		for m in submods {
			writeln!(out, "pub mod {};", m).unwrap();
		}

		eprintln!("Converting {} entries...", module);

		let import_resolver = ImportResolver::new(orig_crate, libast, module, items);
		let mut type_resolver = TypeResolver::new(module, import_resolver, crate_types);

		for item in items.iter() {
			match item {
				syn::Item::Use(_) => {}, // Handled above
				syn::Item::Static(_) => {},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						writeln_enum(&mut out, &e, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Impl(i) => {
					writeln_impl(&mut out, &mut out_uses, &i, &mut type_resolver);
				},
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						writeln_struct(&mut out, &s, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Trait(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						writeln_trait(&mut out, &t, &mut type_resolver, header_file, cpp_header_file);
					}
				},
				syn::Item::Mod(m) => {
					convert_priv_mod(&mut out, &mut out_uses, libast, crate_types, out_dir, &format!("{}::{}", module, m.ident), m);
				},
				syn::Item::Const(c) => {
					// Re-export any primitive-type constants.
					if let syn::Visibility::Public(_) = c.vis {
						if let syn::Type::Path(p) = &*c.ty {
							let resolved_path = type_resolver.resolve_path(&p.path, None);
							if type_resolver.is_primitive(&resolved_path) {
								writeln_field_docs(&mut out, &c.attrs, "", &mut type_resolver, None, &*c.ty);
								writeln!(out, "\n#[no_mangle]").unwrap();
								writeln!(out, "pub static {}: {} = {}::{};", c.ident, resolved_path, module, c.ident).unwrap();
							}
						}
					}
				},
				syn::Item::Type(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
							ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
						}

						match &*t.ty {
							syn::Type::Path(p) => {
								let real_ty = type_resolver.resolve_path(&p.path, None);
								let real_generic_bounds = type_resolver.crate_types.opaques.get(&real_ty).map(|t| t.1).or(
									type_resolver.crate_types.priv_structs.get(&real_ty).map(|r| *r)).unwrap();
								let mut resolved_generics = t.generics.clone();

								// Assume blindly that the bounds in the struct definition where
								// clause matches any equivalent bounds on the type alias.
								assert!(resolved_generics.where_clause.is_none());
								resolved_generics.where_clause = real_generic_bounds.where_clause.clone();

								if let syn::PathArguments::AngleBracketed(real_generics) = &p.path.segments.last().unwrap().arguments {
									for (real_idx, real_param) in real_generics.args.iter().enumerate() {
										if let syn::GenericArgument::Type(syn::Type::Path(real_param_path)) = real_param {
											for param in resolved_generics.params.iter_mut() {
												if let syn::GenericParam::Type(type_param) = param {
													if Some(&type_param.ident) == real_param_path.path.get_ident() {
														if let syn::GenericParam::Type(real_type_param) = &real_generic_bounds.params[real_idx] {
															type_param.bounds = real_type_param.bounds.clone();
															type_param.default = real_type_param.default.clone();

														}
													}
												}
											}
										}
									}
								}

								writeln_opaque(&mut out, &t.ident, &format!("{}", t.ident), &resolved_generics, &t.attrs, &type_resolver, header_file, cpp_header_file)},
							_ => {}
						}
					}
				},
				syn::Item::Fn(f) => {
					if let syn::Visibility::Public(_) = f.vis {
						writeln_fn(&mut out, &f, &mut type_resolver);
					}
				},
				syn::Item::Macro(_) => {},
				syn::Item::Verbatim(_) => {},
				syn::Item::ExternCrate(_) => {},
				_ => unimplemented!(),
			}
		}

		for use_stmt in out_uses {
			writeln!(out, "{}", use_stmt).unwrap();
		}

		out.flush().unwrap();
	}
}


/// Walk the FullLibraryAST, determining if impl aliases need to be marked cloneable.
fn walk_ast_second_pass<'a>(ast_storage: &'a FullLibraryAST, crate_types: &CrateTypes<'a>) {
	for (module, astmod) in ast_storage.modules.iter() {
		let orig_crate = module.splitn(2, "::").next().unwrap();
		let ASTModule { ref attrs, ref items, .. } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);

		let import_resolver = ImportResolver::new(orig_crate, ast_storage, module, items);
		let mut types = TypeResolver::new(module, import_resolver, crate_types);

		for item in items.iter() {
			match item {
				syn::Item::Impl(i) => {
					match export_status(&i.attrs) {
						ExportStatus::Export => {},
						ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
					}
					if let Some(trait_path) = i.trait_.as_ref() {
						if path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) ||
						   path_matches_nongeneric(&trait_path.1, &["Clone"])
						{
							if let &syn::Type::Path(ref p) = &*i.self_ty {
								if let Some(resolved_path) = types.maybe_resolve_path(&p.path, None) {
									create_alias_for_impl(resolved_path, i, &mut types, |aliased_impl, types| {
										if let &syn::Type::Path(ref p) = &*aliased_impl.self_ty {
											if let Some(resolved_aliased_path) = types.maybe_resolve_path(&p.path, None) {
												crate_types.set_clonable("crate::".to_owned() + &resolved_aliased_path);
											}
										}
									});
								}
							}
						}
					}
				}
				_ => {}
			}
		}
	}
}

fn walk_private_mod<'a>(ast_storage: &'a FullLibraryAST, orig_crate: &str, module: String, items: &'a syn::ItemMod, crate_types: &mut CrateTypes<'a>) {
	let import_resolver = ImportResolver::new(orig_crate, ast_storage, &module, &items.content.as_ref().unwrap().1);
	for item in items.content.as_ref().unwrap().1.iter() {
		match item {
			syn::Item::Mod(m) => walk_private_mod(ast_storage, orig_crate, format!("{}::{}", module, m.ident), m, crate_types),
			syn::Item::Impl(i) => {
				if let &syn::Type::Path(ref p) = &*i.self_ty {
					if let Some(trait_path) = i.trait_.as_ref() {
						if let Some(tp) = import_resolver.maybe_resolve_path(&trait_path.1, None) {
							if let Some(sp) = import_resolver.maybe_resolve_path(&p.path, None) {
								match crate_types.trait_impls.entry(sp.clone()) {
									hash_map::Entry::Occupied(mut e) => { e.get_mut().push(tp.clone()); },
									hash_map::Entry::Vacant(e) => { e.insert(vec![tp.clone()]); },
								}
								match crate_types.traits_impld.entry(tp) {
									hash_map::Entry::Occupied(mut e) => { e.get_mut().push(sp); },
									hash_map::Entry::Vacant(e) => { e.insert(vec![sp]); },
								}
							}
						}
					}
				}
			},
			_ => {},
		}
	}
}

/// Walk the FullLibraryAST, deciding how things will be mapped and adding tracking to CrateTypes.
fn walk_ast_first_pass<'a>(ast_storage: &'a FullLibraryAST, crate_types: &mut CrateTypes<'a>) {
	for (module, astmod) in ast_storage.modules.iter() {
		let ASTModule { ref attrs, ref items, submods: _ } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);
		let orig_crate = module.splitn(2, "::").next().unwrap();
		let import_resolver = ImportResolver::new(orig_crate, ast_storage, module, items);

		for item in items.iter() {
			match item {
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						let struct_path = format!("{}::{}", module, s.ident);
						match export_status(&s.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => {
								crate_types.priv_structs.insert(struct_path, &s.generics);
								continue
							},
							ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
						}
						crate_types.opaques.insert(struct_path, (&s.ident, &s.generics));
					}
				},
				syn::Item::Trait(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export|ExportStatus::NotImplementable => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let trait_path = format!("{}::{}", module, t.ident);
						walk_supertraits!(t, None, (
							("Clone", _, _) => {
								crate_types.set_clonable("crate::".to_owned() + &trait_path);
							},
							(_, _, _) => {}
						) );
						crate_types.traits.insert(trait_path, &t);
					}
				},
				syn::Item::Type(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
							ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
						}
						let type_path = format!("{}::{}", module, t.ident);
						match &*t.ty {
							syn::Type::Path(p) => {
								// If its a path with no generics, assume we don't map the aliased type and map it opaque
								let args_obj = p.path.segments.last().unwrap().arguments.clone();
								match crate_types.reverse_alias_map.entry(import_resolver.maybe_resolve_path(&p.path, None).unwrap()) {
									hash_map::Entry::Occupied(mut e) => { e.get_mut().push((type_path.clone(), args_obj)); },
									hash_map::Entry::Vacant(e) => { e.insert(vec![(type_path.clone(), args_obj)]); },
								}

								crate_types.opaques.insert(type_path, (&t.ident, &t.generics));
							},
							_ => {
								crate_types.type_aliases.insert(type_path, import_resolver.resolve_imported_refs((*t.ty).clone()));
							}
						}
					}
				},
				syn::Item::Enum(e) if is_enum_opaque(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
							ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.opaques.insert(enum_path, (&e.ident, &e.generics));
					}
				},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
							ExportStatus::NotImplementable => panic!("(C-not implementable) must only appear on traits"),
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.mirrored_enums.insert(enum_path, &e);
					}
				},
				syn::Item::Impl(i) => {
					if let &syn::Type::Path(ref p) = &*i.self_ty {
						if let Some(trait_path) = i.trait_.as_ref() {
							if path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) ||
							   path_matches_nongeneric(&trait_path.1, &["Clone"]) {
								if let Some(full_path) = import_resolver.maybe_resolve_path(&p.path, None) {
									crate_types.set_clonable("crate::".to_owned() + &full_path);
								}
							}
							if let Some(tp) = import_resolver.maybe_resolve_path(&trait_path.1, None) {
								if let Some(sp) = import_resolver.maybe_resolve_path(&p.path, None) {
									match crate_types.trait_impls.entry(sp.clone()) {
										hash_map::Entry::Occupied(mut e) => { e.get_mut().push(tp.clone()); },
										hash_map::Entry::Vacant(e) => { e.insert(vec![tp.clone()]); },
									}
									match crate_types.traits_impld.entry(tp) {
										hash_map::Entry::Occupied(mut e) => { e.get_mut().push(sp); },
										hash_map::Entry::Vacant(e) => { e.insert(vec![sp]); },
									}
								}
							}
						}
					}
				},
				syn::Item::Mod(m) => walk_private_mod(ast_storage, orig_crate, format!("{}::{}", module, m.ident), m, crate_types),
				_ => {},
			}
		}
	}
}

fn main() {
	let args: Vec<String> = env::args().collect();
	if args.len() != 5 {
		eprintln!("Usage: target/dir derived_templates.rs extra/includes.h extra/cpp/includes.hpp");
		process::exit(1);
	}

	let mut derived_templates = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[2]).expect("Unable to open new header file");
	writeln!(&mut derived_templates, "{}", DEFAULT_IMPORTS).unwrap();
	let mut header_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[3]).expect("Unable to open new header file");
	let mut cpp_header_file = std::fs::OpenOptions::new().write(true).create(true).truncate(true)
		.open(&args[4]).expect("Unable to open new header file");

	writeln!(header_file, "#if defined(__GNUC__)").unwrap();
	writeln!(header_file, "#define MUST_USE_STRUCT __attribute__((warn_unused))").unwrap();
	writeln!(header_file, "#define MUST_USE_RES __attribute__((warn_unused_result))").unwrap();
	writeln!(header_file, "#else").unwrap();
	writeln!(header_file, "#define MUST_USE_STRUCT").unwrap();
	writeln!(header_file, "#define MUST_USE_RES").unwrap();
	writeln!(header_file, "#endif").unwrap();
	writeln!(header_file, "#if defined(__clang__)").unwrap();
	writeln!(header_file, "#define NONNULL_PTR _Nonnull").unwrap();
	writeln!(header_file, "#else").unwrap();
	writeln!(header_file, "#define NONNULL_PTR").unwrap();
	writeln!(header_file, "#endif").unwrap();
	writeln!(cpp_header_file, "#include <string.h>\nnamespace LDK {{").unwrap();

	// Write a few manually-defined types into the C++ header file
	write_cpp_wrapper(&mut cpp_header_file, "Str", true, None);

	// First parse the full crate's ASTs, caching them so that we can hold references to the AST
	// objects in other datastructures:
	let mut lib_src = String::new();
	std::io::stdin().lock().read_to_string(&mut lib_src).unwrap();
	let lib_syntax = syn::parse_file(&lib_src).expect("Unable to parse file");
	let libast = FullLibraryAST::load_lib(lib_syntax);

	// ...then walk the ASTs tracking what types we will map, and how, so that we can resolve them
	// when parsing other file ASTs...
	let mut libtypes = CrateTypes::new(&mut derived_templates, &libast);
	walk_ast_first_pass(&libast, &mut libtypes);

	// ... using the generated data, determine a few additional fields, specifically which type
	// aliases are to be clone-able...
	walk_ast_second_pass(&libast, &libtypes);

	// ... finally, do the actual file conversion/mapping, writing out types as we go.
	convert_file(&libast, &libtypes, &args[1], &mut header_file, &mut cpp_header_file);

	// For container templates which we created while walking the crate, make sure we add C++
	// mapped types so that C++ users can utilize the auto-destructors available.
	for (ty, has_destructor) in libtypes.templates_defined.borrow().iter() {
		write_cpp_wrapper(&mut cpp_header_file, ty, *has_destructor, None);
	}
	writeln!(cpp_header_file, "}}").unwrap();

	header_file.flush().unwrap();
	cpp_header_file.flush().unwrap();
	derived_templates.flush().unwrap();
}
