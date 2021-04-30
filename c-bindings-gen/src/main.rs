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

use std::collections::{HashMap, hash_map};
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

use proc_macro2::Span;
use quote::format_ident;
use syn::parse_quote;

mod types;
mod blocks;
use types::*;
use blocks::*;

const DEFAULT_IMPORTS: &'static str = "\nuse std::str::FromStr;\nuse std::ffi::c_void;\nuse bitcoin::hashes::Hash;\nuse crate::c_types::*;\n";

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
			if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
				for_obj = format!("{}", ident);
				full_obj_path = for_obj.clone();
				has_inner = types.c_type_has_inner_from_path(&types.resolve_path(&p.path, Some(generics)));
			} else { return; }
		} else {
			// We assume that anything that isn't a Path is somehow a generic that ends up in our
			// derived-types module.
			let mut for_obj_vec = Vec::new();
			types.write_c_type(&mut for_obj_vec, for_ty, Some(generics), false);
			full_obj_path = String::from_utf8(for_obj_vec).unwrap();
			assert!(full_obj_path.starts_with(TypeResolver::generated_container_path()));
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
			"lightning::util::ser::Readable"|"lightning::util::ser::ReadableArgs" => {
				// Create the Result<Object, DecodeError> syn::Type
				let res_ty: syn::Type = parse_quote!(Result<#for_ty, ::ln::msgs::DecodeError>);

				writeln!(w, "#[no_mangle]").unwrap();
				writeln!(w, "/// Read a {} from a byte array, created by {}_write", for_obj, for_obj).unwrap();
				write!(w, "pub extern \"C\" fn {}_read(ser: crate::c_types::u8slice", for_obj).unwrap();

				let mut arg_conv = Vec::new();
				if t == "lightning::util::ser::ReadableArgs" {
					write!(w, ", arg: ").unwrap();
					assert!(trait_path.leading_colon.is_none());
					let args_seg = trait_path.segments.iter().last().unwrap();
					assert_eq!(format!("{}", args_seg.ident), "ReadableArgs");
					if let syn::PathArguments::AngleBracketed(args) = &args_seg.arguments {
						assert_eq!(args.args.len(), 1);
						if let syn::GenericArgument::Type(args_ty) = args.args.iter().next().unwrap() {
							types.write_c_type(w, args_ty, Some(generics), false);

							assert!(!types.write_from_c_conversion_new_var(&mut arg_conv, &format_ident!("arg"), &args_ty, Some(generics)));

							write!(&mut arg_conv, "\tlet arg_conv = ").unwrap();
							types.write_from_c_conversion_prefix(&mut arg_conv, &args_ty, Some(generics));
							write!(&mut arg_conv, "arg").unwrap();
							types.write_from_c_conversion_suffix(&mut arg_conv, &args_ty, Some(generics));
						} else { unreachable!(); }
					} else { unreachable!(); }
				}
				write!(w, ") -> ").unwrap();
				types.write_c_type(w, &res_ty, Some(generics), false);
				writeln!(w, " {{").unwrap();

				if t == "lightning::util::ser::ReadableArgs" {
					w.write(&arg_conv).unwrap();
					write!(w, ";\n\tlet res: ").unwrap();
					// At least in one case we need type annotations here, so provide them.
					types.write_rust_type(w, Some(generics), &res_ty);
					writeln!(w, " = crate::c_types::deserialize_obj_arg(ser, arg_conv);").unwrap();
				} else {
					writeln!(w, "\tlet res = crate::c_types::deserialize_obj(ser);").unwrap();
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
eprintln!("{}", trait_path);
	match trait_path {
		"lightning::util::ser::Writeable" => {
			writeln!(w, "impl {} for {} {{", trait_path, for_obj).unwrap();
			writeln!(w, "\tfn write<W: lightning::util::ser::Writer>(&self, w: &mut W) -> Result<(), ::std::io::Error> {{").unwrap();
			writeln!(w, "\t\tlet vec = (self.write)(self.this_arg);").unwrap();
			writeln!(w, "\t\tw.write_all(vec.as_slice())").unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		_ => panic!(),
	}
}

// *******************************
// *** Per-Type Printing Logic ***
// *******************************

macro_rules! walk_supertraits { ($t: expr, $types: expr, ($( $pat: pat => $e: expr),*) ) => { {
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
							match (&path as &str, &supertrait.path.segments.iter().last().unwrap().ident) {
								$( $pat => $e, )*
							}
							continue;
						}
					}
					if let Some(ident) = supertrait.path.get_ident() {
						match (&format!("{}", ident) as &str, &ident) {
							$( $pat => $e, )*
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

/// Prints a C-mapped trait object containing a void pointer and a jump table for each function in
/// the original trait.
/// Implements the native Rust trait and relevant parent traits for the new C-mapped trait.
///
/// Finally, implements Deref<MappedTrait> for MappedTrait which allows its use in types which need
/// a concrete Deref to the Rust trait.
fn writeln_trait<'a, 'b, W: std::io::Write>(w: &mut W, t: &'a syn::ItemTrait, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	let trait_name = format!("{}", t.ident);
	match export_status(&t.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}
	writeln_docs(w, &t.attrs, "");

	let mut gen_types = GenericTypes::new(None);
	assert!(gen_types.learn_generics(&t.generics, types));
	gen_types.learn_associated_types(&t, types);

	writeln!(w, "#[repr(C)]\npub struct {} {{", trait_name).unwrap();
	writeln!(w, "\t/// An opaque pointer which is passed to your function implementations as an argument.").unwrap();
	writeln!(w, "\t/// This has no meaning in the LDK, and can be NULL or any other value.").unwrap();
	writeln!(w, "\tpub this_arg: *mut c_void,").unwrap();
	let mut generated_fields = Vec::new(); // Every field's (name, is_clonable) except this_arg, used in Clone generation
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
				}
				if m.default.is_some() { unimplemented!(); }

				let mut meth_gen_types = gen_types.push_ctx();
				assert!(meth_gen_types.learn_generics(&m.sig.generics, types));

				writeln_docs(w, &m.attrs, "\t");

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
						write!(w, "\tpub {}: ", m.sig.ident).unwrap();
						generated_fields.push((format!("{}", m.sig.ident), true));
						types.write_c_type(w, &*r.elem, Some(&meth_gen_types), false);
						writeln!(w, ",").unwrap();
						writeln!(w, "\t/// Fill in the {} field as a reference to it will be given to Rust after this returns", m.sig.ident).unwrap();
						writeln!(w, "\t/// Note that this takes a pointer to this object, not the this_ptr like other methods do").unwrap();
						writeln!(w, "\t/// This function pointer may be NULL if {} is filled in when this object is created and never needs updating.", m.sig.ident).unwrap();
						writeln!(w, "\tpub set_{}: Option<extern \"C\" fn(&{})>,", m.sig.ident, trait_name).unwrap();
						generated_fields.push((format!("set_{}", m.sig.ident), true));
						// Note that cbindgen will now generate
						// typedef struct Thing {..., set_thing: (const Thing*), ...} Thing;
						// which does not compile since Thing is not defined before it is used.
						writeln!(extra_headers, "struct LDK{};", trait_name).unwrap();
						writeln!(extra_headers, "typedef struct LDK{} LDK{};", trait_name, trait_name).unwrap();
						continue;
					}
					// Sadly, this currently doesn't do what we want, but it should be easy to get
					// cbindgen to support it. See https://github.com/eqrion/cbindgen/issues/531
					writeln!(w, "\t#[must_use]").unwrap();
				}

				write!(w, "\tpub {}: extern \"C\" fn (", m.sig.ident).unwrap();
				generated_fields.push((format!("{}", m.sig.ident), true));
				write_method_params(w, &m.sig, "c_void", types, Some(&meth_gen_types), true, false);
				writeln!(w, ",").unwrap();
			},
			&syn::TraitItem::Type(_) => {},
			_ => unimplemented!(),
		}
	}
	// Add functions which may be required for supertrait implementations.
	let mut requires_clone = false;
	walk_supertraits!(t, Some(&types), (
		("Clone", _) => requires_clone = true,
		(_, _) => {}
	) );
	walk_supertraits!(t, Some(&types), (
		("Clone", _) => {
			writeln!(w, "\t/// Creates a copy of the object pointed to by this_arg, for a copy of this {}.", trait_name).unwrap();
			writeln!(w, "\t/// Note that the ultimate copy of the {} will have all function pointers the same as the original.", trait_name).unwrap();
			writeln!(w, "\t/// May be NULL if no action needs to be taken, the this_arg pointer will be copied into the new {}.", trait_name).unwrap();
			writeln!(w, "\tpub clone: Option<extern \"C\" fn (this_arg: *const c_void) -> *mut c_void>,").unwrap();
			generated_fields.push(("clone".to_owned(), true));
		},
		("std::cmp::Eq", _) => {
			writeln!(w, "\t/// Checks if two objects are equal given this object's this_arg pointer and another object.").unwrap();
			writeln!(w, "\tpub eq: extern \"C\" fn (this_arg: *const c_void, other_arg: &{}) -> bool,", trait_name).unwrap();
			writeln!(extra_headers, "typedef struct LDK{} LDK{};", trait_name, trait_name).unwrap();
			generated_fields.push(("eq".to_owned(), true));
		},
		("std::hash::Hash", _) => {
			writeln!(w, "\t/// Calculate a succinct non-cryptographic hash for an object given its this_arg pointer.").unwrap();
			writeln!(w, "\t/// This is used, for example, for inclusion of this object in a hash map.").unwrap();
			writeln!(w, "\tpub hash: extern \"C\" fn (this_arg: *const c_void) -> u64,").unwrap();
			generated_fields.push(("hash".to_owned(), true));
		},
		("Send", _) => {}, ("Sync", _) => {},
		(s, i) => {
			generated_fields.push(if types.crate_types.traits.get(s).is_none() {
				let (docs, name, ret) = convert_trait_impl_field(s);
				writeln!(w, "\t/// {}", docs).unwrap();
				writeln!(w, "\tpub {}: extern \"C\" fn (this_arg: *const c_void) -> {},", name, ret).unwrap();
				(name, true) // Assume clonable
			} else {
				// For in-crate supertraits, just store a C-mapped copy of the supertrait as a member.
				writeln!(w, "\t/// Implementation of {} for this object.", i).unwrap();
				writeln!(w, "\tpub {}: crate::{},", i, s).unwrap();
				let is_clonable = types.is_clonable(s);
				if !is_clonable && requires_clone {
					writeln!(w, "\t/// Creates a copy of the {}, for a copy of this {}.", i, trait_name).unwrap();
					writeln!(w, "\t/// Because {} doesn't natively support copying itself, you have to provide a full copy implementation here.", i).unwrap();
					writeln!(w, "\tpub {}_clone: extern \"C\" fn (orig_{}: &{}) -> {},", i, i, i, i).unwrap();
				}
				(format!("{}", i), is_clonable)
			});
		}
	) );
	writeln!(w, "\t/// Frees any resources associated with this object given its this_arg pointer.").unwrap();
	writeln!(w, "\t/// Does not need to free the outer struct containing function pointers and may be NULL is no resources need to be freed.").unwrap();
	writeln!(w, "\tpub free: Option<extern \"C\" fn(this_arg: *mut c_void)>,").unwrap();
	generated_fields.push(("free".to_owned(), true));
	writeln!(w, "}}").unwrap();

	macro_rules! impl_trait_for_c {
		($t: expr, $impl_accessor: expr, $type_resolver: expr) => {
			for item in $t.items.iter() {
				match item {
					syn::TraitItem::Method(m) => {
						if let ExportStatus::TestOnly = export_status(&m.attrs) { continue; }
						if m.default.is_some() { unimplemented!(); }
						if m.sig.constness.is_some() || m.sig.asyncness.is_some() || m.sig.unsafety.is_some() ||
								m.sig.abi.is_some() || m.sig.variadic.is_some() {
							unimplemented!();
						}
						let mut meth_gen_types = gen_types.push_ctx();
						assert!(meth_gen_types.learn_generics(&m.sig.generics, $type_resolver));
						write!(w, "\tfn {}", m.sig.ident).unwrap();
						$type_resolver.write_rust_generic_param(w, Some(&meth_gen_types), m.sig.generics.params.iter());
						write!(w, "(").unwrap();
						for inp in m.sig.inputs.iter() {
							match inp {
								syn::FnArg::Receiver(recv) => {
									if !recv.attrs.is_empty() || recv.reference.is_none() { unimplemented!(); }
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
									if !arg.attrs.is_empty() { unimplemented!(); }
									match &*arg.pat {
										syn::Pat::Ident(ident) => {
											if !ident.attrs.is_empty() || ident.by_ref.is_some() ||
													ident.mutability.is_some() || ident.subpat.is_some() {
												unimplemented!();
											}
											write!(w, ", {}{}: ", if $type_resolver.skip_arg(&*arg.ty, Some(&meth_gen_types)) { "_" } else { "" }, ident.ident).unwrap();
										}
										_ => unimplemented!(),
									}
									$type_resolver.write_rust_type(w, Some(&meth_gen_types), &*arg.ty);
								}
							}
						}
						write!(w, ")").unwrap();
						match &m.sig.output {
							syn::ReturnType::Type(_, rtype) => {
								write!(w, " -> ").unwrap();
								$type_resolver.write_rust_type(w, Some(&meth_gen_types), &*rtype)
							},
							_ => {},
						}
						write!(w, " {{\n\t\t").unwrap();
						match export_status(&m.attrs) {
							ExportStatus::NoExport => {
								unimplemented!();
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
								write!(w, "self{}.{}", $impl_accessor, m.sig.ident).unwrap();
								$type_resolver.write_from_c_conversion_to_ref_suffix(w, &*r.elem, Some(&meth_gen_types));
								writeln!(w, "\n\t}}").unwrap();
								continue;
							}
						}
						write_method_var_decl_body(w, &m.sig, "\t", $type_resolver, Some(&meth_gen_types), true);
						write!(w, "(self{}.{})(", $impl_accessor, m.sig.ident).unwrap();
						write_method_call_params(w, &m.sig, "\t", $type_resolver, Some(&meth_gen_types), "", true);

						writeln!(w, "\n\t}}").unwrap();
					},
					&syn::TraitItem::Type(ref t) => {
						if t.default.is_some() || t.generics.lt_token.is_some() { unimplemented!(); }
						let mut bounds_iter = t.bounds.iter();
						match bounds_iter.next().unwrap() {
							syn::TypeParamBound::Trait(tr) => {
								writeln!(w, "\ttype {} = crate::{};", t.ident, $type_resolver.resolve_path(&tr.path, Some(&gen_types))).unwrap();
							},
							_ => unimplemented!(),
						}
						if bounds_iter.next().is_some() { unimplemented!(); }
					},
					_ => unimplemented!(),
				}
			}
		}
	}


	// Implement supertraits for the C-mapped struct.
	walk_supertraits!(t, Some(&types), (
		("Send", _) => writeln!(w, "unsafe impl Send for {} {{}}", trait_name).unwrap(),
		("Sync", _) => writeln!(w, "unsafe impl Sync for {} {{}}", trait_name).unwrap(),
		("std::cmp::Eq", _) => {
			writeln!(w, "impl std::cmp::Eq for {} {{}}", trait_name).unwrap();
			writeln!(w, "impl std::cmp::PartialEq for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn eq(&self, o: &Self) -> bool {{ (self.eq)(self.this_arg, o) }}\n}}").unwrap();
		},
		("std::hash::Hash", _) => {
			writeln!(w, "impl std::hash::Hash for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {{ hasher.write_u64((self.hash)(self.this_arg)) }}\n}}").unwrap();
		},
		("Clone", _) => {
			writeln!(w, "#[no_mangle]").unwrap();
			writeln!(w, "/// Creates a copy of a {}", trait_name).unwrap();
			writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", trait_name, trait_name, trait_name).unwrap();
			writeln!(w, "\t{} {{", trait_name).unwrap();
			writeln!(w, "\t\tthis_arg: if let Some(f) = orig.clone {{ (f)(orig.this_arg) }} else {{ orig.this_arg }},").unwrap();
			for (field, clonable) in generated_fields.iter() {
				if *clonable {
					writeln!(w, "\t\t{}: Clone::clone(&orig.{}),", field, field).unwrap();
				} else {
					writeln!(w, "\t\t{}: (orig.{}_clone)(&orig.{}),", field, field, field).unwrap();
					writeln!(w, "\t\t{}_clone: orig.{}_clone,", field, field).unwrap();
				}
			}
			writeln!(w, "\t}}\n}}").unwrap();
			writeln!(w, "impl Clone for {} {{", trait_name).unwrap();
			writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
			writeln!(w, "\t\t{}_clone(self)", trait_name).unwrap();
			writeln!(w, "\t}}\n}}").unwrap();
		},
		(s, i) => {
			if let Some(supertrait) = types.crate_types.traits.get(s) {
				let mut module_iter = s.rsplitn(2, "::");
				module_iter.next().unwrap();
				let supertrait_module = module_iter.next().unwrap();
				let imports = ImportResolver::new(supertrait_module.splitn(2, "::").next().unwrap(), &types.crate_types.lib_ast.dependencies,
					supertrait_module, &types.crate_types.lib_ast.modules.get(supertrait_module).unwrap().items);
				let resolver = TypeResolver::new(&supertrait_module, imports, types.crate_types);
				writeln!(w, "impl {} for {} {{", s, trait_name).unwrap();
				impl_trait_for_c!(supertrait, format!(".{}", i), &resolver);
				writeln!(w, "}}").unwrap();
				walk_supertraits!(supertrait, Some(&types), (
					("Send", _) => writeln!(w, "unsafe impl Send for {} {{}}", trait_name).unwrap(),
					("Sync", _) => writeln!(w, "unsafe impl Sync for {} {{}}", trait_name).unwrap(),
					_ => unimplemented!()
				) );
			} else {
				do_write_impl_trait(w, s, i, &trait_name);
			}
		}
	) );

	// Finally, implement the original Rust trait for the newly created mapped trait.
	writeln!(w, "\nuse {}::{} as rust{};", types.module_path, t.ident, trait_name).unwrap();
	write!(w, "impl rust{}", t.ident).unwrap();
	maybe_write_generics(w, &t.generics, types, false);
	writeln!(w, " for {} {{", trait_name).unwrap();
	impl_trait_for_c!(t, "", types);
	writeln!(w, "}}\n").unwrap();
	writeln!(w, "// We're essentially a pointer already, or at least a set of pointers, so allow us to be used").unwrap();
	writeln!(w, "// directly as a Deref trait in higher-level structs:").unwrap();
	writeln!(w, "impl std::ops::Deref for {} {{\n\ttype Target = Self;", trait_name).unwrap();
	writeln!(w, "\tfn deref(&self) -> &Self {{\n\t\tself\n\t}}\n}}").unwrap();

	writeln!(w, "/// Calls the free function if one is set").unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", trait_name, trait_name).unwrap();
	writeln!(w, "impl Drop for {} {{", trait_name).unwrap();
	writeln!(w, "\tfn drop(&mut self) {{").unwrap();
	writeln!(w, "\t\tif let Some(f) = self.free {{").unwrap();
	writeln!(w, "\t\t\tf(self.this_arg);").unwrap();
	writeln!(w, "\t\t}}\n\t}}\n}}").unwrap();

	write_cpp_wrapper(cpp_headers, &trait_name, true);
}

/// Write out a simple "opaque" type (eg structs) which contain a pointer to the native Rust type
/// and a flag to indicate whether Drop'ing the mapped struct drops the underlying Rust type.
///
/// Also writes out a _free function and a C++ wrapper which handles calling _free.
fn writeln_opaque<W: std::io::Write>(w: &mut W, ident: &syn::Ident, struct_name: &str, generics: &syn::Generics, attrs: &[syn::Attribute], types: &TypeResolver, extra_headers: &mut File, cpp_headers: &mut File) {
	// If we directly read the original type by its original name, cbindgen hits
	// https://github.com/eqrion/cbindgen/issues/286 Thus, instead, we import it as a temporary
	// name and then reference it by that name, which works around the issue.
	write!(w, "\nuse {}::{} as native{}Import;\ntype native{} = native{}Import", types.module_path, ident, ident, ident, ident).unwrap();
	maybe_write_generics(w, &generics, &types, true);
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
	writeln!(w, "\t\t\tlet _ = unsafe {{ Box::from_raw(self.inner) }};\n\t\t}}\n\t}}\n}}").unwrap();
	writeln!(w, "/// Frees any resources used by the {}, if is_owned is set and inner is non-NULL.", struct_name).unwrap();
	writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_obj: {}) {{ }}", struct_name, struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "/// Used only if an object of this type is returned as a trait impl by a method").unwrap();
	writeln!(w, "extern \"C\" fn {}_free_void(this_ptr: *mut c_void) {{", struct_name).unwrap();
	writeln!(w, "\tunsafe {{ let _ = Box::from_raw(this_ptr as *mut native{}); }}\n}}", struct_name).unwrap();
	writeln!(w, "#[allow(unused)]").unwrap();
	writeln!(w, "/// When moving out of the pointer, we have to ensure we aren't a reference, this makes that easy").unwrap();
	writeln!(w, "impl {} {{", struct_name).unwrap();
	writeln!(w, "\tpub(crate) fn take_inner(mut self) -> *mut native{} {{", struct_name).unwrap();
	writeln!(w, "\t\tassert!(self.is_owned);").unwrap();
	writeln!(w, "\t\tlet ret = self.inner;").unwrap();
	writeln!(w, "\t\tself.inner = std::ptr::null_mut();").unwrap();
	writeln!(w, "\t\tret").unwrap();
	writeln!(w, "\t}}\n}}").unwrap();

	// Implement the conversion into rust as owned object, as reference and as mut reference.
	// We can also get a 'static reference by taking the inner ptr and consuming the struct
	writeln!(w, "impl crate::c_types::mapping::IntoRust<native{}> for {} {{", struct_name, struct_name).unwrap();
	writeln!(w, "\tfn into_rust_owned(self) -> native{} {{ *unsafe {{ Box::from_raw(self.take_inner()) }} }}", struct_name).unwrap();
	writeln!(w, "}}").unwrap();
	writeln!(w, "impl crate::c_types::mapping::IntoRustRef<native{}> for {} {{", struct_name, struct_name).unwrap();
	writeln!(w, "\tfn into_rust_ref(&self) -> &native{} {{ unsafe {{ &*self.inner }} }}", struct_name).unwrap();
	writeln!(w, "}}").unwrap();
	writeln!(w, "impl crate::c_types::mapping::IntoRust<&'static native{}> for {} {{", struct_name, struct_name).unwrap();
	writeln!(w, "\tfn into_rust_owned(mut self) -> &'static native{} {{ unsafe {{ &*self.take_inner() }} }}", struct_name).unwrap();
	writeln!(w, "}}").unwrap();
	writeln!(w, "impl crate::c_types::mapping::IntoRustRefMut<native{}> for {} {{", struct_name, struct_name).unwrap();
	writeln!(w, "\tfn into_rust_ref_mut(&self) -> &mut native{} {{ unsafe {{ &mut *self.inner }} }}", struct_name).unwrap();
	writeln!(w, "}}").unwrap();
	writeln!(w, "impl crate::c_types::mapping::IntoRust<&'static mut native{}> for {} {{", struct_name, struct_name).unwrap();
	writeln!(w, "\tfn into_rust_owned(mut self) -> &'static mut native{} {{ unsafe {{ &mut *self.take_inner() }} }}", struct_name).unwrap();
	writeln!(w, "}}").unwrap();

	write_cpp_wrapper(cpp_headers, &format!("{}", ident), true);
}

/// Writes out all the relevant mappings for a Rust struct, deferring to writeln_opaque to generate
/// the struct itself, and then writing getters and setters for public, understood-type fields and
/// a constructor if every field is public.
fn writeln_struct<'a, 'b, W: std::io::Write>(w: &mut W, s: &'a syn::ItemStruct, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	if export_status(&s.attrs) != ExportStatus::Export { return; }

	let struct_name = &format!("{}", s.ident);
	writeln_opaque(w, &s.ident, struct_name, &s.generics, &s.attrs, types, extra_headers, cpp_headers);

	if let syn::Fields::Named(fields) = &s.fields {
		let mut self_path_segs = syn::punctuated::Punctuated::new();
		self_path_segs.push(s.ident.clone().into());
		let self_path = syn::Path { leading_colon: None, segments: self_path_segs};
		let mut gen_types = GenericTypes::new(Some((types.resolve_path(&self_path, None), &self_path)));
		assert!(gen_types.learn_generics(&s.generics, types));

		let mut all_fields_settable = true;
		for field in fields.named.iter() {
			if let syn::Visibility::Public(_) = field.vis {
				let export = export_status(&field.attrs);
				match export {
					ExportStatus::Export => {},
					ExportStatus::NoExport|ExportStatus::TestOnly => {
						all_fields_settable = false;
						continue
					},
				}

				if let Some(ident) = &field.ident {
					let ref_type = syn::Type::Reference(syn::TypeReference {
						and_token: syn::Token!(&)(Span::call_site()), lifetime: None, mutability: None,
						elem: Box::new(field.ty.clone()) });
					if types.understood_c_type(&ref_type, Some(&gen_types)) {
						writeln_docs(w, &field.attrs, "");
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_get_{}(this_ptr: &{}) -> ", struct_name, ident, struct_name).unwrap();
						types.write_c_type(w, &ref_type, Some(&gen_types), true);
						write!(w, " {{\n\tlet mut inner_val = &mut unsafe {{ &mut *this_ptr.inner }}.{};\n\t", ident).unwrap();
						let local_var = types.write_to_c_conversion_new_var(w, &format_ident!("inner_val"), &ref_type, Some(&gen_types), true);
						if local_var { write!(w, "\n\t").unwrap(); }
						types.write_to_c_conversion_inline_prefix(w, &ref_type, Some(&gen_types), true);
						write!(w, "inner_val").unwrap();
						types.write_to_c_conversion_inline_suffix(w, &ref_type, Some(&gen_types), true);
						writeln!(w, "\n}}").unwrap();
					}

					if types.understood_c_type(&field.ty, Some(&gen_types)) {
						writeln_docs(w, &field.attrs, "");
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_set_{}(this_ptr: &mut {}, mut val: ", struct_name, ident, struct_name).unwrap();
						types.write_c_type(w, &field.ty, Some(&gen_types), false);
						write!(w, ") {{\n\t").unwrap();
						let local_var = types.write_from_c_conversion_new_var(w, &format_ident!("val"), &field.ty, Some(&gen_types));
						if local_var { write!(w, "\n\t").unwrap(); }
						write!(w, "unsafe {{ &mut *this_ptr.inner }}.{} = ", ident).unwrap();
						types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
						write!(w, "val").unwrap();
						types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
						writeln!(w, ";\n}}").unwrap();
					} else { all_fields_settable = false; }
				} else { all_fields_settable = false; }
			} else { all_fields_settable = false; }
		}

		if all_fields_settable {
			// Build a constructor!
			writeln!(w, "/// Constructs a new {} given each field", struct_name).unwrap();
			write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_new(", struct_name).unwrap();
			for (idx, field) in fields.named.iter().enumerate() {
				if idx != 0 { write!(w, ", ").unwrap(); }
				write!(w, "mut {}_arg: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_c_type(w, &field.ty, Some(&gen_types), false);
			}
			write!(w, ") -> {} {{\n\t", struct_name).unwrap();
			for field in fields.named.iter() {
				let field_ident = format_ident!("{}_arg", field.ident.as_ref().unwrap());
				if types.write_from_c_conversion_new_var(w, &field_ident, &field.ty, Some(&gen_types)) {
					write!(w, "\n\t").unwrap();
				}
			}
			writeln!(w, "{} {{ inner: Box::into_raw(Box::new(native{} {{", struct_name, s.ident).unwrap();
			for field in fields.named.iter() {
				write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_from_c_conversion_prefix(w, &field.ty, Some(&gen_types));
				write!(w, "{}_arg", field.ident.as_ref().unwrap()).unwrap();
				types.write_from_c_conversion_suffix(w, &field.ty, Some(&gen_types));
				writeln!(w, ",").unwrap();
			}
			writeln!(w, "\t}})), is_owned: true }}\n}}").unwrap();
		}
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
fn writeln_impl<W: std::io::Write>(w: &mut W, i: &syn::ItemImpl, types: &mut TypeResolver) {
	match export_status(&i.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
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
		if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
			if let Some(resolved_path) = types.maybe_resolve_non_ignored_ident(&ident) {
				let mut gen_types = GenericTypes::new(Some((resolved_path.clone(), &p.path)));
				if !gen_types.learn_generics(&i.generics, types) {
					eprintln!("Not implementing anything for impl {} due to not understood generics", ident);
					return;
				}

				if i.defaultness.is_some() || i.unsafety.is_some() { unimplemented!(); }
				if let Some(trait_path) = i.trait_.as_ref() {
					if trait_path.0.is_some() { unimplemented!(); }
					if types.understood_c_path(&trait_path.1) {
						let full_trait_path = types.resolve_path(&trait_path.1, None);
						let trait_obj = *types.crate_types.traits.get(&full_trait_path).unwrap();
						// We learn the associated types maping from the original trait object.
						// That's great, except that they are unresolved idents, so if we learn
						// mappings from a trai defined in a different file, we may mis-resolve or
						// fail to resolve the mapped types.
						gen_types.learn_associated_types(trait_obj, types);
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
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => return,
						}

						// For cases where we have a concrete native object which implements a
						// trait and need to return the C-mapped version of the trait, provide a
						// From<> implementation which does all the work to ensure free is handled
						// properly. This way we can call this method from deep in the
						// type-conversion logic without actually knowing the concrete native type.
						writeln!(w, "impl From<native{}> for crate::{} {{", ident, full_trait_path).unwrap();
						writeln!(w, "\tfn from(obj: native{}) -> Self {{", ident).unwrap();
						writeln!(w, "\t\tlet mut rust_obj = {} {{ inner: Box::into_raw(Box::new(obj)), is_owned: true }};", ident).unwrap();
						writeln!(w, "\t\tlet mut ret = {}_as_{}(&rust_obj);", ident, trait_obj.ident).unwrap();
						writeln!(w, "\t\t// We want to free rust_obj when ret gets drop()'d, not rust_obj, so wipe rust_obj's pointer and set ret's free() fn").unwrap();
						writeln!(w, "\t\trust_obj.inner = std::ptr::null_mut();").unwrap();
						writeln!(w, "\t\tret.free = Some({}_free_void);", ident).unwrap();
						writeln!(w, "\t\tret\n\t}}\n}}").unwrap();

						writeln!(w, "/// Constructs a new {} which calls the relevant methods on this_arg.", trait_obj.ident).unwrap();
						writeln!(w, "/// This copies the `inner` pointer in this_arg and thus the returned {} must be freed before this_arg is", trait_obj.ident).unwrap();
						write!(w, "#[no_mangle]\npub extern \"C\" fn {}_as_{}(this_arg: &{}) -> crate::{} {{\n", ident, trait_obj.ident, ident, full_trait_path).unwrap();
						writeln!(w, "\tcrate::{} {{", full_trait_path).unwrap();
						writeln!(w, "\t\tthis_arg: unsafe {{ (*this_arg).inner as *mut c_void }},").unwrap();
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
								}

								let mut printed = false;
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										write!(w, "\n\t\t{}{}: ", $indent, $m.sig.ident).unwrap();
										types.write_empty_rust_val(Some(&gen_types), w, &*r.elem);
										writeln!(w, ",\n{}\t\tset_{}: Some({}_{}_set_{}),", $indent, $m.sig.ident, ident, $trait.ident, $m.sig.ident).unwrap();
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
							("Clone", _) => requires_clone = true,
							(_, _) => {}
						) );
						walk_supertraits!(trait_obj, Some(&types), (
							("Clone", _) => {
								writeln!(w, "\t\tclone: Some({}_clone_void),", ident).unwrap();
							},
							("Sync", _) => {}, ("Send", _) => {},
							("std::marker::Sync", _) => {}, ("std::marker::Send", _) => {},
							(s, t) => {
								if let Some(supertrait_obj) = types.crate_types.traits.get(s) {
									writeln!(w, "\t\t{}: crate::{} {{", t, s).unwrap();
									writeln!(w, "\t\t\tthis_arg: unsafe {{ (*this_arg).inner as *mut c_void }},").unwrap();
									writeln!(w, "\t\t\tfree: None,").unwrap();
									for item in supertrait_obj.items.iter() {
										match item {
											syn::TraitItem::Method(m) => {
												write_meth!(m, supertrait_obj, "\t");
											},
											_ => {},
										}
									}
									write!(w, "\t\t}},\n").unwrap();
									if !types.is_clonable(s) && requires_clone {
										writeln!(w, "\t\t{}_clone: {}_{}_clone,", t, ident, t).unwrap();
									}
								} else {
									write_trait_impl_field_assign(w, s, ident);
								}
							}
						) );
						writeln!(w, "\t}}\n}}\n").unwrap();

						macro_rules! impl_meth {
							($m: expr, $trait_path: expr, $trait: expr, $indent: expr) => {
								let trait_method = $trait.items.iter().filter_map(|item| {
									if let syn::TraitItem::Method(t_m) = item { Some(t_m) } else { None }
								}).find(|trait_meth| trait_meth.sig.ident == $m.sig.ident).unwrap();
								match export_status(&trait_method.attrs) {
									ExportStatus::Export => {},
									ExportStatus::NoExport|ExportStatus::TestOnly => continue,
								}

								if let syn::ReturnType::Type(_, _) = &$m.sig.output {
									writeln!(w, "#[must_use]").unwrap();
								}
								write!(w, "extern \"C\" fn {}_{}_{}(", ident, $trait.ident, $m.sig.ident).unwrap();
								let mut meth_gen_types = gen_types.push_ctx();
								assert!(meth_gen_types.learn_generics(&$m.sig.generics, types));
								write_method_params(w, &$m.sig, "c_void", types, Some(&meth_gen_types), true, true);
								write!(w, " {{\n\t").unwrap();
								write_method_var_decl_body(w, &$m.sig, "", types, Some(&meth_gen_types), false);
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
								write_method_call_params(w, &$m.sig, "", types, Some(&meth_gen_types), &real_type, false);
								write!(w, "\n}}\n").unwrap();
								if let syn::ReturnType::Type(_, rtype) = &$m.sig.output {
									if let syn::Type::Reference(r) = &**rtype {
										assert_eq!($m.sig.inputs.len(), 1); // Must only take self
										writeln!(w, "extern \"C\" fn {}_{}_set_{}(trait_self_arg: &{}) {{", ident, $trait.ident, $m.sig.ident, $trait.ident).unwrap();
										writeln!(w, "\t// This is a bit race-y in the general case, but for our specific use-cases today, we're safe").unwrap();
										writeln!(w, "\t// Specifically, we must ensure that the first time we're called it can never be in parallel").unwrap();
										write!(w, "\tif ").unwrap();
										types.write_empty_rust_val_check(Some(&meth_gen_types), w, &*r.elem, &format!("trait_self_arg.{}", $m.sig.ident));
										writeln!(w, " {{").unwrap();
										writeln!(w, "\t\tunsafe {{ &mut *(trait_self_arg as *const {}  as *mut {}) }}.{} = {}_{}_{}(trait_self_arg.this_arg);", $trait.ident, $trait.ident, $m.sig.ident, ident, $trait.ident, $m.sig.ident).unwrap();
										writeln!(w, "\t}}").unwrap();
										writeln!(w, "}}").unwrap();
									}
								}
							}
						}

						for item in i.items.iter() {
							match item {
								syn::ImplItem::Method(m) => {
									impl_meth!(m, full_trait_path, trait_obj, "");
								},
								syn::ImplItem::Type(_) => {},
								_ => unimplemented!(),
							}
						}
						walk_supertraits!(trait_obj, Some(&types), (
							(s, t) => {
								if let Some(supertrait_obj) = types.crate_types.traits.get(s) {
									if !types.is_clonable(s) && requires_clone {
										writeln!(w, "extern \"C\" fn {}_{}_clone(orig: &crate::{}) -> crate::{} {{", ident, t, s, s).unwrap();
										writeln!(w, "\tcrate::{} {{", s).unwrap();
										writeln!(w, "\t\tthis_arg: orig.this_arg,").unwrap();
										writeln!(w, "\t\tfree: None,").unwrap();
										for item in supertrait_obj.items.iter() {
											match item {
												syn::TraitItem::Method(m) => {
													write_meth!(m, supertrait_obj, "");
												},
												_ => {},
											}
										}
										write!(w, "\t}}\n}}\n").unwrap();
									}
								}
							}
						) );
						write!(w, "\n").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["From"]) {
					} else if path_matches_nongeneric(&trait_path.1, &["Default"]) {
						writeln!(w, "/// Creates a \"default\" {}. See struct and individual field documentaiton for details on which values are used.", ident).unwrap();
						write!(w, "#[must_use]\n#[no_mangle]\npub extern \"C\" fn {}_default() -> {} {{\n", ident, ident).unwrap();
						write!(w, "\t{} {{ inner: Box::into_raw(Box::new(Default::default())), is_owned: true }}\n", ident).unwrap();
						write!(w, "}}\n").unwrap();
					} else if path_matches_nongeneric(&trait_path.1, &["core", "cmp", "PartialEq"]) {
					} else if (path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) || path_matches_nongeneric(&trait_path.1, &["Clone"])) &&
							types.c_type_has_inner_from_path(&resolved_path) {
						writeln!(w, "impl Clone for {} {{", ident).unwrap();
						writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
						writeln!(w, "\t\tSelf {{").unwrap();
						writeln!(w, "\t\t\tinner: if <*mut native{}>::is_null(self.inner) {{ std::ptr::null_mut() }} else {{", ident).unwrap();
						writeln!(w, "\t\t\t\tBox::into_raw(Box::new(unsafe {{ &*self.inner }}.clone())) }},").unwrap();
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
						if let Some(container) = types.get_c_mangled_container_type(
								vec![&*i.self_ty, &syn::Type::Tuple(syn::TypeTuple { paren_token: Default::default(), elems: syn::punctuated::Punctuated::new() })],
								Some(&gen_types), "Result") {
							writeln!(w, "#[no_mangle]").unwrap();
							writeln!(w, "/// Read a {} object from a string", ident).unwrap();
							writeln!(w, "pub extern \"C\" fn {}_from_str(s: crate::c_types::Str) -> {} {{", ident, container).unwrap();
							writeln!(w, "\tmatch {}::from_str(s.into()) {{", resolved_path).unwrap();
							writeln!(w, "\t\tOk(r) => {{").unwrap();
							let new_var = types.write_to_c_conversion_new_var(w, &syn::Ident::new("r", Span::call_site()), &*i.self_ty, Some(&gen_types), false);
							write!(w, "\t\t\tcrate::c_types::CResultTempl::ok(\n\t\t\t\t").unwrap();
							types.write_to_c_conversion_inline_prefix(w, &*i.self_ty, Some(&gen_types), false);
							write!(w, "{}r", if new_var { "local_" } else { "" }).unwrap();
							types.write_to_c_conversion_inline_suffix(w, &*i.self_ty, Some(&gen_types), false);
							writeln!(w, "\n\t\t\t)\n\t\t}},").unwrap();
							writeln!(w, "\t\tErr(e) => crate::c_types::CResultTempl::err(0u8),").unwrap();
							writeln!(w, "\t}}.into()\n}}").unwrap();
						}
					} else if path_matches_nongeneric(&trait_path.1, &["Display"]) {
						writeln!(w, "#[no_mangle]").unwrap();
						writeln!(w, "/// Get the string representation of a {} object", ident).unwrap();
						writeln!(w, "pub extern \"C\" fn {}_to_str(o: &{}) -> Str {{", ident, resolved_path).unwrap();
						writeln!(w, "\tformat!(\"{{}}\", o).into()").unwrap();
						writeln!(w, "}}").unwrap();
					} else {
						//XXX: implement for other things like ToString
						// If we have no generics, try a manual implementation:
						maybe_convert_trait_impl(w, &trait_path.1, &*i.self_ty, types, &gen_types);
					}
				} else {
					let declared_type = (*types.get_declared_type(&ident).unwrap()).clone();
					for item in i.items.iter() {
						match item {
							syn::ImplItem::Method(m) => {
								if let syn::Visibility::Public(_) = m.vis {
									match export_status(&m.attrs) {
										ExportStatus::Export => {},
										ExportStatus::NoExport|ExportStatus::TestOnly => continue,
									}
									if m.defaultness.is_some() { unimplemented!(); }
									writeln_docs(w, &m.attrs, "");
									if let syn::ReturnType::Type(_, _) = &m.sig.output {
										writeln!(w, "#[must_use]").unwrap();
									}
									write!(w, "#[no_mangle]\npub extern \"C\" fn {}_{}(", ident, m.sig.ident).unwrap();
									let ret_type = match &declared_type {
										DeclType::MirroredEnum => format!("{}", ident),
										DeclType::StructImported => format!("{}", ident),
										_ => unimplemented!(),
									};
									let mut meth_gen_types = gen_types.push_ctx();
									assert!(meth_gen_types.learn_generics(&m.sig.generics, types));
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
										match &declared_type {
											DeclType::MirroredEnum => write!(w, "this_arg.to_native().{}(", m.sig.ident).unwrap(),
											DeclType::StructImported => {
												if takes_owned_self {
													write!(w, "(*unsafe {{ Box::from_raw(this_arg.take_inner()) }}).{}(", m.sig.ident).unwrap();
												} else if takes_mut_self {
													write!(w, "unsafe {{ &mut (*(this_arg.inner as *mut native{})) }}.{}(", ident, m.sig.ident).unwrap();
												} else {
													write!(w, "unsafe {{ &*this_arg.inner }}.{}(", m.sig.ident).unwrap();
												}
											},
											_ => unimplemented!(),
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
				if let Some(aliases) = types.crate_types.reverse_alias_map.get(&resolved_path).cloned() {
					'alias_impls: for (alias, arguments) in aliases {
						let alias_resolved = types.resolve_path(&alias, None);
						for (idx, gen) in i.generics.params.iter().enumerate() {
							match gen {
								syn::GenericParam::Type(type_param) => {
									'bounds_check: for bound in type_param.bounds.iter() {
										if let syn::TypeParamBound::Trait(trait_bound) = bound {
											if let syn::PathArguments::AngleBracketed(ref t) = &arguments {
												assert!(idx < t.args.len());
												if let syn::GenericArgument::Type(syn::Type::Path(p)) = &t.args[idx] {
													let generic_arg = types.resolve_path(&p.path, None);
													let generic_bound = types.resolve_path(&trait_bound.path, None);
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
												} else { unimplemented!(); }
											} else { unimplemented!(); }
										} else { unimplemented!(); }
									}
								},
								syn::GenericParam::Lifetime(_) => {},
								syn::GenericParam::Const(_) => unimplemented!(),
							}
						}
						let aliased_impl = syn::ItemImpl {
							attrs: i.attrs.clone(),
							brace_token: syn::token::Brace(Span::call_site()),
							defaultness: None,
							generics: syn::Generics {
								lt_token: None,
								params: syn::punctuated::Punctuated::new(),
								gt_token: None,
								where_clause: None,
							},
							impl_token: syn::Token![impl](Span::call_site()),
							items: i.items.clone(),
							self_ty: Box::new(syn::Type::Path(syn::TypePath { qself: None, path: alias.clone() })),
							trait_: i.trait_.clone(),
							unsafety: None,
						};
						writeln_impl(w, &aliased_impl, types);
					}
				} else {
					eprintln!("Not implementing anything for {} due to it being marked not exported", ident);
				}
			} else {
				eprintln!("Not implementing anything for {} due to no-resolve (probably the type isn't pub)", ident);
			}
		}
	}
}


/// Print a mapping of an enum. If all of the enum's fields are C-mapped in some form (or the enum
/// is unitary), we generate an equivalent enum with all types replaced with their C mapped
/// versions followed by conversion functions which map between the Rust version and the C mapped
/// version.
fn writeln_enum<'a, 'b, W: std::io::Write>(w: &mut W, e: &'a syn::ItemEnum, types: &mut TypeResolver<'b, 'a>, extra_headers: &mut File, cpp_headers: &mut File) {
	match export_status(&e.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}

	if is_enum_opaque(e) {
		eprintln!("Skipping enum {} as it contains non-unit fields", e.ident);
		writeln_opaque(w, &e.ident, &format!("{}", e.ident), &e.generics, &e.attrs, types, extra_headers, cpp_headers);
		return;
	}
	writeln_docs(w, &e.attrs, "");

	if e.generics.lt_token.is_some() {
		unimplemented!();
	}

	let mut needs_free = false;

	writeln!(w, "#[must_use]\n#[derive(Clone)]\n#[repr(C)]\npub enum {} {{", e.ident).unwrap();
	for var in e.variants.iter() {
		assert_eq!(export_status(&var.attrs), ExportStatus::Export); // We can't partially-export a mirrored enum
		writeln_docs(w, &var.attrs, "\t");
		write!(w, "\t{}", var.ident).unwrap();
		if let syn::Fields::Named(fields) = &var.fields {
			needs_free = true;
			writeln!(w, " {{").unwrap();
			for field in fields.named.iter() {
				if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
				writeln_docs(w, &field.attrs, "\t\t");
				write!(w, "\t\t{}: ", field.ident.as_ref().unwrap()).unwrap();
				types.write_c_type(w, &field.ty, None, false);
				writeln!(w, ",").unwrap();
			}
			write!(w, "\t}}").unwrap();
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			needs_free = true;
			write!(w, "(").unwrap();
			for (idx, field) in fields.unnamed.iter().enumerate() {
				if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
				types.write_c_type(w, &field.ty, None, false);
				if idx != fields.unnamed.len() - 1 {
					write!(w, ",").unwrap();
				}
			}
			write!(w, ")").unwrap();
		}
		if var.discriminant.is_some() { unimplemented!(); }
		writeln!(w, ",").unwrap();
	}
	writeln!(w, "}}\nuse {}::{} as native{};\nimpl {} {{", types.module_path, e.ident, e.ident, e.ident).unwrap();

	macro_rules! write_conv {
		($fn_sig: expr, $to_c: expr, $ref: expr) => {
			writeln!(w, "\t#[allow(unused)]\n\tpub(crate) fn {} {{\n\t\tmatch {} {{", $fn_sig, if $to_c { "native" } else { "self" }).unwrap();
			for var in e.variants.iter() {
				write!(w, "\t\t\t{}{}::{} ", if $to_c { "native" } else { "" }, e.ident, var.ident).unwrap();
				if let syn::Fields::Named(fields) = &var.fields {
					write!(w, "{{").unwrap();
					for field in fields.named.iter() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "{}{}, ", if $ref { "ref " } else { "mut " }, field.ident.as_ref().unwrap()).unwrap();
					}
					write!(w, "}} ").unwrap();
				} else if let syn::Fields::Unnamed(fields) = &var.fields {
					write!(w, "(").unwrap();
					for (idx, field) in fields.unnamed.iter().enumerate() {
						if export_status(&field.attrs) == ExportStatus::TestOnly { continue; }
						write!(w, "{}{}, ", if $ref { "ref " } else { "mut " }, ('a' as u8 + idx as u8) as char).unwrap();
					}
					write!(w, ") ").unwrap();
				}
				write!(w, "=>").unwrap();

				macro_rules! handle_field_a {
					($field: expr, $field_ident: expr) => { {
						if export_status(&$field.attrs) == ExportStatus::TestOnly { continue; }
						let mut sink = ::std::io::sink();
						let mut out: &mut dyn std::io::Write = if $ref { &mut sink } else { w };
						let new_var = if $to_c {
							types.write_to_c_conversion_new_var(&mut out, $field_ident, &$field.ty, None, false)
						} else {
							types.write_from_c_conversion_new_var(&mut out, $field_ident, &$field.ty, None)
						};
						if $ref || new_var {
							if $ref {
								write!(w, "let mut {}_nonref = (*{}).clone();\n\t\t\t\t", $field_ident, $field_ident).unwrap();
								if new_var {
									let nonref_ident = format_ident!("{}_nonref", $field_ident);
									if $to_c {
										types.write_to_c_conversion_new_var(w, &nonref_ident, &$field.ty, None, false);
									} else {
										types.write_from_c_conversion_new_var(w, &nonref_ident, &$field.ty, None);
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
						handle_field_a!(field, &format_ident!("{}", ('a' as u8 + idx as u8) as char));
					}
				} else { write!(w, " ").unwrap(); }

				write!(w, "{}{}::{}", if $to_c { "" } else { "native" }, e.ident, var.ident).unwrap();

				macro_rules! handle_field_b {
					($field: expr, $field_ident: expr) => { {
						if export_status(&$field.attrs) == ExportStatus::TestOnly { continue; }
						if $to_c {
							types.write_to_c_conversion_inline_prefix(w, &$field.ty, None, false);
						} else {
							types.write_from_c_conversion_prefix(w, &$field.ty, None);
						}
						write!(w, "{}{}", $field_ident,
							if $ref { "_nonref" } else { "" }).unwrap();
						if $to_c {
							types.write_to_c_conversion_inline_suffix(w, &$field.ty, None, false);
						} else {
							types.write_from_c_conversion_suffix(w, &$field.ty, None);
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
					write!(w, " (").unwrap();
					for (idx, field) in fields.unnamed.iter().enumerate() {
						write!(w, "\n\t\t\t\t\t").unwrap();
						handle_field_b!(field, &format_ident!("{}", ('a' as u8 + idx as u8) as char));
					}
					writeln!(w, "\n\t\t\t\t)").unwrap();
					write!(w, "\t\t\t}}").unwrap();
				}
				writeln!(w, ",").unwrap();
			}
			writeln!(w, "\t\t}}\n\t}}").unwrap();
		}
	}

	write_conv!(format!("to_native(&self) -> native{}", e.ident), false, true);
	write_conv!(format!("into_native(self) -> native{}", e.ident), false, false);
	write_conv!(format!("from_native(native: &native{}) -> Self", e.ident), true, true);
	write_conv!(format!("native_into(native: native{}) -> Self", e.ident), true, false);
	writeln!(w, "}}").unwrap();

	// Implement the conversion into rust only as owned object, because even when using
	// `to_native()` the returned structure will have a copy of the data and won't reference into
	// the original instance. Implement for Borrow<T> instead of T so that the same trait can be
	// used on references and owned objects since the behavior doesn't change. This could cause a
	// performance regression when used on owned objects because the inner data instead of being
	// moved is copied, but on the other end we gain a lot in terms of convenience.
	writeln!(w, "impl<F: std::borrow::Borrow<{}>> crate::c_types::mapping::IntoRust<native{}> for F {{", e.ident, e.ident).unwrap();
	writeln!(w, "\tfn into_rust_owned(self) -> native{} {{ use std::borrow::Borrow; self.borrow().to_native() }}", e.ident).unwrap();
	writeln!(w, "}}").unwrap();

	if needs_free {
		writeln!(w, "/// Frees any resources used by the {}", e.ident).unwrap();
		writeln!(w, "#[no_mangle]\npub extern \"C\" fn {}_free(this_ptr: {}) {{ }}", e.ident, e.ident).unwrap();
	}
	writeln!(w, "/// Creates a copy of the {}", e.ident).unwrap();
	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{", e.ident, e.ident, e.ident).unwrap();
	writeln!(w, "\torig.clone()").unwrap();
	writeln!(w, "}}").unwrap();
	write_cpp_wrapper(cpp_headers, &format!("{}", e.ident), needs_free);
}

fn writeln_fn<'a, 'b, W: std::io::Write>(w: &mut W, f: &'a syn::ItemFn, types: &mut TypeResolver<'b, 'a>) {
	match export_status(&f.attrs) {
		ExportStatus::Export => {},
		ExportStatus::NoExport|ExportStatus::TestOnly => return,
	}
	writeln_docs(w, &f.attrs, "");

	let mut gen_types = GenericTypes::new(None);
	if !gen_types.learn_generics(&f.sig.generics, types) { return; }

	write!(w, "#[no_mangle]\npub extern \"C\" fn {}(", f.sig.ident).unwrap();
	write_method_params(w, &f.sig, "", types, Some(&gen_types), false, true);
	write!(w, " {{\n\t").unwrap();
	write_method_var_decl_body(w, &f.sig, "", types, Some(&gen_types), false);
	write!(w, "{}::{}(", types.module_path, f.sig.ident).unwrap();
	write_method_call_params(w, &f.sig, "", types, Some(&gen_types), "", false);
	writeln!(w, "\n}}\n").unwrap();
}

// ********************************
// *** File/Crate Walking Logic ***
// ********************************

fn convert_priv_mod<'a, 'b: 'a, W: std::io::Write>(w: &mut W, libast: &'b FullLibraryAST, crate_types: &CrateTypes<'b>, out_dir: &str, mod_path: &str, module: &'b syn::ItemMod) {
	// We want to ignore all items declared in this module (as they are not pub), but we still need
	// to give the ImportResolver any use statements, so we copy them here.
	let mut use_items = Vec::new();
	for item in module.content.as_ref().unwrap().1.iter() {
		if let syn::Item::Use(_) = item {
			use_items.push(item);
		}
	}
	let import_resolver = ImportResolver::from_borrowed_items(mod_path.splitn(2, "::").next().unwrap(), &libast.dependencies, mod_path, &use_items);
	let mut types = TypeResolver::new(mod_path, import_resolver, crate_types);

	writeln!(w, "mod {} {{\n{}", module.ident, DEFAULT_IMPORTS).unwrap();
	for item in module.content.as_ref().unwrap().1.iter() {
		match item {
			syn::Item::Mod(m) => convert_priv_mod(w, libast, crate_types, out_dir, &format!("{}::{}", mod_path, module.ident), m),
			syn::Item::Impl(i) => {
				if let &syn::Type::Path(ref p) = &*i.self_ty {
					if p.path.get_ident().is_some() {
						writeln_impl(w, i, &mut types);
					}
				}
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
			writeln!(out, "pub mod c_types;").unwrap();
		} else {
			writeln!(out, "{}", DEFAULT_IMPORTS).unwrap();
		}

		for m in submods {
			writeln!(out, "pub mod {};", m).unwrap();
		}

		eprintln!("Converting {} entries...", module);

		let import_resolver = ImportResolver::new(orig_crate, &libast.dependencies, module, items);
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
					writeln_impl(&mut out, &i, &mut type_resolver);
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
					convert_priv_mod(&mut out, libast, crate_types, out_dir, &format!("{}::{}", module, m.ident), m);
				},
				syn::Item::Const(c) => {
					// Re-export any primitive-type constants.
					if let syn::Visibility::Public(_) = c.vis {
						if let syn::Type::Path(p) = &*c.ty {
							let resolved_path = type_resolver.resolve_path(&p.path, None);
							if type_resolver.is_primitive(&resolved_path) {
								writeln_docs(&mut out, &c.attrs, "");
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
						}

						let mut process_alias = true;
						for tok in t.generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = tok {}
							else { process_alias = false; }
						}
						if process_alias {
							match &*t.ty {
								syn::Type::Path(_) =>
									writeln_opaque(&mut out, &t.ident, &format!("{}", t.ident), &t.generics, &t.attrs, &type_resolver, header_file, cpp_header_file),
								_ => {}
							}
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

		out.flush().unwrap();
	}
}

fn walk_private_mod<'a>(ast_storage: &'a FullLibraryAST, orig_crate: &str, module: String, items: &'a syn::ItemMod, crate_types: &mut CrateTypes<'a>) {
	let import_resolver = ImportResolver::new(orig_crate, &ast_storage.dependencies, &module, &items.content.as_ref().unwrap().1);
	for item in items.content.as_ref().unwrap().1.iter() {
		match item {
			syn::Item::Mod(m) => walk_private_mod(ast_storage, orig_crate, format!("{}::{}", module, m.ident), m, crate_types),
			syn::Item::Impl(i) => {
				if let &syn::Type::Path(ref p) = &*i.self_ty {
					if let Some(trait_path) = i.trait_.as_ref() {
						if let Some(tp) = import_resolver.maybe_resolve_path(&trait_path.1, None) {
							if let Some(sp) = import_resolver.maybe_resolve_path(&p.path, None) {
								match crate_types.trait_impls.entry(sp) {
									hash_map::Entry::Occupied(mut e) => { e.get_mut().push(tp); },
									hash_map::Entry::Vacant(e) => { e.insert(vec![tp]); },
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
fn walk_ast<'a>(ast_storage: &'a FullLibraryAST, crate_types: &mut CrateTypes<'a>) {
	for (module, astmod) in ast_storage.modules.iter() {
		let ASTModule { ref attrs, ref items, submods: _ } = astmod;
		assert_eq!(export_status(&attrs), ExportStatus::Export);
		let orig_crate = module.splitn(2, "::").next().unwrap();
		let import_resolver = ImportResolver::new(orig_crate, &ast_storage.dependencies, module, items);

		for item in items.iter() {
			match item {
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						match export_status(&s.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let struct_path = format!("{}::{}", module, s.ident);
						crate_types.opaques.insert(struct_path, &s.ident);
					}
				},
				syn::Item::Trait(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let trait_path = format!("{}::{}", module, t.ident);
						walk_supertraits!(t, None, (
							("Clone", _) => {
								crate_types.set_clonable("crate::".to_owned() + &trait_path);
							},
							(_, _) => {}
						) );
						crate_types.traits.insert(trait_path, &t);
					}
				},
				syn::Item::Type(t) => {
					if let syn::Visibility::Public(_) = t.vis {
						match export_status(&t.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let type_path = format!("{}::{}", module, t.ident);
						let mut process_alias = true;
						for tok in t.generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = tok {}
							else { process_alias = false; }
						}
						if process_alias {
							match &*t.ty {
								syn::Type::Path(p) => {
									let t_ident = &t.ident;

									// If its a path with no generics, assume we don't map the aliased type and map it opaque
									let path_obj = parse_quote!(#t_ident);
									let args_obj = p.path.segments.last().unwrap().arguments.clone();
									match crate_types.reverse_alias_map.entry(import_resolver.maybe_resolve_path(&p.path, None).unwrap()) {
										hash_map::Entry::Occupied(mut e) => { e.get_mut().push((path_obj, args_obj)); },
										hash_map::Entry::Vacant(e) => { e.insert(vec![(path_obj, args_obj)]); },
									}

									crate_types.opaques.insert(type_path, t_ident);
								},
								_ => {
									crate_types.type_aliases.insert(type_path, import_resolver.resolve_imported_refs((*t.ty).clone()));
								}
							}
						}
					}
				},
				syn::Item::Enum(e) if is_enum_opaque(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.opaques.insert(enum_path, &e.ident);
					}
				},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export => {},
							ExportStatus::NoExport|ExportStatus::TestOnly => continue,
						}
						let enum_path = format!("{}::{}", module, e.ident);
						crate_types.mirrored_enums.insert(enum_path, &e);
					}
				},
				syn::Item::Impl(i) => {
					if let &syn::Type::Path(ref p) = &*i.self_ty {
						if let Some(trait_path) = i.trait_.as_ref() {
							if path_matches_nongeneric(&trait_path.1, &["core", "clone", "Clone"]) {
								if let Some(full_path) = import_resolver.maybe_resolve_path(&p.path, None) {
									crate_types.set_clonable("crate::".to_owned() + &full_path);
								}
							}
							if let Some(tp) = import_resolver.maybe_resolve_path(&trait_path.1, None) {
								if let Some(sp) = import_resolver.maybe_resolve_path(&p.path, None) {
									match crate_types.trait_impls.entry(sp) {
										hash_map::Entry::Occupied(mut e) => { e.get_mut().push(tp); },
										hash_map::Entry::Vacant(e) => { e.insert(vec![tp]); },
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

	// First parse the full crate's ASTs, caching them so that we can hold references to the AST
	// objects in other datastructures:
	let mut lib_src = String::new();
	std::io::stdin().lock().read_to_string(&mut lib_src).unwrap();
	let lib_syntax = syn::parse_file(&lib_src).expect("Unable to parse file");
	let libast = FullLibraryAST::load_lib(lib_syntax);

	// ...then walk the ASTs tracking what types we will map, and how, so that we can resolve them
	// when parsing other file ASTs...
	let mut libtypes = CrateTypes::new(&mut derived_templates, &libast);
	walk_ast(&libast, &mut libtypes);

	// ... finally, do the actual file conversion/mapping, writing out types as we go.
	convert_file(&libast, &libtypes, &args[1], &mut header_file, &mut cpp_header_file);

	// For container templates which we created while walking the crate, make sure we add C++
	// mapped types so that C++ users can utilize the auto-destructors available.
	for (ty, has_destructor) in libtypes.templates_defined.borrow().iter() {
		write_cpp_wrapper(&mut cpp_header_file, ty, *has_destructor);
	}
	writeln!(cpp_header_file, "}}").unwrap();

	header_file.flush().unwrap();
	cpp_header_file.flush().unwrap();
	derived_templates.flush().unwrap();
}
