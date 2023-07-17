// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use std::hash;

use crate::blocks::*;

use proc_macro2::{TokenTree, Span};
use quote::format_ident;
use syn::parse_quote;

// The following utils are used purely to build our known types maps - they break down all the
// types we need to resolve to include the given object, and no more.

pub fn first_seg_self<'a>(t: &'a syn::Type) -> Option<impl Iterator<Item=&syn::PathSegment> + 'a> {
	match t {
		syn::Type::Path(p) => {
			if p.qself.is_some() || p.path.leading_colon.is_some() {
				return None;
			}
			let mut segs = p.path.segments.iter();
			let ty = segs.next().unwrap();
			if !ty.arguments.is_empty() { return None; }
			if format!("{}", ty.ident) == "Self" {
				Some(segs)
			} else { None }
		},
		_ => None,
	}
}

pub fn get_single_remaining_path_seg<'a, I: Iterator<Item=&'a syn::PathSegment>>(segs: &mut I) -> Option<&'a syn::Ident> {
	if let Some(ty) = segs.next() {
		if !ty.arguments.is_empty() { unimplemented!(); }
		if segs.next().is_some() { return None; }
		Some(&ty.ident)
	} else { None }
}

pub fn first_seg_is_stdlib(first_seg_str: &str) -> bool {
	first_seg_str == "std" || first_seg_str == "core" || first_seg_str == "alloc"
}

pub fn single_ident_generic_path_to_ident(p: &syn::Path) -> Option<&syn::Ident> {
	if p.segments.len() == 1 {
		Some(&p.segments.iter().next().unwrap().ident)
	} else { None }
}

pub fn path_matches_nongeneric(p: &syn::Path, exp: &[&str]) -> bool {
	if p.segments.len() != exp.len() { return false; }
	for (seg, e) in p.segments.iter().zip(exp.iter()) {
		if seg.arguments != syn::PathArguments::None { return false; }
		if &format!("{}", seg.ident) != *e { return false; }
	}
	true
}

pub fn string_path_to_syn_path(path: &str) -> syn::Path {
	let mut segments = syn::punctuated::Punctuated::new();
	for seg in path.split("::") {
		segments.push(syn::PathSegment {
			ident: syn::Ident::new(seg, Span::call_site()),
			arguments: syn::PathArguments::None,
		});
	}
	syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments }
}

#[derive(Debug, PartialEq)]
pub enum ExportStatus {
	Export,
	NoExport,
	TestOnly,
	/// This is used only for traits to indicate that users should not be able to implement their
	/// own version of a trait, but we should export Rust implementations of the trait (and the
	/// trait itself).
	/// Concretly, this means that we do not implement the Rust trait for the C trait struct.
	NotImplementable,
}
/// Gets the ExportStatus of an object (struct, fn, etc) given its attributes.
pub fn export_status(attrs: &[syn::Attribute]) -> ExportStatus {
	for attr in attrs.iter() {
		let tokens_clone = attr.tokens.clone();
		let mut token_iter = tokens_clone.into_iter();
		if let Some(token) = token_iter.next() {
			match token {
				TokenTree::Punct(c) if c.as_char() == '=' => {
					// Really not sure where syn gets '=' from here -
					// it somehow represents '///' or '//!'
				},
				TokenTree::Group(g) => {
					if format!("{}", single_ident_generic_path_to_ident(&attr.path).unwrap()) == "cfg" {
						let mut iter = g.stream().into_iter();
						if let TokenTree::Ident(i) = iter.next().unwrap() {
							if i == "any" {
								// #[cfg(any(test, feature = ""))]
								if let TokenTree::Group(g) = iter.next().unwrap() {
									let mut all_test = true;
									for token in g.stream().into_iter() {
										if let TokenTree::Ident(i) = token {
											match format!("{}", i).as_str() {
												"test" => {},
												"feature" => {},
												_ => all_test = false,
											}
										} else if let TokenTree::Literal(lit) = token {
											if format!("{}", lit) != "fuzztarget" {
												all_test = false;
											}
										}
									}
									if all_test { return ExportStatus::TestOnly; }
								}
							} else if i == "test" {
								return ExportStatus::TestOnly;
							}
						}
					}
					continue; // eg #[derive()]
				},
				_ => unimplemented!(),
			}
		} else { continue; }
		match token_iter.next().unwrap() {
			TokenTree::Literal(lit) => {
				let line = format!("{}", lit);
				if line.contains("(C-not exported)") || line.contains("This is not exported to bindings users") {
					return ExportStatus::NoExport;
				} else if line.contains("(C-not implementable)") {
					return ExportStatus::NotImplementable;
				}
			},
			_ => unimplemented!(),
		}
	}
	ExportStatus::Export
}

pub fn assert_simple_bound(bound: &syn::TraitBound) {
	if bound.paren_token.is_some() { unimplemented!(); }
	if let syn::TraitBoundModifier::Maybe(_) = bound.modifier { unimplemented!(); }
}

/// Returns true if the enum will be mapped as an opaue (ie struct with a pointer to the underlying
/// type), otherwise it is mapped into a transparent, C-compatible version of itself.
pub fn is_enum_opaque(e: &syn::ItemEnum) -> bool {
	for var in e.variants.iter() {
		if let syn::Fields::Named(fields) = &var.fields {
			for field in fields.named.iter() {
				match export_status(&field.attrs) {
					ExportStatus::Export|ExportStatus::TestOnly => {},
					ExportStatus::NotImplementable => panic!("(C-not implementable) should only appear on traits!"),
					ExportStatus::NoExport => return true,
				}
			}
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			for field in fields.unnamed.iter() {
				match export_status(&field.attrs) {
					ExportStatus::Export|ExportStatus::TestOnly => {},
					ExportStatus::NotImplementable => panic!("(C-not implementable) should only appear on traits!"),
					ExportStatus::NoExport => return true,
				}
			}
		}
	}
	false
}

/// A stack of sets of generic resolutions.
///
/// This tracks the template parameters for a function, struct, or trait, allowing resolution into
/// a concrete type. By pushing a new context onto the stack, this can track a function's template
/// parameters inside of a generic struct or trait.
///
/// It maps both direct types as well as Deref<Target = X>, mapping them via the provided
/// TypeResolver's resolve_path function (ie traits map to the concrete jump table, structs to the
/// concrete C container struct, etc).
#[must_use]
pub struct GenericTypes<'a, 'b> {
	self_ty: Option<String>,
	parent: Option<&'b GenericTypes<'b, 'b>>,
	typed_generics: HashMap<&'a syn::Ident, String>,
	default_generics: HashMap<&'a syn::Ident, (syn::Type, syn::Type, syn::Type)>,
}
impl<'a, 'p: 'a> GenericTypes<'a, 'p> {
	pub fn new(self_ty: Option<String>) -> Self {
		Self { self_ty, parent: None, typed_generics: HashMap::new(), default_generics: HashMap::new(), }
	}

	/// push a new context onto the stack, allowing for a new set of generics to be learned which
	/// will override any lower contexts, but which will still fall back to resoltion via lower
	/// contexts.
	pub fn push_ctx<'c>(&'c self) -> GenericTypes<'a, 'c> {
		GenericTypes { self_ty: None, parent: Some(self), typed_generics: HashMap::new(), default_generics: HashMap::new(), }
	}

	/// Learn the generics in generics in the current context, given a TypeResolver.
	pub fn learn_generics_with_impls<'b, 'c>(&mut self, generics: &'a syn::Generics, impld_generics: &'a syn::PathArguments, types: &'b TypeResolver<'a, 'c>) -> bool {
		let mut new_typed_generics = HashMap::new();
		// First learn simple generics...
		for (idx, generic) in generics.params.iter().enumerate() {
			match generic {
				syn::GenericParam::Type(type_param) => {
					let mut non_lifetimes_processed = false;
					'bound_loop: for bound in type_param.bounds.iter() {
						if let syn::TypeParamBound::Trait(trait_bound) = bound {
							if let Some(ident) = single_ident_generic_path_to_ident(&trait_bound.path) {
								match &format!("{}", ident) as &str { "Send" => continue, "Sync" => continue, _ => {} }
							}
							if path_matches_nongeneric(&trait_bound.path, &["core", "clone", "Clone"]) { continue; }

							assert_simple_bound(&trait_bound);
							if let Some(path) = types.maybe_resolve_path(&trait_bound.path, None) {
								if types.skip_path(&path) { continue; }
								if path == "Sized" { continue; }
								if non_lifetimes_processed { return false; }
								non_lifetimes_processed = true;
								if path != "std::ops::Deref" && path != "core::ops::Deref" {
									let p = string_path_to_syn_path(&path);
									let ref_ty = parse_quote!(&#p);
									let mut_ref_ty = parse_quote!(&mut #p);
									self.default_generics.insert(&type_param.ident, (syn::Type::Path(syn::TypePath { qself: None, path: p }), ref_ty, mut_ref_ty));
									new_typed_generics.insert(&type_param.ident, Some(path));
								} else {
									// If we're templated on Deref<Target = ConcreteThing>, store
									// the reference type in `default_generics` which handles full
									// types and not just paths.
									if let syn::PathArguments::AngleBracketed(ref args) =
											trait_bound.path.segments[0].arguments {
										assert_eq!(trait_bound.path.segments.len(), 1);
										for subargument in args.args.iter() {
											match subargument {
												syn::GenericArgument::Lifetime(_) => {},
												syn::GenericArgument::Binding(ref b) => {
													if &format!("{}", b.ident) != "Target" { return false; }
													let default = &b.ty;
													self.default_generics.insert(&type_param.ident, (parse_quote!(&#default), parse_quote!(&#default), parse_quote!(&mut #default)));
													break 'bound_loop;
												},
												_ => unimplemented!(),
											}
										}
									} else {
										new_typed_generics.insert(&type_param.ident, None);
									}
								}
							}
						}
					}
					if let Some(default) = type_param.default.as_ref() {
						assert!(type_param.bounds.is_empty());
						self.default_generics.insert(&type_param.ident, (default.clone(), parse_quote!(&#default), parse_quote!(&mut #default)));
					} else if type_param.bounds.is_empty() {
						if let syn::PathArguments::AngleBracketed(args) = impld_generics {
							match &args.args[idx] {
								syn::GenericArgument::Type(ty) => {
									self.default_generics.insert(&type_param.ident, (ty.clone(), parse_quote!(&#ty), parse_quote!(&mut #ty)));
								}
								_ => unimplemented!(),
							}
						}
					}
				},
				_ => {},
			}
		}
		// Then find generics where we are required to pass a Deref<Target=X> and pretend its just X.
		if let Some(wh) = &generics.where_clause {
			for pred in wh.predicates.iter() {
				if let syn::WherePredicate::Type(t) = pred {
					if let syn::Type::Path(p) = &t.bounded_ty {
						if first_seg_self(&t.bounded_ty).is_some() && p.path.segments.len() == 1 { continue; }
						if p.qself.is_some() { return false; }
						if p.path.leading_colon.is_some() { return false; }
						let mut p_iter = p.path.segments.iter();
						let p_ident = &p_iter.next().unwrap().ident;
						if let Some(gen) = new_typed_generics.get_mut(p_ident) {
							if gen.is_some() { return false; }
							if &format!("{}", p_iter.next().unwrap().ident) != "Target" {return false; }

							let mut non_lifetimes_processed = false;
							for bound in t.bounds.iter() {
								if let syn::TypeParamBound::Trait(trait_bound) = bound {
									if let Some(id) = trait_bound.path.get_ident() {
										if format!("{}", id) == "Sized" { continue; }
									}
									if non_lifetimes_processed { return false; }
									non_lifetimes_processed = true;
									assert_simple_bound(&trait_bound);
									let resolved = types.resolve_path(&trait_bound.path, None);
									let ty = syn::Type::Path(syn::TypePath {
										qself: None, path: string_path_to_syn_path(&resolved)
									});
									let ref_ty = parse_quote!(&#ty);
									let mut_ref_ty = parse_quote!(&mut #ty);
									if types.crate_types.traits.get(&resolved).is_some() {
										self.default_generics.insert(p_ident, (ty, ref_ty, mut_ref_ty));
									} else {
										self.default_generics.insert(p_ident, (ref_ty.clone(), ref_ty, mut_ref_ty));
									}

									*gen = Some(resolved);
								}
							}
						} else { return false; }
					} else { return false; }
				}
			}
		}
		for (key, value) in new_typed_generics.drain() {
			if let Some(v) = value {
				assert!(self.typed_generics.insert(key, v).is_none());
			} else { return false; }
		}
		true
	}

	/// Learn the generics in generics in the current context, given a TypeResolver.
	pub fn learn_generics<'b, 'c>(&mut self, generics: &'a syn::Generics, types: &'b TypeResolver<'a, 'c>) -> bool {
		self.learn_generics_with_impls(generics, &syn::PathArguments::None, types)
	}

	/// Learn the associated types from the trait in the current context.
	pub fn learn_associated_types<'b, 'c>(&mut self, t: &'a syn::ItemTrait, types: &'b TypeResolver<'a, 'c>) {
		for item in t.items.iter() {
			match item {
				&syn::TraitItem::Type(ref t) => {
					if t.default.is_some() || t.generics.lt_token.is_some() { unimplemented!(); }
					let mut bounds_iter = t.bounds.iter();
					loop {
						match bounds_iter.next().unwrap() {
							syn::TypeParamBound::Trait(tr) => {
								assert_simple_bound(&tr);
								if let Some(path) = types.maybe_resolve_path(&tr.path, None) {
									if types.skip_path(&path) { continue; }
									// In general we handle Deref<Target=X> as if it were just X (and
									// implement Deref<Target=Self> for relevant types). We don't
									// bother to implement it for associated types, however, so we just
									// ignore such bounds.
									if path != "std::ops::Deref" && path != "core::ops::Deref" {
										self.typed_generics.insert(&t.ident, path);
									}
								} else { unimplemented!(); }
								for bound in bounds_iter {
									if let syn::TypeParamBound::Trait(_) = bound { unimplemented!(); }
								}
								break;
							},
							syn::TypeParamBound::Lifetime(_) => {},
						}
					}
				},
				_ => {},
			}
		}
	}

	/// Attempt to resolve a Path as a generic parameter and return the full path. as both a string
	/// and syn::Path.
	pub fn maybe_resolve_path<'b>(&'b self, path: &syn::Path) -> Option<&'b String> {
		if let Some(ident) = path.get_ident() {
			if let Some(ty) = &self.self_ty {
				if format!("{}", ident) == "Self" {
					return Some(&ty);
				}
			}
			if let Some(res) = self.typed_generics.get(ident) {
				return Some(res);
			}
		} else {
			// Associated types are usually specified as "Self::Generic", so we check for that
			// explicitly here.
			let mut it = path.segments.iter();
			if path.segments.len() == 2 && format!("{}", it.next().unwrap().ident) == "Self" {
				let ident = &it.next().unwrap().ident;
				if let Some(res) = self.typed_generics.get(ident) {
					return Some(res);
				}
			}
		}
		if let Some(parent) = self.parent {
			parent.maybe_resolve_path(path)
		} else {
			None
		}
	}
}

pub trait ResolveType<'a> { fn resolve_type(&'a self, ty: &'a syn::Type) -> &'a syn::Type; }
impl<'a, 'b, 'c: 'a + 'b> ResolveType<'c> for Option<&GenericTypes<'a, 'b>> {
	fn resolve_type(&'c self, ty: &'c syn::Type) -> &'c syn::Type {
		if let Some(us) = self {
			match ty {
				syn::Type::Path(p) => {
					if let Some(ident) = p.path.get_ident() {
						if let Some((ty, _, _)) = us.default_generics.get(ident) {
							return self.resolve_type(ty);
						}
					}
				},
				syn::Type::Reference(syn::TypeReference { elem, mutability, .. }) => {
					if let syn::Type::Path(p) = &**elem {
						if let Some(ident) = p.path.get_ident() {
							if let Some((_, refty, mut_ref_ty)) = us.default_generics.get(ident) {
								if mutability.is_some() {
									return self.resolve_type(mut_ref_ty);
								} else {
									return self.resolve_type(refty);
								}
							}
						}
					}
				}
				_ => {},
			}
			us.parent.resolve_type(ty)
		} else { ty }
	}
}

#[derive(Clone, PartialEq)]
// The type of declaration and the object itself
pub enum DeclType<'a> {
	MirroredEnum,
	Trait(&'a syn::ItemTrait),
	StructImported { generics: &'a syn::Generics  },
	StructIgnored,
	EnumIgnored { generics: &'a syn::Generics },
}

pub struct ImportResolver<'mod_lifetime, 'crate_lft: 'mod_lifetime> {
	pub crate_name: &'mod_lifetime str,
	library: &'crate_lft FullLibraryAST,
	module_path: &'mod_lifetime str,
	imports: HashMap<syn::Ident, (String, syn::Path)>,
	declared: HashMap<syn::Ident, DeclType<'crate_lft>>,
	priv_modules: HashSet<syn::Ident>,
}
impl<'mod_lifetime, 'crate_lft: 'mod_lifetime> ImportResolver<'mod_lifetime, 'crate_lft> {
	fn walk_use_intern<F: FnMut(syn::Ident, (String, syn::Path))>(
		crate_name: &str, module_path: &str, dependencies: &HashSet<syn::Ident>, u: &syn::UseTree,
		partial_path: &str,
		mut path: syn::punctuated::Punctuated<syn::PathSegment, syn::token::Colon2>, handle_use: &mut F
	) {
		let new_path;
		macro_rules! push_path {
			($ident: expr, $path_suffix: expr) => {
				if partial_path == "" && format!("{}", $ident) == "super" {
					let mut mod_iter = module_path.rsplitn(2, "::");
					mod_iter.next().unwrap();
					let super_mod = mod_iter.next().unwrap();
					new_path = format!("{}{}", super_mod, $path_suffix);
					assert_eq!(path.len(), 0);
					for module in super_mod.split("::") {
						path.push(syn::PathSegment { ident: syn::Ident::new(module, Span::call_site()), arguments: syn::PathArguments::None });
					}
				} else if partial_path == "" && format!("{}", $ident) == "self" {
					new_path = format!("{}{}", module_path, $path_suffix);
					for module in module_path.split("::") {
						path.push(syn::PathSegment { ident: syn::Ident::new(module, Span::call_site()), arguments: syn::PathArguments::None });
					}
				} else if partial_path == "" && format!("{}", $ident) == "crate" {
					new_path = format!("{}{}", crate_name, $path_suffix);
					let crate_name_ident = format_ident!("{}", crate_name);
					path.push(parse_quote!(#crate_name_ident));
				} else if partial_path == "" && !dependencies.contains(&$ident) {
					new_path = format!("{}::{}{}", module_path, $ident, $path_suffix);
					for module in module_path.split("::") {
						path.push(syn::PathSegment { ident: syn::Ident::new(module, Span::call_site()), arguments: syn::PathArguments::None });
					}
					let ident_str = format_ident!("{}", $ident);
					path.push(parse_quote!(#ident_str));
				} else if format!("{}", $ident) == "self" {
					let mut path_iter = partial_path.rsplitn(2, "::");
					path_iter.next().unwrap();
					new_path = path_iter.next().unwrap().to_owned();
				} else {
					new_path = format!("{}{}{}", partial_path, $ident, $path_suffix);
				}
				let ident = &$ident;
				path.push(parse_quote!(#ident));
			}
		}
		match u {
			syn::UseTree::Path(p) => {
				push_path!(p.ident, "::");
				Self::walk_use_intern(crate_name, module_path, dependencies, &p.tree, &new_path, path, handle_use);
			},
			syn::UseTree::Name(n) => {
				push_path!(n.ident, "");
				let imported_ident = syn::Ident::new(new_path.rsplitn(2, "::").next().unwrap(), Span::call_site());
				handle_use(imported_ident, (new_path, syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments: path }));
			},
			syn::UseTree::Group(g) => {
				for i in g.items.iter() {
					Self::walk_use_intern(crate_name, module_path, dependencies, i, partial_path, path.clone(), handle_use);
				}
			},
			syn::UseTree::Rename(r) => {
				push_path!(r.ident, "");
				handle_use(r.rename.clone(), (new_path, syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments: path }));
			},
			syn::UseTree::Glob(_) => {
				eprintln!("Ignoring * use for {} - this may result in resolution failures", partial_path);
			},
		}
	}

	fn process_use_intern(crate_name: &str, module_path: &str, dependencies: &HashSet<syn::Ident>,
		imports: &mut HashMap<syn::Ident, (String, syn::Path)>, u: &syn::UseTree, partial_path: &str,
		path: syn::punctuated::Punctuated<syn::PathSegment, syn::token::Colon2>
	) {
		Self::walk_use_intern(crate_name, module_path, dependencies, u, partial_path, path,
			&mut |k, v| { imports.insert(k, v); });
	}

	fn process_use(crate_name: &str, module_path: &str, dependencies: &HashSet<syn::Ident>, imports: &mut HashMap<syn::Ident, (String, syn::Path)>, u: &syn::ItemUse) {
		if u.leading_colon.is_some() { eprintln!("Ignoring leading-colon use!"); return; }
		Self::process_use_intern(crate_name, module_path, dependencies, imports, &u.tree, "", syn::punctuated::Punctuated::new());
	}

	fn insert_primitive(imports: &mut HashMap<syn::Ident, (String, syn::Path)>, id: &str) {
		let ident = format_ident!("{}", id);
		let path = parse_quote!(#ident);
		imports.insert(ident, (id.to_owned(), path));
	}

	pub fn new(crate_name: &'mod_lifetime str, library: &'crate_lft FullLibraryAST, module_path: &'mod_lifetime str, contents: &'crate_lft [syn::Item]) -> Self {
		Self::from_borrowed_items(crate_name, library, module_path, &contents.iter().map(|a| a).collect::<Vec<_>>())
	}
	pub fn from_borrowed_items(crate_name: &'mod_lifetime str, library: &'crate_lft FullLibraryAST, module_path: &'mod_lifetime str, contents: &[&'crate_lft syn::Item]) -> Self {
		let mut imports = HashMap::new();
		// Add primitives to the "imports" list:
		Self::insert_primitive(&mut imports, "bool");
		Self::insert_primitive(&mut imports, "u128");
		Self::insert_primitive(&mut imports, "u64");
		Self::insert_primitive(&mut imports, "u32");
		Self::insert_primitive(&mut imports, "u16");
		Self::insert_primitive(&mut imports, "u8");
		Self::insert_primitive(&mut imports, "usize");
		Self::insert_primitive(&mut imports, "str");
		Self::insert_primitive(&mut imports, "String");

		// These are here to allow us to print native Rust types in trait fn impls even if we don't
		// have C mappings:
		Self::insert_primitive(&mut imports, "Result");
		Self::insert_primitive(&mut imports, "Vec");
		Self::insert_primitive(&mut imports, "Option");

		let mut declared = HashMap::new();
		let mut priv_modules = HashSet::new();

		for item in contents.iter() {
			match item {
				syn::Item::Use(u) => Self::process_use(crate_name, module_path, &library.dependencies, &mut imports, &u),
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						match export_status(&s.attrs) {
							ExportStatus::Export => { declared.insert(s.ident.clone(), DeclType::StructImported { generics: &s.generics }); },
							ExportStatus::NoExport => { declared.insert(s.ident.clone(), DeclType::StructIgnored); },
							ExportStatus::TestOnly => continue,
							ExportStatus::NotImplementable => panic!("(C-not implementable) should only appear on traits!"),
						}
					}
				},
				syn::Item::Type(t) if export_status(&t.attrs) == ExportStatus::Export => {
					if let syn::Visibility::Public(_) = t.vis {
						declared.insert(t.ident.clone(), DeclType::StructImported { generics: &t.generics });
					}
				},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export if is_enum_opaque(e) => { declared.insert(e.ident.clone(), DeclType::EnumIgnored { generics: &e.generics }); },
							ExportStatus::Export => { declared.insert(e.ident.clone(), DeclType::MirroredEnum); },
							ExportStatus::NotImplementable => panic!("(C-not implementable) should only appear on traits!"),
							_ => continue,
						}
					}
				},
				syn::Item::Trait(t) => {
					match export_status(&t.attrs) {
						ExportStatus::Export|ExportStatus::NotImplementable => {
							if let syn::Visibility::Public(_) = t.vis {
								declared.insert(t.ident.clone(), DeclType::Trait(t));
							}
						},
						_ => continue,
					}
				},
				syn::Item::Mod(m) => {
					priv_modules.insert(m.ident.clone());
				},
				_ => {},
			}
		}

		Self { crate_name, library, module_path, imports, declared, priv_modules }
	}

	pub fn maybe_resolve_declared(&self, id: &syn::Ident) -> Option<&DeclType<'crate_lft>> {
		self.declared.get(id)
	}

	pub fn maybe_resolve_ident(&self, id: &syn::Ident) -> Option<String> {
		if let Some((imp, _)) = self.imports.get(id) {
			Some(imp.clone())
		} else if self.declared.get(id).is_some() {
			Some(self.module_path.to_string() + "::" + &format!("{}", id))
		} else { None }
	}

	fn maybe_resolve_imported_path(&self, p: &syn::Path, generics: Option<&GenericTypes>) -> Option<String> {
		if let Some(gen_types) = generics {
			if let Some(resp) = gen_types.maybe_resolve_path(p) {
				return Some(resp.clone());
			}
		}

		if p.leading_colon.is_some() {
			let mut res: String = p.segments.iter().enumerate().map(|(idx, seg)| {
				format!("{}{}", if idx == 0 { "" } else { "::" }, seg.ident)
			}).collect();
			let firstseg = p.segments.iter().next().unwrap();
			if !self.library.dependencies.contains(&firstseg.ident) {
				res = self.crate_name.to_owned() + "::" + &res;
			}
			Some(res)
		} else if let Some(id) = p.get_ident() {
			self.maybe_resolve_ident(id)
		} else {
			if p.segments.len() == 1 {
				let seg = p.segments.iter().next().unwrap();
				return self.maybe_resolve_ident(&seg.ident);
			}
			let mut seg_iter = p.segments.iter();
			let first_seg = seg_iter.next().unwrap();
			let remaining: String = seg_iter.map(|seg| {
				format!("::{}", seg.ident)
			}).collect();
			let first_seg_str = format!("{}", first_seg.ident);
			if let Some((imp, _)) = self.imports.get(&first_seg.ident) {
				if remaining != "" {
					Some(imp.clone() + &remaining)
				} else {
					Some(imp.clone())
				}
			} else if let Some(_) = self.priv_modules.get(&first_seg.ident) {
				Some(format!("{}::{}{}", self.module_path, first_seg.ident, remaining))
			} else if first_seg_is_stdlib(&first_seg_str) || self.library.dependencies.contains(&first_seg.ident) {
				Some(first_seg_str + &remaining)
			} else if first_seg_str == "crate" {
				Some(self.crate_name.to_owned() + &remaining)
			} else { None }
		}
	}

	pub fn maybe_resolve_path(&self, p: &syn::Path, generics: Option<&GenericTypes>) -> Option<String> {
		self.maybe_resolve_imported_path(p, generics).map(|mut path| {
			loop {
				// Now that we've resolved the path to the path as-imported, check whether the path
				// is actually a pub(.*) use statement and map it to the real path.
				let path_tmp = path.clone();
				let crate_name = path_tmp.splitn(2, "::").next().unwrap();
				let mut module_riter = path_tmp.rsplitn(2, "::");
				let obj = module_riter.next().unwrap();
				if let Some(module_path) = module_riter.next() {
					if let Some(m) = self.library.modules.get(module_path) {
						for item in m.items.iter() {
							if let syn::Item::Use(syn::ItemUse { vis, tree, .. }) = item {
								match vis {
									syn::Visibility::Public(_)|
									syn::Visibility::Crate(_)|
									syn::Visibility::Restricted(_) => {
										Self::walk_use_intern(crate_name, module_path,
											&self.library.dependencies, tree, "",
											syn::punctuated::Punctuated::new(), &mut |ident, (use_path, _)| {
												if format!("{}", ident) == obj {
													path = use_path;
												}
										});
									},
									syn::Visibility::Inherited => {},
								}
							}
						}
					}
				}
				break;
			}
			path
		})
	}

	/// Map all the Paths in a Type into absolute paths given a set of imports (generated via process_use_intern)
	pub fn resolve_imported_refs(&self, mut ty: syn::Type) -> syn::Type {
		match &mut ty {
			syn::Type::Path(p) => {
				if p.path.segments.len() != 1 { unimplemented!(); }
				let mut args = p.path.segments[0].arguments.clone();
				if let syn::PathArguments::AngleBracketed(ref mut generics) = &mut args {
					for arg in generics.args.iter_mut() {
						if let syn::GenericArgument::Type(ref mut t) = arg {
							*t = self.resolve_imported_refs(t.clone());
						}
					}
				}
				if let Some((_, newpath)) = self.imports.get(single_ident_generic_path_to_ident(&p.path).unwrap()) {
					p.path = newpath.clone();
				}
				p.path.segments[0].arguments = args;
			},
			syn::Type::Reference(r) => {
				r.elem = Box::new(self.resolve_imported_refs((*r.elem).clone()));
			},
			syn::Type::Slice(s) => {
				s.elem = Box::new(self.resolve_imported_refs((*s.elem).clone()));
			},
			syn::Type::Tuple(t) => {
				for e in t.elems.iter_mut() {
					*e = self.resolve_imported_refs(e.clone());
				}
			},
			_ => unimplemented!(),
		}
		ty
	}
}

// templates_defined is walked to write the C++ header, so if we use the default hashing it get
// reordered on each genbindings run. Instead, we use SipHasher (which defaults to 0-keys) so that
// the sorting is stable across runs. It is deprecated, but the "replacement" doesn't actually
// accomplish the same goals, so we just ignore it.
#[allow(deprecated)]
pub type NonRandomHash = hash::BuildHasherDefault<hash::SipHasher>;

/// A public module
pub struct ASTModule {
	pub attrs: Vec<syn::Attribute>,
	pub items: Vec<syn::Item>,
	pub submods: Vec<String>,
}
/// A struct containing the syn::File AST for each file in the crate.
pub struct FullLibraryAST {
	pub modules: HashMap<String, ASTModule, NonRandomHash>,
	pub dependencies: HashSet<syn::Ident>,
}
impl FullLibraryAST {
	fn load_module(&mut self, module: String, attrs: Vec<syn::Attribute>, mut items: Vec<syn::Item>) {
		let mut non_mod_items = Vec::with_capacity(items.len());
		let mut submods = Vec::with_capacity(items.len());
		for item in items.drain(..) {
			match item {
				syn::Item::Mod(m) if m.content.is_some() => {
					if export_status(&m.attrs) == ExportStatus::Export {
						if let syn::Visibility::Public(_) = m.vis {
							let modident = format!("{}", m.ident);
							let modname = if module != "" {
								module.clone() + "::" + &modident
							} else {
								self.dependencies.insert(m.ident);
								modident.clone()
							};
							self.load_module(modname, m.attrs, m.content.unwrap().1);
							submods.push(modident);
						} else {
							non_mod_items.push(syn::Item::Mod(m));
						}
					}
				},
				syn::Item::Mod(_) => panic!("--pretty=expanded output should never have non-body modules"),
				syn::Item::ExternCrate(c) => {
					if export_status(&c.attrs) == ExportStatus::Export {
						self.dependencies.insert(c.ident);
					}
				},
				_ => { non_mod_items.push(item); }
			}
		}
		self.modules.insert(module, ASTModule { attrs, items: non_mod_items, submods });
	}

	pub fn load_lib(lib: syn::File) -> Self {
		assert_eq!(export_status(&lib.attrs), ExportStatus::Export);
		let mut res = Self { modules: HashMap::default(), dependencies: HashSet::new() };
		res.load_module("".to_owned(), lib.attrs, lib.items);
		res
	}
}

/// List of manually-generated types which are clonable
fn initial_clonable_types() -> HashSet<String> {
	let mut res = HashSet::new();
	res.insert("crate::c_types::U5".to_owned());
	res.insert("crate::c_types::U128".to_owned());
	res.insert("crate::c_types::FourBytes".to_owned());
	res.insert("crate::c_types::TwelveBytes".to_owned());
	res.insert("crate::c_types::SixteenBytes".to_owned());
	res.insert("crate::c_types::TwentyBytes".to_owned());
	res.insert("crate::c_types::ThirtyTwoBytes".to_owned());
	res.insert("crate::c_types::EightU16s".to_owned());
	res.insert("crate::c_types::SecretKey".to_owned());
	res.insert("crate::c_types::PublicKey".to_owned());
	res.insert("crate::c_types::Transaction".to_owned());
	res.insert("crate::c_types::Witness".to_owned());
	res.insert("crate::c_types::WitnessVersion".to_owned());
	res.insert("crate::c_types::TxOut".to_owned());
	res.insert("crate::c_types::Signature".to_owned());
	res.insert("crate::c_types::RecoverableSignature".to_owned());
	res.insert("crate::c_types::BigEndianScalar".to_owned());
	res.insert("crate::c_types::Bech32Error".to_owned());
	res.insert("crate::c_types::Secp256k1Error".to_owned());
	res.insert("crate::c_types::IOError".to_owned());
	res.insert("crate::c_types::Error".to_owned());
	res.insert("crate::c_types::Str".to_owned());

	// Because some types are manually-mapped to CVec_u8Z we may end up checking if its clonable
	// before we ever get to constructing the type fully via
	// `write_c_mangled_container_path_intern` (which will add it here too), so we have to manually
	// add it on startup.
	res.insert("crate::c_types::derived::CVec_u8Z".to_owned());
	res
}

/// Top-level struct tracking everything which has been defined while walking the crate.
pub struct CrateTypes<'a> {
	/// This may contain structs or enums, but only when either is mapped as
	/// struct X { inner: *mut originalX, .. }
	pub opaques: HashMap<String, (&'a syn::Ident, &'a syn::Generics)>,
	/// structs that weren't exposed
	pub priv_structs: HashMap<String, &'a syn::Generics>,
	/// Enums which are mapped as C enums with conversion functions
	pub mirrored_enums: HashMap<String, &'a syn::ItemEnum>,
	/// Traits which are mapped as a pointer + jump table
	pub traits: HashMap<String, &'a syn::ItemTrait>,
	/// Aliases from paths to some other Type
	pub type_aliases: HashMap<String, syn::Type>,
	/// Value is an alias to Key (maybe with some generics)
	pub reverse_alias_map: HashMap<String, Vec<(String, syn::PathArguments)>>,
	/// Template continer types defined, map from mangled type name -> whether a destructor fn
	/// exists.
	///
	/// This is used at the end of processing to make C++ wrapper classes
	pub templates_defined: RefCell<HashMap<String, bool, NonRandomHash>>,
	/// The output file for any created template container types, written to as we find new
	/// template containers which need to be defined.
	template_file: RefCell<&'a mut File>,
	/// Set of containers which are clonable
	clonable_types: RefCell<HashSet<String>>,
	/// Key impls Value
	pub trait_impls: HashMap<String, Vec<String>>,
	/// The full set of modules in the crate(s)
	pub lib_ast: &'a FullLibraryAST,
}

impl<'a> CrateTypes<'a> {
	pub fn new(template_file: &'a mut File, libast: &'a FullLibraryAST) -> Self {
		CrateTypes {
			opaques: HashMap::new(), mirrored_enums: HashMap::new(), traits: HashMap::new(),
			type_aliases: HashMap::new(), reverse_alias_map: HashMap::new(),
			templates_defined: RefCell::new(HashMap::default()), priv_structs: HashMap::new(),
			clonable_types: RefCell::new(initial_clonable_types()), trait_impls: HashMap::new(),
			template_file: RefCell::new(template_file), lib_ast: &libast,
		}
	}
	pub fn set_clonable(&self, object: String) {
		self.clonable_types.borrow_mut().insert(object);
	}
	pub fn is_clonable(&self, object: &str) -> bool {
		self.clonable_types.borrow().contains(object)
	}
	pub fn write_new_template(&self, mangled_container: String, has_destructor: bool, created_container: &[u8]) {
		self.template_file.borrow_mut().write(created_container).unwrap();
		self.templates_defined.borrow_mut().insert(mangled_container, has_destructor);
	}
}

/// A struct which tracks resolving rust types into C-mapped equivalents, exists for one specific
/// module but contains a reference to the overall CrateTypes tracking.
pub struct TypeResolver<'mod_lifetime, 'crate_lft: 'mod_lifetime> {
	pub module_path: &'mod_lifetime str,
	pub crate_types: &'mod_lifetime CrateTypes<'crate_lft>,
	pub types: ImportResolver<'mod_lifetime, 'crate_lft>,
}

/// Returned by write_empty_rust_val_check_suffix to indicate what type of dereferencing needs to
/// happen to get the inner value of a generic.
enum EmptyValExpectedTy {
	/// A type which has a flag for being empty (eg an array where we treat all-0s as empty).
	NonPointer,
	/// A Option mapped as a COption_*Z
	OptionType,
	/// A pointer which we want to convert to a reference.
	ReferenceAsPointer,
}

#[derive(PartialEq)]
/// Describes the appropriate place to print a general type-conversion string when converting a
/// container.
enum ContainerPrefixLocation {
	/// Prints a general type-conversion string prefix and suffix outside of the
	/// container-conversion strings.
	OutsideConv,
	/// Prints a general type-conversion string prefix and suffix inside of the
	/// container-conversion strings.
	PerConv,
	/// Does not print the usual type-conversion string prefix and suffix.
	NoPrefix,
}

impl<'a, 'c: 'a> TypeResolver<'a, 'c> {
	pub fn new(module_path: &'a str, types: ImportResolver<'a, 'c>, crate_types: &'a CrateTypes<'c>) -> Self {
		Self { module_path, types, crate_types }
	}

	// *************************************************
	// *** Well know type and conversion definitions ***
	// *************************************************

	/// Returns true we if can just skip passing this to C entirely
	pub fn skip_path(&self, full_path: &str) -> bool {
		full_path == "bitcoin::secp256k1::Secp256k1" ||
		full_path == "bitcoin::secp256k1::Signing" ||
		full_path == "bitcoin::secp256k1::Verification"
	}
	/// Returns true we if can just skip passing this to C entirely
	fn no_arg_path_to_rust(&self, full_path: &str) -> &str {
		if full_path == "bitcoin::secp256k1::Secp256k1" {
			"secp256k1::global::SECP256K1"
		} else { unimplemented!(); }
	}

	/// Returns true if the object is a primitive and is mapped as-is with no conversion
	/// whatsoever.
	pub fn is_primitive(&self, full_path: &str) -> bool {
		match full_path {
			"bool" => true,
			"u64" => true,
			"u32" => true,
			"u16" => true,
			"u8" => true,
			"usize" => true,
			_ => false,
		}
	}
	pub fn is_clonable(&self, ty: &str) -> bool {
		if self.crate_types.is_clonable(ty) { return true; }
		if self.is_primitive(ty) { return true; }
		match ty {
			"()" => true,
			_ => false,
		}
	}
	/// Gets the C-mapped type for types which are outside of the crate, or which are manually
	/// ignored by for some reason need mapping anyway.
	fn c_type_from_path<'b>(&self, full_path: &'b str, is_ref: bool, _ptr_for_ref: bool) -> Option<&'b str> {
		if self.is_primitive(full_path) {
			return Some(full_path);
		}
		match full_path {
			// Note that no !is_ref types can map to an array because Rust and C's call semantics
			// for arrays are different (https://github.com/eqrion/cbindgen/issues/528)

			"[u8; 32]" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"[u8; 20]" if !is_ref => Some("crate::c_types::TwentyBytes"),
			"[u8; 16]" if !is_ref => Some("crate::c_types::SixteenBytes"),
			"[u8; 12]" if !is_ref => Some("crate::c_types::TwelveBytes"),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes"),
			"[u8; 3]" if !is_ref => Some("crate::c_types::ThreeBytes"), // Used for RGB values
			"[u16; 8]" if !is_ref => Some("crate::c_types::EightU16s"),

			"str" if is_ref => Some("crate::c_types::Str"),
			"alloc::string::String"|"String" => Some("crate::c_types::Str"),

			"bitcoin::Address" => Some("crate::c_types::Str"),

			"std::time::Duration"|"core::time::Duration" => Some("u64"),
			"std::time::SystemTime" => Some("u64"),
			"std::io::Error"|"lightning::io::Error"|"lightning::io::ErrorKind" => Some("crate::c_types::IOError"),
			"core::fmt::Arguments" if is_ref => Some("crate::c_types::Str"),

			"core::convert::Infallible" => Some("crate::c_types::NotConstructable"),

			"bitcoin::bech32::Error"|"bech32::Error"
				if !is_ref => Some("crate::c_types::Bech32Error"),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some("crate::c_types::Secp256k1Error"),

			"core::num::ParseIntError" => Some("crate::c_types::Error"),
			"core::str::Utf8Error" => Some("crate::c_types::Error"),

			"bitcoin::bech32::u5"|"bech32::u5" => Some("crate::c_types::U5"),
			"u128" => Some("crate::c_types::U128"),
			"core::num::NonZeroU8" => Some("u8"),

			"secp256k1::PublicKey"|"bitcoin::secp256k1::PublicKey" => Some("crate::c_types::PublicKey"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some("crate::c_types::Signature"),
			"bitcoin::secp256k1::ecdsa::RecoverableSignature" => Some("crate::c_types::RecoverableSignature"),
			"bitcoin::secp256k1::SecretKey" if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::secp256k1::SecretKey" if !is_ref => Some("crate::c_types::SecretKey"),
			"bitcoin::secp256k1::Scalar" if is_ref  => Some("*const crate::c_types::BigEndianScalar"),
			"bitcoin::secp256k1::Scalar" if !is_ref => Some("crate::c_types::BigEndianScalar"),
			"bitcoin::secp256k1::ecdh::SharedSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),

			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("crate::c_types::derived::CVec_u8Z"),
			"bitcoin::OutPoint"|"bitcoin::blockdata::transaction::OutPoint" => Some("crate::lightning::chain::transaction::OutPoint"),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" => Some("crate::c_types::Transaction"),
			"bitcoin::Witness" => Some("crate::c_types::Witness"),
			"bitcoin::TxOut"|"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut"),
			"bitcoin::network::constants::Network" => Some("crate::bitcoin::network::Network"),
			"bitcoin::util::address::WitnessVersion" => Some("crate::c_types::WitnessVersion"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref  => Some("*const [u8; 80]"),
			"bitcoin::blockdata::block::Block" if is_ref  => Some("crate::c_types::u8slice"),

			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if !is_ref => Some("crate::c_types::TwentyBytes"),
			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if is_ref => Some("*const [u8; 20]"),
			"bitcoin::hash_types::WScriptHash"
				if is_ref => Some("*const [u8; 32]"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"|"bitcoin::blockdata::constants::ChainHash"
				if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"|"bitcoin::blockdata::constants::ChainHash"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if is_ref => Some("*const [u8; 32]"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),

			"lightning::io::Read" => Some("crate::c_types::u8slice"),

			_ => None,
		}
	}

	fn from_c_conversion_new_var_from_path<'b>(&self, _full_path: &str, _is_ref: bool) -> Option<(&'b str, &'b str)> {
		None
	}
	fn from_c_conversion_prefix_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Vec" if !is_ref => Some("local_"),
			"Result" if !is_ref => Some("local_"),
			"Option" if is_ref => Some("&local_"),
			"Option" => Some("local_"),

			"[u8; 32]" if is_ref => Some("unsafe { &*"),
			"[u8; 32]" if !is_ref => Some(""),
			"[u8; 20]" if !is_ref => Some(""),
			"[u8; 16]" if !is_ref => Some(""),
			"[u8; 12]" if !is_ref => Some(""),
			"[u8; 4]" if !is_ref => Some(""),
			"[u8; 3]" if !is_ref => Some(""),
			"[u16; 8]" if !is_ref => Some(""),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(""),
			"alloc::string::String"|"String" => Some(""),
			"std::io::Error"|"lightning::io::Error"|"lightning::io::ErrorKind" => Some(""),
			// Note that we'll panic for String if is_ref, as we only have non-owned memory, we
			// cannot create a &String.

			"core::convert::Infallible" => Some("panic!(\"You must never construct a NotConstructable! : "),

			"bitcoin::bech32::Error"|"bech32::Error" if !is_ref => Some(""),
			"bitcoin::secp256k1::Error"|"secp256k1::Error" if !is_ref => Some(""),

			"core::num::ParseIntError" => Some("u8::from_str_radix(\" a\", 10).unwrap_err() /*"),
			"core::str::Utf8Error" => Some("core::str::from_utf8(&[0xff]).unwrap_err() /*"),

			"std::time::Duration"|"core::time::Duration" => Some("core::time::Duration::from_secs("),
			"std::time::SystemTime" => Some("(::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs("),

			"bitcoin::bech32::u5"|"bech32::u5" => Some(""),
			"u128" => Some(""),
			"core::num::NonZeroU8" => Some("core::num::NonZeroU8::new("),

			"bitcoin::secp256k1::PublicKey"|"secp256k1::PublicKey" if is_ref => Some("&"),
			"bitcoin::secp256k1::PublicKey"|"secp256k1::PublicKey" => Some(""),
			"bitcoin::secp256k1::ecdsa::Signature" if is_ref => Some("&"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some(""),
			"bitcoin::secp256k1::ecdsa::RecoverableSignature" => Some(""),
			"bitcoin::secp256k1::SecretKey" if is_ref => Some("&::bitcoin::secp256k1::SecretKey::from_slice(&unsafe { *"),
			"bitcoin::secp256k1::SecretKey" if !is_ref => Some(""),
			"bitcoin::secp256k1::Scalar" if is_ref => Some("&"),
			"bitcoin::secp256k1::Scalar" if !is_ref => Some(""),
			"bitcoin::secp256k1::ecdh::SharedSecret" if !is_ref => Some("::bitcoin::secp256k1::ecdh::SharedSecret::from_bytes("),

			"bitcoin::blockdata::script::Script" if is_ref => Some("&::bitcoin::blockdata::script::Script::from(Vec::from("),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("::bitcoin::blockdata::script::Script::from("),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" if is_ref => Some("&"),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" => Some(""),
			"bitcoin::Witness" if is_ref => Some("&"),
			"bitcoin::Witness" => Some(""),
			"bitcoin::OutPoint"|"bitcoin::blockdata::transaction::OutPoint" => Some("crate::c_types::C_to_bitcoin_outpoint("),
			"bitcoin::TxOut"|"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(""),
			"bitcoin::network::constants::Network" => Some(""),
			"bitcoin::util::address::WitnessVersion" => Some(""),
			"bitcoin::blockdata::block::BlockHeader" => Some("&::bitcoin::consensus::encode::deserialize(unsafe { &*"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("&::bitcoin::consensus::encode::deserialize("),

			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash" if !is_ref =>
				Some("bitcoin::hash_types::PubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner("),
			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash" if is_ref =>
				Some("&bitcoin::hash_types::PubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner(unsafe { *"),
			"bitcoin::hash_types::WPubkeyHash" if is_ref =>
				Some("&bitcoin::hash_types::WPubkeyHash::from_hash(bitcoin::hashes::Hash::from_inner(unsafe { *"),
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash" if !is_ref =>
				Some("bitcoin::hash_types::ScriptHash::from_hash(bitcoin::hashes::Hash::from_inner("),
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash" if is_ref =>
				Some("&bitcoin::hash_types::ScriptHash::from_hash(bitcoin::hashes::Hash::from_inner(unsafe { *"),
			"bitcoin::hash_types::WScriptHash" if is_ref =>
				Some("&bitcoin::hash_types::WScriptHash::from_hash(bitcoin::hashes::Hash::from_inner(unsafe { *"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some("&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*"),
			"bitcoin::hash_types::Txid" if !is_ref => Some("::bitcoin::hash_types::Txid::from_slice(&"),
			"bitcoin::hash_types::BlockHash"|"bitcoin::BlockHash" => Some("::bitcoin::hash_types::BlockHash::from_slice(&"),
			"bitcoin::blockdata::constants::ChainHash" => Some("::bitcoin::blockdata::constants::ChainHash::from(&"),
			"lightning::ln::PaymentHash" if !is_ref => Some("::lightning::ln::PaymentHash("),
			"lightning::ln::PaymentHash" if is_ref => Some("&::lightning::ln::PaymentHash(unsafe { *"),
			"lightning::ln::PaymentPreimage" if !is_ref => Some("::lightning::ln::PaymentPreimage("),
			"lightning::ln::PaymentPreimage" if is_ref => Some("&::lightning::ln::PaymentPreimage(unsafe { *"),
			"lightning::ln::PaymentSecret" if !is_ref => Some("::lightning::ln::PaymentSecret("),
			"lightning::ln::channelmanager::PaymentId" if !is_ref => Some("::lightning::ln::channelmanager::PaymentId("),
			"lightning::ln::channelmanager::PaymentId" if is_ref=> Some("&::lightning::ln::channelmanager::PaymentId( unsafe { *"),
			"lightning::ln::channelmanager::InterceptId" if !is_ref => Some("::lightning::ln::channelmanager::InterceptId("),
			"lightning::ln::channelmanager::InterceptId" if is_ref=> Some("&::lightning::ln::channelmanager::InterceptId( unsafe { *"),
			"lightning::chain::keysinterface::KeyMaterial" if !is_ref => Some("::lightning::chain::keysinterface::KeyMaterial("),
			"lightning::chain::keysinterface::KeyMaterial" if is_ref=> Some("&::lightning::chain::keysinterface::KeyMaterial( unsafe { *"),

			// List of traits we map (possibly during processing of other files):
			"lightning::io::Read" => Some("&mut "),

			_ => None,
		}.map(|s| s.to_owned())
	}
	fn from_c_conversion_suffix_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Vec" if !is_ref => Some(""),
			"Option" => Some(""),
			"Result" if !is_ref => Some(""),

			"[u8; 32]" if is_ref => Some("}"),
			"[u8; 32]" if !is_ref => Some(".data"),
			"[u8; 20]" if !is_ref => Some(".data"),
			"[u8; 16]" if !is_ref => Some(".data"),
			"[u8; 12]" if !is_ref => Some(".data"),
			"[u8; 4]" if !is_ref => Some(".data"),
			"[u8; 3]" if !is_ref => Some(".data"),
			"[u16; 8]" if !is_ref => Some(".data"),

			"[u8]" if is_ref => Some(".to_slice()"),
			"[usize]" if is_ref => Some(".to_slice()"),

			"str" if is_ref => Some(".into_str()"),
			"alloc::string::String"|"String" => Some(".into_string()"),
			"std::io::Error"|"lightning::io::Error" => Some(".to_rust()"),
			"lightning::io::ErrorKind" => Some(".to_rust_kind()"),

			"core::convert::Infallible" => Some("\")"),

			"bitcoin::bech32::Error"|"bech32::Error" if !is_ref => Some(".into_rust()"),
			"bitcoin::secp256k1::Error"|"secp256k1::Error" if !is_ref => Some(".into_rust()"),

			"core::num::ParseIntError" => Some("*/"),
			"core::str::Utf8Error" => Some("*/"),

			"std::time::Duration"|"core::time::Duration" => Some(")"),
			"std::time::SystemTime" => Some("))"),

			"bitcoin::bech32::u5"|"bech32::u5" => Some(".into()"),
			"u128" => Some(".into()"),
			"core::num::NonZeroU8" => Some(").expect(\"Value must be non-zero\")"),

			"bitcoin::secp256k1::PublicKey"|"secp256k1::PublicKey" => Some(".into_rust()"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some(".into_rust()"),
			"bitcoin::secp256k1::ecdsa::RecoverableSignature" => Some(".into_rust()"),
			"bitcoin::secp256k1::SecretKey" if !is_ref => Some(".into_rust()"),
			"bitcoin::secp256k1::SecretKey" if is_ref => Some("}[..]).unwrap()"),
			"bitcoin::secp256k1::Scalar" => Some(".into_rust()"),
			"bitcoin::secp256k1::ecdh::SharedSecret" if !is_ref => Some(".data)"),

			"bitcoin::blockdata::script::Script" if is_ref => Some(".to_slice()))"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_rust())"),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" => Some(".into_bitcoin()"),
			"bitcoin::Witness" => Some(".into_bitcoin()"),
			"bitcoin::OutPoint"|"bitcoin::blockdata::transaction::OutPoint" => Some(")"),
			"bitcoin::TxOut"|"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(".into_rust()"),
			"bitcoin::network::constants::Network" => Some(".into_bitcoin()"),
			"bitcoin::util::address::WitnessVersion" => Some(".into()"),
			"bitcoin::blockdata::block::BlockHeader" => Some(" }).unwrap()"),
			"bitcoin::blockdata::block::Block" => Some(".to_slice()).unwrap()"),

			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|"bitcoin::hash_types::WScriptHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if !is_ref => Some(".data))"),
			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|"bitcoin::hash_types::WScriptHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if is_ref => Some(" }.clone()))"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some(" }[..]).unwrap()"),
			"bitcoin::hash_types::Txid" => Some(".data[..]).unwrap()"),
			"bitcoin::hash_types::BlockHash"|"bitcoin::BlockHash" if !is_ref => Some(".data[..]).unwrap()"),
			"bitcoin::blockdata::constants::ChainHash" if !is_ref => Some(".data[..])"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if !is_ref => Some(".data)"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if is_ref => Some(" })"),

			// List of traits we map (possibly during processing of other files):
			"lightning::io::Read" => Some(".to_reader()"),

			_ => None,
		}.map(|s| s.to_owned())
	}

	fn to_c_conversion_new_var_from_path<'b>(&self, full_path: &str, is_ref: bool) -> Option<(&'b str, &'b str)> {
		if self.is_primitive(full_path) {
			return None;
		}
		match full_path {
			"[u8]" if is_ref => Some(("crate::c_types::u8slice::from_slice(", ")")),
			"[usize]" if is_ref => Some(("crate::c_types::usizeslice::from_slice(", ")")),

			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some(("{ let mut s = [0u8; 80]; s[..].copy_from_slice(&::bitcoin::consensus::encode::serialize(", ")); s }")),
			"bitcoin::blockdata::block::Block" if is_ref => Some(("::bitcoin::consensus::encode::serialize(", ")")),
			"bitcoin::hash_types::Txid" => None,

			_ => None,
		}.map(|s| s.to_owned())
	}
	fn to_c_conversion_inline_prefix_from_path(&self, full_path: &str, is_ref: bool, _ptr_for_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Result" if !is_ref => Some("local_"),
			"Vec" if !is_ref => Some("local_"),
			"Option" => Some("local_"),

			"[u8; 32]" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"[u8; 32]" if is_ref => Some(""),
			"[u8; 20]" if !is_ref => Some("crate::c_types::TwentyBytes { data: "),
			"[u8; 16]" if !is_ref => Some("crate::c_types::SixteenBytes { data: "),
			"[u8; 12]" if !is_ref => Some("crate::c_types::TwelveBytes { data: "),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes { data: "),
			"[u8; 3]" if is_ref => Some(""),
			"[u16; 8]" if !is_ref => Some("crate::c_types::EightU16s { data: "),

			"[u8]" if is_ref => Some("local_"),
			"[usize]" if is_ref => Some("local_"),

			"str" if is_ref => Some(""),
			"alloc::string::String"|"String" => Some(""),

			"bitcoin::Address" => Some("alloc::string::ToString::to_string(&"),

			"std::time::Duration"|"core::time::Duration" => Some(""),
			"std::time::SystemTime" => Some(""),
			"std::io::Error"|"lightning::io::Error" => Some("crate::c_types::IOError::from_rust("),
			"lightning::io::ErrorKind" => Some("crate::c_types::IOError::from_rust_kind("),
			"core::fmt::Arguments" => Some("alloc::format!(\"{}\", "),

			"core::convert::Infallible" => Some("panic!(\"Cannot construct an Infallible: "),

			"bitcoin::bech32::Error"|"bech32::Error"
				if !is_ref => Some("crate::c_types::Bech32Error::from_rust("),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some("crate::c_types::Secp256k1Error::from_rust("),

			"core::num::ParseIntError" => Some("crate::c_types::Error { _dummy: 0 } /*"),
			"core::str::Utf8Error" => Some("crate::c_types::Error { _dummy: 0 } /*"),

			"bitcoin::bech32::u5"|"bech32::u5" => Some(""),
			"u128" => Some(""),

			"bitcoin::secp256k1::PublicKey"|"secp256k1::PublicKey" => Some("crate::c_types::PublicKey::from_rust(&"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some("crate::c_types::Signature::from_rust(&"),
			"bitcoin::secp256k1::ecdsa::RecoverableSignature" => Some("crate::c_types::RecoverableSignature::from_rust(&"),
			"bitcoin::secp256k1::SecretKey" if is_ref => Some(""),
			"bitcoin::secp256k1::SecretKey" if !is_ref => Some("crate::c_types::SecretKey::from_rust("),
			"bitcoin::secp256k1::Scalar" if !is_ref => Some("crate::c_types::BigEndianScalar::from_rust(&"),
			"bitcoin::secp256k1::ecdh::SharedSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice::from_slice(&"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(""),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" if is_ref => Some("crate::c_types::Transaction::from_bitcoin("),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" => Some("crate::c_types::Transaction::from_bitcoin(&"),
			"bitcoin::Witness" if is_ref => Some("crate::c_types::Witness::from_bitcoin("),
			"bitcoin::Witness" if !is_ref => Some("crate::c_types::Witness::from_bitcoin(&"),
			"bitcoin::OutPoint"|"bitcoin::blockdata::transaction::OutPoint" => Some("crate::c_types::bitcoin_to_C_outpoint("),
			"bitcoin::TxOut"|"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut::from_rust("),
			"bitcoin::network::constants::Network" => Some("crate::bitcoin::network::Network::from_bitcoin("),
			"bitcoin::util::address::WitnessVersion" => Some(""),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some("&local_"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("crate::c_types::u8slice::from_slice(&local_"),

			"bitcoin::hash_types::Txid" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|"bitcoin::hash_types::WScriptHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if !is_ref => Some("crate::c_types::TwentyBytes { data: "),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"|"bitcoin::blockdata::constants::ChainHash"
				if is_ref => Some(""),
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"|"bitcoin::blockdata::constants::ChainHash"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if is_ref => Some("&"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			"lightning::io::Read" => Some("crate::c_types::u8slice::from_vec(&crate::c_types::reader_to_vec("),

			_ => None,
		}.map(|s| s.to_owned())
	}
	fn to_c_conversion_inline_suffix_from_path(&self, full_path: &str, is_ref: bool, _ptr_for_ref: bool) -> Option<String> {
		if self.is_primitive(full_path) {
			return Some("".to_owned());
		}
		match full_path {
			"Result" if !is_ref => Some(""),
			"Vec" if !is_ref => Some(".into()"),
			"Option" => Some(""),

			"[u8; 32]" if !is_ref => Some(" }"),
			"[u8; 32]" if is_ref => Some(""),
			"[u8; 20]" if !is_ref => Some(" }"),
			"[u8; 16]" if !is_ref => Some(" }"),
			"[u8; 12]" if !is_ref => Some(" }"),
			"[u8; 4]" if !is_ref => Some(" }"),
			"[u8; 3]" if is_ref => Some(""),
			"[u16; 8]" if !is_ref => Some(" }"),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(".into()"),
			"alloc::string::String"|"String" if is_ref => Some(".as_str().into()"),
			"alloc::string::String"|"String" => Some(".into()"),

			"bitcoin::Address" => Some(").into()"),

			"std::time::Duration"|"core::time::Duration" => Some(".as_secs()"),
			"std::time::SystemTime" => Some(".duration_since(::std::time::SystemTime::UNIX_EPOCH).expect(\"Times must be post-1970\").as_secs()"),
			"std::io::Error"|"lightning::io::Error"|"lightning::io::ErrorKind" => Some(")"),
			"core::fmt::Arguments" => Some(").into()"),

			"core::convert::Infallible" => Some("\")"),

			"bitcoin::secp256k1::Error"|"bech32::Error"
				if !is_ref => Some(")"),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some(")"),

			"core::num::ParseIntError" => Some("*/"),
			"core::str::Utf8Error" => Some("*/"),

			"bitcoin::bech32::u5"|"bech32::u5" => Some(".into()"),
			"u128" => Some(".into()"),

			"bitcoin::secp256k1::PublicKey"|"secp256k1::PublicKey" => Some(")"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some(")"),
			"bitcoin::secp256k1::ecdsa::RecoverableSignature" => Some(")"),
			"bitcoin::secp256k1::SecretKey" if !is_ref => Some(")"),
			"bitcoin::secp256k1::SecretKey" if is_ref => Some(".as_ref()"),
			"bitcoin::secp256k1::Scalar" if !is_ref => Some(")"),
			"bitcoin::secp256k1::ecdh::SharedSecret" if !is_ref => Some(".secret_bytes() }"),

			"bitcoin::blockdata::script::Script" if is_ref => Some("[..])"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_bytes().into()"),
			"bitcoin::blockdata::transaction::Transaction"|"bitcoin::Transaction" => Some(")"),
			"bitcoin::Witness" => Some(")"),
			"bitcoin::OutPoint"|"bitcoin::blockdata::transaction::OutPoint" => Some(")"),
			"bitcoin::TxOut"|"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(")"),
			"bitcoin::network::constants::Network" => Some(")"),
			"bitcoin::util::address::WitnessVersion" => Some(".into()"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some(""),
			"bitcoin::blockdata::block::Block" if is_ref => Some(")"),

			"bitcoin::hash_types::Txid" if !is_ref => Some(".into_inner() }"),

			"bitcoin::PubkeyHash"|"bitcoin::hash_types::PubkeyHash"|
			"bitcoin::hash_types::WPubkeyHash"|"bitcoin::hash_types::WScriptHash"|
			"bitcoin::ScriptHash"|"bitcoin::hash_types::ScriptHash"
				if !is_ref => Some(".as_hash().into_inner() }"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if is_ref => Some(".as_inner()"),
			"bitcoin::hash_types::Txid"|"bitcoin::BlockHash"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if !is_ref => Some(".into_inner() }"),
			"bitcoin::blockdata::constants::ChainHash" if is_ref => Some(".as_bytes() }"),
			"bitcoin::blockdata::constants::ChainHash" if !is_ref => Some(".to_bytes() }"),
			"bitcoin::secp256k1::Message" if !is_ref => Some(".as_ref().clone() }"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if is_ref => Some(".0"),
			"lightning::ln::PaymentHash"|"lightning::ln::PaymentPreimage"|"lightning::ln::PaymentSecret"
			|"lightning::ln::channelmanager::PaymentId"|"lightning::ln::channelmanager::InterceptId"
			|"lightning::chain::keysinterface::KeyMaterial"
				if !is_ref => Some(".0 }"),

			"lightning::io::Read" => Some("))"),

			_ => None,
		}.map(|s| s.to_owned())
	}

	fn empty_val_check_suffix_from_path(&self, full_path: &str) -> Option<&str> {
		match full_path {
			"secp256k1::PublicKey"|"bitcoin::secp256k1::PublicKey" => Some(".is_null()"),
			"bitcoin::secp256k1::ecdsa::Signature" => Some(".is_null()"),
			_ => None
		}
	}

	/// When printing a reference to the source crate's rust type, if we need to map it to a
	/// different "real" type, it can be done so here.
	/// This is useful to work around limitations in the binding type resolver, where we reference
	/// a non-public `use` alias.
	/// TODO: We should never need to use this!
	fn real_rust_type_mapping<'equiv>(&self, thing: &'equiv str) -> &'equiv str {
		match thing {
			"lightning::io::Read" => "crate::c_types::io::Read",
			_ => thing,
		}
	}

	// ****************************
	// *** Container Processing ***
	// ****************************

	/// Returns the module path in the generated mapping crate to the containers which we generate
	/// when writing to CrateTypes::template_file.
	pub fn generated_container_path() -> &'static str {
		"crate::c_types::derived"
	}
	/// Returns the module path in the generated mapping crate to the container templates, which
	/// are then concretized and put in the generated container path/template_file.
	fn container_templ_path() -> &'static str {
		"crate::c_types"
	}

	/// This should just be a closure, but doing so gets an error like
	/// error: reached the recursion limit while instantiating `types::TypeResolver::is_transpar...c/types.rs:1358:104: 1358:110]>>`
	/// which implies the concrete function instantiation of `is_transparent_container` ends up
	/// being recursive.
	fn deref_type<'one, 'b: 'one> (obj: &'one &'b syn::Type) -> &'b syn::Type { *obj }

	/// Returns true if the path containing the given args is a "transparent" container, ie an
	/// Option or a container which does not require a generated continer class.
	fn is_transparent_container<'i, I: Iterator<Item=&'i syn::Type>>(&self, full_path: &str, _is_ref: bool, mut args: I, generics: Option<&GenericTypes>) -> bool {
		if full_path == "Option" {
			let inner = args.next().unwrap();
			assert!(args.next().is_none());
			match generics.resolve_type(inner) {
				syn::Type::Reference(r) => {
					let elem = &*r.elem;
					match elem {
						syn::Type::Path(_) =>
							self.is_transparent_container(full_path, true, [elem].iter().map(Self::deref_type), generics),
						_ => true,
					}
				},
				syn::Type::Array(a) => {
					if let syn::Expr::Lit(l) = &a.len {
						if let syn::Lit::Int(i) = &l.lit {
							if i.base10_digits().parse::<usize>().unwrap() >= 32 {
								let mut buf = Vec::new();
								self.write_rust_type(&mut buf, generics, &a.elem, false);
								let ty = String::from_utf8(buf).unwrap();
								ty == "u8"
							} else {
								// Blindly assume that if we're trying to create an empty value for an
								// array < 32 entries that all-0s may be a valid state.
								unimplemented!();
							}
						} else { unimplemented!(); }
					} else { unimplemented!(); }
				},
				syn::Type::Path(p) => {
					if let Some(resolved) = self.maybe_resolve_path(&p.path, generics) {
						if self.c_type_has_inner_from_path(&resolved) { return true; }
						if self.is_primitive(&resolved) { return false; }
						// We want to move to using `Option_` mappings where possible rather than
						// manual mappings, as it makes downstream bindings simpler and is more
						// clear for users. Thus, we default to false but override for a few
						// types which had mappings defined when we were avoiding the `Option_`s.
						match &resolved as &str {
							"secp256k1::PublicKey"|"bitcoin::secp256k1::PublicKey" => true,
							_ => false,
						}
					} else { unimplemented!(); }
				},
				syn::Type::Tuple(_) => false,
				_ => unimplemented!(),
			}
		} else { false }
	}
	/// Returns true if the path is a "transparent" container, ie an Option or a container which does
	/// not require a generated continer class.
	pub fn is_path_transparent_container(&self, full_path: &syn::Path, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		let inner_iter = match &full_path.segments.last().unwrap().arguments {
			syn::PathArguments::None => return false,
			syn::PathArguments::AngleBracketed(args) => args.args.iter().map(|arg| {
				if let syn::GenericArgument::Type(ref ty) = arg {
					ty
				} else { unimplemented!() }
			}),
			syn::PathArguments::Parenthesized(_) => unimplemented!(),
		};
		self.is_transparent_container(&self.resolve_path(full_path, generics), is_ref, inner_iter, generics)
	}
	/// Returns true if this is a known, supported, non-transparent container.
	fn is_known_container(&self, full_path: &str, is_ref: bool) -> bool {
		(full_path == "Result" && !is_ref) || (full_path == "Vec" && !is_ref) || full_path.ends_with("Tuple") || full_path == "Option"
	}
	fn to_c_conversion_container_new_var<'b>(&self, generics: Option<&GenericTypes>, full_path: &str, is_ref: bool, single_contained: Option<&syn::Type>, var_name: &syn::Ident, var_access: &str)
			// Returns prefix + Vec<(prefix, var-name-to-inline-convert)> + suffix
			// expecting one element in the vec per generic type, each of which is inline-converted
			-> Option<(&'b str, Vec<(String, String)>, &'b str, ContainerPrefixLocation)> {
		match full_path {
			"Result" if !is_ref => {
				Some(("match ",
						vec![(" { Ok(mut o) => crate::c_types::CResultTempl::ok(".to_string(), "o".to_string()),
							(").into(), Err(mut e) => crate::c_types::CResultTempl::err(".to_string(), "e".to_string())],
						").into() }", ContainerPrefixLocation::PerConv))
			},
			"Vec" => {
				if is_ref {
					// We should only get here if the single contained has an inner
					assert!(self.c_type_has_inner(single_contained.unwrap()));
				}
				Some(("Vec::new(); for mut item in ", vec![(format!(".drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Slice" => {
				if let Some(syn::Type::Reference(_)) = single_contained {
					Some(("Vec::new(); for item in ", vec![(format!(".iter() {{ local_{}.push(", var_name), "(*item)".to_string())], "); }", ContainerPrefixLocation::PerConv))
				} else {
					Some(("Vec::new(); for item in ", vec![(format!(".iter() {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
				}
			},
			"Option" => {
				let mut is_contained_ref = false;
				let contained_struct = if let Some(syn::Type::Path(p)) = single_contained {
					Some(self.resolve_path(&p.path, generics))
				} else if let Some(syn::Type::Reference(r)) = single_contained {
					is_contained_ref = true;
					if let syn::Type::Path(p) = &*r.elem {
						Some(self.resolve_path(&p.path, generics))
					} else { None }
				} else { None };
				if let Some(inner_path) = contained_struct {
					let only_contained_has_inner = self.c_type_has_inner_from_path(&inner_path);
					if self.c_type_has_inner_from_path(&inner_path) {
						let is_inner_ref = if let Some(syn::Type::Reference(_)) = single_contained { true } else { false };
						if is_ref {
							return Some(("if ", vec![
								(".is_none() { core::ptr::null() } else { ObjOps::nonnull_ptr_to_inner(".to_owned(),
									format!("({}{}.unwrap())", var_access, if is_inner_ref { "" } else { ".as_ref()" }))
								], ") }", ContainerPrefixLocation::OutsideConv));
						} else {
							return Some(("if ", vec![
								(".is_none() { core::ptr::null_mut() } else { ".to_owned(), format!("({}.unwrap())", var_access))
								], " }", ContainerPrefixLocation::OutsideConv));
						}
					} else if !self.is_transparent_container("Option", is_ref, [single_contained.unwrap()].iter().map(|a| *a), generics) {
						if self.is_primitive(&inner_path) || (!is_contained_ref && !is_ref) || only_contained_has_inner {
							let inner_name = self.get_c_mangled_container_type(vec![single_contained.unwrap()], generics, "Option").unwrap();
							return Some(("if ", vec![
								(format!(".is_none() {{ {}::None }} else {{ {}::Some(", inner_name, inner_name),
								 format!("{}.unwrap()", var_access))
								], ") }", ContainerPrefixLocation::PerConv));
						} else {
							let inner_name = self.get_c_mangled_container_type(vec![single_contained.unwrap()], generics, "Option").unwrap();
							return Some(("if ", vec![
								(format!(".is_none() {{ {}::None }} else {{ {}::Some(/* WARNING: CLONING CONVERSION HERE! &Option<Enum> is otherwise un-expressable. */", inner_name, inner_name),
								 format!("(*{}.as_ref().unwrap()).clone()", var_access))
								], ") }", ContainerPrefixLocation::PerConv));
						}
					} else {
						// If c_type_from_path is some (ie there's a manual mapping for the inner
						// type), lean on write_empty_rust_val, below.
					}
				}
				if let Some(t) = single_contained {
					if let syn::Type::Tuple(syn::TypeTuple { elems, .. }) = t {
						let inner_name = self.get_c_mangled_container_type(vec![single_contained.unwrap()], generics, "Option").unwrap();
						if elems.is_empty() {
							return Some(("if ", vec![
								(format!(".is_none() {{ {}::None }} else {{ {}::Some /* ",
									inner_name, inner_name), format!(""))
								], " */ }", ContainerPrefixLocation::PerConv));
						} else {
							return Some(("if ", vec![
								(format!(".is_none() {{ {}::None }} else {{ {}::Some(",
									inner_name, inner_name), format!("({}.unwrap())", var_access))
								], ") }", ContainerPrefixLocation::PerConv));
						}
					}
					if let syn::Type::Reference(syn::TypeReference { elem, .. }) = t {
						if let syn::Type::Slice(_) = &**elem {
							return Some(("if ", vec![
									(".is_none() { SmartPtr::null() } else { SmartPtr::from_obj(".to_string(),
									 format!("({}.unwrap())", var_access))
								], ") }", ContainerPrefixLocation::PerConv));
						}
					}
					let mut v = Vec::new();
					self.write_empty_rust_val(generics, &mut v, t);
					let s = String::from_utf8(v).unwrap();
					return Some(("if ", vec![
						(format!(".is_none() {{ {} }} else {{ ", s), format!("({}.unwrap())", var_access))
						], " }", ContainerPrefixLocation::PerConv));
				} else { unreachable!(); }
			},
			_ => None,
		}
	}

	/// only_contained_has_inner implies that there is only one contained element in the container
	/// and it has an inner field (ie is an "opaque" type we've defined).
	fn from_c_conversion_container_new_var<'b>(&self, generics: Option<&GenericTypes>, full_path: &str, is_ref: bool, single_contained: Option<&syn::Type>, var_name: &syn::Ident, var_access: &str)
			// Returns prefix + Vec<(prefix, var-name-to-inline-convert)> + suffix
			// expecting one element in the vec per generic type, each of which is inline-converted
			-> Option<(&'b str, Vec<(String, String)>, &'b str, ContainerPrefixLocation)> {
		let mut only_contained_has_inner = false;
		let only_contained_resolved = if let Some(syn::Type::Path(p)) = single_contained {
			let res = self.resolve_path(&p.path, generics);
			only_contained_has_inner = self.c_type_has_inner_from_path(&res);
			Some(res)
		} else { None };
		match full_path {
			"Result" if !is_ref => {
				Some(("match ",
						vec![(".result_ok { true => Ok(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.result)) }})", var_access)),
						     ("), false => Err(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.err)) }})", var_access))],
						")}", ContainerPrefixLocation::PerConv))
			},
			"Slice" if is_ref && only_contained_has_inner => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".as_slice().iter() {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Vec"|"Slice" => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".into_rust().drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Option" => {
				if let Some(resolved) = only_contained_resolved {
					if self.is_primitive(&resolved) {
						return Some(("if ", vec![(".is_some() { Some(".to_string(), format!("{}.take()", var_access))], ") } else { None }", ContainerPrefixLocation::NoPrefix))
					} else if only_contained_has_inner {
						if is_ref {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some((*".to_string(), format!("{}", var_access))], ").clone()) }", ContainerPrefixLocation::PerConv))
						} else {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some(".to_string(), format!("{}", var_access))], ") }", ContainerPrefixLocation::PerConv));
						}
					}
				}

				if let Some(t) = single_contained {
					match t {
						syn::Type::Reference(_)|syn::Type::Path(_)|syn::Type::Slice(_)|syn::Type::Array(_) => {
							let mut v = Vec::new();
							let ret_ref = self.write_empty_rust_val_check_suffix(generics, &mut v, t);
							let s = String::from_utf8(v).unwrap();
							match ret_ref {
								EmptyValExpectedTy::ReferenceAsPointer =>
									return Some(("if ", vec![
										(format!("{} {{ None }} else {{ Some(", s), format!("unsafe {{ &mut *{} }}", var_access))
									], ") }", ContainerPrefixLocation::NoPrefix)),
								EmptyValExpectedTy::OptionType =>
									return Some(("{ /*", vec![
										(format!("*/ let {}_opt = {}; if {}_opt{} {{ None }} else {{ Some({{", var_name, var_access, var_name, s),
										format!("{{ {}_opt.take() }}", var_name))
									], "})} }", ContainerPrefixLocation::PerConv)),
								EmptyValExpectedTy::NonPointer =>
									return Some(("if ", vec![
										(format!("{} {{ None }} else {{ Some(", s), format!("{}", var_access))
									], ") }", ContainerPrefixLocation::PerConv)),
							}
						},
						syn::Type::Tuple(_) => {
							return Some(("if ", vec![(".is_some() { Some(".to_string(), format!("{}.take()", var_access))], ") } else { None }", ContainerPrefixLocation::PerConv))
						},
						_ => unimplemented!(),
					}
				} else { unreachable!(); }
			},
			_ => None,
		}
	}

	/// Constructs a reference to the given type, possibly tweaking the type if relevant to make it
	/// convertable to C.
	pub fn create_ownable_reference(&self, t: &syn::Type, generics: Option<&GenericTypes>) -> Option<syn::Type> {
		let default_value = Some(syn::Type::Reference(syn::TypeReference {
			and_token: syn::Token!(&)(Span::call_site()), lifetime: None, mutability: None,
			elem: Box::new(t.clone()) }));
		match generics.resolve_type(t) {
			syn::Type::Path(p) => {
				if let Some(resolved_path) = self.maybe_resolve_path(&p.path, generics) {
					if resolved_path != "Vec" { return default_value; }
					if p.path.segments.len() != 1 { unimplemented!(); }
					let only_seg = p.path.segments.iter().next().unwrap();
					if let syn::PathArguments::AngleBracketed(args) = &only_seg.arguments {
						if args.args.len() != 1 { unimplemented!(); }
						let inner_arg = args.args.iter().next().unwrap();
						if let syn::GenericArgument::Type(ty) = &inner_arg {
							let mut can_create = self.c_type_has_inner(&ty);
							if let syn::Type::Path(inner) = ty {
								if inner.path.segments.len() == 1 &&
										format!("{}", inner.path.segments[0].ident) == "Vec" {
									can_create = true;
								}
							}
							if !can_create { return default_value; }
							if let Some(inner_ty) = self.create_ownable_reference(&ty, generics) {
								return Some(syn::Type::Reference(syn::TypeReference {
									and_token: syn::Token![&](Span::call_site()),
									lifetime: None,
									mutability: None,
									elem: Box::new(syn::Type::Slice(syn::TypeSlice {
										bracket_token: syn::token::Bracket { span: Span::call_site() },
										elem: Box::new(inner_ty)
									}))
								}));
							} else { return default_value; }
						} else { unimplemented!(); }
					} else { unimplemented!(); }
				} else { return None; }
			},
			_ => default_value,
		}
	}

	// *************************************************
	// *** Type definition during main.rs processing ***
	// *************************************************

	/// Returns true if the object at the given path is mapped as X { inner: *mut origX, .. }.
	pub fn c_type_has_inner_from_path(&self, full_path: &str) -> bool {
		self.crate_types.opaques.get(full_path).is_some()
	}

	/// Returns true if the object at the given path is mapped as X { inner: *mut origX, .. }.
	pub fn c_type_has_inner(&self, ty: &syn::Type) -> bool {
		match ty {
			syn::Type::Path(p) => {
				if let Some(full_path) = self.maybe_resolve_path(&p.path, None) {
					self.c_type_has_inner_from_path(&full_path)
				} else { false }
			},
			syn::Type::Reference(r) => {
				self.c_type_has_inner(&*r.elem)
			},
			_ => false,
		}
	}

	pub fn maybe_resolve_ident(&self, id: &syn::Ident) -> Option<String> {
		self.types.maybe_resolve_ident(id)
	}

	pub fn maybe_resolve_path(&self, p_arg: &syn::Path, generics: Option<&GenericTypes>) -> Option<String> {
		self.types.maybe_resolve_path(p_arg, generics)
	}
	pub fn resolve_path(&self, p: &syn::Path, generics: Option<&GenericTypes>) -> String {
		self.maybe_resolve_path(p, generics).unwrap()
	}

	// ***********************************
	// *** Original Rust Type Printing ***
	// ***********************************

	fn in_rust_prelude(resolved_path: &str) -> bool {
		match resolved_path {
			"Vec" => true,
			"Result" => true,
			"Option" => true,
			_ => false,
		}
	}

	fn write_rust_path<W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, path: &syn::Path, with_ref_lifetime: bool, generated_crate_ref: bool) {
		if let Some(resolved) = self.maybe_resolve_path(&path, generics_resolver) {
			if self.is_primitive(&resolved) {
				write!(w, "{}", path.get_ident().unwrap()).unwrap();
			} else {
				// TODO: We should have a generic "is from a dependency" check here instead of
				// checking for "bitcoin" explicitly.
				if resolved.starts_with("bitcoin::") || Self::in_rust_prelude(&resolved) {
					write!(w, "{}", resolved).unwrap();
				} else if !generated_crate_ref {
					// If we're printing a generic argument, it needs to reference the crate, otherwise
					// the original crate.
					write!(w, "{}", self.real_rust_type_mapping(&resolved)).unwrap();
				} else {
					write!(w, "crate::{}", resolved).unwrap();
				}
			}
			if let syn::PathArguments::AngleBracketed(args) = &path.segments.iter().last().unwrap().arguments {
				self.write_rust_generic_arg(w, generics_resolver, args.args.iter(), with_ref_lifetime);
			}
		} else {
			if path.leading_colon.is_some() {
				write!(w, "::").unwrap();
			}
			for (idx, seg) in path.segments.iter().enumerate() {
				if idx != 0 { write!(w, "::").unwrap(); }
				write!(w, "{}", seg.ident).unwrap();
				if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
					self.write_rust_generic_arg(w, generics_resolver, args.args.iter(), with_ref_lifetime);
				}
			}
		}
	}
	pub fn write_rust_generic_param<'b, W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, generics: impl Iterator<Item=&'b syn::GenericParam>) {
		let mut had_params = false;
		for (idx, arg) in generics.enumerate() {
			if idx != 0 { write!(w, ", ").unwrap(); } else { write!(w, "<").unwrap(); }
			had_params = true;
			match arg {
				syn::GenericParam::Lifetime(lt) => write!(w, "'{}", lt.lifetime.ident).unwrap(),
				syn::GenericParam::Type(t) => {
					write!(w, "{}", t.ident).unwrap();
					if t.colon_token.is_some() { write!(w, ":").unwrap(); }
					for (idx, bound) in t.bounds.iter().enumerate() {
						if idx != 0 { write!(w, " + ").unwrap(); }
						match bound {
							syn::TypeParamBound::Trait(tb) => {
								if tb.paren_token.is_some() || tb.lifetimes.is_some() { unimplemented!(); }
								self.write_rust_path(w, generics_resolver, &tb.path, false, false);
							},
							_ => unimplemented!(),
						}
					}
					if t.eq_token.is_some() || t.default.is_some() { unimplemented!(); }
				},
				_ => unimplemented!(),
			}
		}
		if had_params { write!(w, ">").unwrap(); }
	}

	pub fn write_rust_generic_arg<'b, W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, generics: impl Iterator<Item=&'b syn::GenericArgument>, with_ref_lifetime: bool) {
		write!(w, "<").unwrap();
		for (idx, arg) in generics.enumerate() {
			if idx != 0 { write!(w, ", ").unwrap(); }
			match arg {
				syn::GenericArgument::Type(t) => self.write_rust_type(w, generics_resolver, t, with_ref_lifetime),
				_ => unimplemented!(),
			}
		}
		write!(w, ">").unwrap();
	}
	fn do_write_rust_type<W: std::io::Write>(&self, w: &mut W, generics: Option<&GenericTypes>, t: &syn::Type, with_ref_lifetime: bool, force_crate_ref: bool) {
		let real_ty = generics.resolve_type(t);
		let mut generate_crate_ref = force_crate_ref || t != real_ty;
		match real_ty {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				if let Some(resolved_ty) = self.maybe_resolve_path(&p.path, generics) {
					generate_crate_ref |= self.maybe_resolve_path(&p.path, None).as_ref() != Some(&resolved_ty);
					if self.crate_types.traits.get(&resolved_ty).is_none() { generate_crate_ref = false; }
				}
				self.write_rust_path(w, generics, &p.path, with_ref_lifetime, generate_crate_ref);
			},
			syn::Type::Reference(r) => {
				write!(w, "&").unwrap();
				if let Some(lft) = &r.lifetime {
					write!(w, "'{} ", lft.ident).unwrap();
				} else if with_ref_lifetime {
					write!(w, "'static ").unwrap();
				}
				if r.mutability.is_some() {
					write!(w, "mut ").unwrap();
				}
				self.do_write_rust_type(w, generics, &*r.elem, with_ref_lifetime, generate_crate_ref);
			},
			syn::Type::Array(a) => {
				write!(w, "[").unwrap();
				self.do_write_rust_type(w, generics, &a.elem, with_ref_lifetime, generate_crate_ref);
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, "; {}]", i).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			syn::Type::Slice(s) => {
				write!(w, "[").unwrap();
				self.do_write_rust_type(w, generics, &s.elem, with_ref_lifetime, generate_crate_ref);
				write!(w, "]").unwrap();
			},
			syn::Type::Tuple(s) => {
				write!(w, "(").unwrap();
				for (idx, t) in s.elems.iter().enumerate() {
					if idx != 0 { write!(w, ", ").unwrap(); }
					self.do_write_rust_type(w, generics, &t, with_ref_lifetime, generate_crate_ref);
				}
				write!(w, ")").unwrap();
			},
			_ => unimplemented!(),
		}
	}
	pub fn write_rust_type<W: std::io::Write>(&self, w: &mut W, generics: Option<&GenericTypes>, t: &syn::Type, with_ref_lifetime: bool) {
		self.do_write_rust_type(w, generics, t, with_ref_lifetime, false);
	}


	/// Prints a constructor for something which is "uninitialized" (but obviously not actually
	/// unint'd memory).
	pub fn write_empty_rust_val<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) {
		match t {
			syn::Type::Reference(r) => {
				self.write_empty_rust_val(generics, w, &*r.elem)
			},
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, "crate::{} {{ inner: core::ptr::null_mut(), is_owned: true }}", resolved).unwrap();
				} else {
					// Assume its a manually-mapped C type, where we can just define an null() fn
					write!(w, "{}::null()", self.c_type_from_path(&resolved, false, false).unwrap()).unwrap();
				}
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						if i.base10_digits().parse::<usize>().unwrap() < 32 {
							// Blindly assume that if we're trying to create an empty value for an
							// array < 32 entries that all-0s may be a valid state.
							unimplemented!();
						}
						let arrty = format!("[u8; {}]", i.base10_digits());
						write!(w, "{}", self.to_c_conversion_inline_prefix_from_path(&arrty, false, false).unwrap()).unwrap();
						write!(w, "[0; {}]", i.base10_digits()).unwrap();
						write!(w, "{}", self.to_c_conversion_inline_suffix_from_path(&arrty, false, false).unwrap()).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			_ => unimplemented!(),
		}
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	/// See EmptyValExpectedTy for information on return types.
	fn write_empty_rust_val_check_suffix<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) -> EmptyValExpectedTy {
		match t {
			syn::Type::Reference(r) => {
				return self.write_empty_rust_val_check_suffix(generics, w, &*r.elem);
			},
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, ".inner.is_null()").unwrap();
					EmptyValExpectedTy::NonPointer
				} else {
					if let Some(suffix) = self.empty_val_check_suffix_from_path(&resolved) {
						write!(w, "{}", suffix).unwrap();
						// We may eventually need to allow empty_val_check_suffix_from_path to specify if we need a deref or not
						EmptyValExpectedTy::NonPointer
					} else {
						write!(w, ".is_none()").unwrap();
						EmptyValExpectedTy::OptionType
					}
				}
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, ".data == [0; {}]", i.base10_digits()).unwrap();
						EmptyValExpectedTy::NonPointer
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(_) => {
				// Option<[]> always implies that we want to treat len() == 0 differently from
				// None, so we always map an Option<[]> into a pointer.
				write!(w, " == core::ptr::null_mut()").unwrap();
				EmptyValExpectedTy::ReferenceAsPointer
			},
			_ => unimplemented!(),
		}
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	pub fn write_empty_rust_val_check<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type, var_access: &str) {
		match t {
			syn::Type::Reference(r) => {
				self.write_empty_rust_val_check(generics, w, &*r.elem, var_access);
			},
			syn::Type::Path(_) => {
				write!(w, "{}", var_access).unwrap();
				self.write_empty_rust_val_check_suffix(generics, w, t);
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						let arrty = format!("[u8; {}]", i.base10_digits());
						// We don't (yet) support a new-var conversion here.
						assert!(self.from_c_conversion_new_var_from_path(&arrty, false).is_none());
						write!(w, "{}{}{}",
							self.from_c_conversion_prefix_from_path(&arrty, false).unwrap(),
							var_access,
							self.from_c_conversion_suffix_from_path(&arrty, false).unwrap()).unwrap();
						self.write_empty_rust_val_check_suffix(generics, w, t);
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			_ => unimplemented!(),
		}
	}

	// ********************************
	// *** Type conversion printing ***
	// ********************************

	/// Returns true we if can just skip passing this to C entirely
	pub fn skip_arg(&self, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() { unimplemented!(); }
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					self.skip_path(&full_path)
				} else { false }
			},
			syn::Type::Reference(r) => {
				self.skip_arg(&*r.elem, generics)
			},
			_ => false,
		}
	}
	pub fn no_arg_to_rust<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() { unimplemented!(); }
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					write!(w, "{}", self.no_arg_path_to_rust(&full_path)).unwrap();
				}
			},
			syn::Type::Reference(r) => {
				self.no_arg_to_rust(w, &*r.elem, generics);
			},
			_ => {},
		}
	}

	fn write_conversion_inline_intern<W: std::io::Write,
			LP: Fn(&str, bool, bool) -> Option<String>, DL: Fn(&mut W, &DeclType, &str, bool, bool), SC: Fn(bool, Option<&str>) -> String>
			(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool,
			 tupleconv: &str, prefix: bool, sliceconv: SC, path_lookup: LP, decl_lookup: DL) {
		match generics.resolve_type(t) {
			syn::Type::Reference(r) => {
				self.write_conversion_inline_intern(w, &*r.elem, generics, true, r.mutability.is_some(),
					ptr_for_ref, tupleconv, prefix, sliceconv, path_lookup, decl_lookup);
			},
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}

				let resolved_path = self.resolve_path(&p.path, generics);
				if let Some(aliased_type) = self.crate_types.type_aliases.get(&resolved_path) {
					return self.write_conversion_inline_intern(w, aliased_type, None, is_ref, is_mut, ptr_for_ref, tupleconv, prefix, sliceconv, path_lookup, decl_lookup);
				} else if self.is_primitive(&resolved_path) {
					if is_ref && prefix {
						write!(w, "*").unwrap();
					}
				} else if let Some(c_type) = path_lookup(&resolved_path, is_ref, ptr_for_ref) {
					write!(w, "{}", c_type).unwrap();
				} else if let Some((_, generics)) = self.crate_types.opaques.get(&resolved_path) {
					decl_lookup(w, &DeclType::StructImported { generics: &generics }, &resolved_path, is_ref, is_mut);
				} else if self.crate_types.mirrored_enums.get(&resolved_path).is_some() {
					decl_lookup(w, &DeclType::MirroredEnum, &resolved_path, is_ref, is_mut);
				} else if let Some(t) = self.crate_types.traits.get(&resolved_path) {
					decl_lookup(w, &DeclType::Trait(t), &resolved_path, is_ref, is_mut);
				} else if let Some(ident) = single_ident_generic_path_to_ident(&p.path) {
					if let Some(decl_type) = self.types.maybe_resolve_declared(ident) {
						decl_lookup(w, decl_type, &self.maybe_resolve_ident(ident).unwrap(), is_ref, is_mut);
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Array(a) => {
				if let syn::Type::Path(p) = &*a.elem {
					let inner_ty = self.resolve_path(&p.path, generics);
					if let syn::Expr::Lit(l) = &a.len {
						if let syn::Lit::Int(i) = &l.lit {
							write!(w, "{}", path_lookup(&format!("[{}; {}]", inner_ty, i.base10_digits()), is_ref, ptr_for_ref).unwrap()).unwrap();
						} else { unimplemented!(); }
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(s) => {
				// We assume all slices contain only literals or references.
				// This may result in some outputs not compiling.
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					if self.is_primitive(&resolved) {
						write!(w, "{}", path_lookup("[u8]", is_ref, ptr_for_ref).unwrap()).unwrap();
					} else {
						write!(w, "{}", sliceconv(true, None)).unwrap();
					}
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						write!(w, "{}", sliceconv(self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)), None)).unwrap();
					} else if let syn::Type::Slice(_) = &*r.elem {
						write!(w, "{}", sliceconv(false, None)).unwrap();
					} else { unimplemented!(); }
				} else if let syn::Type::Tuple(t) = &*s.elem {
					assert!(!t.elems.is_empty());
					if prefix {
						write!(w, "{}", sliceconv(false, None)).unwrap();
					} else {
						let mut needs_map = false;
						for e in t.elems.iter() {
							if let syn::Type::Reference(_) = e {
								needs_map = true;
							}
						}
						if needs_map {
							let mut map_str = Vec::new();
							write!(&mut map_str, ".map(|(").unwrap();
							for i in 0..t.elems.len() {
								write!(&mut map_str, "{}{}", if i != 0 { ", " } else { "" }, ('a' as u8 + i as u8) as char).unwrap();
							}
							write!(&mut map_str, ")| (").unwrap();
							for (idx, e) in t.elems.iter().enumerate() {
								if let syn::Type::Reference(_) = e {
									write!(&mut map_str, "{}{}", if idx != 0 { ", " } else { "" }, (idx as u8 + 'a' as u8) as char).unwrap();
								} else if let syn::Type::Path(_) = e {
									write!(&mut map_str, "{}*{}", if idx != 0 { ", " } else { "" }, (idx as u8 + 'a' as u8) as char).unwrap();
								} else { unimplemented!(); }
							}
							write!(&mut map_str, "))").unwrap();
							write!(w, "{}", sliceconv(false, Some(&String::from_utf8(map_str).unwrap()))).unwrap();
						} else {
							write!(w, "{}", sliceconv(false, None)).unwrap();
						}
					}
				} else if let syn::Type::Array(_) = &*s.elem {
					write!(w, "{}", sliceconv(false, Some(".map(|a| *a)"))).unwrap();
				} else { unimplemented!(); }
			},
			syn::Type::Tuple(t) => {
				if t.elems.is_empty() {
					// cbindgen has poor support for (), see, eg https://github.com/eqrion/cbindgen/issues/527
					// so work around it by just pretending its a 0u8
					write!(w, "{}", tupleconv).unwrap();
				} else {
					if prefix { write!(w, "local_").unwrap(); }
				}
			},
			_ => unimplemented!(),
		}
	}

	fn write_to_c_conversion_inline_prefix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool, from_ptr: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, ptr_for_ref, "() /*", true, |_, _| "local_".to_owned(),
				|a, b, c| self.to_c_conversion_inline_prefix_from_path(a, b, c),
				|w, decl_type, decl_path, is_ref, _is_mut| {
					match decl_type {
						DeclType::MirroredEnum if is_ref && ptr_for_ref => write!(w, "crate::{}::from_native(", decl_path).unwrap(),
						DeclType::MirroredEnum if is_ref => write!(w, "&crate::{}::from_native(", decl_path).unwrap(),
						DeclType::MirroredEnum => write!(w, "crate::{}::native_into(", decl_path).unwrap(),
						DeclType::EnumIgnored {..}|DeclType::StructImported {..} if is_ref && from_ptr => {
							if !ptr_for_ref { write!(w, "&").unwrap(); }
							write!(w, "crate::{} {{ inner: unsafe {{ (", decl_path).unwrap()
						},
						DeclType::EnumIgnored {..}|DeclType::StructImported {..} if is_ref => {
							if !ptr_for_ref { write!(w, "&").unwrap(); }
							write!(w, "crate::{} {{ inner: unsafe {{ ObjOps::nonnull_ptr_to_inner((", decl_path).unwrap()
						},
						DeclType::EnumIgnored {..}|DeclType::StructImported {..} if !is_ref && from_ptr =>
							write!(w, "crate::{} {{ inner: ", decl_path).unwrap(),
						DeclType::EnumIgnored {..}|DeclType::StructImported {..} if !is_ref =>
							write!(w, "crate::{} {{ inner: ObjOps::heap_alloc(", decl_path).unwrap(),
						DeclType::Trait(_) if is_ref => write!(w, "").unwrap(),
						DeclType::Trait(_) if !is_ref => write!(w, "Into::into(").unwrap(),
						_ => panic!("{:?}", decl_path),
					}
				});
	}
	pub fn write_to_c_conversion_inline_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		self.write_to_c_conversion_inline_prefix_inner(w, t, generics, false, ptr_for_ref, false);
	}
	fn write_to_c_conversion_inline_suffix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool, from_ptr: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, ptr_for_ref, "*/", false, |_, _| ".into()".to_owned(),
				|a, b, c| self.to_c_conversion_inline_suffix_from_path(a, b, c),
				|w, decl_type, full_path, is_ref, _is_mut| match decl_type {
					DeclType::MirroredEnum => write!(w, ")").unwrap(),
					DeclType::EnumIgnored { generics }|DeclType::StructImported { generics } if is_ref => {
						write!(w, " as *const {}<", full_path).unwrap();
						for param in generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = param {
								write!(w, "'_, ").unwrap();
							} else {
								write!(w, "_, ").unwrap();
							}
						}
						if from_ptr {
							write!(w, ">) as *mut _ }}, is_owned: false }}").unwrap();
						} else {
							write!(w, ">) as *mut _) }}, is_owned: false }}").unwrap();
						}
					},
					DeclType::EnumIgnored {..}|DeclType::StructImported {..} if !is_ref && from_ptr =>
						write!(w, ", is_owned: true }}").unwrap(),
					DeclType::EnumIgnored {..}|DeclType::StructImported {..} if !is_ref => write!(w, "), is_owned: true }}").unwrap(),
					DeclType::Trait(_) if is_ref => {},
					DeclType::Trait(_) => {
						// This is used when we're converting a concrete Rust type into a C trait
						// for use when a Rust trait method returns an associated type.
						// Because all of our C traits implement From<RustTypesImplementingTraits>
						// we can just call .into() here and be done.
						write!(w, ")").unwrap()
					},
					_ => unimplemented!(),
				});
	}
	pub fn write_to_c_conversion_inline_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		self.write_to_c_conversion_inline_suffix_inner(w, t, generics, false, ptr_for_ref, false);
	}

	fn write_from_c_conversion_prefix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, _ptr_for_ref: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, false, "() /*", true, |_, _| "&local_".to_owned(),
				|a, b, _c| self.from_c_conversion_prefix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported {..} if is_ref => write!(w, "").unwrap(),
					DeclType::StructImported {..} if !is_ref => write!(w, "*unsafe {{ Box::from_raw(").unwrap(),
					DeclType::MirroredEnum if is_ref => write!(w, "&").unwrap(),
					DeclType::MirroredEnum => {},
					DeclType::Trait(_) => {},
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_from_c_conversion_prefix_inner(w, t, generics, false, false);
	}
	fn write_from_c_conversion_suffix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, false, "*/", false,
				|has_inner, map_str_opt| match (has_inner, map_str_opt) {
					(false, Some(map_str)) => format!(".iter(){}.collect::<Vec<_>>()[..]", map_str),
					(false, None) => ".iter().collect::<Vec<_>>()[..]".to_owned(),
					(true, None) => "[..]".to_owned(),
					(true, Some(_)) => unreachable!(),
				},
				|a, b, _c| self.from_c_conversion_suffix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, is_mut| match decl_type {
					DeclType::StructImported {..} if is_ref && ptr_for_ref => write!(w, "XXX unimplemented").unwrap(),
					DeclType::StructImported {..} if is_mut && is_ref => write!(w, ".get_native_mut_ref()").unwrap(),
					DeclType::StructImported {..} if is_ref => write!(w, ".get_native_ref()").unwrap(),
					DeclType::StructImported {..} if !is_ref => write!(w, ".take_inner()) }}").unwrap(),
					DeclType::MirroredEnum if is_ref => write!(w, ".to_native()").unwrap(),
					DeclType::MirroredEnum => write!(w, ".into_native()").unwrap(),
					DeclType::Trait(_) => {},
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_from_c_conversion_suffix_inner(w, t, generics, false, false);
	}
	// Note that compared to the above conversion functions, the following two are generally
	// significantly undertested:
	pub fn write_from_c_conversion_to_ref_prefix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_conversion_inline_intern(w, t, generics, false, false, false, "() /*", true, |_, _| "&local_".to_owned(),
				|a, b, _c| {
					if let Some(conv) = self.from_c_conversion_prefix_from_path(a, b) {
						Some(format!("&{}", conv))
					} else { None }
				},
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported {..} if !is_ref => write!(w, "").unwrap(),
					_ => unimplemented!(),
				});
	}
	pub fn write_from_c_conversion_to_ref_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>) {
		self.write_conversion_inline_intern(w, t, generics, false, false, false, "*/", false,
				|has_inner, map_str_opt| match (has_inner, map_str_opt) {
					(false, Some(map_str)) => format!(".iter(){}.collect::<Vec<_>>()[..]", map_str),
					(false, None) => ".iter().collect::<Vec<_>>()[..]".to_owned(),
					(true, None) => "[..]".to_owned(),
					(true, Some(_)) => unreachable!(),
				},
				|a, b, _c| self.from_c_conversion_suffix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported {..} if !is_ref => write!(w, ".get_native_ref()").unwrap(),
					_ => unimplemented!(),
				});
	}

	fn write_conversion_new_var_intern<'b, W: std::io::Write,
		LP: Fn(&str, bool) -> Option<(&str, &str)>,
		LC: Fn(&str, bool, Option<&syn::Type>, &syn::Ident, &str) ->  Option<(&'b str, Vec<(String, String)>, &'b str, ContainerPrefixLocation)>,
		VP: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool),
		VS: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool)>
			(&self, w: &mut W, ident: &syn::Ident, var: &str, t: &syn::Type, generics: Option<&GenericTypes>,
			 mut is_ref: bool, mut ptr_for_ref: bool, to_c: bool, from_ownable_ref: bool,
			 path_lookup: &LP, container_lookup: &LC, var_prefix: &VP, var_suffix: &VS) -> bool {

		macro_rules! convert_container {
			($container_type: expr, $args_len: expr, $args_iter: expr) => { {
				// For slices (and Options), we refuse to directly map them as is_ref when they
				// aren't opaque types containing an inner pointer. This is due to the fact that,
				// in both cases, the actual higher-level type is non-is_ref.
				let (ty_has_inner, ty_is_trait) = if $args_len == 1 {
					let ty = $args_iter().next().unwrap();
					if $container_type == "Slice" && to_c {
						// "To C ptr_for_ref" means "return the regular object with is_owned
						// set to false", which is totally what we want in a slice if we're about to
						// set ty_has_inner.
						ptr_for_ref = true;
					}
					if let syn::Type::Reference(t) = ty {
						if let syn::Type::Path(p) = &*t.elem {
							let resolved = self.resolve_path(&p.path, generics);
							(self.c_type_has_inner_from_path(&resolved), self.crate_types.traits.get(&resolved).is_some())
						} else { (false, false) }
					} else if let syn::Type::Path(p) = ty {
						let resolved = self.resolve_path(&p.path, generics);
						(self.c_type_has_inner_from_path(&resolved), self.crate_types.traits.get(&resolved).is_some())
					} else { (false, false) }
				} else { (true, false) };

				// Options get a bunch of special handling, since in general we map Option<>al
				// types into the same C type as non-Option-wrapped types. This ends up being
				// pretty manual here and most of the below special-cases are for Options.
				let mut needs_ref_map = false;
				let mut only_contained_type = None;
				let mut only_contained_type_nonref = None;
				let mut only_contained_has_inner = false;
				let mut contains_slice = false;
				if $args_len == 1 {
					only_contained_has_inner = ty_has_inner;
					let arg = $args_iter().next().unwrap();
					if let syn::Type::Reference(t) = arg {
						only_contained_type = Some(arg);
						only_contained_type_nonref = Some(&*t.elem);
						if let syn::Type::Path(_) = &*t.elem {
							is_ref = true;
						} else if let syn::Type::Slice(_) = &*t.elem {
							contains_slice = true;
						} else { return false; }
						// If the inner element contains an inner pointer, we will just use that,
						// avoiding the need to map elements to references. Otherwise we'll need to
						// do an extra mapping step.
						needs_ref_map = !only_contained_has_inner && !ty_is_trait && $container_type == "Option";
					} else {
						only_contained_type = Some(arg);
						only_contained_type_nonref = Some(arg);
					}
				}

				if let Some((prefix, conversions, suffix, prefix_location)) = container_lookup(&$container_type, is_ref, only_contained_type, ident, var) {
					assert_eq!(conversions.len(), $args_len);
					write!(w, "let mut local_{}{} = ", ident,
						if (!to_c && needs_ref_map) || (to_c && $container_type == "Option" && contains_slice) {"_base"} else { "" }).unwrap();
					if prefix_location == ContainerPrefixLocation::OutsideConv {
						var_prefix(w, $args_iter().next().unwrap(), generics, is_ref, true, true);
					}
					write!(w, "{}{}", prefix, var).unwrap();

					for ((pfx, var_name), (idx, ty)) in conversions.iter().zip($args_iter().enumerate()) {
						let mut var = std::io::Cursor::new(Vec::new());
						write!(&mut var, "{}", var_name).unwrap();
						let var_access = String::from_utf8(var.into_inner()).unwrap();

						let conv_ty = if needs_ref_map { only_contained_type_nonref.as_ref().unwrap() } else { ty };

						write!(w, "{} {{ ", pfx).unwrap();
						let new_var_name = format!("{}_{}", ident, idx);
						let new_var = self.write_conversion_new_var_intern(w, &format_ident!("{}", new_var_name),
								&var_access, conv_ty, generics, contains_slice || (is_ref && ty_has_inner), ptr_for_ref,
								to_c, from_ownable_ref, path_lookup, container_lookup, var_prefix, var_suffix);
						if new_var { write!(w, " ").unwrap(); }

						if prefix_location == ContainerPrefixLocation::PerConv {
							var_prefix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						} else if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, "ObjOps::heap_alloc(").unwrap();
						}

						write!(w, "{}{}", if contains_slice && !to_c { "local_" } else { "" }, if new_var { new_var_name } else { var_access }).unwrap();
						if prefix_location == ContainerPrefixLocation::PerConv {
							var_suffix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						} else if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, ")").unwrap();
						}
						write!(w, " }}").unwrap();
					}
					write!(w, "{}", suffix).unwrap();
					if prefix_location == ContainerPrefixLocation::OutsideConv {
						var_suffix(w, $args_iter().next().unwrap(), generics, is_ref, ptr_for_ref, true);
					}
					write!(w, ";").unwrap();
					if !to_c && needs_ref_map {
						write!(w, " let mut local_{} = local_{}_base.as_ref()", ident, ident).unwrap();
						if contains_slice {
							write!(w, ".map(|a| &a[..])").unwrap();
						}
						write!(w, ";").unwrap();
					} else if to_c && $container_type == "Option" && contains_slice {
						write!(w, " let mut local_{} = *local_{}_base;", ident, ident).unwrap();
					}
					return true;
				}
			} }
		}

		match generics.resolve_type(t) {
			syn::Type::Reference(r) => {
				if let syn::Type::Slice(_) = &*r.elem {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, is_ref, ptr_for_ref, to_c, from_ownable_ref, path_lookup, container_lookup, var_prefix, var_suffix)
				} else {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, true, ptr_for_ref, to_c, from_ownable_ref, path_lookup, container_lookup, var_prefix, var_suffix)
				}
			},
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				let resolved_path = self.resolve_path(&p.path, generics);
				if let Some(aliased_type) = self.crate_types.type_aliases.get(&resolved_path) {
					return self.write_conversion_new_var_intern(w, ident, var, aliased_type, None, is_ref, ptr_for_ref, to_c, from_ownable_ref, path_lookup, container_lookup, var_prefix, var_suffix);
				}
				if self.is_known_container(&resolved_path, is_ref) || self.is_path_transparent_container(&p.path, generics, is_ref) {
					if let syn::PathArguments::AngleBracketed(args) = &p.path.segments.iter().next().unwrap().arguments {
						convert_container!(resolved_path, args.args.len(), || args.args.iter().map(|arg| {
							if let syn::GenericArgument::Type(ty) = arg {
								generics.resolve_type(ty)
							} else { unimplemented!(); }
						}));
					} else { unimplemented!(); }
				}
				if self.is_primitive(&resolved_path) {
					false
				} else if let Some(ty_ident) = single_ident_generic_path_to_ident(&p.path) {
					if let Some((prefix, suffix)) = path_lookup(&resolved_path, is_ref) {
						write!(w, "let mut local_{} = {}{}{};", ident, prefix, var, suffix).unwrap();
						true
					} else if self.types.maybe_resolve_declared(ty_ident).is_some() {
						false
					} else { false }
				} else { false }
			},
			syn::Type::Array(_) => {
				// We assume all arrays contain only primitive types.
				// This may result in some outputs not compiling.
				false
			},
			syn::Type::Slice(s) => {
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					if self.is_primitive(&resolved) {
						let slice_path = format!("[{}]", resolved);
						if let Some((prefix, suffix)) = path_lookup(&slice_path, true) {
							write!(w, "let mut local_{} = {}{}{};", ident, prefix, var, suffix).unwrap();
							true
						} else { false }
					} else {
						let tyref = [&*s.elem];
						if to_c {
							// If we're converting from a slice to a Vec, assume we can clone the
							// elements and clone them into a new Vec first. Next we'll walk the
							// new Vec here and convert them to C types.
							write!(w, "let mut local_{}_clone = Vec::new(); local_{}_clone.extend_from_slice({}); let mut {} = local_{}_clone; ", ident, ident, ident, ident, ident).unwrap();
						}
						is_ref = false;
						convert_container!("Vec", 1, || tyref.iter().map(|t| generics.resolve_type(*t)));
						unimplemented!("convert_container should return true as container_lookup should succeed for slices");
					}
				} else if let syn::Type::Reference(ty) = &*s.elem {
					let tyref = if from_ownable_ref || !to_c { [&*ty.elem] } else { [&*s.elem] };
					is_ref = true;
					convert_container!("Slice", 1, || tyref.iter().map(|t| generics.resolve_type(*t)));
					unimplemented!("convert_container should return true as container_lookup should succeed for slices");
				} else if let syn::Type::Tuple(t) = &*s.elem {
					// When mapping into a temporary new var, we need to own all the underlying objects.
					// Thus, we drop any references inside the tuple and convert with non-reference types.
					let mut elems = syn::punctuated::Punctuated::new();
					for elem in t.elems.iter() {
						if let syn::Type::Reference(r) = elem {
							elems.push((*r.elem).clone());
						} else {
							elems.push(elem.clone());
						}
					}
					let ty = [syn::Type::Tuple(syn::TypeTuple {
						paren_token: t.paren_token, elems
					})];
					is_ref = false;
					ptr_for_ref = true;
					convert_container!("Slice", 1, || ty.iter());
					unimplemented!("convert_container should return true as container_lookup should succeed for slices");
				} else if let syn::Type::Array(_) = &*s.elem {
					is_ref = false;
					ptr_for_ref = true;
					let arr_elem = [(*s.elem).clone()];
					convert_container!("Slice", 1, || arr_elem.iter());
					unimplemented!("convert_container should return true as container_lookup should succeed for slices");
				} else { unimplemented!() }
			},
			syn::Type::Tuple(t) => {
				if !t.elems.is_empty() {
					// We don't (yet) support tuple elements which cannot be converted inline
					write!(w, "let (").unwrap();
					for idx in 0..t.elems.len() {
						if idx != 0 { write!(w, ", ").unwrap(); }
						write!(w, "{} orig_{}_{}", if is_ref { "ref" } else { "mut" }, ident, idx).unwrap();
					}
					write!(w, ") = {}{}; ", var, if !to_c { ".to_rust()" } else { "" }).unwrap();
					// Like other template types, tuples are always mapped as their non-ref
					// versions for types which have different ref mappings. Thus, we convert to
					// non-ref versions and handle opaque types with inner pointers manually.
					for (idx, elem) in t.elems.iter().enumerate() {
						if let syn::Type::Path(p) = elem {
							let v_name = format!("orig_{}_{}", ident, idx);
							let tuple_elem_ident = format_ident!("{}", &v_name);
							if self.write_conversion_new_var_intern(w, &tuple_elem_ident, &v_name, elem, generics,
									false, ptr_for_ref, to_c, from_ownable_ref,
									path_lookup, container_lookup, var_prefix, var_suffix) {
								write!(w, " ").unwrap();
								// Opaque types with inner pointers shouldn't ever create new stack
								// variables, so we don't handle it and just assert that it doesn't
								// here.
								assert!(!self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)));
							}
						}
					}
					write!(w, "let mut local_{} = (", ident).unwrap();
					for (idx, elem) in t.elems.iter().enumerate() {
						let real_elem = generics.resolve_type(&elem);
						let ty_has_inner = {
								if to_c {
									// "To C ptr_for_ref" means "return the regular object with
									// is_owned set to false", which is totally what we want
									// if we're about to set ty_has_inner.
									ptr_for_ref = true;
								}
								if let syn::Type::Reference(t) = real_elem {
									if let syn::Type::Path(p) = &*t.elem {
										self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
									} else { false }
								} else if let syn::Type::Path(p) = real_elem {
									self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
								} else { false }
							};
						if idx != 0 { write!(w, ", ").unwrap(); }
						var_prefix(w, real_elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						if is_ref && ty_has_inner {
							// For ty_has_inner, the regular var_prefix mapping will take a
							// reference, so deref once here to make sure we keep the original ref.
							write!(w, "*").unwrap();
						}
						write!(w, "orig_{}_{}", ident, idx).unwrap();
						if is_ref && !ty_has_inner {
							// If we don't have an inner variable's reference to maintain, just
							// hope the type is Clonable and use that.
							write!(w, ".clone()").unwrap();
						}
						var_suffix(w, real_elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
					}
					write!(w, "){};", if to_c { ".into()" } else { "" }).unwrap();
					true
				} else { false }
			},
			_ => unimplemented!(),
		}
	}

	pub fn write_to_c_conversion_new_var_inner<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, var_access: &str, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool, from_ownable_ref: bool) -> bool {
		self.write_conversion_new_var_intern(w, ident, var_access, t, generics, from_ownable_ref, ptr_for_ref, true, from_ownable_ref,
			&|a, b| self.to_c_conversion_new_var_from_path(a, b),
			&|a, b, c, d, e| self.to_c_conversion_container_new_var(generics, a, b, c, d, e),
			// We force ptr_for_ref here since we can't generate a ref on one line and use it later
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_prefix_inner(a, b, c, d, e, f),
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_suffix_inner(a, b, c, d, e, f))
	}
	pub fn write_to_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) -> bool {
		self.write_to_c_conversion_new_var_inner(w, ident, &format!("{}", ident), t, generics, ptr_for_ref, false)
	}
	/// Prints new-var conversion for an "ownable_ref" type, ie prints conversion for
	/// `create_ownable_reference(t)`, not `t` itself.
	pub fn write_to_c_conversion_from_ownable_ref_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_to_c_conversion_new_var_inner(w, ident, &format!("{}", ident), t, generics, true, true)
	}
	pub fn write_from_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_conversion_new_var_intern(w, ident, &format!("{}", ident), t, generics, false, false, false, false,
			&|a, b| self.from_c_conversion_new_var_from_path(a, b),
			&|a, b, c, d, e| self.from_c_conversion_container_new_var(generics, a, b, c, d, e),
			// We force ptr_for_ref here since we can't generate a ref on one line and use it later
			&|a, b, c, d, e, _f| self.write_from_c_conversion_prefix_inner(a, b, c, d, e),
			&|a, b, c, d, e, _f| self.write_from_c_conversion_suffix_inner(a, b, c, d, e))
	}

	// ******************************************************
	// *** C Container Type Equivalent and alias Printing ***
	// ******************************************************

	fn write_template_generics<'b, W: std::io::Write>(&self, w: &mut W, args: &mut dyn Iterator<Item=&'b syn::Type>, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		for (idx, orig_t) in args.enumerate() {
			if idx != 0 {
				write!(w, ", ").unwrap();
			}
			let t = generics.resolve_type(orig_t);
			if let syn::Type::Reference(r_arg) = t {
				assert!(!is_ref); // We don't currently support outer reference types for non-primitive inners

				if !self.write_c_type_intern(w, &*r_arg.elem, generics, false, false, false, true, true) { return false; }

				// While write_c_type_intern, above is correct, we don't want to blindly convert a
				// reference to something stupid, so check that the container is either opaque or a
				// predefined type (currently only Transaction).
				if let syn::Type::Path(p_arg) = &*r_arg.elem {
					let resolved = self.resolve_path(&p_arg.path, generics);
					assert!(self.crate_types.opaques.get(&resolved).is_some() ||
							self.crate_types.traits.get(&resolved).is_some() ||
							self.c_type_from_path(&resolved, true, true).is_some(), "Template generics should be opaque or have a predefined mapping");
				} else { unimplemented!(); }
			} else if let syn::Type::Path(p_arg) = t {
				if let Some(resolved) = self.maybe_resolve_path(&p_arg.path, generics) {
					if !self.is_primitive(&resolved) {
						if is_ref {
							// We don't currently support outer reference types for non-primitive inners
							return false;
						}
					}
				} else {
					if is_ref {
						// We don't currently support outer reference types for non-primitive inners
						return false;
					}
				}
				if !self.write_c_type_intern(w, t, generics, false, false, false, true, true) { return false; }
			} else {
				// We don't currently support outer reference types for non-primitive inners,
				// except for the empty tuple.
				if let syn::Type::Tuple(t_arg) = t {
					assert!(t_arg.elems.len() == 0 || !is_ref);
				} else {
					assert!(!is_ref);
				}
				if !self.write_c_type_intern(w, t, generics, false, false, false, true, true) { return false; }
			}
		}
		true
	}
	fn check_create_container(&self, mangled_container: String, container_type: &str, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		if !self.crate_types.templates_defined.borrow().get(&mangled_container).is_some() {
			let mut created_container: Vec<u8> = Vec::new();

			if container_type == "Result" {
				let mut a_ty: Vec<u8> = Vec::new();
				if let syn::Type::Tuple(tup) = args.iter().next().unwrap() {
					if tup.elems.is_empty() {
						write!(&mut a_ty, "()").unwrap();
					} else {
						if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t).take(1), generics, is_ref) { return false; }
					}
				} else {
					if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t).take(1), generics, is_ref) { return false; }
				}

				let mut b_ty: Vec<u8> = Vec::new();
				if let syn::Type::Tuple(tup) = args.iter().skip(1).next().unwrap() {
					if tup.elems.is_empty() {
						write!(&mut b_ty, "()").unwrap();
					} else {
						if !self.write_template_generics(&mut b_ty, &mut args.iter().map(|t| *t).skip(1), generics, is_ref) { return false; }
					}
				} else {
					if !self.write_template_generics(&mut b_ty, &mut args.iter().map(|t| *t).skip(1), generics, is_ref) { return false; }
				}

				let ok_str = String::from_utf8(a_ty).unwrap();
				let err_str = String::from_utf8(b_ty).unwrap();
				let is_clonable = self.is_clonable(&ok_str) && self.is_clonable(&err_str);
				write_result_block(&mut created_container, &mangled_container, &ok_str, &err_str, is_clonable);
				if is_clonable {
					self.crate_types.set_clonable(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else if container_type == "Vec" {
				let mut a_ty: Vec<u8> = Vec::new();
				if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t), generics, is_ref) { return false; }
				let ty = String::from_utf8(a_ty).unwrap();
				let is_clonable = self.is_clonable(&ty);
				write_vec_block(&mut created_container, &mangled_container, &ty, is_clonable);
				if is_clonable {
					self.crate_types.set_clonable(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else if container_type.ends_with("Tuple") {
				let mut tuple_args = Vec::new();
				let mut is_clonable = true;
				for arg in args.iter() {
					let mut ty: Vec<u8> = Vec::new();
					if !self.write_template_generics(&mut ty, &mut [arg].iter().map(|t| **t), generics, is_ref) { return false; }
					let ty_str = String::from_utf8(ty).unwrap();
					if !self.is_clonable(&ty_str) {
						is_clonable = false;
					}
					tuple_args.push(ty_str);
				}
				write_tuple_block(&mut created_container, &mangled_container, &tuple_args, is_clonable);
				if is_clonable {
					self.crate_types.set_clonable(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else if container_type == "Option" {
				let mut a_ty: Vec<u8> = Vec::new();
				if !self.write_template_generics(&mut a_ty, &mut args.iter().map(|t| *t), generics, is_ref) { return false; }
				let ty = String::from_utf8(a_ty).unwrap();
				let is_clonable = self.is_clonable(&ty);
				write_option_block(&mut created_container, &mangled_container, &ty, is_clonable);
				if is_clonable {
					self.crate_types.set_clonable(Self::generated_container_path().to_owned() + "::" + &mangled_container);
				}
			} else {
				unreachable!();
			}
			self.crate_types.write_new_template(mangled_container.clone(), true, &created_container);
		}
		true
	}
	fn path_to_generic_args(path: &syn::Path) -> Vec<&syn::Type> {
		if let syn::PathArguments::AngleBracketed(args) = &path.segments.iter().next().unwrap().arguments {
			args.args.iter().map(|gen| if let syn::GenericArgument::Type(t) = gen { t } else { unimplemented!() }).collect()
		} else { unimplemented!(); }
	}
	fn write_c_mangled_container_path_intern<W: std::io::Write>
			(&self, w: &mut W, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, ident: &str, is_ref: bool, is_mut: bool, ptr_for_ref: bool, in_type: bool) -> bool {
		let mut mangled_type: Vec<u8> = Vec::new();
		if !self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a), generics) {
			write!(w, "C{}_", ident).unwrap();
			write!(mangled_type, "C{}_", ident).unwrap();
		} else { assert_eq!(args.len(), 1); }
		for arg in args.iter() {
			macro_rules! write_path {
				($p_arg: expr, $extra_write: expr) => {
					if let Some(subtype) = self.maybe_resolve_path(&$p_arg.path, generics) {
						if self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a), generics) {
							if !in_type {
								if self.c_type_has_inner_from_path(&subtype) {
									if !self.write_c_path_intern(w, &$p_arg.path, generics, is_ref, is_mut, ptr_for_ref, false, true) { return false; }
								} else {
									// Option<T> needs to be converted to a *mut T, ie mut ptr-for-ref
									if !self.write_c_path_intern(w, &$p_arg.path, generics, true, true, true, false, true) { return false; }
								}
							} else {
								write!(w, "{}", $p_arg.path.segments.last().unwrap().ident).unwrap();
							}
						} else if self.is_known_container(&subtype, is_ref) || self.is_path_transparent_container(&$p_arg.path, generics, is_ref) {
							if !self.write_c_mangled_container_path_intern(w, Self::path_to_generic_args(&$p_arg.path), generics,
									&subtype, is_ref, is_mut, ptr_for_ref, true) {
								return false;
							}
							self.write_c_mangled_container_path_intern(&mut mangled_type, Self::path_to_generic_args(&$p_arg.path),
								generics, &subtype, is_ref, is_mut, ptr_for_ref, true);
							if let Some(w2) = $extra_write as Option<&mut Vec<u8>> {
								self.write_c_mangled_container_path_intern(w2, Self::path_to_generic_args(&$p_arg.path),
									generics, &subtype, is_ref, is_mut, ptr_for_ref, true);
							}
						} else {
							let id = subtype.rsplitn(2, ':').next().unwrap(); // Get the "Base" name of the resolved type
							write!(w, "{}", id).unwrap();
							write!(mangled_type, "{}", id).unwrap();
							if let Some(w2) = $extra_write as Option<&mut Vec<u8>> {
								write!(w2, "{}", id).unwrap();
							}
						}
					} else { return false; }
				}
			}
			match generics.resolve_type(arg) {
				syn::Type::Tuple(tuple) => {
					if tuple.elems.len() == 0 {
						write!(w, "None").unwrap();
						write!(mangled_type, "None").unwrap();
					} else {
						let mut mangled_tuple_type: Vec<u8> = Vec::new();

						// Figure out what the mangled type should look like. To disambiguate
						// ((A, B), C) and (A, B, C) we prefix the generic args with a _ and suffix
						// them with a Z. Ideally we wouldn't use Z, but not many special chars are
						// available for use in type names.
						write!(w, "C{}Tuple_", tuple.elems.len()).unwrap();
						write!(mangled_type, "C{}Tuple_", tuple.elems.len()).unwrap();
						write!(mangled_tuple_type, "C{}Tuple_", tuple.elems.len()).unwrap();
						for elem in tuple.elems.iter() {
							if let syn::Type::Path(p) = elem {
								write_path!(p, Some(&mut mangled_tuple_type));
							} else if let syn::Type::Reference(refelem) = elem {
								if let syn::Type::Path(p) = &*refelem.elem {
									write_path!(p, Some(&mut mangled_tuple_type));
								} else { return false; }
							} else if let syn::Type::Array(_) = elem {
								let mut resolved = Vec::new();
								if !self.write_c_type_intern(&mut resolved, &elem, generics, false, false, true, false, true) { return false; }
								let array_inner = String::from_utf8(resolved).unwrap();
								let arr_name = array_inner.split("::").last().unwrap();
								write!(w, "{}", arr_name).unwrap();
								write!(mangled_type, "{}", arr_name).unwrap();
							} else { return false; }
						}
						write!(w, "Z").unwrap();
						write!(mangled_type, "Z").unwrap();
						write!(mangled_tuple_type, "Z").unwrap();
						if !self.check_create_container(String::from_utf8(mangled_tuple_type).unwrap(),
								&format!("{}Tuple", tuple.elems.len()), tuple.elems.iter().collect(), generics, is_ref) {
							return false;
						}
					}
				},
				syn::Type::Path(p_arg) => {
					write_path!(p_arg, None);
				},
				syn::Type::Reference(refty) => {
					if let syn::Type::Path(p_arg) = &*refty.elem {
						write_path!(p_arg, None);
					} else if let syn::Type::Slice(_) = &*refty.elem {
						// write_c_type will actually do exactly what we want here, we just need to
						// make it a pointer so that its an option. Note that we cannot always convert
						// the Vec-as-slice (ie non-ref types) containers, so sometimes need to be able
						// to edit it, hence we use *mut here instead of *const.
						if args.len() != 1 { return false; }
						write!(w, "*mut ").unwrap();
						self.write_c_type(w, arg, None, true);
					} else { return false; }
				},
				syn::Type::Array(a) => {
					if let syn::Type::Path(p_arg) = &*a.elem {
						let resolved = self.resolve_path(&p_arg.path, generics);
						if !self.is_primitive(&resolved) { return false; }
						if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(len), .. }) = &a.len {
							if self.c_type_from_path(&format!("[{}; {}]", resolved, len.base10_digits()), is_ref, ptr_for_ref).is_none() { return false; }
							if in_type || args.len() != 1 {
								write!(w, "_{}{}", resolved, len.base10_digits()).unwrap();
								write!(mangled_type, "_{}{}", resolved, len.base10_digits()).unwrap();
							} else {
								let arrty = format!("[{}; {}]", resolved, len.base10_digits());
								let realty = self.c_type_from_path(&arrty, is_ref, ptr_for_ref).unwrap_or(&arrty);
								write!(w, "{}", realty).unwrap();
								write!(mangled_type, "{}", realty).unwrap();
							}
						} else { return false; }
					} else { return false; }
				},
				_ => { return false; },
			}
		}
		if self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a), generics) { return true; }
		// Push the "end of type" Z
		write!(w, "Z").unwrap();
		write!(mangled_type, "Z").unwrap();

		// Make sure the type is actually defined:
		self.check_create_container(String::from_utf8(mangled_type).unwrap(), ident, args, generics, is_ref)
	}
	fn write_c_mangled_container_path<W: std::io::Write>(&self, w: &mut W, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, ident: &str, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		if !self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a), generics) {
			write!(w, "{}::", Self::generated_container_path()).unwrap();
		}
		self.write_c_mangled_container_path_intern(w, args, generics, ident, is_ref, is_mut, ptr_for_ref, false)
	}
	pub fn get_c_mangled_container_type(&self, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, template_name: &str) -> Option<String> {
		let mut out = Vec::new();
		if !self.write_c_mangled_container_path(&mut out, args, generics, template_name, false, false, false) {
			return None;
		}
		Some(String::from_utf8(out).unwrap())
	}

	// **********************************
	// *** C Type Equivalent Printing ***
	// **********************************

	fn write_c_path_intern<W: std::io::Write>(&self, w: &mut W, path: &syn::Path, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool, with_ref_lifetime: bool, c_ty: bool) -> bool {
		let full_path = match self.maybe_resolve_path(&path, generics) {
			Some(path) => path, None => return false };
		if let Some(c_type) = self.c_type_from_path(&full_path, is_ref, ptr_for_ref) {
			write!(w, "{}", c_type).unwrap();
			true
		} else if self.crate_types.traits.get(&full_path).is_some() {
			// Note that we always use the crate:: prefix here as we are always referring to a
			// concrete object which is of the generated type, it just implements the upstream
			// type.
			if is_ref && ptr_for_ref {
				write!(w, "*{} crate::{}", if is_mut { "mut" } else { "const" }, full_path).unwrap();
			} else if is_ref {
				if with_ref_lifetime { unimplemented!(); }
				write!(w, "&{}crate::{}", if is_mut { "mut " } else { "" }, full_path).unwrap();
			} else {
				write!(w, "crate::{}", full_path).unwrap();
			}
			true
		} else if self.crate_types.opaques.get(&full_path).is_some() || self.crate_types.mirrored_enums.get(&full_path).is_some() {
			let crate_pfx = if c_ty { "crate::" } else { "" };
			if is_ref && ptr_for_ref {
				// ptr_for_ref implies we're returning the object, which we can't really do for
				// opaque or mirrored types without box'ing them, which is quite a waste, so return
				// the actual object itself (for opaque types we'll set the pointer to the actual
				// type and note that its a reference).
				write!(w, "{}{}", crate_pfx, full_path).unwrap();
			} else if is_ref && with_ref_lifetime {
				assert!(!is_mut);
				// If we're concretizing something with a lifetime parameter, we have to pick a
				// lifetime, of which the only real available choice is `static`, obviously.
				write!(w, "&'static {}", crate_pfx).unwrap();
				if !c_ty {
					self.write_rust_path(w, generics, path, with_ref_lifetime, false);
				} else {
					// We shouldn't be mapping references in types, so panic here
					unimplemented!();
				}
			} else if is_ref {
				write!(w, "&{}{}{}", if is_mut { "mut " } else { "" }, crate_pfx, full_path).unwrap();
			} else {
				write!(w, "{}{}", crate_pfx, full_path).unwrap();
			}
			true
		} else {
			false
		}
	}
	fn write_c_type_intern<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool, with_ref_lifetime: bool, c_ty: bool) -> bool {
		match generics.resolve_type(t) {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					return false;
				}
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					if self.is_known_container(&full_path, is_ref) || self.is_path_transparent_container(&p.path, generics, is_ref) {
						return self.write_c_mangled_container_path(w, Self::path_to_generic_args(&p.path), generics, &full_path, is_ref, is_mut, ptr_for_ref);
					}
					if let Some(aliased_type) = self.crate_types.type_aliases.get(&full_path).cloned() {
						return self.write_c_type_intern(w, &aliased_type, None, is_ref, is_mut, ptr_for_ref, with_ref_lifetime, c_ty);
					}
				}
				self.write_c_path_intern(w, &p.path, generics, is_ref, is_mut, ptr_for_ref, with_ref_lifetime, c_ty)
			},
			syn::Type::Reference(r) => {
				self.write_c_type_intern(w, &*r.elem, generics, true, r.mutability.is_some(), ptr_for_ref, with_ref_lifetime, c_ty)
			},
			syn::Type::Array(a) => {
				if is_ref && is_mut {
					write!(w, "*mut [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref, with_ref_lifetime, c_ty) { return false; }
				} else if is_ref {
					write!(w, "*const [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref, with_ref_lifetime, c_ty) { return false; }
				}
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						let mut inner_ty = Vec::new();
						if !self.write_c_type_intern(&mut inner_ty, &*a.elem, generics, false, false, ptr_for_ref, false, c_ty) { return false; }
						let inner_ty_str = String::from_utf8(inner_ty).unwrap();
						if !is_ref {
							if let Some(ty) = self.c_type_from_path(&format!("[{}; {}]", inner_ty_str, i.base10_digits()), false, ptr_for_ref) {
								write!(w, "{}", ty).unwrap();
								true
							} else { false }
						} else {
							write!(w, "; {}]", i).unwrap();
							true
						}
					} else { false }
				} else { false }
			}
			syn::Type::Slice(s) => {
				if !is_ref || is_mut { return false; }
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					if self.is_primitive(&resolved) {
						write!(w, "{}::{}slice", Self::container_templ_path(), resolved).unwrap();
						true
					} else {
						let mut inner_c_ty = Vec::new();
						assert!(self.write_c_path_intern(&mut inner_c_ty, &p.path, generics, true, false, ptr_for_ref, with_ref_lifetime, c_ty));
						let inner_ty_str = String::from_utf8(inner_c_ty).unwrap();
						if self.is_clonable(&inner_ty_str) {
							let inner_ty_ident = inner_ty_str.rsplitn(2, "::").next().unwrap();
							let mangled_container = format!("CVec_{}Z", inner_ty_ident);
							write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
							self.check_create_container(mangled_container, "Vec", vec![&*s.elem], generics, false)
						} else { false }
					}
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						// Slices with "real types" inside are mapped as the equivalent non-ref Vec
						let resolved = self.resolve_path(&p.path, generics);
						let mangled_container = if let Some((ident, _)) = self.crate_types.opaques.get(&resolved) {
							format!("CVec_{}Z", ident)
						} else if let Some(en) = self.crate_types.mirrored_enums.get(&resolved) {
							format!("CVec_{}Z", en.ident)
						} else if let Some(id) = p.path.get_ident() {
							format!("CVec_{}Z", id)
						} else { return false; };
						write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
						self.check_create_container(mangled_container, "Vec", vec![&*r.elem], generics, false)
					} else if let syn::Type::Slice(sl2) = &*r.elem {
						if let syn::Type::Reference(r2) = &*sl2.elem {
							if let syn::Type::Path(p) = &*r2.elem {
								// Slices with slices with opaque types (with is_owned flags) are mapped as non-ref Vecs
								let resolved = self.resolve_path(&p.path, generics);
								let mangled_container = if let Some((ident, _)) = self.crate_types.opaques.get(&resolved) {
									format!("CVec_CVec_{}ZZ", ident)
								} else { return false; };
								write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
								let inner = &r2.elem;
								let vec_ty: syn::Type = syn::parse_quote!(Vec<#inner>);
								self.check_create_container(mangled_container, "Vec", vec![&vec_ty], generics, false)
							} else { false }
						} else { false }
					} else { false }
				} else if let syn::Type::Tuple(_) = &*s.elem {
					let mut args = syn::punctuated::Punctuated::<_, syn::token::Comma>::new();
					args.push(syn::GenericArgument::Type((*s.elem).clone()));
					let mut segments = syn::punctuated::Punctuated::new();
					segments.push(parse_quote!(Vec<#args>));
					self.write_c_type_intern(w, &syn::Type::Path(syn::TypePath { qself: None, path: syn::Path { leading_colon: None, segments } }), generics, false, is_mut, ptr_for_ref, with_ref_lifetime, c_ty)
				} else if let syn::Type::Array(a) = &*s.elem {
					if let syn::Expr::Lit(l) = &a.len {
						if let syn::Lit::Int(i) = &l.lit {
							let mut buf = Vec::new();
							self.write_rust_type(&mut buf, generics, &*a.elem, false);
							let arr_ty = String::from_utf8(buf).unwrap();

							let arr_str = format!("[{}; {}]", arr_ty, i.base10_digits());
							let ty = self.c_type_from_path(&arr_str, false, ptr_for_ref).unwrap()
								.rsplitn(2, "::").next().unwrap();

							let mangled_container = format!("CVec_{}Z", ty);
							write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
							self.check_create_container(mangled_container, "Vec", vec![&*s.elem], generics, false)
						} else { false }
					} else { false }
				} else { false }
			},
			syn::Type::Tuple(t) => {
				if t.elems.len() == 0 {
					true
				} else {
					self.write_c_mangled_container_path(w, t.elems.iter().collect(), generics,
						&format!("{}Tuple", t.elems.len()), is_ref, is_mut, ptr_for_ref)
				}
			},
			_ => false,
		}
	}
	pub fn write_c_type<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		assert!(self.write_c_type_intern(w, t, generics, false, false, ptr_for_ref, false, true));
	}
	pub fn write_c_type_in_generic_param<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		assert!(self.write_c_type_intern(w, t, generics, false, false, ptr_for_ref, true, false));
	}
	pub fn understood_c_path(&self, p: &syn::Path) -> bool {
		self.write_c_path_intern(&mut std::io::sink(), p, None, false, false, false, false, true)
	}
	pub fn understood_c_type(&self, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_c_type_intern(&mut std::io::sink(), t, generics, false, false, false, false, true)
	}
}
