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
			if ty.ident == "Self" {
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

pub fn single_ident_generic_path_to_ident(p: &syn::Path) -> Option<&syn::Ident> {
	if p.segments.len() == 1 {
		Some(&p.segments.iter().next().unwrap().ident)
	} else { None }
}

pub fn path_matches_nongeneric(p: &syn::Path, exp: &[&str]) -> bool {
	if p.segments.len() != exp.len() { return false; }
	for (seg, e) in p.segments.iter().zip(exp.iter()) {
		if seg.arguments != syn::PathArguments::None { return false; }
		if &seg.ident != *e { return false; }
	}
	true
}

#[derive(Debug, PartialEq)]
pub enum ExportStatus {
	Export,
	NoExport,
	TestOnly,
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
					if single_ident_generic_path_to_ident(&attr.path).unwrap() == "cfg" {
						let mut iter = g.stream().into_iter();
						if let TokenTree::Ident(i) = iter.next().unwrap() {
							if i == "any" {
								// #[cfg(any(test, feature = ""))]
								if let TokenTree::Group(g) = iter.next().unwrap() {
									let mut all_test = true;
									for token in g.stream().into_iter() {
										if let TokenTree::Ident(i) = token {
											match i.to_string().as_str() {
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
							} else if i == "test" || i == "feature" {
								// If its cfg(feature(...)) we assume its test-only
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
				if line.contains("(C-not exported)") {
					return ExportStatus::NoExport;
				}
			},
			_ => unimplemented!(),
		}
	}
	ExportStatus::Export
}

pub fn assert_simple_bound(bound: &syn::TraitBound) {
	if bound.paren_token.is_some() || bound.lifetimes.is_some() { unimplemented!(); }
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
					ExportStatus::NoExport => return true,
				}
			}
		} else if let syn::Fields::Unnamed(fields) = &var.fields {
			for field in fields.unnamed.iter() {
				match export_status(&field.attrs) {
					ExportStatus::Export|ExportStatus::TestOnly => {},
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
	self_ty: Option<(String, &'a syn::Path)>,
	parent: Option<&'b GenericTypes<'b, 'b>>,
	typed_generics: HashMap<&'a syn::Ident, (String, Option<&'a syn::Path>)>,
}
impl<'a, 'p: 'a> GenericTypes<'a, 'p> {
	pub fn new(self_ty: Option<(String, &'a syn::Path)>) -> Self {
		Self { self_ty, parent: None, typed_generics: HashMap::new(), }
	}

	/// push a new context onto the stack, allowing for a new set of generics to be learned which
	/// will override any lower contexts, but which will still fall back to resoltion via lower
	/// contexts.
	pub fn push_ctx<'c>(&'c self) -> GenericTypes<'a, 'c> {
		GenericTypes { self_ty: None, parent: Some(self), typed_generics: HashMap::new(), }
	}

	/// Learn the generics in generics in the current context, given a TypeResolver.
	pub fn learn_generics<'b, 'c>(&mut self, generics: &'a syn::Generics, types: &'b TypeResolver<'a, 'c>) -> bool {
		// First learn simple generics...
		for generic in generics.params.iter() {
			match generic {
				syn::GenericParam::Type(type_param) => {
					let mut non_lifetimes_processed = false;
					for bound in type_param.bounds.iter() {
						if let syn::TypeParamBound::Trait(trait_bound) = bound {
							if let Some(ident) = single_ident_generic_path_to_ident(&trait_bound.path) {
								match ident.to_string().as_str() { "Send" => continue, "Sync" => continue, _ => {} }
							}
							if path_matches_nongeneric(&trait_bound.path, &["core", "clone", "Clone"]) { continue; }

							assert_simple_bound(&trait_bound);
							if let Some(mut path) = types.maybe_resolve_path(&trait_bound.path, None) {
								if types.skip_path(&path) { continue; }
								if path == "Sized" { continue; }
								if non_lifetimes_processed { return false; }
								non_lifetimes_processed = true;
								let new_ident = if path != "std::ops::Deref" {
									path = "crate::".to_string() + &path;
									Some(&trait_bound.path)
								} else { None };
								self.typed_generics.insert(&type_param.ident, (path, new_ident));
							} else { return false; }
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
						if p.qself.is_some() { return false; }
						if p.path.leading_colon.is_some() { return false; }
						let mut p_iter = p.path.segments.iter();
						if let Some(gen) = self.typed_generics.get_mut(&p_iter.next().unwrap().ident) {
							if gen.0 != "std::ops::Deref" { return false; }
							if p_iter.next().unwrap().ident != "Target" { return false; }

							let mut non_lifetimes_processed = false;
							for bound in t.bounds.iter() {
								if let syn::TypeParamBound::Trait(trait_bound) = bound {
									if let Some(id) = trait_bound.path.get_ident() {
										if id == "Sized" { continue; }
									}
									if non_lifetimes_processed { return false; }
									non_lifetimes_processed = true;
									assert_simple_bound(&trait_bound);
									*gen = ("crate::".to_string() + &types.resolve_path(&trait_bound.path, None),
										Some(&trait_bound.path));
								}
							}
						} else { return false; }
					} else { return false; }
				}
			}
		}
		for (_, (_, ident)) in self.typed_generics.iter() {
			if ident.is_none() { return false; }
		}
		true
	}

	/// Learn the associated types from the trait in the current context.
	pub fn learn_associated_types<'b, 'c>(&mut self, t: &'a syn::ItemTrait, types: &'b TypeResolver<'a, 'c>) {
		for item in t.items.iter() {
			match item {
				&syn::TraitItem::Type(ref t) => {
					if t.default.is_some() || t.generics.lt_token.is_some() { unimplemented!(); }
					let mut bounds_iter = t.bounds.iter();
					match bounds_iter.next().unwrap() {
						syn::TypeParamBound::Trait(tr) => {
							assert_simple_bound(&tr);
							if let Some(mut path) = types.maybe_resolve_path(&tr.path, None) {
								if types.skip_path(&path) { continue; }
								// In general we handle Deref<Target=X> as if it were just X (and
								// implement Deref<Target=Self> for relevant types). We don't
								// bother to implement it for associated types, however, so we just
								// ignore such bounds.
								let new_ident = if path != "std::ops::Deref" {
									path = "crate::".to_string() + &path;
									Some(&tr.path)
								} else { None };
								self.typed_generics.insert(&t.ident, (path, new_ident));
							} else { unimplemented!(); }
						},
						_ => unimplemented!(),
					}
					if bounds_iter.next().is_some() { unimplemented!(); }
				},
				_ => {},
			}
		}
	}

	/// Attempt to resolve an Ident as a generic parameter and return the full path.
	pub fn maybe_resolve_ident<'b>(&'b self, ident: &syn::Ident) -> Option<&'b String> {
		if let Some(ty) = &self.self_ty {
			if format!("{}", ident) == "Self" {
				return Some(&ty.0);
			}
		}
		if let Some(res) = self.typed_generics.get(ident).map(|(a, _)| a) {
			return Some(res);
		}
		if let Some(parent) = self.parent {
			parent.maybe_resolve_ident(ident)
		} else {
			None
		}
	}
	/// Attempt to resolve a Path as a generic parameter and return the full path. as both a string
	/// and syn::Path.
	pub fn maybe_resolve_path<'b>(&'b self, path: &syn::Path) -> Option<(&'b String, &'a syn::Path)> {
		if let Some(ident) = path.get_ident() {
			if let Some(ty) = &self.self_ty {
				if format!("{}", ident) == "Self" {
					return Some((&ty.0, ty.1));
				}
			}
			if let Some(res) = self.typed_generics.get(ident).map(|(a, b)| (a, b.unwrap())) {
				return Some(res);
			}
		} else {
			// Associated types are usually specified as "Self::Generic", so we check for that
			// explicitly here.
			let mut it = path.segments.iter();
			if path.segments.len() == 2 && it.next().unwrap().ident == "Self" {
				let ident = &it.next().unwrap().ident;
				if let Some(res) = self.typed_generics.get(ident).map(|(a, b)| (a, b.unwrap())) {
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

#[derive(Clone, PartialEq)]
// The type of declaration and the object itself
pub enum DeclType<'a> {
	MirroredEnum,
	Trait(&'a syn::ItemTrait),
	StructImported,
	StructIgnored,
	EnumIgnored,
}

pub struct ImportResolver<'mod_lifetime, 'crate_lft: 'mod_lifetime> {
	crate_name: &'mod_lifetime str,
	dependencies: &'mod_lifetime HashSet<syn::Ident>,
	module_path: &'mod_lifetime str,
	imports: HashMap<syn::Ident, (String, syn::Path)>,
	declared: HashMap<syn::Ident, DeclType<'crate_lft>>,
	priv_modules: HashSet<syn::Ident>,
}
impl<'mod_lifetime, 'crate_lft: 'mod_lifetime> ImportResolver<'mod_lifetime, 'crate_lft> {
	fn process_use_intern(crate_name: &str, module_path: &str, dependencies: &HashSet<syn::Ident>, imports: &mut HashMap<syn::Ident, (String, syn::Path)>,
			u: &syn::UseTree, partial_path: &str, mut path: syn::punctuated::Punctuated<syn::PathSegment, syn::token::Colon2>) {

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
				} else if partial_path == "" && !dependencies.contains(&$ident) {
					new_path = format!("{}::{}{}", crate_name, $ident, $path_suffix);
					let crate_name_ident = format_ident!("{}", crate_name);
					path.push(parse_quote!(#crate_name_ident));
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
				Self::process_use_intern(crate_name, module_path, dependencies, imports, &p.tree, &new_path, path);
			},
			syn::UseTree::Name(n) => {
				push_path!(n.ident, "");
				imports.insert(n.ident.clone(), (new_path, syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments: path }));
			},
			syn::UseTree::Group(g) => {
				for i in g.items.iter() {
					Self::process_use_intern(crate_name, module_path, dependencies, imports, i, partial_path, path.clone());
				}
			},
			syn::UseTree::Rename(r) => {
				push_path!(r.ident, "");
				imports.insert(r.rename.clone(), (new_path, syn::Path { leading_colon: Some(syn::Token![::](Span::call_site())), segments: path }));
			},
			syn::UseTree::Glob(_) => {
				eprintln!("Ignoring * use for {} - this may result in resolution failures", partial_path);
			},
		}
	}

	fn process_use(crate_name: &str, module_path: &str, dependencies: &HashSet<syn::Ident>, imports: &mut HashMap<syn::Ident, (String, syn::Path)>, u: &syn::ItemUse) {
		if let syn::Visibility::Public(_) = u.vis {
			// We actually only use these for #[cfg(fuzztarget)]
			eprintln!("Ignoring pub(use) tree!");
			return;
		}
		if u.leading_colon.is_some() { eprintln!("Ignoring leading-colon use!"); return; }
		Self::process_use_intern(crate_name, module_path, dependencies, imports, &u.tree, "", syn::punctuated::Punctuated::new());
	}

	fn insert_primitive(imports: &mut HashMap<syn::Ident, (String, syn::Path)>, id: &str) {
		let ident = format_ident!("{}", id);
		let path = parse_quote!(#ident);
		imports.insert(ident, (id.to_owned(), path));
	}

	pub fn new(crate_name: &'mod_lifetime str, dependencies: &'mod_lifetime HashSet<syn::Ident>, module_path: &'mod_lifetime str, contents: &'crate_lft [syn::Item]) -> Self {
		Self::from_borrowed_items(crate_name, dependencies, module_path, &contents.iter().map(|a| a).collect::<Vec<_>>())
	}
	pub fn from_borrowed_items(crate_name: &'mod_lifetime str, dependencies: &'mod_lifetime HashSet<syn::Ident>, module_path: &'mod_lifetime str, contents: &[&'crate_lft syn::Item]) -> Self {
		let mut imports = HashMap::new();
		// Add primitives to the "imports" list:
		Self::insert_primitive(&mut imports, "bool");
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
				syn::Item::Use(u) => Self::process_use(crate_name, module_path, dependencies, &mut imports, &u),
				syn::Item::Struct(s) => {
					if let syn::Visibility::Public(_) = s.vis {
						match export_status(&s.attrs) {
							ExportStatus::Export => { declared.insert(s.ident.clone(), DeclType::StructImported); },
							ExportStatus::NoExport => { declared.insert(s.ident.clone(), DeclType::StructIgnored); },
							ExportStatus::TestOnly => continue,
						}
					}
				},
				syn::Item::Type(t) if export_status(&t.attrs) == ExportStatus::Export => {
					if let syn::Visibility::Public(_) = t.vis {
						let mut process_alias = true;
						for tok in t.generics.params.iter() {
							if let syn::GenericParam::Lifetime(_) = tok {}
							else { process_alias = false; }
						}
						if process_alias {
							declared.insert(t.ident.clone(), DeclType::StructImported);
						}
					}
				},
				syn::Item::Enum(e) => {
					if let syn::Visibility::Public(_) = e.vis {
						match export_status(&e.attrs) {
							ExportStatus::Export if is_enum_opaque(e) => { declared.insert(e.ident.clone(), DeclType::EnumIgnored); },
							ExportStatus::Export => { declared.insert(e.ident.clone(), DeclType::MirroredEnum); },
							_ => continue,
						}
					}
				},
				syn::Item::Trait(t) if export_status(&t.attrs) == ExportStatus::Export => {
					if let syn::Visibility::Public(_) = t.vis {
						declared.insert(t.ident.clone(), DeclType::Trait(t));
					}
				},
				syn::Item::Mod(m) => {
					priv_modules.insert(m.ident.clone());
				},
				_ => {},
			}
		}

		Self { crate_name, dependencies, module_path, imports, declared, priv_modules }
	}

	pub fn get_declared_type(&self, ident: &syn::Ident) -> Option<&DeclType<'crate_lft>> {
		self.declared.get(ident)
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

	pub fn maybe_resolve_non_ignored_ident(&self, id: &syn::Ident) -> Option<String> {
		if let Some((imp, _)) = self.imports.get(id) {
			Some(imp.clone())
		} else if let Some(decl_type) = self.declared.get(id) {
			match decl_type {
				DeclType::StructIgnored => None,
				_ => Some(self.module_path.to_string() + "::" + &format!("{}", id)),
			}
		} else { None }
	}

	pub fn maybe_resolve_path(&self, p_arg: &syn::Path, generics: Option<&GenericTypes>) -> Option<String> {
		let p = if let Some(gen_types) = generics {
			if let Some((_, synpath)) = gen_types.maybe_resolve_path(p_arg) {
				synpath
			} else { p_arg }
		} else { p_arg };

		if p.leading_colon.is_some() {
			let mut res: String = p.segments.iter().enumerate().map(|(idx, seg)| {
				format!("{}{}", if idx == 0 { "" } else { "::" }, seg.ident)
			}).collect();
			let firstseg = p.segments.iter().next().unwrap();
			if !self.dependencies.contains(&firstseg.ident) {
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
			} else if first_seg_str == "std" || first_seg_str == "core" || self.dependencies.contains(&first_seg.ident) {
				Some(first_seg_str + &remaining)
			} else { None }
		}
	}

	/// Map all the Paths in a Type into absolute paths given a set of imports (generated via process_use_intern)
	pub fn resolve_imported_refs(&self, mut ty: syn::Type) -> syn::Type {
		match &mut ty {
			syn::Type::Path(p) => {
eprintln!("rir {:?}", p);
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
	res.insert("crate::c_types::u5".to_owned());
	res
}

/// Top-level struct tracking everything which has been defined while walking the crate.
pub struct CrateTypes<'a> {
	/// This may contain structs or enums, but only when either is mapped as
	/// struct X { inner: *mut originalX, .. }
	pub opaques: HashMap<String, &'a syn::Ident>,
	/// Enums which are mapped as C enums with conversion functions
	pub mirrored_enums: HashMap<String, &'a syn::ItemEnum>,
	/// Traits which are mapped as a pointer + jump table
	pub traits: HashMap<String, &'a syn::ItemTrait>,
	/// Aliases from paths to some other Type
	pub type_aliases: HashMap<String, syn::Type>,
	/// Value is an alias to Key (maybe with some generics)
	pub reverse_alias_map: HashMap<String, Vec<(syn::Path, syn::PathArguments)>>,
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
			templates_defined: RefCell::new(HashMap::default()),
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
	types: ImportResolver<'mod_lifetime, 'crate_lft>,
}

/// Returned by write_empty_rust_val_check_suffix to indicate what type of dereferencing needs to
/// happen to get the inner value of a generic.
enum EmptyValExpectedTy {
	/// A type which has a flag for being empty (eg an array where we treat all-0s as empty).
	NonPointer,
	/// A pointer that we want to dereference and move out of.
	OwnedPointer,
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
	fn skip_path(&self, full_path: &str) -> bool {
		full_path == "bitcoin::secp256k1::Secp256k1" ||
		full_path == "bitcoin::secp256k1::Signing" ||
		full_path == "bitcoin::secp256k1::Verification"
	}
	/// Returns true we if can just skip passing this to C entirely
	fn no_arg_path_to_rust(&self, full_path: &str) -> &str {
		if full_path == "bitcoin::secp256k1::Secp256k1" {
			"secp256k1::SECP256K1"
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
			"crate::c_types::Signature" => true,
			"crate::c_types::TxOut" => true,
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
			"Result" => Some("crate::c_types::derived::CResult"),
			"Vec" if !is_ref => Some("crate::c_types::derived::CVec"),
			"Option" => Some(""),

			// Note that no !is_ref types can map to an array because Rust and C's call semantics
			// for arrays are different (https://github.com/eqrion/cbindgen/issues/528)

			"[u8; 32]" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"[u8; 20]" if !is_ref => Some("crate::c_types::TwentyBytes"),
			"[u8; 16]" if !is_ref => Some("crate::c_types::SixteenBytes"),
			"[u8; 10]" if !is_ref => Some("crate::c_types::TenBytes"),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes"),
			"[u8; 3]" if !is_ref => Some("crate::c_types::ThreeBytes"), // Used for RGB values

			"str" if is_ref => Some("crate::c_types::Str"),
			"String" if !is_ref => Some("crate::c_types::derived::CVec_u8Z"),
			"String" if is_ref => Some("crate::c_types::Str"),

			"std::time::Duration" => Some("u64"),
			"std::time::SystemTime" => Some("u64"),
			"std::io::Error" => Some("crate::c_types::IOError"),

			"bech32::u5" => Some("crate::c_types::u5"),

			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				=> Some("crate::c_types::PublicKey"),
			"bitcoin::secp256k1::Signature" => Some("crate::c_types::Signature"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if !is_ref => Some("crate::c_types::SecretKey"),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some("crate::c_types::Secp256k1Error"),
			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("crate::c_types::derived::CVec_u8Z"),
			"bitcoin::blockdata::transaction::OutPoint" => Some("crate::lightning::chain::transaction::OutPoint"),
			"bitcoin::blockdata::transaction::Transaction" => Some("crate::c_types::Transaction"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut"),
			"bitcoin::network::constants::Network" => Some("crate::c_types::Network"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref  => Some("*const [u8; 80]"),
			"bitcoin::blockdata::block::Block" if is_ref  => Some("crate::c_types::u8slice"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if is_ref  => Some("*const [u8; 32]"),
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"lightning::ln::channelmanager::PaymentHash" if is_ref => Some("*const [u8; 32]"),
			"lightning::ln::channelmanager::PaymentHash" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"lightning::ln::channelmanager::PaymentPreimage" if is_ref => Some("*const [u8; 32]"),
			"lightning::ln::channelmanager::PaymentPreimage" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"lightning::ln::channelmanager::PaymentSecret" if is_ref => Some("crate::c_types::ThirtyTwoBytes"),
			"lightning::ln::channelmanager::PaymentSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes"),

			// Override the default since Records contain an fmt with a lifetime:
			"lightning::util::logger::Record" => Some("*const std::os::raw::c_char"),

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
			"[u8; 10]" if !is_ref => Some(""),
			"[u8; 4]" if !is_ref => Some(""),
			"[u8; 3]" if !is_ref => Some(""),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(""),
			"String" if !is_ref => Some("String::from_utf8("),
			// Note that we'll panic for String if is_ref, as we only have non-owned memory, we
			// cannot create a &String.

			"std::time::Duration" => Some("std::time::Duration::from_secs("),
			"std::time::SystemTime" => Some("(::std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs("),

			"bech32::u5" => Some(""),

			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				if is_ref => Some("&"),
			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				=> Some(""),
			"bitcoin::secp256k1::Signature" if is_ref => Some("&"),
			"bitcoin::secp256k1::Signature" => Some(""),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if is_ref => Some("&::bitcoin::secp256k1::key::SecretKey::from_slice(&unsafe { *"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if !is_ref => Some(""),
			"bitcoin::blockdata::script::Script" if is_ref => Some("&::bitcoin::blockdata::script::Script::from(Vec::from("),
			"bitcoin::blockdata::script::Script" if !is_ref => Some("::bitcoin::blockdata::script::Script::from("),
			"bitcoin::blockdata::transaction::Transaction" if is_ref => Some("&"),
			"bitcoin::blockdata::transaction::Transaction" => Some(""),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(""),
			"bitcoin::network::constants::Network" => Some(""),
			"bitcoin::blockdata::block::BlockHeader" => Some("&::bitcoin::consensus::encode::deserialize(unsafe { &*"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("&::bitcoin::consensus::encode::deserialize("),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some("&::bitcoin::hash_types::Txid::from_slice(&unsafe { &*"),
			"bitcoin::hash_types::Txid" if !is_ref => Some("::bitcoin::hash_types::Txid::from_slice(&"),
			"bitcoin::hash_types::BlockHash" => Some("::bitcoin::hash_types::BlockHash::from_slice(&"),
			"lightning::ln::channelmanager::PaymentHash" if !is_ref => Some("::lightning::ln::channelmanager::PaymentHash("),
			"lightning::ln::channelmanager::PaymentHash" if is_ref => Some("&::lightning::ln::channelmanager::PaymentHash(unsafe { *"),
			"lightning::ln::channelmanager::PaymentPreimage" if !is_ref => Some("::lightning::ln::channelmanager::PaymentPreimage("),
			"lightning::ln::channelmanager::PaymentPreimage" if is_ref => Some("&::lightning::ln::channelmanager::PaymentPreimage(unsafe { *"),
			"lightning::ln::channelmanager::PaymentSecret" => Some("::lightning::ln::channelmanager::PaymentSecret("),

			// List of traits we map (possibly during processing of other files):
			"crate::util::logger::Logger" => Some(""),

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
			"[u8; 10]" if !is_ref => Some(".data"),
			"[u8; 4]" if !is_ref => Some(".data"),
			"[u8; 3]" if !is_ref => Some(".data"),

			"[u8]" if is_ref => Some(".to_slice()"),
			"[usize]" if is_ref => Some(".to_slice()"),

			"str" if is_ref => Some(".into()"),
			"String" if !is_ref => Some(".into_rust()).unwrap()"),

			"std::time::Duration" => Some(")"),
			"std::time::SystemTime" => Some("))"),

			"bech32::u5" => Some(".into()"),

			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				=> Some(".into_rust()"),
			"bitcoin::secp256k1::Signature" => Some(".into_rust()"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if !is_ref => Some(".into_rust()"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if is_ref => Some("}[..]).unwrap()"),
			"bitcoin::blockdata::script::Script" if is_ref => Some(".to_slice()))"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_rust())"),
			"bitcoin::blockdata::transaction::Transaction" => Some(".into_bitcoin()"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(".into_rust()"),
			"bitcoin::network::constants::Network" => Some(".into_bitcoin()"),
			"bitcoin::blockdata::block::BlockHeader" => Some(" }).unwrap()"),
			"bitcoin::blockdata::block::Block" => Some(".to_slice()).unwrap()"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid" if is_ref => Some(" }[..]).unwrap()"),
			"bitcoin::hash_types::Txid" => Some(".data[..]).unwrap()"),
			"bitcoin::hash_types::BlockHash" if !is_ref => Some(".data[..]).unwrap()"),
			"lightning::ln::channelmanager::PaymentHash" if !is_ref => Some(".data)"),
			"lightning::ln::channelmanager::PaymentHash" if is_ref => Some(" })"),
			"lightning::ln::channelmanager::PaymentPreimage" if !is_ref => Some(".data)"),
			"lightning::ln::channelmanager::PaymentPreimage" if is_ref => Some(" })"),
			"lightning::ln::channelmanager::PaymentSecret" => Some(".data)"),

			// List of traits we map (possibly during processing of other files):
			"crate::util::logger::Logger" => Some(""),

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

			// Override the default since Records contain an fmt with a lifetime:
			// TODO: We should include the other record fields
			"lightning::util::logger::Record" => Some(("std::ffi::CString::new(format!(\"{}\", ", ".args)).unwrap()")),
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
			"[u8; 10]" if !is_ref => Some("crate::c_types::TenBytes { data: "),
			"[u8; 4]" if !is_ref => Some("crate::c_types::FourBytes { data: "),
			"[u8; 3]" if is_ref => Some(""),

			"[u8]" if is_ref => Some("local_"),
			"[usize]" if is_ref => Some("local_"),

			"str" if is_ref => Some(""),
			"String" => Some(""),

			"std::time::Duration" => Some(""),
			"std::time::SystemTime" => Some(""),
			"std::io::Error" if !is_ref => Some("crate::c_types::IOError::from_rust("),

			"bech32::u5" => Some(""),

			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				=> Some("crate::c_types::PublicKey::from_rust(&"),
			"bitcoin::secp256k1::Signature" => Some("crate::c_types::Signature::from_rust(&"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if is_ref => Some(""),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if !is_ref => Some("crate::c_types::SecretKey::from_rust("),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some("crate::c_types::Secp256k1Error::from_rust("),
			"bitcoin::blockdata::script::Script" if is_ref => Some("crate::c_types::u8slice::from_slice(&"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(""),
			"bitcoin::blockdata::transaction::Transaction" if is_ref => Some("crate::c_types::Transaction::from_bitcoin("),
			"bitcoin::blockdata::transaction::Transaction" => Some("crate::c_types::Transaction::from_bitcoin(&"),
			"bitcoin::blockdata::transaction::OutPoint" => Some("crate::c_types::bitcoin_to_C_outpoint("),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some("crate::c_types::TxOut::from_rust("),
			"bitcoin::network::constants::Network" => Some("crate::c_types::Network::from_bitcoin("),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some("&local_"),
			"bitcoin::blockdata::block::Block" if is_ref => Some("crate::c_types::u8slice::from_slice(&local_"),

			"bitcoin::hash_types::Txid" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if is_ref => Some(""),
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"bitcoin::secp256k1::Message" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"lightning::ln::channelmanager::PaymentHash" if is_ref => Some("&"),
			"lightning::ln::channelmanager::PaymentHash" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"lightning::ln::channelmanager::PaymentPreimage" if is_ref => Some("&"),
			"lightning::ln::channelmanager::PaymentPreimage" => Some("crate::c_types::ThirtyTwoBytes { data: "),
			"lightning::ln::channelmanager::PaymentSecret" if !is_ref => Some("crate::c_types::ThirtyTwoBytes { data: "),

			// Override the default since Records contain an fmt with a lifetime:
			"lightning::util::logger::Record" => Some("local_"),

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
			"[u8; 10]" if !is_ref => Some(" }"),
			"[u8; 4]" if !is_ref => Some(" }"),
			"[u8; 3]" if is_ref => Some(""),

			"[u8]" if is_ref => Some(""),
			"[usize]" if is_ref => Some(""),

			"str" if is_ref => Some(".into()"),
			"String" if !is_ref => Some(".into_bytes().into()"),
			"String" if is_ref => Some(".as_str().into()"),

			"std::time::Duration" => Some(".as_secs()"),
			"std::time::SystemTime" => Some(".duration_since(::std::time::SystemTime::UNIX_EPOCH).expect(\"Times must be post-1970\").as_secs()"),
			"std::io::Error" if !is_ref => Some(")"),

			"bech32::u5" => Some(".into()"),

			"bitcoin::secp256k1::key::PublicKey"|"bitcoin::secp256k1::PublicKey"|"secp256k1::key::PublicKey"
				=> Some(")"),
			"bitcoin::secp256k1::Signature" => Some(")"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if !is_ref => Some(")"),
			"bitcoin::secp256k1::key::SecretKey"|"bitcoin::secp256k1::SecretKey"
				if is_ref => Some(".as_ref()"),
			"bitcoin::secp256k1::Error"|"secp256k1::Error"
				if !is_ref => Some(")"),
			"bitcoin::blockdata::script::Script" if is_ref => Some("[..])"),
			"bitcoin::blockdata::script::Script" if !is_ref => Some(".into_bytes().into()"),
			"bitcoin::blockdata::transaction::Transaction" => Some(")"),
			"bitcoin::blockdata::transaction::OutPoint" => Some(")"),
			"bitcoin::blockdata::transaction::TxOut" if !is_ref => Some(")"),
			"bitcoin::network::constants::Network" => Some(")"),
			"bitcoin::blockdata::block::BlockHeader" if is_ref => Some(""),
			"bitcoin::blockdata::block::Block" if is_ref => Some(")"),

			"bitcoin::hash_types::Txid" if !is_ref => Some(".into_inner() }"),

			// Newtypes that we just expose in their original form.
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if is_ref => Some(".as_inner()"),
			"bitcoin::hash_types::Txid"|"bitcoin::hash_types::BlockHash"|"bitcoin_hashes::sha256::Hash"
				if !is_ref => Some(".into_inner() }"),
			"bitcoin::secp256k1::Message" if !is_ref => Some(".as_ref().clone() }"),
			"lightning::ln::channelmanager::PaymentHash" if is_ref => Some(".0"),
			"lightning::ln::channelmanager::PaymentHash" => Some(".0 }"),
			"lightning::ln::channelmanager::PaymentPreimage" if is_ref => Some(".0"),
			"lightning::ln::channelmanager::PaymentPreimage" => Some(".0 }"),
			"lightning::ln::channelmanager::PaymentSecret" if !is_ref => Some(".0 }"),

			// Override the default since Records contain an fmt with a lifetime:
			"lightning::util::logger::Record" => Some(".as_ptr()"),

			_ => None,
		}.map(|s| s.to_owned())
	}

	fn empty_val_check_suffix_from_path(&self, full_path: &str) -> Option<&str> {
		match full_path {
			"lightning::ln::channelmanager::PaymentSecret" => Some(".data == [0; 32]"),
			"secp256k1::key::PublicKey"|"bitcoin::secp256k1::key::PublicKey" => Some(".is_null()"),
			"bitcoin::secp256k1::Signature" => Some(".is_null()"),
			_ => None
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

	/// Returns true if the path containing the given args is a "transparent" container, ie an
	/// Option or a container which does not require a generated continer class.
	fn is_transparent_container<'i, I: Iterator<Item=&'i syn::Type>>(&self, full_path: &str, _is_ref: bool, mut args: I) -> bool {
		if full_path == "Option" {
			let inner = args.next().unwrap();
			assert!(args.next().is_none());
			match inner {
				syn::Type::Reference(_) => true,
				syn::Type::Path(p) => {
					if let Some(resolved) = self.maybe_resolve_path(&p.path, None) {
						if self.is_primitive(&resolved) { false } else { true }
					} else { true }
				},
				syn::Type::Tuple(_) => false,
				_ => unimplemented!(),
			}
		} else { false }
	}
	/// Returns true if the path is a "transparent" container, ie an Option or a container which does
	/// not require a generated continer class.
	fn is_path_transparent_container(&self, full_path: &syn::Path, generics: Option<&GenericTypes>, is_ref: bool) -> bool {
		let inner_iter = match &full_path.segments.last().unwrap().arguments {
			syn::PathArguments::None => return false,
			syn::PathArguments::AngleBracketed(args) => args.args.iter().map(|arg| {
				if let syn::GenericArgument::Type(ref ty) = arg {
					ty
				} else { unimplemented!() }
			}),
			syn::PathArguments::Parenthesized(_) => unimplemented!(),
		};
		self.is_transparent_container(&self.resolve_path(full_path, generics), is_ref, inner_iter)
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
			"Vec" if !is_ref => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Vec" => {
				// We should only get here if the single contained has an inner
				assert!(self.c_type_has_inner(single_contained.unwrap()));
				Some(("Vec::new(); for mut item in ", vec![(format!(".drain(..) {{ local_{}.push(", var_name), "*item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Slice" => {
				Some(("Vec::new(); for item in ", vec![(format!(".iter() {{ local_{}.push(", var_name), "*item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Option" => {
				if let Some(syn::Type::Path(p)) = single_contained {
					let inner_path = self.resolve_path(&p.path, generics);
					if self.is_primitive(&inner_path) {
						return Some(("if ", vec![
							(format!(".is_none() {{ {}::COption_{}Z::None }} else {{ ", Self::generated_container_path(), inner_path),
							 format!("{}::COption_{}Z::Some({}.unwrap())", Self::generated_container_path(), inner_path, var_access))
							], " }", ContainerPrefixLocation::NoPrefix));
					} else if self.c_type_has_inner_from_path(&inner_path) {
						if is_ref {
							return Some(("if ", vec![
								(".is_none() { std::ptr::null() } else { ".to_owned(), format!("({}.as_ref().unwrap())", var_access))
								], " }", ContainerPrefixLocation::OutsideConv));
						} else {
							return Some(("if ", vec![
								(".is_none() { std::ptr::null_mut() } else { ".to_owned(), format!("({}.unwrap())", var_access))
								], " }", ContainerPrefixLocation::OutsideConv));
						}
					}
				}
				if let Some(t) = single_contained {
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
		match full_path {
			"Result" if !is_ref => {
				Some(("match ",
						vec![(".result_ok { true => Ok(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.result)) }})", var_access)),
						     ("), false => Err(".to_string(), format!("(*unsafe {{ Box::from_raw(<*mut _>::take_ptr(&mut {}.contents.err)) }})", var_access))],
						")}", ContainerPrefixLocation::PerConv))
			},
			"Slice" if is_ref => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".as_slice().iter() {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Vec"|"Slice" => {
				Some(("Vec::new(); for mut item in ", vec![(format!(".into_rust().drain(..) {{ local_{}.push(", var_name), "item".to_string())], "); }", ContainerPrefixLocation::PerConv))
			},
			"Option" => {
				if let Some(syn::Type::Path(p)) = single_contained {
					let inner_path = self.resolve_path(&p.path, generics);
					if self.is_primitive(&inner_path) {
						return Some(("if ", vec![(".is_some() { Some(".to_string(), format!("{}.take()", var_access))], ") } else { None }", ContainerPrefixLocation::NoPrefix))
					} else if self.c_type_has_inner_from_path(&inner_path) {
						if is_ref {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some((*".to_string(), format!("{}", var_access))], ").clone()) }", ContainerPrefixLocation::PerConv))
						} else {
							return Some(("if ", vec![(".inner.is_null() { None } else { Some(".to_string(), format!("{}", var_access))], ") }", ContainerPrefixLocation::PerConv));
						}
					}
				}

				if let Some(t) = single_contained {
					match t {
						syn::Type::Reference(_)|syn::Type::Path(_)|syn::Type::Slice(_) => {
							let mut v = Vec::new();
							let ret_ref = self.write_empty_rust_val_check_suffix(generics, &mut v, t);
							let s = String::from_utf8(v).unwrap();
							match ret_ref {
								EmptyValExpectedTy::ReferenceAsPointer =>
									return Some(("if ", vec![
										(format!("{} {{ None }} else {{ Some(", s), format!("unsafe {{ &mut *{} }}", var_access))
									], ") }", ContainerPrefixLocation::NoPrefix)),
								EmptyValExpectedTy::OwnedPointer => {
									if let syn::Type::Slice(_) = t {
											panic!();
									}
									return Some(("if ", vec![
										(format!("{} {{ None }} else {{ Some(", s), format!("unsafe {{ *Box::from_raw({}) }}", var_access))
									], ") }", ContainerPrefixLocation::NoPrefix));
								}
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

	// *************************************************
	// *** Type definition during main.rs processing ***
	// *************************************************

	pub fn get_declared_type(&'a self, ident: &syn::Ident) -> Option<&'a DeclType<'c>> {
		self.types.get_declared_type(ident)
	}
	/// Returns true if the object at the given path is mapped as X { inner: *mut origX, .. }.
	pub fn c_type_has_inner_from_path(&self, full_path: &str) -> bool {
		self.crate_types.opaques.get(full_path).is_some()
	}
	/// Returns true if the object at the given path is mapped as X { inner: *mut origX, .. }.
	pub fn c_type_has_inner(&self, ty: &syn::Type) -> bool {
		match ty {
			syn::Type::Path(p) => {
				let full_path = self.resolve_path(&p.path, None);
				self.c_type_has_inner_from_path(&full_path)
			},
			_ => false,
		}
	}

	pub fn maybe_resolve_ident(&self, id: &syn::Ident) -> Option<String> {
		self.types.maybe_resolve_ident(id)
	}

	pub fn maybe_resolve_non_ignored_ident(&self, id: &syn::Ident) -> Option<String> {
		self.types.maybe_resolve_non_ignored_ident(id)
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

	fn write_rust_path<W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, path: &syn::Path) {
		if let Some(resolved) = self.maybe_resolve_path(&path, generics_resolver) {
			if self.is_primitive(&resolved) {
				write!(w, "{}", path.get_ident().unwrap()).unwrap();
			} else {
				// TODO: We should have a generic "is from a dependency" check here instead of
				// checking for "bitcoin" explicitly.
				if resolved.starts_with("bitcoin::") || Self::in_rust_prelude(&resolved) {
					write!(w, "{}", resolved).unwrap();
				// If we're printing a generic argument, it needs to reference the crate, otherwise
				// the original crate:
				} else if self.maybe_resolve_path(&path, None).as_ref() == Some(&resolved) {
					write!(w, "{}", resolved).unwrap();
				} else {
					write!(w, "crate::{}", resolved).unwrap();
				}
			}
			if let syn::PathArguments::AngleBracketed(args) = &path.segments.iter().last().unwrap().arguments {
				self.write_rust_generic_arg(w, generics_resolver, args.args.iter());
			}
		} else {
			if path.leading_colon.is_some() {
				write!(w, "::").unwrap();
			}
			for (idx, seg) in path.segments.iter().enumerate() {
				if idx != 0 { write!(w, "::").unwrap(); }
				write!(w, "{}", seg.ident).unwrap();
				if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
					self.write_rust_generic_arg(w, generics_resolver, args.args.iter());
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
								self.write_rust_path(w, generics_resolver, &tb.path);
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

	pub fn write_rust_generic_arg<'b, W: std::io::Write>(&self, w: &mut W, generics_resolver: Option<&GenericTypes>, generics: impl Iterator<Item=&'b syn::GenericArgument>) {
		write!(w, "<").unwrap();
		for (idx, arg) in generics.enumerate() {
			if idx != 0 { write!(w, ", ").unwrap(); }
			match arg {
				syn::GenericArgument::Type(t) => self.write_rust_type(w, generics_resolver, t),
				_ => unimplemented!(),
			}
		}
		write!(w, ">").unwrap();
	}
	pub fn write_rust_type<W: std::io::Write>(&self, w: &mut W, generics: Option<&GenericTypes>, t: &syn::Type) {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				self.write_rust_path(w, generics, &p.path);
			},
			syn::Type::Reference(r) => {
				write!(w, "&").unwrap();
				if let Some(lft) = &r.lifetime {
					write!(w, "'{} ", lft.ident).unwrap();
				}
				if r.mutability.is_some() {
					write!(w, "mut ").unwrap();
				}
				self.write_rust_type(w, generics, &*r.elem);
			},
			syn::Type::Array(a) => {
				write!(w, "[").unwrap();
				self.write_rust_type(w, generics, &a.elem);
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, "; {}]", i).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			}
			syn::Type::Slice(s) => {
				write!(w, "[").unwrap();
				self.write_rust_type(w, generics, &s.elem);
				write!(w, "]").unwrap();
			},
			syn::Type::Tuple(s) => {
				write!(w, "(").unwrap();
				for (idx, t) in s.elems.iter().enumerate() {
					if idx != 0 { write!(w, ", ").unwrap(); }
					self.write_rust_type(w, generics, &t);
				}
				write!(w, ")").unwrap();
			},
			_ => unimplemented!(),
		}
	}

	/// Prints a constructor for something which is "uninitialized" (but obviously not actually
	/// unint'd memory).
	pub fn write_empty_rust_val<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) {
		match t {
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, "crate::{} {{ inner: std::ptr::null_mut(), is_owned: true }}", resolved).unwrap();
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

	fn is_real_type_array(&self, resolved_type: &str) -> Option<syn::Type> {
		if let Some(real_ty) = self.c_type_from_path(&resolved_type, true, false) {
			if real_ty.ends_with("]") && real_ty.starts_with("*const [u8; ") {
				let mut split = real_ty.split("; ");
				split.next().unwrap();
				let tail_str = split.next().unwrap();
				assert!(split.next().is_none());
				let len = usize::from_str_radix(&tail_str[..tail_str.len() - 1], 10).unwrap();
				Some(parse_quote!([u8; #len]))
			} else { None }
		} else { None }
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	/// See EmptyValExpectedTy for information on return types.
	fn write_empty_rust_val_check_suffix<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type) -> EmptyValExpectedTy {
		match t {
			syn::Type::Path(p) => {
				let resolved = self.resolve_path(&p.path, generics);
				if let Some(arr_ty) = self.is_real_type_array(&resolved) {
					write!(w, ".data").unwrap();
					return self.write_empty_rust_val_check_suffix(generics, w, &arr_ty);
				}
				if self.crate_types.opaques.get(&resolved).is_some() {
					write!(w, ".inner.is_null()").unwrap();
					EmptyValExpectedTy::NonPointer
				} else {
					if let Some(suffix) = self.empty_val_check_suffix_from_path(&resolved) {
						write!(w, "{}", suffix).unwrap();
						// We may eventually need to allow empty_val_check_suffix_from_path to specify if we need a deref or not
						EmptyValExpectedTy::NonPointer
					} else {
						write!(w, " == std::ptr::null_mut()").unwrap();
						EmptyValExpectedTy::OwnedPointer
					}
				}
			},
			syn::Type::Array(a) => {
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, " == [0; {}]", i.base10_digits()).unwrap();
						EmptyValExpectedTy::NonPointer
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(_) => {
				// Option<[]> always implies that we want to treat len() == 0 differently from
				// None, so we always map an Option<[]> into a pointer.
				write!(w, " == std::ptr::null_mut()").unwrap();
				EmptyValExpectedTy::ReferenceAsPointer
			},
			_ => unimplemented!(),
		}
	}

	/// Prints a suffix to determine if a variable is empty (ie was set by write_empty_rust_val).
	pub fn write_empty_rust_val_check<W: std::io::Write>(&self, generics: Option<&GenericTypes>, w: &mut W, t: &syn::Type, var_access: &str) {
		match t {
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
		match t {
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
				} else if self.crate_types.opaques.get(&resolved_path).is_some() {
					decl_lookup(w, &DeclType::StructImported, &resolved_path, is_ref, is_mut);
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
				// We assume all arrays contain only [int_literal; X]s.
				// This may result in some outputs not compiling.
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						write!(w, "{}", path_lookup(&format!("[u8; {}]", i.base10_digits()), is_ref, ptr_for_ref).unwrap()).unwrap();
					} else { unimplemented!(); }
				} else { unimplemented!(); }
			},
			syn::Type::Slice(s) => {
				// We assume all slices contain only literals or references.
				// This may result in some outputs not compiling.
				if let syn::Type::Path(p) = &*s.elem {
					let resolved = self.resolve_path(&p.path, generics);
					assert!(self.is_primitive(&resolved));
					write!(w, "{}", path_lookup("[u8]", is_ref, ptr_for_ref).unwrap()).unwrap();
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						write!(w, "{}", sliceconv(self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics)), None)).unwrap();
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
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, ptr_for_ref, "0u8 /*", true, |_, _| "local_".to_owned(),
				|a, b, c| self.to_c_conversion_inline_prefix_from_path(a, b, c),
				|w, decl_type, decl_path, is_ref, _is_mut| {
					match decl_type {
						DeclType::MirroredEnum if is_ref && ptr_for_ref => write!(w, "crate::{}::from_native(", decl_path).unwrap(),
						DeclType::MirroredEnum if is_ref => write!(w, "&crate::{}::from_native(", decl_path).unwrap(),
						DeclType::MirroredEnum => write!(w, "crate::{}::native_into(", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref && from_ptr =>
							write!(w, "crate::{} {{ inner: unsafe {{ (", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref =>
							write!(w, "crate::{} {{ inner: unsafe {{ ( (&(*", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if is_ref =>
							write!(w, "&crate::{} {{ inner: unsafe {{ (", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if !is_ref && from_ptr =>
							write!(w, "crate::{} {{ inner: ", decl_path).unwrap(),
						DeclType::EnumIgnored|DeclType::StructImported if !is_ref =>
							write!(w, "crate::{} {{ inner: Box::into_raw(Box::new(", decl_path).unwrap(),
						DeclType::Trait(_) if is_ref => write!(w, "").unwrap(),
						DeclType::Trait(_) if !is_ref => {},
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
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::MirroredEnum => write!(w, ")").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref && from_ptr =>
						write!(w, " as *const _) as *mut _ }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref && ptr_for_ref =>
						write!(w, ") as *const _) as *mut _) }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if is_ref =>
						write!(w, " as *const _) as *mut _ }}, is_owned: false }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if !is_ref && from_ptr =>
						write!(w, ", is_owned: true }}").unwrap(),
					DeclType::EnumIgnored|DeclType::StructImported if !is_ref => write!(w, ")), is_owned: true }}").unwrap(),
					DeclType::Trait(_) if is_ref => {},
					DeclType::Trait(_) => {
						// This is used when we're converting a concrete Rust type into a C trait
						// for use when a Rust trait method returns an associated type.
						// Because all of our C traits implement From<RustTypesImplementingTraits>
						// we can just call .into() here and be done.
						write!(w, ".into()").unwrap()
					},
					_ => unimplemented!(),
				});
	}
	pub fn write_to_c_conversion_inline_suffix<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) {
		self.write_to_c_conversion_inline_suffix_inner(w, t, generics, false, ptr_for_ref, false);
	}

	fn write_from_c_conversion_prefix_inner<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, ptr_for_ref: bool) {
		self.write_conversion_inline_intern(w, t, generics, is_ref, false, false, "() /*", true, |_, _| "&local_".to_owned(),
				|a, b, _c| self.from_c_conversion_prefix_from_path(a, b),
				|w, decl_type, _full_path, is_ref, is_mut| match decl_type {
					DeclType::StructImported if is_ref && ptr_for_ref => write!(w, "unsafe {{ &*(*").unwrap(),
					DeclType::StructImported if is_mut && is_ref => write!(w, "unsafe {{ &mut *").unwrap(),
					DeclType::StructImported if is_ref => write!(w, "unsafe {{ &*").unwrap(),
					DeclType::StructImported if !is_ref => write!(w, "*unsafe {{ Box::from_raw(").unwrap(),
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
				|w, decl_type, _full_path, is_ref, _is_mut| match decl_type {
					DeclType::StructImported if is_ref && ptr_for_ref => write!(w, ").inner }}").unwrap(),
					DeclType::StructImported if is_ref => write!(w, ".inner }}").unwrap(),
					DeclType::StructImported if !is_ref => write!(w, ".take_inner()) }}").unwrap(),
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
					DeclType::StructImported if !is_ref => write!(w, "unsafe {{ &*").unwrap(),
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
					DeclType::StructImported if !is_ref => write!(w, ".inner }}").unwrap(),
					_ => unimplemented!(),
				});
	}

	fn write_conversion_new_var_intern<'b, W: std::io::Write,
		LP: Fn(&str, bool) -> Option<(&str, &str)>,
		LC: Fn(&str, bool, Option<&syn::Type>, &syn::Ident, &str) ->  Option<(&'b str, Vec<(String, String)>, &'b str, ContainerPrefixLocation)>,
		VP: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool),
		VS: Fn(&mut W, &syn::Type, Option<&GenericTypes>, bool, bool, bool)>
			(&self, w: &mut W, ident: &syn::Ident, var: &str, t: &syn::Type, generics: Option<&GenericTypes>,
			 mut is_ref: bool, mut ptr_for_ref: bool, to_c: bool,
			 path_lookup: &LP, container_lookup: &LC, var_prefix: &VP, var_suffix: &VS) -> bool {

		macro_rules! convert_container {
			($container_type: expr, $args_len: expr, $args_iter: expr) => { {
				// For slices (and Options), we refuse to directly map them as is_ref when they
				// aren't opaque types containing an inner pointer. This is due to the fact that,
				// in both cases, the actual higher-level type is non-is_ref.
				let ty_has_inner = if $args_len == 1 {
					let ty = $args_iter().next().unwrap();
					if $container_type == "Slice" && to_c {
						// "To C ptr_for_ref" means "return the regular object with is_owned
						// set to false", which is totally what we want in a slice if we're about to
						// set ty_has_inner.
						ptr_for_ref = true;
					}
					if let syn::Type::Reference(t) = ty {
						if let syn::Type::Path(p) = &*t.elem {
							self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
						} else { false }
					} else if let syn::Type::Path(p) = ty {
						self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
					} else { false }
				} else { true };

				// Options get a bunch of special handling, since in general we map Option<>al
				// types into the same C type as non-Option-wrapped types. This ends up being
				// pretty manual here and most of the below special-cases are for Options.
				let mut needs_ref_map = false;
				let mut only_contained_type = None;
				let mut only_contained_has_inner = false;
				let mut contains_slice = false;
				if $args_len == 1 {
					only_contained_has_inner = ty_has_inner;
					let arg = $args_iter().next().unwrap();
					if let syn::Type::Reference(t) = arg {
						only_contained_type = Some(&*t.elem);
						if let syn::Type::Path(_) = &*t.elem {
							is_ref = true;
						} else if let syn::Type::Slice(_) = &*t.elem {
							contains_slice = true;
						} else { return false; }
						// If the inner element contains an inner pointer, we will just use that,
						// avoiding the need to map elements to references. Otherwise we'll need to
						// do an extra mapping step.
						needs_ref_map = !only_contained_has_inner;
					} else {
						only_contained_type = Some(&arg);
					}
				}

				if let Some((prefix, conversions, suffix, prefix_location)) = container_lookup(&$container_type, is_ref && ty_has_inner, only_contained_type, ident, var) {
					assert_eq!(conversions.len(), $args_len);
					write!(w, "let mut local_{}{} = ", ident, if !to_c && needs_ref_map {"_base"} else { "" }).unwrap();
					if prefix_location == ContainerPrefixLocation::OutsideConv {
						var_prefix(w, $args_iter().next().unwrap(), generics, is_ref, ptr_for_ref, true);
					}
					write!(w, "{}{}", prefix, var).unwrap();

					for ((pfx, var_name), (idx, ty)) in conversions.iter().zip($args_iter().enumerate()) {
						let mut var = std::io::Cursor::new(Vec::new());
						write!(&mut var, "{}", var_name).unwrap();
						let var_access = String::from_utf8(var.into_inner()).unwrap();

						let conv_ty = if needs_ref_map { only_contained_type.as_ref().unwrap() } else { ty };

						write!(w, "{} {{ ", pfx).unwrap();
						let new_var_name = format!("{}_{}", ident, idx);
						let new_var = self.write_conversion_new_var_intern(w, &format_ident!("{}", new_var_name),
								&var_access, conv_ty, generics, contains_slice || (is_ref && ty_has_inner), ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix);
						if new_var { write!(w, " ").unwrap(); }

						if prefix_location == ContainerPrefixLocation::PerConv {
							var_prefix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						} else if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, "Box::into_raw(Box::new(").unwrap();
						}

						write!(w, "{}{}", if contains_slice { "local_" } else { "" }, if new_var { new_var_name } else { var_access }).unwrap();
						if prefix_location == ContainerPrefixLocation::PerConv {
							var_suffix(w, conv_ty, generics, is_ref && ty_has_inner, ptr_for_ref, false);
						} else if !is_ref && !needs_ref_map && to_c && only_contained_has_inner {
							write!(w, "))").unwrap();
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
					}
					return true;
				}
			} }
		}

		match t {
			syn::Type::Reference(r) => {
				if let syn::Type::Slice(_) = &*r.elem {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, is_ref, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix)
				} else {
					self.write_conversion_new_var_intern(w, ident, var, &*r.elem, generics, true, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix)
				}
			},
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					unimplemented!();
				}
				let resolved_path = self.resolve_path(&p.path, generics);
				if let Some(aliased_type) = self.crate_types.type_aliases.get(&resolved_path) {
					return self.write_conversion_new_var_intern(w, ident, var, aliased_type, None, is_ref, ptr_for_ref, to_c, path_lookup, container_lookup, var_prefix, var_suffix);
				}
				if self.is_known_container(&resolved_path, is_ref) || self.is_path_transparent_container(&p.path, generics, is_ref) {
					if let syn::PathArguments::AngleBracketed(args) = &p.path.segments.iter().next().unwrap().arguments {
						convert_container!(resolved_path, args.args.len(), || args.args.iter().map(|arg| {
							if let syn::GenericArgument::Type(ty) = arg {
								ty
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
					assert!(self.is_primitive(&resolved));
					let slice_path = format!("[{}]", resolved);
					if let Some((prefix, suffix)) = path_lookup(&slice_path, true) {
						write!(w, "let mut local_{} = {}{}{};", ident, prefix, var, suffix).unwrap();
						true
					} else { false }
				} else if let syn::Type::Reference(ty) = &*s.elem {
					let tyref = [&*ty.elem];
					is_ref = true;
					convert_container!("Slice", 1, || tyref.iter().map(|t| *t));
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
									false, ptr_for_ref, to_c,
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
						let ty_has_inner = {
								if to_c {
									// "To C ptr_for_ref" means "return the regular object with
									// is_owned set to false", which is totally what we want
									// if we're about to set ty_has_inner.
									ptr_for_ref = true;
								}
								if let syn::Type::Reference(t) = elem {
									if let syn::Type::Path(p) = &*t.elem {
										self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
									} else { false }
								} else if let syn::Type::Path(p) = elem {
									self.c_type_has_inner_from_path(&self.resolve_path(&p.path, generics))
								} else { false }
							};
						if idx != 0 { write!(w, ", ").unwrap(); }
						var_prefix(w, elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
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
						var_suffix(w, elem, generics, is_ref && ty_has_inner, ptr_for_ref, false);
					}
					write!(w, "){};", if to_c { ".into()" } else { "" }).unwrap();
					true
				} else { false }
			},
			_ => unimplemented!(),
		}
	}

	pub fn write_to_c_conversion_new_var_inner<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, var_access: &str, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) -> bool {
		self.write_conversion_new_var_intern(w, ident, var_access, t, generics, false, ptr_for_ref, true,
			&|a, b| self.to_c_conversion_new_var_from_path(a, b),
			&|a, b, c, d, e| self.to_c_conversion_container_new_var(generics, a, b, c, d, e),
			// We force ptr_for_ref here since we can't generate a ref on one line and use it later
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_prefix_inner(a, b, c, d, e, f),
			&|a, b, c, d, e, f| self.write_to_c_conversion_inline_suffix_inner(a, b, c, d, e, f))
	}
	pub fn write_to_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>, ptr_for_ref: bool) -> bool {
		self.write_to_c_conversion_new_var_inner(w, ident, &format!("{}", ident), t, generics, ptr_for_ref)
	}
	pub fn write_from_c_conversion_new_var<W: std::io::Write>(&self, w: &mut W, ident: &syn::Ident, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_conversion_new_var_intern(w, ident, &format!("{}", ident), t, generics, false, false, false,
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
		for (idx, t) in args.enumerate() {
			if idx != 0 {
				write!(w, ", ").unwrap();
			}
			if let syn::Type::Reference(r_arg) = t {
				assert!(!is_ref); // We don't currently support outer reference types for non-primitive inners

				if !self.write_c_type_intern(w, &*r_arg.elem, generics, false, false, false) { return false; }

				// While write_c_type_intern, above is correct, we don't want to blindly convert a
				// reference to something stupid, so check that the container is either opaque or a
				// predefined type (currently only Transaction).
				if let syn::Type::Path(p_arg) = &*r_arg.elem {
					let resolved = self.resolve_path(&p_arg.path, generics);
					assert!(self.crate_types.opaques.get(&resolved).is_some() ||
							self.c_type_from_path(&resolved, true, true).is_some(), "Template generics should be opaque or have a predefined mapping");
				} else { unimplemented!(); }
			} else if let syn::Type::Path(p_arg) = t {
				if let Some(resolved) = self.maybe_resolve_path(&p_arg.path, generics) {
					if !self.is_primitive(&resolved) {
						assert!(!is_ref); // We don't currently support outer reference types for non-primitive inners
					}
				} else {
					assert!(!is_ref); // We don't currently support outer reference types for non-primitive inners
				}
				if !self.write_c_type_intern(w, t, generics, false, false, false) { return false; }
			} else {
				assert!(!is_ref); // We don't currently support outer reference types for non-primitive inners
				if !self.write_c_type_intern(w, t, generics, false, false, false) { return false; }
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
		if !self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a)) {
			write!(w, "C{}_", ident).unwrap();
			write!(mangled_type, "C{}_", ident).unwrap();
		} else { assert_eq!(args.len(), 1); }
		for arg in args.iter() {
			macro_rules! write_path {
				($p_arg: expr, $extra_write: expr) => {
					if let Some(subtype) = self.maybe_resolve_path(&$p_arg.path, generics) {
						if self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a)) {
							if !in_type {
								if self.c_type_has_inner_from_path(&subtype) {
									if !self.write_c_path_intern(w, &$p_arg.path, generics, is_ref, is_mut, ptr_for_ref) { return false; }
								} else {
									if let Some(arr_ty) = self.is_real_type_array(&subtype) {
										if !self.write_c_type_intern(w, &arr_ty, generics, false, true, false) { return false; }
									} else {
										// Option<T> needs to be converted to a *mut T, ie mut ptr-for-ref
										if !self.write_c_path_intern(w, &$p_arg.path, generics, true, true, true) { return false; }
									}
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
			if let syn::Type::Tuple(tuple) = arg {
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
			} else if let syn::Type::Path(p_arg) = arg {
				write_path!(p_arg, None);
			} else if let syn::Type::Reference(refty) = arg {
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
			} else if let syn::Type::Array(a) = arg {
				if let syn::Type::Path(p_arg) = &*a.elem {
					let resolved = self.resolve_path(&p_arg.path, generics);
					if !self.is_primitive(&resolved) { return false; }
					if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(len), .. }) = &a.len {
						if self.c_type_from_path(&format!("[{}; {}]", resolved, len.base10_digits()), is_ref, ptr_for_ref).is_none() { return false; }
						write!(w, "_{}{}", resolved, len.base10_digits()).unwrap();
						write!(mangled_type, "_{}{}", resolved, len.base10_digits()).unwrap();
					} else { return false; }
				} else { return false; }
			} else { return false; }
		}
		if self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a)) { return true; }
		// Push the "end of type" Z
		write!(w, "Z").unwrap();
		write!(mangled_type, "Z").unwrap();

		// Make sure the type is actually defined:
		self.check_create_container(String::from_utf8(mangled_type).unwrap(), ident, args, generics, is_ref)
	}
	fn write_c_mangled_container_path<W: std::io::Write>(&self, w: &mut W, args: Vec<&syn::Type>, generics: Option<&GenericTypes>, ident: &str, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		if !self.is_transparent_container(ident, is_ref, args.iter().map(|a| *a)) {
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

	fn write_c_path_intern<W: std::io::Write>(&self, w: &mut W, path: &syn::Path, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		let full_path = match self.maybe_resolve_path(&path, generics) {
			Some(path) => path, None => return false };
		if let Some(c_type) = self.c_type_from_path(&full_path, is_ref, ptr_for_ref) {
			write!(w, "{}", c_type).unwrap();
			true
		} else if self.crate_types.traits.get(&full_path).is_some() {
			if is_ref && ptr_for_ref {
				write!(w, "*{} crate::{}", if is_mut { "mut" } else { "const" }, full_path).unwrap();
			} else if is_ref {
				write!(w, "&{}crate::{}", if is_mut { "mut " } else { "" }, full_path).unwrap();
			} else {
				write!(w, "crate::{}", full_path).unwrap();
			}
			true
		} else if self.crate_types.opaques.get(&full_path).is_some() || self.crate_types.mirrored_enums.get(&full_path).is_some() {
			if is_ref && ptr_for_ref {
				// ptr_for_ref implies we're returning the object, which we can't really do for
				// opaque or mirrored types without box'ing them, which is quite a waste, so return
				// the actual object itself (for opaque types we'll set the pointer to the actual
				// type and note that its a reference).
				write!(w, "crate::{}", full_path).unwrap();
			} else if is_ref {
				write!(w, "&{}crate::{}", if is_mut { "mut " } else { "" }, full_path).unwrap();
			} else {
				write!(w, "crate::{}", full_path).unwrap();
			}
			true
		} else {
			false
		}
	}
	fn write_c_type_intern<W: std::io::Write>(&self, w: &mut W, t: &syn::Type, generics: Option<&GenericTypes>, is_ref: bool, is_mut: bool, ptr_for_ref: bool) -> bool {
		match t {
			syn::Type::Path(p) => {
				if p.qself.is_some() {
					return false;
				}
				if let Some(full_path) = self.maybe_resolve_path(&p.path, generics) {
					if self.is_known_container(&full_path, is_ref) || self.is_path_transparent_container(&p.path, generics, is_ref) {
						return self.write_c_mangled_container_path(w, Self::path_to_generic_args(&p.path), generics, &full_path, is_ref, is_mut, ptr_for_ref);
					}
					if let Some(aliased_type) = self.crate_types.type_aliases.get(&full_path).cloned() {
						return self.write_c_type_intern(w, &aliased_type, None, is_ref, is_mut, ptr_for_ref);
					}
				}
				self.write_c_path_intern(w, &p.path, generics, is_ref, is_mut, ptr_for_ref)
			},
			syn::Type::Reference(r) => {
				self.write_c_type_intern(w, &*r.elem, generics, true, r.mutability.is_some(), ptr_for_ref)
			},
			syn::Type::Array(a) => {
				if is_ref && is_mut {
					write!(w, "*mut [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref) { return false; }
				} else if is_ref {
					write!(w, "*const [").unwrap();
					if !self.write_c_type_intern(w, &a.elem, generics, false, false, ptr_for_ref) { return false; }
				} else {
					let mut typecheck = Vec::new();
					if !self.write_c_type_intern(&mut typecheck, &a.elem, generics, false, false, ptr_for_ref) { return false; }
					if typecheck[..] != ['u' as u8, '8' as u8] { return false; }
				}
				if let syn::Expr::Lit(l) = &a.len {
					if let syn::Lit::Int(i) = &l.lit {
						if !is_ref {
							if let Some(ty) = self.c_type_from_path(&format!("[u8; {}]", i.base10_digits()), false, ptr_for_ref) {
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
					} else { false }
				} else if let syn::Type::Reference(r) = &*s.elem {
					if let syn::Type::Path(p) = &*r.elem {
						// Slices with "real types" inside are mapped as the equivalent non-ref Vec
						let resolved = self.resolve_path(&p.path, generics);
						let mangled_container = if let Some(ident) = self.crate_types.opaques.get(&resolved) {
							format!("CVec_{}Z", ident)
						} else if let Some(en) = self.crate_types.mirrored_enums.get(&resolved) {
							format!("CVec_{}Z", en.ident)
						} else if let Some(id) = p.path.get_ident() {
							format!("CVec_{}Z", id)
						} else { return false; };
						write!(w, "{}::{}", Self::generated_container_path(), mangled_container).unwrap();
						self.check_create_container(mangled_container, "Vec", vec![&*r.elem], generics, false)
					} else { false }
				} else if let syn::Type::Tuple(_) = &*s.elem {
					let mut args = syn::punctuated::Punctuated::<_, syn::token::Comma>::new();
					args.push(syn::GenericArgument::Type((*s.elem).clone()));
					let mut segments = syn::punctuated::Punctuated::new();
					segments.push(parse_quote!(Vec<#args>));
					self.write_c_type_intern(w, &syn::Type::Path(syn::TypePath { qself: None, path: syn::Path { leading_colon: None, segments } }), generics, false, is_mut, ptr_for_ref)
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
		assert!(self.write_c_type_intern(w, t, generics, false, false, ptr_for_ref));
	}
	pub fn understood_c_path(&self, p: &syn::Path) -> bool {
		if p.leading_colon.is_some() { return false; }
		self.write_c_path_intern(&mut std::io::sink(), p, None, false, false, false)
	}
	pub fn understood_c_type(&self, t: &syn::Type, generics: Option<&GenericTypes>) -> bool {
		self.write_c_type_intern(&mut std::io::sink(), t, generics, false, false, false)
	}
}
