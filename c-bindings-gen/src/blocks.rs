// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE>
// or the MIT license <LICENSE-MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Printing logic for basic blocks of Rust-mapped code - parts of functions and declarations but
//! not the full mapping logic.

use std::fs::File;
use std::io::Write;

use proc_macro2::TokenTree;
use quote::format_ident;

use crate::types::*;

/// Writes out a C++ wrapper class for the given type, which contains various utilities to access
/// the underlying C-mapped type safely avoiding some common memory management issues by handling
/// resource-freeing and prevending accidental raw copies.
pub fn write_cpp_wrapper(cpp_header_file: &mut File, ty: &str, has_destructor: bool, trait_methods: Option<Vec<(String, String)>>) {
	writeln!(cpp_header_file, "class {} {{", ty).unwrap();
	writeln!(cpp_header_file, "private:").unwrap();
	writeln!(cpp_header_file, "\tLDK{} self;", ty).unwrap();
	writeln!(cpp_header_file, "public:").unwrap();
	writeln!(cpp_header_file, "\t{}(const {}&) = delete;", ty, ty).unwrap();
	writeln!(cpp_header_file, "\t{}({}&& o) : self(o.self) {{ memset(&o, 0, sizeof({})); }}", ty, ty, ty).unwrap();
	writeln!(cpp_header_file, "\t{}(LDK{}&& m_self) : self(m_self) {{ memset(&m_self, 0, sizeof(LDK{})); }}", ty, ty, ty).unwrap();
	writeln!(cpp_header_file, "\toperator LDK{}() && {{ LDK{} res = self; memset(&self, 0, sizeof(LDK{})); return res; }}", ty, ty, ty).unwrap();
	if has_destructor {
		writeln!(cpp_header_file, "\t~{}() {{ {}_free(self); }}", ty, ty).unwrap();
		writeln!(cpp_header_file, "\t{}& operator=({}&& o) {{ {}_free(self); self = o.self; memset(&o, 0, sizeof({})); return *this; }}", ty, ty, ty, ty).unwrap();
	} else {
		writeln!(cpp_header_file, "\t{}& operator=({}&& o) {{ self = o.self; memset(&o, 0, sizeof({})); return *this; }}", ty, ty, ty).unwrap();
	}
	writeln!(cpp_header_file, "\tLDK{}* operator &() {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tLDK{}* operator ->() {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tconst LDK{}* operator &() const {{ return &self; }}", ty).unwrap();
	writeln!(cpp_header_file, "\tconst LDK{}* operator ->() const {{ return &self; }}", ty).unwrap();
	if let Some(methods) = trait_methods {
		for (meth_name, meth_docs) in methods {
			cpp_header_file.write_all(meth_docs.as_bytes()).unwrap();
			// Note that we have zero logic to print C/C__ code for a given function. Instead, we
			// simply use sed to replace the following in genbindings.sh
			writeln!(cpp_header_file, "XXX {} {}", ty, meth_name).unwrap();
		}
	}
	writeln!(cpp_header_file, "}};").unwrap();
}

/// Writes out a C-callable concrete Result<A, B> struct and utility methods
pub fn write_result_block<W: std::io::Write>(w: &mut W, mangled_container: &str, ok_type: &str, err_type: &str, clonable: bool) {
	writeln!(w, "#[repr(C)]").unwrap();
	writeln!(w, "/// The contents of {}", mangled_container).unwrap();
	writeln!(w, "pub union {}Ptr {{", mangled_container).unwrap();
	if ok_type != "()" {
		writeln!(w, "\t/// A pointer to the contents in the success state.").unwrap();
		writeln!(w, "\t/// Reading from this pointer when `result_ok` is not set is undefined.").unwrap();
		writeln!(w, "\tpub result: *mut {},", ok_type).unwrap();
	} else {
		writeln!(w, "\t/// Note that this value is always NULL, as there are no contents in the OK variant").unwrap();
		writeln!(w, "\tpub result: *mut std::ffi::c_void,").unwrap();
	}
	if err_type != "()" {
		writeln!(w, "\t/// A pointer to the contents in the error state.").unwrap();
		writeln!(w, "\t/// Reading from this pointer when `result_ok` is set is undefined.").unwrap();
		writeln!(w, "\tpub err: *mut {},", err_type).unwrap();
	} else {
		writeln!(w, "\t/// Note that this value is always NULL, as there are no contents in the Err variant").unwrap();
		writeln!(w, "\tpub err: *mut std::ffi::c_void,").unwrap();
	}
	writeln!(w, "}}").unwrap();
	writeln!(w, "#[repr(C)]").unwrap();
	writeln!(w, "/// A {} represents the result of a fallible operation,", mangled_container).unwrap();
	writeln!(w, "/// containing a {} on success and a {} on failure.", ok_type, err_type).unwrap();
	writeln!(w, "/// `result_ok` indicates the overall state, and the contents are provided via `contents`.").unwrap();
	writeln!(w, "pub struct {} {{", mangled_container).unwrap();
	writeln!(w, "\t/// The contents of this {}, accessible via either", mangled_container).unwrap();
	writeln!(w, "\t/// `err` or `result` depending on the state of `result_ok`.").unwrap();
	writeln!(w, "\tpub contents: {}Ptr,", mangled_container).unwrap();
	writeln!(w, "\t/// Whether this {} represents a success state.", mangled_container).unwrap();
	writeln!(w, "\tpub result_ok: bool,").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	if ok_type != "()" {
		writeln!(w, "/// Creates a new {} in the success state.", mangled_container).unwrap();
		writeln!(w, "pub extern \"C\" fn {}_ok(o: {}) -> {} {{", mangled_container, ok_type, mangled_container).unwrap();
	} else {
		writeln!(w, "/// Creates a new {} in the success state.", mangled_container).unwrap();
		writeln!(w, "pub extern \"C\" fn {}_ok() -> {} {{", mangled_container, mangled_container).unwrap();
	}
	writeln!(w, "\t{} {{", mangled_container).unwrap();
	writeln!(w, "\t\tcontents: {}Ptr {{", mangled_container).unwrap();
	if ok_type != "()" {
		writeln!(w, "\t\t\tresult: Box::into_raw(Box::new(o)),").unwrap();
	} else {
		writeln!(w, "\t\t\tresult: std::ptr::null_mut(),").unwrap();
	}
	writeln!(w, "\t\t}},").unwrap();
	writeln!(w, "\t\tresult_ok: true,").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	if err_type != "()" {
		writeln!(w, "/// Creates a new {} in the error state.", mangled_container).unwrap();
		writeln!(w, "pub extern \"C\" fn {}_err(e: {}) -> {} {{", mangled_container, err_type, mangled_container).unwrap();
	} else {
		writeln!(w, "/// Creates a new {} in the error state.", mangled_container).unwrap();
		writeln!(w, "pub extern \"C\" fn {}_err() -> {} {{", mangled_container, mangled_container).unwrap();
	}
	writeln!(w, "\t{} {{", mangled_container).unwrap();
	writeln!(w, "\t\tcontents: {}Ptr {{", mangled_container).unwrap();
	if err_type != "()" {
		writeln!(w, "\t\t\terr: Box::into_raw(Box::new(e)),").unwrap();
	} else {
		writeln!(w, "\t\t\terr: std::ptr::null_mut(),").unwrap();
	}
	writeln!(w, "\t\t}},").unwrap();
	writeln!(w, "\t\tresult_ok: false,").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Frees any resources used by the {}.", mangled_container).unwrap();
	writeln!(w, "pub extern \"C\" fn {}_free(_res: {}) {{ }}", mangled_container, mangled_container).unwrap();
	writeln!(w, "impl Drop for {} {{", mangled_container).unwrap();
	writeln!(w, "\tfn drop(&mut self) {{").unwrap();
	writeln!(w, "\t\tif self.result_ok {{").unwrap();
	if ok_type != "()" {
		writeln!(w, "\t\t\tif unsafe {{ !(self.contents.result as *mut ()).is_null() }} {{").unwrap();
		writeln!(w, "\t\t\t\tlet _ = unsafe {{ Box::from_raw(self.contents.result) }};").unwrap();
		writeln!(w, "\t\t\t}}").unwrap();
	}
	writeln!(w, "\t\t}} else {{").unwrap();
	if err_type != "()" {
		writeln!(w, "\t\t\tif unsafe {{ !(self.contents.err as *mut ()).is_null() }} {{").unwrap();
		writeln!(w, "\t\t\t\tlet _ = unsafe {{ Box::from_raw(self.contents.err) }};").unwrap();
		writeln!(w, "\t\t\t}}").unwrap();
	}
	writeln!(w, "\t\t}}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "impl From<crate::c_types::CResultTempl<{}, {}>> for {} {{", ok_type, err_type, mangled_container).unwrap();
	writeln!(w, "\tfn from(mut o: crate::c_types::CResultTempl<{}, {}>) -> Self {{", ok_type, err_type).unwrap();
	writeln!(w, "\t\tlet contents = if o.result_ok {{").unwrap();
	if ok_type != "()" {
		writeln!(w, "\t\t\tlet result = unsafe {{ o.contents.result }};").unwrap();
		writeln!(w, "\t\t\tunsafe {{ o.contents.result = std::ptr::null_mut() }};").unwrap();
		writeln!(w, "\t\t\t{}Ptr {{ result }}", mangled_container).unwrap();
	} else {
		writeln!(w, "\t\t\tlet _ = unsafe {{ Box::from_raw(o.contents.result) }};").unwrap();
		writeln!(w, "\t\t\to.contents.result = std::ptr::null_mut();").unwrap();
		writeln!(w, "\t\t\t{}Ptr {{ result: std::ptr::null_mut() }}", mangled_container).unwrap();
	}
	writeln!(w, "\t\t}} else {{").unwrap();
	if err_type != "()" {
		writeln!(w, "\t\t\tlet err = unsafe {{ o.contents.err }};").unwrap();
		writeln!(w, "\t\t\tunsafe {{ o.contents.err = std::ptr::null_mut(); }}").unwrap();
		writeln!(w, "\t\t\t{}Ptr {{ err }}", mangled_container).unwrap();
	} else {
		writeln!(w, "\t\t\tlet _ = unsafe {{ Box::from_raw(o.contents.err) }};").unwrap();
		writeln!(w, "\t\t\to.contents.err = std::ptr::null_mut();").unwrap();
		writeln!(w, "\t\t\t{}Ptr {{ err: std::ptr::null_mut() }}", mangled_container).unwrap();
	}
	writeln!(w, "\t\t}};").unwrap();
	writeln!(w, "\t\tSelf {{").unwrap();
	writeln!(w, "\t\t\tcontents,").unwrap();
	writeln!(w, "\t\t\tresult_ok: o.result_ok,").unwrap();
	writeln!(w, "\t\t}}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	if clonable {
		writeln!(w, "impl Clone for {} {{", mangled_container).unwrap();
		writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
		writeln!(w, "\t\tif self.result_ok {{").unwrap();
		writeln!(w, "\t\t\tSelf {{ result_ok: true, contents: {}Ptr {{", mangled_container).unwrap();
		if ok_type != "()" {
			writeln!(w, "\t\t\t\tresult: Box::into_raw(Box::new(<{}>::clone(unsafe {{ &*self.contents.result }})))", ok_type).unwrap();
		} else {
			writeln!(w, "\t\t\t\tresult: std::ptr::null_mut()").unwrap();
		}
		writeln!(w, "\t\t\t}} }}").unwrap();
		writeln!(w, "\t\t}} else {{").unwrap();
		writeln!(w, "\t\t\tSelf {{ result_ok: false, contents: {}Ptr {{", mangled_container).unwrap();
		if err_type != "()" {
			writeln!(w, "\t\t\t\terr: Box::into_raw(Box::new(<{}>::clone(unsafe {{ &*self.contents.err }})))", err_type).unwrap();
		} else {
			writeln!(w, "\t\t\t\terr: std::ptr::null_mut()").unwrap();
		}
		writeln!(w, "\t\t\t}} }}").unwrap();
		writeln!(w, "\t\t}}").unwrap();
		writeln!(w, "\t}}").unwrap();
		writeln!(w, "}}").unwrap();
		writeln!(w, "#[no_mangle]").unwrap();
		writeln!(w, "/// Creates a new {} which has the same data as `orig`", mangled_container).unwrap();
		writeln!(w, "/// but with all dynamically-allocated buffers duplicated in new buffers.").unwrap();
		writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{ orig.clone() }}", mangled_container, mangled_container, mangled_container).unwrap();
	}
}

/// Writes out a C-callable concrete Vec<A> struct and utility methods
pub fn write_vec_block<W: std::io::Write>(w: &mut W, mangled_container: &str, inner_type: &str, clonable: bool) {
	writeln!(w, "#[repr(C)]").unwrap();
	writeln!(w, "/// A dynamically-allocated array of {}s of arbitrary size.", inner_type).unwrap();
	writeln!(w, "/// This corresponds to std::vector in C++").unwrap();
	writeln!(w, "pub struct {} {{", mangled_container).unwrap();
	writeln!(w, "\t/// The elements in the array.").unwrap();
	writeln!(w, "\t/// If datalen is non-0 this must be a valid, non-NULL pointer allocated by malloc().").unwrap();
	writeln!(w, "\tpub data: *mut {},", inner_type).unwrap();
	writeln!(w, "\t/// The number of elements pointed to by `data`.").unwrap();
	writeln!(w, "\tpub datalen: usize").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "impl {} {{", mangled_container).unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn into_rust(&mut self) -> Vec<{}> {{", inner_type).unwrap();
	writeln!(w, "\t\tif self.datalen == 0 {{ return Vec::new(); }}").unwrap();
	writeln!(w, "\t\tlet ret = unsafe {{ Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }}.into();").unwrap();
	writeln!(w, "\t\tself.data = std::ptr::null_mut();").unwrap();
	writeln!(w, "\t\tself.datalen = 0;").unwrap();
	writeln!(w, "\t\tret").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn as_slice(&self) -> &[{}] {{", inner_type).unwrap();
	writeln!(w, "\t\tunsafe {{ std::slice::from_raw_parts_mut(self.data, self.datalen) }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "impl From<Vec<{}>> for {} {{", inner_type, mangled_container).unwrap();
	writeln!(w, "\tfn from(v: Vec<{}>) -> Self {{", inner_type).unwrap();
	writeln!(w, "\t\tlet datalen = v.len();").unwrap();
	writeln!(w, "\t\tlet data = Box::into_raw(v.into_boxed_slice());").unwrap();
	writeln!(w, "\t\tSelf {{ datalen, data: unsafe {{ (*data).as_mut_ptr() }} }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Frees the buffer pointed to by `data` if `datalen` is non-0.").unwrap();
	writeln!(w, "pub extern \"C\" fn {}_free(_res: {}) {{ }}", mangled_container, mangled_container).unwrap();
	writeln!(w, "impl Drop for {} {{", mangled_container).unwrap();
	writeln!(w, "\tfn drop(&mut self) {{").unwrap();
	writeln!(w, "\t\tif self.datalen == 0 {{ return; }}").unwrap();
	writeln!(w, "\t\tunsafe {{ Box::from_raw(std::slice::from_raw_parts_mut(self.data, self.datalen)) }};").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();
	if clonable {
		writeln!(w, "impl Clone for {} {{", mangled_container).unwrap();
		writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
		writeln!(w, "\t\tlet mut res = Vec::new();").unwrap();
		writeln!(w, "\t\tif self.datalen == 0 {{ return Self::from(res); }}").unwrap();
		writeln!(w, "\t\tres.extend_from_slice(unsafe {{ std::slice::from_raw_parts_mut(self.data, self.datalen) }});").unwrap();
		writeln!(w, "\t\tSelf::from(res)").unwrap();
		writeln!(w, "\t}}").unwrap();
		writeln!(w, "}}").unwrap();
	}
}

/// Writes out a C-callable concrete (A, B, ...) struct and utility methods
pub fn write_tuple_block<W: std::io::Write>(w: &mut W, mangled_container: &str, types: &[String], clonable: bool) {
	writeln!(w, "#[repr(C)]").unwrap();
	writeln!(w, "/// A tuple of {} elements. See the individual fields for the types contained.", types.len()).unwrap();
	writeln!(w, "pub struct {} {{", mangled_container).unwrap();
	for (idx, ty) in types.iter().enumerate() {
		writeln!(w, "\t/// The element at position {}", idx).unwrap();
		writeln!(w, "\tpub {}: {},", ('a' as u8 + idx as u8) as char, ty).unwrap();
	}
	writeln!(w, "}}").unwrap();

	let mut tuple_str = "(".to_owned();
	for (idx, ty) in types.iter().enumerate() {
		if idx != 0 { tuple_str += ", "; }
		tuple_str += ty;
	}
	tuple_str += ")";

	writeln!(w, "impl From<{}> for {} {{", tuple_str, mangled_container).unwrap();
	writeln!(w, "\tfn from (tup: {}) -> Self {{", tuple_str).unwrap();
	writeln!(w, "\t\tSelf {{").unwrap();
	for idx in 0..types.len() {
		writeln!(w, "\t\t\t{}: tup.{},", ('a' as u8 + idx as u8) as char, idx).unwrap();
	}
	writeln!(w, "\t\t}}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();
	writeln!(w, "impl {} {{", mangled_container).unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn to_rust(mut self) -> {} {{", tuple_str).unwrap();
	write!(w, "\t\t(").unwrap();
	for idx in 0..types.len() {
		write!(w, "{}self.{}", if idx != 0 {", "} else {""}, ('a' as u8 + idx as u8) as char).unwrap();
	}
	writeln!(w, ")").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	if clonable {
		writeln!(w, "impl Clone for {} {{", mangled_container).unwrap();
		writeln!(w, "\tfn clone(&self) -> Self {{").unwrap();
		writeln!(w, "\t\tSelf {{").unwrap();
		for idx in 0..types.len() {
			writeln!(w, "\t\t\t{}: self.{}.clone(),", ('a' as u8 + idx as u8) as char, ('a' as u8 + idx as u8) as char).unwrap();
		}
		writeln!(w, "\t\t}}").unwrap();
		writeln!(w, "\t}}").unwrap();
		writeln!(w, "}}").unwrap();
		writeln!(w, "#[no_mangle]").unwrap();
		writeln!(w, "/// Creates a new tuple which has the same data as `orig`").unwrap();
		writeln!(w, "/// but with all dynamically-allocated buffers duplicated in new buffers.").unwrap();
		writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{ orig.clone() }}", mangled_container, mangled_container, mangled_container).unwrap();
	}

	writeln!(w, "/// Creates a new {} from the contained elements.", mangled_container).unwrap();
	write!(w, "#[no_mangle]\npub extern \"C\" fn {}_new(", mangled_container).unwrap();
	for (idx, gen) in types.iter().enumerate() {
		write!(w, "{}{}: ", if idx != 0 { ", " } else { "" }, ('a' as u8 + idx as u8) as char).unwrap();
		//if !self.write_c_type_intern(&mut created_container, gen, generics, false, false, false) { return false; }
		write!(w, "{}", gen).unwrap();
	}
	writeln!(w, ") -> {} {{", mangled_container).unwrap();
	write!(w, "\t{} {{ ", mangled_container).unwrap();
	for idx in 0..types.len() {
		write!(w, "{}, ", ('a' as u8 + idx as u8) as char).unwrap();
	}
	writeln!(w, "}}\n}}\n").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Frees any resources used by the {}.", mangled_container).unwrap();
	writeln!(w, "pub extern \"C\" fn {}_free(_res: {}) {{ }}", mangled_container, mangled_container).unwrap();
}

/// Writes out a C-callable concrete Option<A> struct and utility methods
pub fn write_option_block<W: std::io::Write>(w: &mut W, mangled_container: &str, inner_type: &str, clonable: bool) {
	writeln!(w, "#[repr(C)]").unwrap();
	if clonable {
		writeln!(w, "#[derive(Clone)]").unwrap();
	}
	writeln!(w, "/// An enum which can either contain a {} or not", inner_type).unwrap();
	writeln!(w, "pub enum {} {{", mangled_container).unwrap();
	writeln!(w, "\t/// When we're in this state, this {} contains a {}", mangled_container, inner_type).unwrap();
	writeln!(w, "\tSome({}),", inner_type).unwrap();
	writeln!(w, "\t/// When we're in this state, this {} contains nothing", mangled_container).unwrap();
	writeln!(w, "\tNone").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "impl {} {{", mangled_container).unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn is_some(&self) -> bool {{").unwrap();
	writeln!(w, "\t\tif let Self::Some(_) = self {{ true }} else {{ false }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn is_none(&self) -> bool {{").unwrap();
	writeln!(w, "\t\t!self.is_some()").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "\t#[allow(unused)] pub(crate) fn take(mut self) -> {} {{", inner_type).unwrap();
	writeln!(w, "\t\tif let Self::Some(v) = self {{ v }} else {{ unreachable!() }}").unwrap();
	writeln!(w, "\t}}").unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Constructs a new {} containing a {}", mangled_container, inner_type).unwrap();
	writeln!(w, "pub extern \"C\" fn {}_some(o: {}) -> {} {{", mangled_container, inner_type, mangled_container).unwrap();
	writeln!(w, "\t{}::Some(o)", mangled_container).unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Constructs a new {} containing nothing", mangled_container).unwrap();
	writeln!(w, "pub extern \"C\" fn {}_none() -> {} {{", mangled_container, mangled_container).unwrap();
	writeln!(w, "\t{}::None", mangled_container).unwrap();
	writeln!(w, "}}").unwrap();

	writeln!(w, "#[no_mangle]").unwrap();
	writeln!(w, "/// Frees any resources associated with the {}, if we are in the Some state", inner_type).unwrap();
	writeln!(w, "pub extern \"C\" fn {}_free(_res: {}) {{ }}", mangled_container, mangled_container).unwrap();
	if clonable {
		writeln!(w, "#[no_mangle]").unwrap();
		writeln!(w, "/// Creates a new {} which has the same data as `orig`", mangled_container).unwrap();
		writeln!(w, "/// but with all dynamically-allocated buffers duplicated in new buffers.").unwrap();
		writeln!(w, "pub extern \"C\" fn {}_clone(orig: &{}) -> {} {{ orig.clone() }}", mangled_container, mangled_container, mangled_container).unwrap();
	}
}

/// Prints the docs from a given attribute list unless its tagged no export
pub fn writeln_fn_docs<'a, W: std::io::Write, I>(w: &mut W, attrs: &[syn::Attribute], prefix: &str, types: &mut TypeResolver, generics: Option<&GenericTypes>, args: I, ret: &syn::ReturnType) where I: Iterator<Item = &'a syn::FnArg> {
	writeln_docs_impl(w, attrs, prefix, Some((types, generics,
		args.filter_map(|arg| if let syn::FnArg::Typed(ty) = arg {
				if let syn::Pat::Ident(id) = &*ty.pat {
					Some((id.ident.to_string(), &*ty.ty))
				} else { unimplemented!() }
			} else { None }),
		if let syn::ReturnType::Type(_, ty) = ret { Some(&**ty) } else { None },
		None
	)));
}

/// Prints the docs from a given attribute list unless its tagged no export
pub fn writeln_docs<W: std::io::Write>(w: &mut W, attrs: &[syn::Attribute], prefix: &str) {
	writeln_docs_impl(w, attrs, prefix, None::<(_, _, std::vec::Drain<'_, (String, &syn::Type)>, _, _)>);
}

pub fn writeln_arg_docs<'a, W: std::io::Write, I>(w: &mut W, attrs: &[syn::Attribute], prefix: &str, types: &mut TypeResolver, generics: Option<&GenericTypes>, args: I, ret: Option<&syn::Type>) where I: Iterator<Item = (String, &'a syn::Type)> {
	writeln_docs_impl(w, attrs, prefix, Some((types, generics, args, ret, None)))
}

pub fn writeln_field_docs<W: std::io::Write>(w: &mut W, attrs: &[syn::Attribute], prefix: &str, types: &mut TypeResolver, generics: Option<&GenericTypes>, field: &syn::Type) {
	writeln_docs_impl(w, attrs, prefix, Some((types, generics, vec![].drain(..), None, Some(field))))
}

/// Prints the docs from a given attribute list unless its tagged no export
fn writeln_docs_impl<'a, W: std::io::Write, I>(w: &mut W, attrs: &[syn::Attribute], prefix: &str, method_args_ret: Option<(&mut TypeResolver, Option<&GenericTypes>, I, Option<&syn::Type>, Option<&syn::Type>)>) where I: Iterator<Item = (String, &'a syn::Type)> {
	for attr in attrs.iter() {
		let tokens_clone = attr.tokens.clone();
		let mut token_iter = tokens_clone.into_iter();
		if let Some(token) = token_iter.next() {
			match token {
				TokenTree::Punct(c) if c.as_char() == '=' => {
					// syn gets '=' from '///' or '//!' as it is syntax for #[doc = ""]
				},
				TokenTree::Group(_) => continue, // eg #[derive()]
				_ => unimplemented!(),
			}
		} else { continue; }
		match attr.style {
			syn::AttrStyle::Inner(_) => {
				match token_iter.next().unwrap() {
					TokenTree::Literal(lit) => {
						// Drop the first and last chars from lit as they are always "
						let doc = format!("{}", lit);
						writeln!(w, "{}//!{}", prefix, &doc[1..doc.len() - 1]).unwrap();
					},
					_ => unimplemented!(),
				}
			},
			syn::AttrStyle::Outer => {
				match token_iter.next().unwrap() {
					TokenTree::Literal(lit) => {
						// Drop the first and last chars from lit as they are always "
						let doc = format!("{}", lit);
						writeln!(w, "{}///{}", prefix, &doc[1..doc.len() - 1]).unwrap();
					},
					_ => unimplemented!(),
				}
			},
		}
	}
	if let Some((types, generics, inp, outp, field)) = method_args_ret {
		let mut nullable_found = false;
		for (name, inp) in inp {
			if types.skip_arg(inp, generics) { continue; }
			if if let syn::Type::Reference(syn::TypeReference { elem, .. }) = inp {
				if let syn::Type::Path(syn::TypePath { ref path, .. }) = &**elem {
					types.is_path_transparent_container(path, generics, true)
				} else { false }
			} else if let syn::Type::Path(syn::TypePath { ref path, .. }) = inp {
				types.is_path_transparent_container(path, generics, true)
			} else { false } {
				// Note downstream clients match this text exactly so any changes may require
				// changes in the Java and Swift bindings, at least.
				if !nullable_found { writeln!(w, "{}///", prefix).unwrap(); }
				nullable_found = true;
				writeln!(w, "{}/// Note that {} (or a relevant inner pointer) may be NULL or all-0s to represent None", prefix, name).unwrap();
			}
		}
		if if let Some(syn::Type::Reference(syn::TypeReference { elem, .. })) = outp {
			if let syn::Type::Path(syn::TypePath { ref path, .. }) = &**elem {
				types.is_path_transparent_container(path, generics, true)
			} else { false }
		} else if let Some(syn::Type::Path(syn::TypePath { ref path, .. })) = outp {
			types.is_path_transparent_container(path, generics, true)
		} else { false } {
			// Note downstream clients match this text exactly so any changes may require
			// changes in the Java and Swift bindings, at least.
			if !nullable_found { writeln!(w, "{}///", prefix).unwrap(); }
			nullable_found = true;
			writeln!(w, "{}/// Note that the return value (or a relevant inner pointer) may be NULL or all-0s to represent None", prefix).unwrap();
		}
		if if let Some(syn::Type::Reference(syn::TypeReference { elem, .. })) = field {
			if let syn::Type::Path(syn::TypePath { ref path, .. }) = &**elem {
				types.is_path_transparent_container(path, generics, true)
			} else { false }
		} else if let Some(syn::Type::Path(syn::TypePath { ref path, .. })) = field {
			types.is_path_transparent_container(path, generics, true)
		} else { false } {
			// Note downstream clients match this text exactly so any changes may require
			// changes in the Java and Swift bindings, at least.
			if !nullable_found { writeln!(w, "{}///", prefix).unwrap(); }
			writeln!(w, "{}/// Note that this (or a relevant inner pointer) may be NULL or all-0s to represent None", prefix).unwrap();
		}
	}

}

/// Print the parameters in a method declaration, starting after the open parenthesis, through and
/// including the closing parenthesis and return value, but not including the open bracket or any
/// trailing semicolons.
///
/// Usable both for a function definition and declaration.
///
/// this_param is used when returning Self or accepting a self parameter, and should be the
/// concrete, mapped type.
pub fn write_method_params<W: std::io::Write>(w: &mut W, sig: &syn::Signature, this_param: &str, types: &mut TypeResolver, generics: Option<&GenericTypes>, self_ptr: bool, fn_decl: bool) {
	if sig.constness.is_some() || sig.asyncness.is_some() || sig.unsafety.is_some() ||
			sig.abi.is_some() || sig.variadic.is_some() {
		unimplemented!();
	}
	if sig.generics.lt_token.is_some() {
		for generic in sig.generics.params.iter() {
			match generic {
				syn::GenericParam::Type(_)|syn::GenericParam::Lifetime(_) => {
					// We ignore these, if they're not on skipped args, we'll blow up
					// later, and lifetimes we just hope the C client enforces.
				},
				_ => unimplemented!(),
			}
		}
	}

	let mut first_arg = true;
	let mut num_unused = 0;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(recv) => {
				if !recv.attrs.is_empty() { unimplemented!(); }
				write!(w, "{}this_arg: {}{}", if recv.reference.is_none() { "mut " } else { "" },
					if recv.reference.is_some() {
						match (self_ptr, recv.mutability.is_some()) {
							(true, true) => "*mut ",
							(true, false) => "*const ",
							(false, true) => "&mut ",
							(false, false) => "&",
						}
					} else { "" }, this_param).unwrap();
				assert!(first_arg);
				first_arg = false;
			},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) { continue; }
				if !arg.attrs.is_empty() { unimplemented!(); }
				// First get the c type so that we can check if it ends up being a reference:
				let mut c_type = Vec::new();
				types.write_c_type(&mut c_type, &*arg.ty, generics, false);
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write!(w, "{}{}{}: ", if first_arg { "" } else { ", " }, if !fn_decl || c_type[0] == '&' as u8 || c_type[0] == '*' as u8 { "" } else { "mut " }, ident.ident).unwrap();
						first_arg = false;
					},
					syn::Pat::Wild(wild) => {
						if !wild.attrs.is_empty() { unimplemented!(); }
						write!(w, "{}unused_{}: ", if first_arg { "" } else { ", " }, num_unused).unwrap();
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
				w.write(&c_type).unwrap();
			}
		}
	}
	write!(w, ")").unwrap();
	match &sig.output {
		syn::ReturnType::Type(_, rtype) => {
			write!(w, " -> ").unwrap();
			if let Some(mut remaining_path) = first_seg_self(&*rtype) {
				if remaining_path.next().is_none() {
					write!(w, "{}", this_param).unwrap();
					return;
				}
			}
			types.write_c_type(w, &*rtype, generics, true);
		},
		_ => {},
	}
}

/// Print the main part of a method declaration body, starting with a newline after the function
/// open bracket and converting each function parameter to or from C-mapped types. Ends with "let
/// mut ret = " assuming the next print will be the unmapped Rust function to call followed by the
/// parameters we mapped to/from C here.
pub fn write_method_var_decl_body<W: std::io::Write>(w: &mut W, sig: &syn::Signature, extra_indent: &str, types: &TypeResolver, generics: Option<&GenericTypes>, to_c: bool) {
	let mut num_unused = 0u32;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(_) => {},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) { continue; }
				if !arg.attrs.is_empty() { unimplemented!(); }
				macro_rules! write_new_var {
					($ident: expr, $ty: expr) => {
						if to_c {
							if types.write_to_c_conversion_new_var(w, &$ident, &$ty, generics, false) {
								write!(w, "\n\t{}", extra_indent).unwrap();
							}
						} else {
							if types.write_from_c_conversion_new_var(w, &$ident, &$ty, generics) {
								write!(w, "\n\t{}", extra_indent).unwrap();
							}
						}
					}
				}
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write_new_var!(ident.ident, *arg.ty);
					},
					syn::Pat::Wild(w) => {
						if !w.attrs.is_empty() { unimplemented!(); }
						write_new_var!(format_ident!("unused_{}", num_unused), *arg.ty);
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
			}
		}
	}
	match &sig.output {
		syn::ReturnType::Type(_, _) => {
			write!(w, "let mut ret = ").unwrap();
		},
		_ => {},
	}
}

/// Prints the parameters in a method call, starting after the open parenthesis and ending with a
/// final return statement returning the method's result. Should be followed by a single closing
/// bracket.
///
/// The return value is expected to be bound to a variable named `ret` which is available after a
/// method-call-ending semicolon.
pub fn write_method_call_params<W: std::io::Write>(w: &mut W, sig: &syn::Signature, extra_indent: &str, types: &TypeResolver, generics: Option<&GenericTypes>, this_type: &str, to_c: bool) {
	let mut first_arg = true;
	let mut num_unused = 0;
	for inp in sig.inputs.iter() {
		match inp {
			syn::FnArg::Receiver(recv) => {
				if !recv.attrs.is_empty() { unimplemented!(); }
				if to_c {
					if recv.reference.is_none() { unimplemented!(); }
					write!(w, "self.this_arg").unwrap();
					first_arg = false;
				}
			},
			syn::FnArg::Typed(arg) => {
				if types.skip_arg(&*arg.ty, generics) {
					if !to_c {
						if !first_arg {
							write!(w, ", ").unwrap();
						}
						first_arg = false;
						types.no_arg_to_rust(w, &*arg.ty, generics);
					}
					continue;
				}
				if !arg.attrs.is_empty() { unimplemented!(); }
				macro_rules! write_ident {
					($ident: expr) => {
						if !first_arg {
							write!(w, ", ").unwrap();
						}
						first_arg = false;
						if to_c {
							types.write_to_c_conversion_inline_prefix(w, &*arg.ty, generics, false);
							write!(w, "{}", $ident).unwrap();
							types.write_to_c_conversion_inline_suffix(w, &*arg.ty, generics, false);
						} else {
							types.write_from_c_conversion_prefix(w, &*arg.ty, generics);
							write!(w, "{}", $ident).unwrap();
							types.write_from_c_conversion_suffix(w, &*arg.ty, generics);
						}
					}
				}
				match &*arg.pat {
					syn::Pat::Ident(ident) => {
						if !ident.attrs.is_empty() || ident.subpat.is_some() {
							unimplemented!();
						}
						write_ident!(ident.ident);
					},
					syn::Pat::Wild(w) => {
						if !w.attrs.is_empty() { unimplemented!(); }
						write_ident!(format!("unused_{}", num_unused));
						num_unused += 1;
					},
					_ => unimplemented!(),
				}
			}
		}
	}
	write!(w, ")").unwrap();
	match &sig.output {
		syn::ReturnType::Type(_, rtype) => {
			write!(w, ";\n\t{}", extra_indent).unwrap();

			let self_segs_iter = first_seg_self(&*rtype);
			if to_c && first_seg_self(&*rtype).is_some() {
				// Assume rather blindly that we're returning an associated trait from a C fn call to a Rust trait object.
				write!(w, "ret").unwrap();
			} else if !to_c && self_segs_iter.is_some() && self_segs_iter.unwrap().next().is_none() {
				// If we're returning "Self" (and not "Self::X"), just do it manually
				write!(w, "{} {{ inner: ObjOps::heap_alloc(ret), is_owned: true }}", this_type).unwrap();
			} else if to_c {
				let new_var = types.write_from_c_conversion_new_var(w, &format_ident!("ret"), rtype, generics);
				if new_var {
					write!(w, "\n\t{}", extra_indent).unwrap();
				}
				types.write_from_c_conversion_prefix(w, &*rtype, generics);
				write!(w, "ret").unwrap();
				types.write_from_c_conversion_suffix(w, &*rtype, generics);
			} else {
				let new_var = types.write_to_c_conversion_new_var(w, &format_ident!("ret"), &rtype, generics, true);
				if new_var {
					write!(w, "\n\t{}", extra_indent).unwrap();
				}
				types.write_to_c_conversion_inline_prefix(w, &rtype, generics, true);
				write!(w, "ret").unwrap();
				types.write_to_c_conversion_inline_suffix(w, &rtype, generics, true);
			}
		}
		_ => {},
	}
}

/// Prints concrete generic parameters for a struct/trait/function, including the less-than and
/// greater-than symbols, if any generic parameters are defined.
pub fn maybe_write_generics<W: std::io::Write>(w: &mut W, generics: &syn::Generics, types: &TypeResolver, concrete_lifetimes: bool) {
	let mut gen_types = GenericTypes::new(None);
	assert!(gen_types.learn_generics(generics, types));
	if !generics.params.is_empty() {
		write!(w, "<").unwrap();
		for (idx, generic) in generics.params.iter().enumerate() {
			match generic {
				syn::GenericParam::Type(type_param) => {
					let mut printed_param = false;
					for bound in type_param.bounds.iter() {
						if let syn::TypeParamBound::Trait(trait_bound) = bound {
							assert_simple_bound(&trait_bound);
							write!(w, "{}crate::{}", if idx != 0 { ", " } else { "" }, gen_types.maybe_resolve_ident(&type_param.ident).unwrap()).unwrap();
							if printed_param {
								unimplemented!("Can't print generic params that have multiple non-lifetime bounds");
							}
							printed_param = true;
						}
					}
				},
				syn::GenericParam::Lifetime(lt) => {
					if concrete_lifetimes {
						write!(w, "'static").unwrap();
					} else {
						write!(w, "{}'{}", if idx != 0 { ", " } else { "" }, lt.lifetime.ident).unwrap();
					}
				},
				_ => unimplemented!(),
			}
		}
		write!(w, ">").unwrap();
	}
}


