use cranelift::prelude::*;
use cranelift_codegen::ir::*;
use cranelift_codegen::isa::CallConv;
use cranelift_module::{DataContext, DataId, FuncId, Linkage, Module};
use cranelift_object::{ObjectBuilder, ObjectModule};
use libc::c_char;
use std::boxed::Box;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::slice;
use std::str::FromStr;
use target_lexicon::*;

pub struct ModuleData {
    builder_ctx: FunctionBuilderContext,
    ctx: codegen::Context,
    data_ctx: DataContext,
    module: Option<ObjectModule>,
    userdata: usize,
    error_callback: Option<fn(userdata: usize, *const c_char, *const c_char) -> ()>,
    message_callback: Option<fn(userdata: usize, *const c_char, *const c_char) -> ()>,
}
pub struct FunctionData<'a> {
    variable_counter: u32,
    builder: FunctionBuilder<'a>,
    module: &'a mut ObjectModule,
}

impl ModuleData {
    fn emit_error(&self, err: &dyn Display, filename: Option<&str>) {
        let error = err.to_string();
        if let Some(cb) = &self.error_callback {
            cb(
                self.userdata,
                CString::new(error).unwrap().as_ptr() as *const c_char,
                filename.unwrap_or("").as_ptr() as *const c_char,
            );
        }
    }

    fn emit_error_string(&self, err: &str, filename: Option<&str>) {
        if let Some(cb) = &self.error_callback {
            cb(
                self.userdata,
                err.as_ptr() as *const c_char,
                filename.unwrap_or("").as_ptr() as *const c_char,
            );
        }
    }

    fn emit_message_string(&self, err: &str, filename: Option<&str>) {
        if let Some(cb) = &self.message_callback {
            cb(
                self.userdata,
                err.as_ptr() as *const c_char,
                filename.unwrap_or("").as_ptr() as *const c_char,
            );
        }
    }
}

#[no_mangle]
pub extern "C" fn cranelift_module_new(
    target_triple: *const c_char,
    flags: *const c_char,
    name: *const c_char,
    userdata: usize,
    error_cb: Option<fn(userdata: usize, *const c_char, *const c_char) -> ()>,
    message_cb: Option<fn(userdata: usize, *const c_char, *const c_char) -> ()>,
) -> *mut ModuleData {
    let mut flag_builder = settings::builder();
    let trip: &str = unsafe { CStr::from_ptr(target_triple) }.to_str().unwrap();
    let flag: &str = unsafe { CStr::from_ptr(flags) }.to_str().unwrap();
    let name_str: &str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();
    let triple = triple!(trip);
    let isa_builder = isa::lookup(triple).unwrap();

    for s in flag.split(',') {
        if !s.is_empty() {
            let n = s.find(',');
            if n.is_none() {
                let res = flag_builder.enable(s);
                if res.is_err() && error_cb.is_some() {
                    let dd: &dyn Display = &res.err().unwrap();
                    error_cb.unwrap()(
                        userdata,
                        CString::new(dd.to_string()).unwrap().as_ptr() as *const c_char,
                        std::ptr::null::<c_char>(),
                    );
                    return std::ptr::null_mut::<ModuleData>();
                }
                res.unwrap();
            } else {
                let args = s.split_at(n.unwrap());
                let res = flag_builder.set(args.0, args.1);
                if res.is_err() && error_cb.is_some() {
                    let dd: &dyn Display = &res.err().unwrap();
                    let dd_str = CString::new(dd.to_string()).unwrap();
                    error_cb.unwrap()(
                        userdata,
                        dd_str.as_ptr() as *const c_char,
                        std::ptr::null::<c_char>(),
                    );
                    return std::ptr::null_mut::<ModuleData>();
                }
                res.unwrap();
            }
        }
    }

    let isa = isa_builder
        .finish(settings::Flags::new(flag_builder))
        .unwrap();

    let builder = ObjectBuilder::new(
        isa,
        name_str.to_owned(),
        cranelift_module::default_libcall_names(),
    )
    .unwrap();

    let module = ObjectModule::new(builder);
    Box::into_raw(Box::new(ModuleData {
        builder_ctx: FunctionBuilderContext::new(),
        ctx: module.make_context(),
        data_ctx: DataContext::new(),
        module: Some(module),
        userdata,
        message_callback: message_cb,
        error_callback: error_cb,
    }))
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CraneliftLinkage {
    Import = 0,
    Local = 1,
    Preemptible = 2,
    Hidden = 3,
    Export = 4,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CraneliftDataFlags {
    None = 0,
    TLS = 1,
    Writable = 2,
}

fn convert_linkage(l: CraneliftLinkage) -> Linkage {
    match l {
        CraneliftLinkage::Export => Linkage::Export,
        CraneliftLinkage::Import => Linkage::Import,
        CraneliftLinkage::Local => Linkage::Local,
        CraneliftLinkage::Preemptible => Linkage::Preemptible,
        CraneliftLinkage::Hidden => Linkage::Hidden,
    }
}

#[no_mangle]
pub extern "C" fn cranelift_define_data(
    ptr: *mut ModuleData,
    name: *const c_char,
    linkage: CraneliftLinkage,
    data_flags: CraneliftDataFlags,
    _align: u8,
    id: *mut u32,
) -> bool {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let real_name: &str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();

    let intid = inst.module.as_mut().unwrap().declare_data(
        real_name,
        convert_linkage(linkage),
        CraneliftDataFlags::Writable as i32 & data_flags as i32 != 0,
        CraneliftDataFlags::TLS as i32 & data_flags as i32 != 0,
    );

    if intid.is_err() {
        inst.emit_error(&intid.err().unwrap(), None);
        return false;
    }
    unsafe {
        *id = intid.unwrap().as_u32();
    }
    true
}

#[no_mangle]
pub extern "C" fn cranelift_declare_function(
    ptr: *mut ModuleData,
    name: *const c_char,
    linkage: CraneliftLinkage,
    id: *mut u32,
) -> bool {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let real_name: &str = unsafe { CStr::from_ptr(name) }.to_str().unwrap();

    let intid = inst.module.as_mut().unwrap().declare_function(
        real_name,
        convert_linkage(linkage),
        &mut inst.ctx.func.signature,
    );

    if intid.is_err() {
        inst.emit_error(&intid.err().unwrap(), None);
        return false;
    }
    unsafe {
        *id = intid.unwrap().as_u32();
    }
    true
}

#[no_mangle]
pub extern "C" fn cranelift_define_function(ptr: *mut ModuleData, func: u32) -> i32 {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let res = inst
        .module
        .as_mut()
        .unwrap()
        .define_function(FuncId::from_u32(func), &mut inst.ctx);
    if res.is_err() {
        inst.emit_error(&res.err().unwrap(), None);
        return -1;
    }
    res.unwrap().size as i32
}

#[no_mangle]
pub extern "C" fn cranelift_set_data_value(
    ptr: *mut ModuleData,
    content: *const u8,
    length: i32,
) -> bool {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    if content.is_null() {
        inst.data_ctx.define_zeroinit(length as usize);
    } else {
        //let data = Vec::from_raw_parts(content, length as usize, length as usize);
        let data = unsafe { slice::from_raw_parts(content, length as usize).to_vec() };
        inst.data_ctx.define(data.into_boxed_slice());
    }
    true
}

#[no_mangle]
pub extern "C" fn cranelift_set_data_section(
    ptr: *mut ModuleData,
    seg: *const c_char,
    sec: *const c_char,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let real_seg: &str = unsafe { CStr::from_ptr(seg) }.to_str().unwrap();
    let real_sec: &str = unsafe { CStr::from_ptr(sec) }.to_str().unwrap();

    inst.data_ctx.set_segment_section(real_seg, real_sec);
}

#[no_mangle]
pub extern "C" fn cranelift_clear_data(ptr: *mut ModuleData) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.data_ctx.clear();
}

#[no_mangle]
pub extern "C" fn cranelift_write_function_in_data(
    ptr: *mut ModuleData,
    target_id: u32,
    _offset: u32,
    source_id: u32,
    data_ctx: &mut DataContext,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let _gv = inst
        .module
        .as_mut()
        .unwrap()
        .declare_func_in_data(FuncId::from_u32(source_id), &mut inst.data_ctx);
    inst.module
        .as_mut()
        .unwrap()
        .declare_func_in_data(FuncId::from_u32(target_id), data_ctx);
}

#[no_mangle]
pub extern "C" fn cranelift_assign_data_to_global(ptr: *mut ModuleData, id: u32) -> bool {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let res = inst
        .module
        .as_mut()
        .unwrap()
        .define_data(DataId::from_u32(id), &inst.data_ctx);
    if res.is_err() {
        inst.emit_error(&res.err().unwrap(), None);
        return false;
    }
    inst.data_ctx.clear();
    true
}

#[no_mangle]
pub extern "C" fn cranelift_module_emit_object(
    ptr: *mut ModuleData,
    filename: *const c_char,
) -> bool {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let product = inst.module.take().unwrap().finish();
    let filenamestr: &str = unsafe { CStr::from_ptr(filename) }.to_str().unwrap();

    if cfg!(debug_assertions) {
        inst.emit_message_string(&format!("Emitting object file {}", filenamestr)[..], None)
    }

    let file = File::create(filenamestr);
    if file.is_err() {
        inst.emit_error(&file.err().unwrap(), Some(filenamestr));
        return false;
    }

    let data = product.emit();
    if data.is_err() {
        inst.emit_error(&data.err().unwrap(), Some(filenamestr));
        return false;
    }

    let write_err = file.unwrap().write(&data.unwrap());
    if write_err.is_err() {
        {
            inst.emit_error(&write_err.err().unwrap(), Some(filenamestr));
            return false;
        }
    }

    if cfg!(debug_assertions) {
        inst.emit_message_string(
            &format!("Done emitting object file {}", filenamestr)[..],
            None,
        )
    }

    true
}

#[no_mangle]
pub extern "C" fn cranelift_module_delete(ptr: *mut ModuleData) {
    if !ptr.is_null() {
        unsafe {
            Box::from_raw(ptr);
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CraneliftCallConv {
    CraneliftCallConvDefault = 0xffffffff,
    CraneliftCallConvFast = 0,
    CraneliftCallConvCold = 1,
    CraneliftCallConvSystemV = 2,
    CraneliftCallConvWindowsFastcall = 3,
    CraneliftCallConvBaldrdashSystemV = 4,
    CraneliftCallConvBaldrdashWindows = 5,
    CraneliftCallConvProbestack = 6,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CraneliftIntCC {
    CraneliftIntCCEqual = 0,
    CraneliftIntCCNotEqual = 1,
    CraneliftIntCCSignedLessThan = 2,
    CraneliftIntCCSignedGreaterThanOrEqual = 3,
    CraneliftIntCCSignedGreaterThan = 4,
    CraneliftIntCCSignedLessThanOrEqual = 5,
    CraneliftIntCCUnsignedLessThan = 6,
    CraneliftIntCCUnsignedGreaterThanOrEqual = 7,
    CraneliftIntCCUnsignedGreaterThan = 8,
    CraneliftIntCCUnsignedLessThanOrEqual = 9,
    CraneliftIntCCOverflow = 10,
    CraneliftIntCCNotOverflow = 11,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CraneliftFloatCC {
    CraneliftFloatCCOrdered = 0,
    CraneliftFloatCCUnordered = 1,
    CraneliftFloatCCEqual = 2,
    CraneliftFloatCCNotEqual = 3,
    CraneliftFloatCCOrderedNotEqual = 4,
    CraneliftFloatCCUnorderedOrEqual = 5,
    CraneliftFloatCCLessThan = 6,
    CraneliftFloatCCLessThanOrEqual = 7,
    CraneliftFloatCCGreaterThan = 8,
    CraneliftFloatCCGreaterThanOrEqual = 9,
    CraneliftFloatCCUnorderedOrLessThan = 10,
    CraneliftFloatCCUnorderedOrLessThanOrEqual = 11,
    CraneliftFloatCCUnorderedOrGreaterThan = 12,
    CraneliftFloatCCUnorderedOrGreaterThanOrEqual = 13,
}
/// CPU flags representing the result of an integer comparison. These flags
/// can be tested with an :u8:`intcc` condition code.
#[allow(non_upper_case_globals)]
pub const TypeIFLAGS: u8 = 0x1;

/// CPU flags representing the result of a floating point comparison. These
/// flags can be tested with a :u8:`floatcc` condition code.
#[allow(non_upper_case_globals)]
pub const TypeFFLAGS: u8 = 0x2;

/// A boolean u8 with 1 bits.
#[allow(non_upper_case_globals)]
pub const TypeB1: u8 = 0x70;

/// A boolean u8 with 8 bits.
#[allow(non_upper_case_globals)]
pub const TypeB8: u8 = 0x71;

/// A boolean u8 with 16 bits.
#[allow(non_upper_case_globals)]
pub const TypeB16: u8 = 0x72;

/// A boolean u8 with 32 bits.
#[allow(non_upper_case_globals)]
pub const TypeB32: u8 = 0x73;

/// A boolean u8 with 64 bits.
#[allow(non_upper_case_globals)]
pub const TypeB64: u8 = 0x74;

/// A boolean u8 with 128 bits.
#[allow(non_upper_case_globals)]
pub const TypeB128: u8 = 0x75;

/// An integer u8 with 8 bits.
/// WARNING: arithmetic on 8bit integers is incomplete
#[allow(non_upper_case_globals)]
pub const TypeI8: u8 = 0x76;

/// An integer u8 with 16 bits.
/// WARNING: arithmetic on 16bit integers is incomplete
#[allow(non_upper_case_globals)]
pub const TypeI16: u8 = 0x77;

/// An integer u8 with 32 bits.
#[allow(non_upper_case_globals)]
pub const TypeI32: u8 = 0x78;

/// An integer u8 with 64 bits.
#[allow(non_upper_case_globals)]
pub const TypeI64: u8 = 0x79;

/// An integer u8 with 128 bits.
#[allow(non_upper_case_globals)]
pub const TypeI128: u8 = 0x7a;

/// A 32-bit floating point u8 represented in the IEEE 754-2008
/// *binary32* interchange format. This corresponds to the :c:u8:`float`
/// u8 in most C implementations.
#[allow(non_upper_case_globals)]
pub const TypeF32: u8 = 0x7b;

/// A 64-bit floating point u8 represented in the IEEE 754-2008
/// *binary64* interchange format. This corresponds to the :c:u8:`double`
/// u8 in most C implementations.
#[allow(non_upper_case_globals)]
pub const TypeF64: u8 = 0x7c;

/// An opaque reference u8 with 32 bits.
#[allow(non_upper_case_globals)]
pub const TypeR32: u8 = 0x7e;

/// An opaque reference u8 with 64 bits.
#[allow(non_upper_case_globals)]
pub const TypeR64: u8 = 0x7f;

/// A SIMD vector with 8 lanes containing a `b8` each.
#[allow(non_upper_case_globals)]
pub const TypeB8X8: u8 = 0xa1;

/// A SIMD vector with 4 lanes containing a `b16` each.
#[allow(non_upper_case_globals)]
pub const TypeB16X4: u8 = 0x92;

/// A SIMD vector with 2 lanes containing a `b32` each.
#[allow(non_upper_case_globals)]
pub const TypeB32X2: u8 = 0x83;

/// A SIMD vector with 8 lanes containing a `i8` each.
#[allow(non_upper_case_globals)]
pub const TypeI8X8: u8 = 0xa6;

/// A SIMD vector with 4 lanes containing a `i16` each.
#[allow(non_upper_case_globals)]
pub const TypeI16X4: u8 = 0x97;

/// A SIMD vector with 2 lanes containing a `i32` each.
#[allow(non_upper_case_globals)]
pub const TypeI32X2: u8 = 0x88;

/// A SIMD vector with 2 lanes containing a `f32` each.
#[allow(non_upper_case_globals)]
pub const TypeF32X2: u8 = 0x8b;

/// A SIMD vector with 16 lanes containing a `b8` each.
#[allow(non_upper_case_globals)]
pub const TypeB8X16: u8 = 0xb1;

/// A SIMD vector with 8 lanes containing a `b16` each.
#[allow(non_upper_case_globals)]
pub const TypeB16X8: u8 = 0xa2;

/// A SIMD vector with 4 lanes containing a `b32` each.
#[allow(non_upper_case_globals)]
pub const TypeB32X4: u8 = 0x93;

/// A SIMD vector with 2 lanes containing a `b64` each.
#[allow(non_upper_case_globals)]
pub const TypeB64X2: u8 = 0x84;

/// A SIMD vector with 16 lanes containing a `i8` each.
#[allow(non_upper_case_globals)]
pub const TypeI8X16: u8 = 0xb6;

/// A SIMD vector with 8 lanes containing a `i16` each.
#[allow(non_upper_case_globals)]
pub const TypeI16X8: u8 = 0xa7;

/// A SIMD vector with 4 lanes containing a `i32` each.
#[allow(non_upper_case_globals)]
pub const TypeI32X4: u8 = 0x98;

/// A SIMD vector with 2 lanes containing a `i64` each.
#[allow(non_upper_case_globals)]
pub const TypeI64X2: u8 = 0x89;

/// A SIMD vector with 4 lanes containing a `f32` each.
#[allow(non_upper_case_globals)]
pub const TypeF32X4: u8 = 0x9b;

/// A SIMD vector with 2 lanes containing a `f64` each.
#[allow(non_upper_case_globals)]
pub const TypeF64X2: u8 = 0x8c;

/// A SIMD vector with 32 lanes containing a `b8` each.
#[allow(non_upper_case_globals)]
pub const TypeB8X32: u8 = 0xc1;

/// A SIMD vector with 16 lanes containing a `b16` each.
#[allow(non_upper_case_globals)]
pub const TypeB16X16: u8 = 0xb2;

/// A SIMD vector with 8 lanes containing a `b32` each.
#[allow(non_upper_case_globals)]
pub const TypeB32X8: u8 = 0xa3;

/// A SIMD vector with 4 lanes containing a `b64` each.
#[allow(non_upper_case_globals)]
pub const TypeB64X4: u8 = 0x94;

/// A SIMD vector with 2 lanes containing a `b128` each.
#[allow(non_upper_case_globals)]
pub const TypeB128X2: u8 = 0x85;

/// A SIMD vector with 32 lanes containing a `i8` each.
#[allow(non_upper_case_globals)]
pub const TypeI8X32: u8 = 0xc6;

/// A SIMD vector with 16 lanes containing a `i16` each.
#[allow(non_upper_case_globals)]
pub const TypeI16X16: u8 = 0xb7;

/// A SIMD vector with 8 lanes containing a `i32` each.
#[allow(non_upper_case_globals)]
pub const TypeI32X8: u8 = 0xa8;

/// A SIMD vector with 4 lanes containing a `i64` each.
#[allow(non_upper_case_globals)]
pub const TypeI64X4: u8 = 0x99;

/// A SIMD vector with 2 lanes containing a `i128` each.
#[allow(non_upper_case_globals)]
pub const TypeI128X2: u8 = 0x8a;

/// A SIMD vector with 8 lanes containing a `f32` each.
#[allow(non_upper_case_globals)]
pub const TypeF32X8: u8 = 0xab;

/// A SIMD vector with 4 lanes containing a `f64` each.
#[allow(non_upper_case_globals)]
pub const TypeF64X4: u8 = 0x9c;

/// A SIMD vector with 64 lanes containing a `b8` each.
#[allow(non_upper_case_globals)]
pub const TypeB8X64: u8 = 0xd1;

/// A SIMD vector with 32 lanes containing a `b16` each.
#[allow(non_upper_case_globals)]
pub const TypeB16X32: u8 = 0xc2;

/// A SIMD vector with 16 lanes containing a `b32` each.
#[allow(non_upper_case_globals)]
pub const TypeB32X16: u8 = 0xb3;

/// A SIMD vector with 8 lanes containing a `b64` each.
#[allow(non_upper_case_globals)]
pub const TypeB64X8: u8 = 0xa4;

/// A SIMD vector with 4 lanes containing a `b128` each.
#[allow(non_upper_case_globals)]
pub const TypeB128X4: u8 = 0x95;

/// A SIMD vector with 64 lanes containing a `i8` each.
#[allow(non_upper_case_globals)]
pub const TypeI8X64: u8 = 0xd6;

/// A SIMD vector with 32 lanes containing a `i16` each.
#[allow(non_upper_case_globals)]
pub const TypeI16X32: u8 = 0xc7;

/// A SIMD vector with 16 lanes containing a `i32` each.
#[allow(non_upper_case_globals)]
pub const TypeI32X16: u8 = 0xb8;

/// A SIMD vector with 8 lanes containing a `i64` each.
#[allow(non_upper_case_globals)]
pub const TypeI64X8: u8 = 0xa9;

/// A SIMD vector with 4 lanes containing a `i128` each.
#[allow(non_upper_case_globals)]
pub const TypeI128X4: u8 = 0x9a;

/// A SIMD vector with 16 lanes containing a `f32` each.
#[allow(non_upper_case_globals)]
pub const TypeF32X16: u8 = 0xbb;

/// A SIMD vector with 8 lanes containing a `f64` each.
#[allow(non_upper_case_globals)]
pub const TypeF64X8: u8 = 0xac;
type Type = u8;

type TrapCode = u32;
/// The current stack space was exhausted.
///
/// On some platforms, a stack overflow may also be indicated by a segmentation fault from the
/// stack guard page.
#[allow(non_upper_case_globals)]
pub const TrapCodeStackOverflow: u32 = 1 << 16;

/// A `heap_addr` instruction detected an out-of-bounds error.
///
/// Note that not all out-of-bounds heap accesses are reported this way;
/// some are detected by a segmentation fault on the heap unmapped or
/// offset-guard pages.
#[allow(non_upper_case_globals)]
pub const TrapCodeHeapOutOfBounds: u32 = 2 << 16;

/// A `table_addr` instruction detected an out-of-bounds error.
#[allow(non_upper_case_globals)]
pub const TrapCodeTableOutOfBounds: u32 = 3 << 16;

/// Indirect call to a null table entry.
#[allow(non_upper_case_globals)]
pub const TrapCodeIndirectCallToNull: u32 = 5 << 16;

/// Signature mismatch on indirect call.
#[allow(non_upper_case_globals)]
pub const TrapCodeBadSignature: u32 = 6 << 16;

/// An integer arithmetic operation caused an overflow.
#[allow(non_upper_case_globals)]
pub const TrapCodeIntegerOverflow: u32 = 7 << 16;

/// An integer division by zero.
#[allow(non_upper_case_globals)]
pub const TrapCodeIntegerDivisionByZero: u32 = 8 << 16;

/// Failed float-to-int conversion.
#[allow(non_upper_case_globals)]
pub const TrapCodeBadConversionToInteger: u32 = 9 << 16;

/// Code that was supposed to have been unreachable was reached.
#[allow(non_upper_case_globals)]
pub const TrapCodeUnreachableCodeReached: u32 = 10 << 16;

/// Execution has potentially run too long and may be interrupted.
/// This trap is resumable.
#[allow(non_upper_case_globals)]
pub const TrapCodeInterrupt: u32 = 11 << 16;

#[no_mangle]
pub extern "C" fn cranelift_get_pointer_type(ptr: *mut ModuleData) -> Type {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .module
        .as_ref()
        .unwrap()
        .target_config()
        .pointer_type()
        .index() as u8;
}

#[no_mangle]
pub extern "C" fn cranelift_get_pointer_size_bytes(ptr: *mut ModuleData) -> u8 {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .module
        .as_ref()
        .unwrap()
        .target_config()
        .pointer_bytes();
}

#[no_mangle]
pub extern "C" fn cranelift_clear_context(ptr: *mut ModuleData) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.ctx.clear()
}

fn convert_cc(cc: CraneliftCallConv, default: CallConv) -> CallConv {
    match cc {
        CraneliftCallConv::CraneliftCallConvDefault => default,
        CraneliftCallConv::CraneliftCallConvSystemV => CallConv::SystemV,
        CraneliftCallConv::CraneliftCallConvWindowsFastcall => CallConv::WindowsFastcall,
        CraneliftCallConv::CraneliftCallConvProbestack => CallConv::Probestack,
        CraneliftCallConv::CraneliftCallConvFast => CallConv::Fast,
        CraneliftCallConv::CraneliftCallConvCold => CallConv::Cold,
        CraneliftCallConv::CraneliftCallConvBaldrdashWindows => CallConv::BaldrdashWindows,
        CraneliftCallConv::CraneliftCallConvBaldrdashSystemV => CallConv::BaldrdashSystemV,
    }
}

#[no_mangle]
pub extern "C" fn cranelift_signature_builder_reset(ptr: *mut ModuleData, cc: CraneliftCallConv) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    inst.ctx.func.signature.clear(convert_cc(
        cc,
        inst.module
            .as_ref()
            .unwrap()
            .target_config()
            .default_call_conv,
    ));
}

fn convert_type(typ: Type) -> cranelift_codegen::ir::types::Type {
    #[allow(non_upper_case_globals)]
    match typ {
        TypeIFLAGS => cranelift_codegen::ir::types::IFLAGS,
        TypeFFLAGS => cranelift_codegen::ir::types::FFLAGS,
        TypeB1 => cranelift_codegen::ir::types::B1,
        TypeB8 => cranelift_codegen::ir::types::B8,
        TypeB16 => cranelift_codegen::ir::types::B16,
        TypeB32 => cranelift_codegen::ir::types::B32,
        TypeB64 => cranelift_codegen::ir::types::B64,
        TypeB128 => cranelift_codegen::ir::types::B128,
        TypeI8 => cranelift_codegen::ir::types::I8,
        TypeI16 => cranelift_codegen::ir::types::I16,
        TypeI32 => cranelift_codegen::ir::types::I32,
        TypeI64 => cranelift_codegen::ir::types::I64,
        TypeI128 => cranelift_codegen::ir::types::I128,
        TypeF32 => cranelift_codegen::ir::types::F32,
        TypeF64 => cranelift_codegen::ir::types::F64,
        TypeR32 => cranelift_codegen::ir::types::R32,
        TypeR64 => cranelift_codegen::ir::types::R64,
        TypeB8X8 => cranelift_codegen::ir::types::B8X8,
        TypeB16X4 => cranelift_codegen::ir::types::B16X4,
        TypeB32X2 => cranelift_codegen::ir::types::B32X2,
        TypeI8X8 => cranelift_codegen::ir::types::I8X8,
        TypeI16X4 => cranelift_codegen::ir::types::I16X4,
        TypeI32X2 => cranelift_codegen::ir::types::I32X2,
        TypeF32X2 => cranelift_codegen::ir::types::F32X2,
        TypeB8X16 => cranelift_codegen::ir::types::B8X16,
        TypeB16X8 => cranelift_codegen::ir::types::B16X8,
        TypeB32X4 => cranelift_codegen::ir::types::B32X4,
        TypeB64X2 => cranelift_codegen::ir::types::B64X2,
        TypeI8X16 => cranelift_codegen::ir::types::I8X16,
        TypeI16X8 => cranelift_codegen::ir::types::I16X8,
        TypeI32X4 => cranelift_codegen::ir::types::I32X4,
        TypeI64X2 => cranelift_codegen::ir::types::I64X2,
        TypeF32X4 => cranelift_codegen::ir::types::F32X4,
        TypeF64X2 => cranelift_codegen::ir::types::F64X2,
        TypeB8X32 => cranelift_codegen::ir::types::B8X32,
        TypeB16X16 => cranelift_codegen::ir::types::B16X16,
        TypeB32X8 => cranelift_codegen::ir::types::B32X8,
        TypeB64X4 => cranelift_codegen::ir::types::B64X4,
        TypeB128X2 => cranelift_codegen::ir::types::B128X2,
        TypeI8X32 => cranelift_codegen::ir::types::I8X32,
        TypeI16X16 => cranelift_codegen::ir::types::I16X16,
        TypeI32X8 => cranelift_codegen::ir::types::I32X8,
        TypeI64X4 => cranelift_codegen::ir::types::I64X4,
        TypeI128X2 => cranelift_codegen::ir::types::I128X2,
        TypeF32X8 => cranelift_codegen::ir::types::F32X8,
        TypeF64X4 => cranelift_codegen::ir::types::F64X4,
        TypeB8X64 => cranelift_codegen::ir::types::B8X64,
        TypeB16X32 => cranelift_codegen::ir::types::B16X32,
        TypeB32X16 => cranelift_codegen::ir::types::B32X16,
        TypeB64X8 => cranelift_codegen::ir::types::B64X8,
        TypeB128X4 => cranelift_codegen::ir::types::B128X4,
        TypeI8X64 => cranelift_codegen::ir::types::I8X64,
        TypeI16X32 => cranelift_codegen::ir::types::I16X32,
        TypeI32X16 => cranelift_codegen::ir::types::I32X16,
        TypeI64X8 => cranelift_codegen::ir::types::I64X8,
        TypeI128X4 => cranelift_codegen::ir::types::I128X4,
        TypeF32X16 => cranelift_codegen::ir::types::F32X16,
        TypeF64X8 => cranelift_codegen::ir::types::F64X8,

        _ => cranelift_codegen::ir::types::I32,
    }
}

#[no_mangle]
pub extern "C" fn cranelift_signature_builder_add_param(ptr: *mut ModuleData, typ: Type) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    inst.ctx
        .func
        .signature
        .params
        .push(AbiParam::new(convert_type(typ)));
}

#[no_mangle]
pub extern "C" fn cranelift_signature_builder_add_result(ptr: *mut ModuleData, typ: Type) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    inst.ctx
        .func
        .signature
        .returns
        .push(AbiParam::new(convert_type(typ)));
}

#[no_mangle]
pub extern "C" fn cranelift_build_function(
    ptr: *mut ModuleData,
    userdata: usize,
    cb: extern "C" fn(userdata: usize, builder: &mut FunctionData),
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let fnbuilder = FunctionBuilder::new(&mut inst.ctx.func, &mut inst.builder_ctx);

    let fd = &mut FunctionData {
        module: inst.module.as_mut().unwrap(),
        builder: fnbuilder,
        variable_counter: 0,
    };
    cb(userdata, fd);

    fd.builder.finalize()
}

#[no_mangle]
pub extern "C" fn cranelift_function_to_string(
    ptr: *mut ModuleData,
    userdata: usize,
    cb: extern "C" fn(userdata: usize, str: *const c_char),
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let str = inst.ctx.func.to_string();
    cb(userdata, str.as_ptr() as *const c_char);
}

#[no_mangle]
pub extern "C" fn cranelift_set_source_loc(ptr: *mut FunctionData, loc: u32) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.set_srcloc(SourceLoc::new(loc))
}

type BlockCode = u32;
type VariableCode = u32;
type ValueCode = u32;
type ValueLabelCode = u32;
type JumpTableCode = u32;
type TableCode = u32;
type InstCode = u32;
type FuncRefCode = u32;
type SigRefCode = u32;
type HeapCode = u32;

#[no_mangle]
pub extern "C" fn cranelift_create_block(ptr: *mut FunctionData) -> BlockCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.create_block().as_u32()
}

#[no_mangle]
pub extern "C" fn cranelift_switch_to_block(ptr: *mut FunctionData, block: BlockCode) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.switch_to_block(Block::from_u32(block))
}

#[no_mangle]
pub extern "C" fn cranelift_seal_block(ptr: *mut FunctionData, block: BlockCode) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.seal_block(Block::from_u32(block))
}

#[no_mangle]
pub extern "C" fn cranelift_seal_all_blocks(ptr: *mut FunctionData) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.seal_all_blocks()
}

#[no_mangle]
pub extern "C" fn cranelift_append_block_params_for_function_params(
    ptr: *mut FunctionData,
    block: BlockCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    inst.builder
        .append_block_params_for_function_params(Block::from_u32(block))
}

#[no_mangle]
pub extern "C" fn cranelift_append_block_params_for_function_returns(
    ptr: *mut FunctionData,
    block: BlockCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    inst.builder
        .append_block_params_for_function_returns(Block::from_u32(block))
}

#[no_mangle]
pub extern "C" fn cranelift_block_params_count(ptr: *mut FunctionData, block: BlockCode) -> i32 {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let pars = inst.builder.block_params(Block::from_u32(block));
    (*pars).len() as i32
}

#[no_mangle]
pub extern "C" fn cranelift_block_params(
    ptr: *mut FunctionData,
    block: BlockCode,
    dest: *mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let pars = inst.builder.block_params(Block::from_u32(block));
    for i in 0..(*pars).len() {
        unsafe { *dest.add(i) = (*pars)[i].as_u32() };
    }
}

#[no_mangle]
pub extern "C" fn cranelift_declare_var(ptr: *mut FunctionData, typ: Type) -> VariableCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let next = Variable::new(inst.variable_counter as usize);
    inst.variable_counter += 1;
    inst.builder.declare_var(next, convert_type(typ));
    next.index() as u32
}

#[no_mangle]
pub extern "C" fn cranelift_def_var(ptr: *mut FunctionData, var: VariableCode, val: ValueCode) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder
        .def_var(Variable::with_u32(var), Value::from_u32(val))
}

#[no_mangle]
pub extern "C" fn cranelift_use_var(ptr: *mut FunctionData, var: VariableCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder.use_var(Variable::with_u32(var)).as_u32()
}

#[no_mangle]
pub extern "C" fn cranelift_set_val_label(
    ptr: *mut FunctionData,
    val: ValueCode,
    label: ValueLabelCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.builder
        .set_val_label(Value::from_u32(val), ValueLabel::from_u32(label))
}

#[no_mangle]
pub extern "C" fn cranelift_create_jump_table(
    ptr: *mut FunctionData,
    count: u32,
    targets: *mut BlockCode,
) -> JumpTableCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut jt = JumpTableData::new();
    for i in 0..count {
        jt.push_entry(Block::from_u32(unsafe { *targets.offset(i as isize) }));
    }
    inst.builder.create_jump_table(jt).as_u32()
}

#[no_mangle]
pub extern "C" fn cranelift_import_signature(
    ptr: *mut FunctionData,
    cc: CraneliftCallConv,
    argscount: u32,
    args: *mut Type,
    retcount: u32,
    rets: *mut Type,
) -> SigRefCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut sig = Signature::new(convert_cc(
        cc,
        inst.module.target_config().default_call_conv,
    ));
    for i in 0..argscount {
        sig.params.push(AbiParam::new(convert_type(unsafe {
            *args.offset(i as isize)
        })));
    }
    for i in 0..retcount {
        sig.returns.push(AbiParam::new(convert_type(unsafe {
            *rets.offset(i as isize)
        })));
    }

    inst.builder.import_signature(sig).as_u32()
}

#[no_mangle]
pub extern "C" fn cranelift_declare_func_in_current_func(
    ptr: *mut FunctionData,
    source_id: u32,
) -> FuncRefCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    inst.module
        .declare_func_in_func(FuncId::from_u32(source_id), inst.builder.func)
        .as_u32()
}

#[no_mangle]
pub extern "C" fn cranelift_ins_jump(
    ptr: *mut FunctionData,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .jump(Block::from_u32(block), argsdata.as_mut_slice())
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_brz(
    ptr: *mut FunctionData,
    c: ValueCode,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .brz(
            Value::from_u32(c),
            Block::from_u32(block),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_brnz(
    ptr: *mut FunctionData,
    c: ValueCode,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .brnz(
            Value::from_u32(c),
            Block::from_u32(block),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

fn convert_intcc(cond: CraneliftIntCC) -> IntCC {
    match cond {
        CraneliftIntCC::CraneliftIntCCEqual => IntCC::Equal,
        CraneliftIntCC::CraneliftIntCCNotEqual => IntCC::NotEqual,
        CraneliftIntCC::CraneliftIntCCSignedLessThan => IntCC::SignedLessThan,
        CraneliftIntCC::CraneliftIntCCSignedGreaterThanOrEqual => IntCC::SignedGreaterThanOrEqual,
        CraneliftIntCC::CraneliftIntCCSignedGreaterThan => IntCC::SignedGreaterThan,
        CraneliftIntCC::CraneliftIntCCSignedLessThanOrEqual => IntCC::SignedLessThanOrEqual,
        CraneliftIntCC::CraneliftIntCCUnsignedLessThan => IntCC::UnsignedLessThan,
        CraneliftIntCC::CraneliftIntCCUnsignedGreaterThanOrEqual => {
            IntCC::UnsignedGreaterThanOrEqual
        }
        CraneliftIntCC::CraneliftIntCCUnsignedGreaterThan => IntCC::UnsignedGreaterThan,
        CraneliftIntCC::CraneliftIntCCUnsignedLessThanOrEqual => IntCC::UnsignedLessThanOrEqual,
        CraneliftIntCC::CraneliftIntCCOverflow => IntCC::Overflow,
        CraneliftIntCC::CraneliftIntCCNotOverflow => IntCC::NotOverflow,
    }
}

#[no_mangle]
pub extern "C" fn cranelift_ins_br_icmp(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    x: ValueCode,
    y: ValueCode,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .br_icmp(
            convert_intcc(cond),
            Value::from_u32(x),
            Value::from_u32(y),
            Block::from_u32(block),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_brif(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    c: ValueCode,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .brif(
            convert_intcc(cond),
            Value::from_u32(c),
            Block::from_u32(block),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

fn convert_floatcc(cond: CraneliftFloatCC) -> FloatCC {
    match cond {
        CraneliftFloatCC::CraneliftFloatCCOrdered => FloatCC::Ordered,
        CraneliftFloatCC::CraneliftFloatCCUnordered => FloatCC::Unordered,
        CraneliftFloatCC::CraneliftFloatCCEqual => FloatCC::Equal,
        CraneliftFloatCC::CraneliftFloatCCNotEqual => FloatCC::NotEqual,
        CraneliftFloatCC::CraneliftFloatCCOrderedNotEqual => FloatCC::OrderedNotEqual,
        CraneliftFloatCC::CraneliftFloatCCUnorderedOrEqual => FloatCC::UnorderedOrEqual,
        CraneliftFloatCC::CraneliftFloatCCLessThan => FloatCC::LessThan,
        CraneliftFloatCC::CraneliftFloatCCLessThanOrEqual => FloatCC::LessThanOrEqual,
        CraneliftFloatCC::CraneliftFloatCCGreaterThan => FloatCC::GreaterThan,
        CraneliftFloatCC::CraneliftFloatCCGreaterThanOrEqual => FloatCC::GreaterThanOrEqual,
        CraneliftFloatCC::CraneliftFloatCCUnorderedOrLessThan => FloatCC::UnorderedOrLessThan,
        CraneliftFloatCC::CraneliftFloatCCUnorderedOrLessThanOrEqual => {
            FloatCC::UnorderedOrLessThanOrEqual
        }
        CraneliftFloatCC::CraneliftFloatCCUnorderedOrGreaterThan => FloatCC::UnorderedOrGreaterThan,
        CraneliftFloatCC::CraneliftFloatCCUnorderedOrGreaterThanOrEqual => {
            FloatCC::UnorderedOrGreaterThanOrEqual
        }
    }
}

#[no_mangle]
pub extern "C" fn cranelift_ins_brff(
    ptr: *mut FunctionData,
    cond: CraneliftFloatCC,
    c: ValueCode,
    block: BlockCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .brff(
            convert_floatcc(cond),
            Value::from_u32(c),
            Block::from_u32(block),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_br_table(
    ptr: *mut FunctionData,
    x: ValueCode,
    block: BlockCode,
    jt: JumpTableCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .br_table(
            Value::from_u32(x),
            Block::from_u32(block),
            JumpTable::from_u32(jt),
        )
        .as_u32();
}

fn convert_trapcode(code: TrapCode) -> cranelift_codegen::ir::TrapCode {
    #[allow(non_upper_case_globals)]
    match code {
        TrapCodeStackOverflow => cranelift_codegen::ir::TrapCode::StackOverflow,
        TrapCodeHeapOutOfBounds => cranelift_codegen::ir::TrapCode::HeapOutOfBounds,
        TrapCodeTableOutOfBounds => cranelift_codegen::ir::TrapCode::TableOutOfBounds,
        TrapCodeIndirectCallToNull => cranelift_codegen::ir::TrapCode::IndirectCallToNull,
        TrapCodeBadSignature => cranelift_codegen::ir::TrapCode::BadSignature,
        TrapCodeIntegerOverflow => cranelift_codegen::ir::TrapCode::IntegerOverflow,
        TrapCodeIntegerDivisionByZero => cranelift_codegen::ir::TrapCode::IntegerDivisionByZero,
        TrapCodeBadConversionToInteger => cranelift_codegen::ir::TrapCode::BadConversionToInteger,
        TrapCodeUnreachableCodeReached => cranelift_codegen::ir::TrapCode::UnreachableCodeReached,
        TrapCodeInterrupt => cranelift_codegen::ir::TrapCode::Interrupt,
        _ => cranelift_codegen::ir::TrapCode::User(code as u16),
    }
}

#[no_mangle]
pub extern "C" fn cranelift_ins_trap(ptr: *mut FunctionData, code: TrapCode) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return inst.builder.ins().trap(convert_trapcode(code)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_resumable_trap(ptr: *mut FunctionData, code: TrapCode) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return inst
        .builder
        .ins()
        .resumable_trap(convert_trapcode(code))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_trapz(
    ptr: *mut FunctionData,
    c: ValueCode,
    code: TrapCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return inst
        .builder
        .ins()
        .trapz(Value::from_u32(c), convert_trapcode(code))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_trapnz(
    ptr: *mut FunctionData,
    v: ValueCode,
    code: TrapCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return inst
        .builder
        .ins()
        .trapnz(Value::from_u32(v), convert_trapcode(code))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_trapif(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    f: ValueCode,
    code: TrapCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .trapif(
            convert_intcc(cond),
            Value::from_u32(f),
            convert_trapcode(code),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ins_trapff(
    ptr: *mut FunctionData,
    cond: CraneliftFloatCC,
    f: ValueCode,
    code: TrapCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .trapff(
            convert_floatcc(cond),
            Value::from_u32(f),
            convert_trapcode(code),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_return(
    ptr: *mut FunctionData,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst.builder.ins().return_(argsdata.as_mut_slice()).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fallthrough_return(
    ptr: *mut FunctionData,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .fallthrough_return(argsdata.as_mut_slice())
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_call(
    ptr: *mut FunctionData,
    fnn: FuncRefCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .call(FuncRef::from_u32(fnn), argsdata.as_mut_slice())
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_call_indirect(
    ptr: *mut FunctionData,
    sig: SigRefCode,
    v: ValueCode,
    count: u32,
    args: *mut ValueCode,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let mut argsdata = vec![];
    for i in 0..count {
        argsdata.push(Value::from_u32(unsafe { *args.offset(i as isize) }));
    }
    return inst
        .builder
        .ins()
        .call_indirect(
            SigRef::from_u32(sig),
            Value::from_u32(v),
            argsdata.as_mut_slice(),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_func_addr(
    ptr: *mut FunctionData,
    iaddr: Type,
    fnn: FuncRefCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .func_addr(convert_type(iaddr), FuncRef::from_u32(fnn))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_splat(ptr: *mut FunctionData, txn: Type, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .splat(convert_type(txn), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_swizzle(
    ptr: *mut FunctionData,
    txn: Type,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .swizzle(convert_type(txn), Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

type Uimm8 = u8;
type Uimm32 = u32;
type MemFlagCode = u8;
type Offset32 = i32;
type Offset64 = i64;
type RegUnit = u16;
type StackSlotCode = u32;
type GlobalValueCode = u32;
type ConstantCode = u32;
type ImmediateCode = u32;
type Imm64 = i64;
#[allow(non_upper_case_globals)]
pub const MemFlagNoTrap: u8 = 1;
#[allow(non_upper_case_globals)]
pub const MemFlagAligned: u8 = 2;
#[allow(non_upper_case_globals)]
pub const MemFlagReadonly: u8 = 4;

#[no_mangle]
pub extern "C" fn cranelift_insertlane(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    idx: Uimm8,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .insertlane(Value::from_u32(x), Value::from_u32(y), idx)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_extractlane(
    ptr: *mut FunctionData,
    x: ValueCode,
    idx: Uimm8,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .extractlane(Value::from_u32(x), idx)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_imin(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .imin(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_umin(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .umin(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_imax(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .imax(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_umax(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .umax(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_avg_round(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .avg_round(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

fn convert_memflags(code: MemFlagCode) -> MemFlags {
    let mut mf = MemFlags::new();
    if 0 != (MemFlagAligned & code) {
        mf.set_aligned();
    }
    if 0 != (MemFlagNoTrap & code) {
        mf.set_notrap();
    }
    if 0 != (MemFlagReadonly & code) {
        mf.set_readonly();
    }
    mf
}

#[no_mangle]
pub extern "C" fn cranelift_load(
    ptr: *mut FunctionData,
    mem: Type,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .load(
            convert_type(mem),
            convert_memflags(memflags),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_store(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    x: ValueCode,
    p: ValueCode,
    offset: Offset32,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .store(
            convert_memflags(memflags),
            Value::from_u32(x),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload8(
    ptr: *mut FunctionData,
    iext8: Type,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload8(
            convert_type(iext8),
            convert_memflags(memflags),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload8(
    ptr: *mut FunctionData,
    iext8: Type,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    return inst
        .builder
        .ins()
        .sload8(
            convert_type(iext8),
            convert_memflags(memflags),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_istore8(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    x: ValueCode,
    p: ValueCode,
    offset: Offset32,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .istore8(
            convert_memflags(memflags),
            Value::from_u32(x),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload16(
    ptr: *mut FunctionData,
    iext16: Type,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload16(
            convert_type(iext16),
            convert_memflags(memflags),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload16(
    ptr: *mut FunctionData,
    iext16: Type,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sload16(
            convert_type(iext16),
            convert_memflags(memflags),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_istore16(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    x: ValueCode,
    p: ValueCode,
    offset: Offset32,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .istore16(
            convert_memflags(memflags),
            Value::from_u32(x),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload32(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload32(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload32(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sload32(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_istore32(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    x: ValueCode,
    p: ValueCode,
    offset: Offset32,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .istore32(
            convert_memflags(memflags),
            Value::from_u32(x),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload8x8(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload8x8(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload8x8(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sload8x8(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload16x4(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload16x4(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload16x4(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sload16x4(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uload32x2(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uload32x2(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sload32x2(
    ptr: *mut FunctionData,
    memflags: MemFlagCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sload32x2(convert_memflags(memflags), Value::from_u32(p), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_stack_load(
    ptr: *mut FunctionData,
    mem: Type,
    ss: StackSlotCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .stack_load(convert_type(mem), StackSlot::from_u32(ss), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_stack_store(
    ptr: *mut FunctionData,
    x: ValueCode,
    ss: StackSlotCode,
    offset: Offset32,
) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .stack_store(Value::from_u32(x), StackSlot::from_u32(ss), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_stack_addr(
    ptr: *mut FunctionData,
    iaddr: Type,
    ss: StackSlotCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .stack_addr(convert_type(iaddr), StackSlot::from_u32(ss), offset)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_global_value(
    ptr: *mut FunctionData,
    mem: Type,
    gv: GlobalValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .global_value(convert_type(mem), GlobalValue::from_u32(gv))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_symbol_value(
    ptr: *mut FunctionData,
    mem: Type,
    gv: GlobalValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .symbol_value(convert_type(mem), GlobalValue::from_u32(gv))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_tls_value(
    ptr: *mut FunctionData,
    mem: Type,
    gv: GlobalValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .tls_value(convert_type(mem), GlobalValue::from_u32(gv))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_heap_addr(
    ptr: *mut FunctionData,
    iaddr: Type,
    h: HeapCode,
    p: ValueCode,
    size: Uimm32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .heap_addr(
            convert_type(iaddr),
            Heap::from_u32(h),
            Value::from_u32(p),
            size,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_get_pinned_reg(ptr: *mut FunctionData, iaddr: Type) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .get_pinned_reg(convert_type(iaddr))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_set_pinned_reg(ptr: *mut FunctionData, addr: ValueCode) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .set_pinned_reg(Value::from_u32(addr))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_table_addr(
    ptr: *mut FunctionData,
    iaddr: Type,
    t: TableCode,
    p: ValueCode,
    offset: Offset32,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .table_addr(
            convert_type(iaddr),
            Table::from_u32(t),
            Value::from_u32(p),
            offset,
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iconst(ptr: *mut FunctionData, int: Type, n: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().iconst(convert_type(int), n).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_f32const(ptr: *mut FunctionData, n: f32) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().f32const(n).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_f64const(ptr: *mut FunctionData, n: f64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().f64const(n).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bconst(ptr: *mut FunctionData, bool: Type, n: bool) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().bconst(convert_type(bool), n).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vconst(
    ptr: *mut FunctionData,
    txn: Type,
    n: ConstantCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .vconst(convert_type(txn), Constant::from_u32(n))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_const_addr(
    ptr: *mut FunctionData,
    iaddr: Type,
    constant: ConstantCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .const_addr(convert_type(iaddr), Constant::from_u32(constant))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_shuffle(
    ptr: *mut FunctionData,
    a: ValueCode,
    b: ValueCode,
    mask: ImmediateCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .shuffle(
            Value::from_u32(a),
            Value::from_u32(b),
            Immediate::from_u32(mask),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_null(ptr: *mut FunctionData, _ref: Type) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().null(convert_type(_ref)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_nop(ptr: *mut FunctionData) -> InstCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().nop().as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_select(
    ptr: *mut FunctionData,
    c: ValueCode,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .select(Value::from_u32(c), Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_selectif(
    ptr: *mut FunctionData,
    any: Type,
    cc: CraneliftIntCC,
    flags: ValueCode,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .selectif(
            convert_type(any),
            convert_intcc(cc),
            Value::from_u32(flags),
            Value::from_u32(x),
            Value::from_u32(y),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bitselect(
    ptr: *mut FunctionData,
    c: ValueCode,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bitselect(Value::from_u32(c), Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_copy(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().copy(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ifcmp_sp(ptr: *mut FunctionData, addr: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ifcmp_sp(Value::from_u32(addr)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vsplit(
    ptr: *mut FunctionData,
    x: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    let (tmp1, tmp2) = inst.builder.ins().vsplit(Value::from_u32(x));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vconcat(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .vconcat(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vselect(
    ptr: *mut FunctionData,
    c: ValueCode,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .vselect(Value::from_u32(c), Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vany_true(ptr: *mut FunctionData, a: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().vany_true(Value::from_u32(a)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_vall_true(ptr: *mut FunctionData, a: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().vall_true(Value::from_u32(a)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_icmp(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .icmp(convert_intcc(cond), Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_icmp_imm(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    x: ValueCode,
    y: Imm64,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .icmp_imm(convert_intcc(cond), Value::from_u32(x), y)
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ifcmp(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ifcmp(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ifcmp_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ifcmp_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .iadd(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uadd_sat(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uadd_sat(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sadd_sat(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sadd_sat(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .isub(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_usub_sat(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .usub_sat(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ssub_sat(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ssub_sat(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ineg(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ineg(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_imul(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .imul(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_umulhi(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .umulhi(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_smulhi(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .smulhi(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_udiv(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .udiv(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sdiv(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sdiv(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_urem(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .urem(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_srem(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .srem(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().iadd_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_imul_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().imul_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_udiv_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().udiv_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sdiv_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().sdiv_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_urem_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().urem_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_srem_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().srem_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_irsub_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().irsub_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_cin(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    c_in: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .iadd_cin(
            Value::from_u32(x),
            Value::from_u32(y),
            Value::from_u32(c_in),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_ifcin(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    c_in: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .iadd_ifcin(
            Value::from_u32(x),
            Value::from_u32(y),
            Value::from_u32(c_in),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_cout(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst
        .builder
        .ins()
        .iadd_cout(Value::from_u32(x), Value::from_u32(y));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_ifcout(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst
        .builder
        .ins()
        .iadd_ifcout(Value::from_u32(x), Value::from_u32(y));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_carry(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    c_in: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst.builder.ins().iadd_carry(
        Value::from_u32(x),
        Value::from_u32(y),
        Value::from_u32(c_in),
    );
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iadd_ifcarry(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    c_in: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst.builder.ins().iadd_ifcarry(
        Value::from_u32(x),
        Value::from_u32(y),
        Value::from_u32(c_in),
    );
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_bin(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    b_in: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .isub_bin(
            Value::from_u32(x),
            Value::from_u32(y),
            Value::from_u32(b_in),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_ifbin(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    b_in: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .isub_ifbin(
            Value::from_u32(x),
            Value::from_u32(y),
            Value::from_u32(b_in),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_bout(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst
        .builder
        .ins()
        .isub_bout(Value::from_u32(x), Value::from_u32(y));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_ifbout(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst
        .builder
        .ins()
        .isub_ifbout(Value::from_u32(x), Value::from_u32(y));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_borrow(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    b_in: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst.builder.ins().isub_borrow(
        Value::from_u32(x),
        Value::from_u32(y),
        Value::from_u32(b_in),
    );
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isub_ifborrow(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    b_in: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst.builder.ins().isub_ifborrow(
        Value::from_u32(x),
        Value::from_u32(y),
        Value::from_u32(b_in),
    );
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_band(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .band(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bor(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bor(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bxor(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bxor(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bnot(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().bnot(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_band_not(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .band_not(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bor_not(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bor_not(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bxor_not(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bxor_not(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_band_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().band_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bor_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().bor_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bxor_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().bxor_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_rotl(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .rotl(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_rotr(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .rotr(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_rotl_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().rotl_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_rotr_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().rotr_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ishl(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ishl(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ushr(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ushr(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sshr(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sshr(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ishl_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ishl_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ushr_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ushr_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sshr_imm(ptr: *mut FunctionData, x: ValueCode, y: Imm64) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().sshr_imm(Value::from_u32(x), y).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bitrev(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().bitrev(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_clz(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().clz(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_cls(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().cls(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ctz(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ctz(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_popcnt(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().popcnt(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcmp(
    ptr: *mut FunctionData,
    cond: CraneliftFloatCC,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcmp(
            convert_floatcc(cond),
            Value::from_u32(x),
            Value::from_u32(y),
        )
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ffcmp(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ffcmp(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fadd(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fadd(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fsub(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fsub(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fmul(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fmul(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fdiv(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fdiv(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sqrt(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().sqrt(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fma(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
    z: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fma(Value::from_u32(x), Value::from_u32(y), Value::from_u32(z))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fneg(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().fneg(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fabs(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().fabs(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcopysign(
    ptr: *mut FunctionData,
    x: ValueCode,
    y: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcopysign(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fmin(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fmin(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fmax(ptr: *mut FunctionData, x: ValueCode, y: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fmax(Value::from_u32(x), Value::from_u32(y))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ceil(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().ceil(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_floor(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().floor(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_trunc(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().trunc(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_nearest(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().nearest(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_is_null(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().is_null(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_is_invalid(ptr: *mut FunctionData, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst.builder.ins().is_invalid(Value::from_u32(x)).as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_trueif(
    ptr: *mut FunctionData,
    cond: CraneliftIntCC,
    f: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .trueif(convert_intcc(cond), Value::from_u32(f))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_trueff(
    ptr: *mut FunctionData,
    cond: CraneliftFloatCC,
    f: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .trueff(convert_floatcc(cond), Value::from_u32(f))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bitcast(
    ptr: *mut FunctionData,
    memto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bitcast(convert_type(memto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_raw_bitcast(
    ptr: *mut FunctionData,
    anyto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .raw_bitcast(convert_type(anyto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_scalar_to_vector(
    ptr: *mut FunctionData,
    txn: Type,
    s: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .scalar_to_vector(convert_type(txn), Value::from_u32(s))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_breduce(
    ptr: *mut FunctionData,
    boolto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .breduce(convert_type(boolto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bextend(
    ptr: *mut FunctionData,
    boolto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bextend(convert_type(boolto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bint(ptr: *mut FunctionData, intto: Type, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bint(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_bmask(ptr: *mut FunctionData, intto: Type, x: ValueCode) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .bmask(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_ireduce(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .ireduce(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_uextend(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .uextend(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_sextend(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .sextend(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fpromote(
    ptr: *mut FunctionData,
    floatto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fpromote(convert_type(floatto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fdemote(
    ptr: *mut FunctionData,
    floatto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fdemote(convert_type(floatto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_to_uint(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_to_uint(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_to_uint_sat(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_to_uint_sat(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_to_sint(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_to_sint(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_to_sint_sat(
    ptr: *mut FunctionData,
    intto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_to_sint_sat(convert_type(intto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_from_uint(
    ptr: *mut FunctionData,
    floatto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_from_uint(convert_type(floatto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_fcvt_from_sint(
    ptr: *mut FunctionData,
    floatto: Type,
    x: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .fcvt_from_sint(convert_type(floatto), Value::from_u32(x))
        .as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_isplit(
    ptr: *mut FunctionData,
    x: ValueCode,
    res1: &mut ValueCode,
    res2: &mut ValueCode,
) {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    let (tmp1, tmp2) = inst.builder.ins().isplit(Value::from_u32(x));
    *res1 = tmp1.as_u32();
    *res2 = tmp2.as_u32();
}

#[no_mangle]
pub extern "C" fn cranelift_iconcat(
    ptr: *mut FunctionData,
    lo: ValueCode,
    hi: ValueCode,
) -> ValueCode {
    let inst = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };
    return inst
        .builder
        .ins()
        .iconcat(Value::from_u32(lo), Value::from_u32(hi))
        .as_u32();
}

/*

Todo maybe later:

fn Binary(
opcode: Opcode,
ctrl_typevar: Type,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn BinaryImm(

opcode: Opcode,
ctrl_typevar: Type,
imm: Imm64,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Branch(

opcode: Opcode,
ctrl_typevar: Type,
destination: Block,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn BranchFloat(

opcode: Opcode,
ctrl_typevar: Type,
cond: FloatCC,
destination: Block,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn BranchIcmp(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
destination: Block,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn BranchInt(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
destination: Block,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn BranchTable(

opcode: Opcode,
ctrl_typevar: Type,
destination: Block,
table: JumpTable,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn BranchTableBase(

opcode: Opcode,
ctrl_typevar: Type,
table: JumpTable
) -> (Inst, &'f mut DataFlowGraph)
fn BranchTableEntry(

opcode: Opcode,
ctrl_typevar: Type,
imm: Uimm8,
table: JumpTable,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Call(

opcode: Opcode,
ctrl_typevar: Type,
func_ref: FuncRef,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn CallIndirect(

opcode: Opcode,
ctrl_typevar: Type,
sig_ref: SigRef,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn CondTrap(

opcode: Opcode,
ctrl_typevar: Type,
code: TrapCode,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn CopySpecial(

opcode: Opcode,
ctrl_typevar: Type,
src: RegUnit,
dst: RegUnit
) -> (Inst, &'f mut DataFlowGraph)
fn CopyToSsa(

opcode: Opcode,
ctrl_typevar: Type,
src: RegUnit
) -> (Inst, &'f mut DataFlowGraph)
fn ExtractLane(

opcode: Opcode,
ctrl_typevar: Type,
lane: Uimm8,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn FloatCompare(

opcode: Opcode,
ctrl_typevar: Type,
cond: FloatCC,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn FloatCond(

opcode: Opcode,
ctrl_typevar: Type,
cond: FloatCC,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn FloatCondTrap(

opcode: Opcode,
ctrl_typevar: Type,
cond: FloatCC,
code: TrapCode,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn FuncAddr(

opcode: Opcode,
ctrl_typevar: Type,
func_ref: FuncRef
) -> (Inst, &'f mut DataFlowGraph)
fn HeapAddr(

opcode: Opcode,
ctrl_typevar: Type,
heap: Heap,
imm: Uimm32,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IndirectJump(

opcode: Opcode,
ctrl_typevar: Type,
table: JumpTable,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn InsertLane(

opcode: Opcode,
ctrl_typevar: Type,
lane: Uimm8,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IntCompare(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IntCompareImm(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
imm: Imm64,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IntCond(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IntCondTrap(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
code: TrapCode,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn IntSelect(

opcode: Opcode,
ctrl_typevar: Type,
cond: IntCC,
arg0: Value,
arg1: Value,
arg2: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Jump(

opcode: Opcode,
ctrl_typevar: Type,
destination: Block,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn Load(

opcode: Opcode,
ctrl_typevar: Type,
flags: MemFlags,
offset: Offset32,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn LoadComplex(

opcode: Opcode,
ctrl_typevar: Type,
flags: MemFlags,
offset: Offset32,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn MultiAry(

opcode: Opcode,
ctrl_typevar: Type,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn NullAry(

opcode: Opcode,
ctrl_typevar: Type
) -> (Inst, &'f mut DataFlowGraph)
fn RegFill(

opcode: Opcode,
ctrl_typevar: Type,
src: StackSlot,
dst: RegUnit,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn RegMove(

opcode: Opcode,
ctrl_typevar: Type,
src: RegUnit,
dst: RegUnit,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn RegSpill(

opcode: Opcode,
ctrl_typevar: Type,
src: RegUnit,
dst: StackSlot,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Shuffle(

opcode: Opcode,
ctrl_typevar: Type,
mask: Immediate,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn StackLoad(

opcode: Opcode,
ctrl_typevar: Type,
stack_slot: StackSlot,
offset: Offset32
) -> (Inst, &'f mut DataFlowGraph)
fn StackStore(

opcode: Opcode,
ctrl_typevar: Type,
stack_slot: StackSlot,
offset: Offset32,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Store(

opcode: Opcode,
ctrl_typevar: Type,
flags: MemFlags,
offset: Offset32,
arg0: Value,
arg1: Value
) -> (Inst, &'f mut DataFlowGraph)
fn StoreComplex(

opcode: Opcode,
ctrl_typevar: Type,
flags: MemFlags,
offset: Offset32,
args: ValueList
) -> (Inst, &'f mut DataFlowGraph)
fn TableAddr(

opcode: Opcode,
ctrl_typevar: Type,
table: Table,
offset: Offset32,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Ternary(

opcode: Opcode,
ctrl_typevar: Type,
arg0: Value,
arg1: Value,
arg2: Value
) -> (Inst, &'f mut DataFlowGraph)
fn Trap(

opcode: Opcode,
ctrl_typevar: Type,
code: TrapCode
) -> (Inst, &'f mut DataFlowGraph)
fn Unary(

opcode: Opcode,
ctrl_typevar: Type,
arg0: Value
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryBool(

opcode: Opcode,
ctrl_typevar: Type,
imm: bool
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryConst(

opcode: Opcode,
ctrl_typevar: Type,
constant_handle: Constant
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryGlobalValue(

opcode: Opcode,
ctrl_typevar: Type,
global_value: GlobalValue
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryIeee32(

opcode: Opcode,
ctrl_typevar: Type,
imm: Ieee32
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryIeee64(

opcode: Opcode,
ctrl_typevar: Type,
imm: Ieee64
) -> (Inst, &'f mut DataFlowGraph)
fn UnaryImm(

opcode: Opcode,
ctrl_typevar: Type,
imm: Imm64
) -> (Inst, &'f mut DataFlowGraph)
*/
