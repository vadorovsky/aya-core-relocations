#![no_std]
#![no_main]

// use aya_btf::btf;
use aya_ebpf::{
    Global,
    cty::{c_int, c_uint},
    helpers::bpf_probe_read_kernel,
    macros::kprobe,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<i32> = Global::new(0);

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum FieldInfo {
    ByteOffset = 0,
    ByteSize = 1,
    Exists = 2,
}

fn relocatable_field_info<T>(ptr: *const T, kind: FieldInfo) -> u32 {
    // SAFETY: Placeholder function that exposes the
    // `llvm.bpf.preserve.field.info` intrinsic. It is safe to use and poses no
    // UB risk.
    unsafe extern "C" {
        fn relocatable_field_info(ptr: *const core::ffi::c_void, kind: u32) -> u32;
    }
    unsafe { relocatable_field_info(ptr.cast(), kind as u32) }
}

fn relocatable_field_byte_offset<T>(ptr: *const T) -> usize {
    relocatable_field_info(ptr, FieldInfo::ByteOffset) as usize
}

fn relocatable_field_byte_size<T>(ptr: *const T) -> usize {
    relocatable_field_info(ptr, FieldInfo::ByteSize) as usize
}

fn relocatable_field_exists<T>(ptr: *const T) -> bool {
    if relocatable_field_info(ptr, FieldInfo::Exists) == 0 {
        false
    } else {
        true
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RelocatableFieldAccessError {
    SizeMismatch { expected: usize, actual: usize },
    ProbeRead(i32),
}

#[inline(always)]
pub fn relocatable_field_read<T>(ptr: *const T) -> Result<Option<T>, RelocatableFieldAccessError> {
    if relocatable_field_exists(ptr) {
        let expected = core::mem::size_of::<i32>();
        let actual = relocatable_field_byte_size(ptr);
        if expected == actual {
            let offset = relocatable_field_byte_offset(ptr);
            // SAFETY: We trust LLVM to emit a correct BTF relocation for
            // that offset, and we trust BPF loader libraries to patch it
            // accordingly.
            let field = unsafe {
                bpf_probe_read_kernel(&*ptr.add(offset))
                    .map_err(|code| RelocatableFieldAccessError::ProbeRead(code))?
            };
            Ok(Some(field))
        } else {
            Err(RelocatableFieldAccessError::SizeMismatch { expected, actual })
        }
    } else {
        Ok(None)
    }
}

#[repr(C)]
struct task_struct {
    pid: i32,
    tgid: i32,
}

impl task_struct {
    pub fn pid(&self) -> Result<Option<i32>, RelocatableFieldAccessError> {
        relocatable_field_read(::core::ptr::addr_of!(self.pid))
    }

    pub fn tgid(&self) -> Result<Option<i32>, RelocatableFieldAccessError> {
        relocatable_field_read(::core::ptr::addr_of!(self.pid))
    }
}

#[kprobe]
pub fn kprobe_try_to_wake_up(ctx: ProbeContext) -> u32 {
    let _ = try_kprobe_try_to_wake_up(ctx);
    0
}

fn try_kprobe_try_to_wake_up(ctx: ProbeContext) -> Result<u32, i32> {
    let task: *const task_struct = ctx.arg(0).ok_or(-1)?;
    let task = unsafe { &*task };
    let pid = task.pid().map_err(|_| -1)?.ok_or(-1)?;
    let tgid = task.tgid().map_err(|_| -1)?.ok_or(-1)?;

    let state: c_uint = ctx.arg(1).ok_or(-1)?;
    let wake_flags: c_int = ctx.arg(2).ok_or(-1)?;

    info!(
        &ctx,
        "`try_to_wake_up`: pid: {}, tgid: {}, state: {}, wake_flags: {}",
        pid,
        tgid,
        state,
        wake_flags
    );

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
