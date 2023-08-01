use std::cmp::min;
use std::ffi::CStr;
use std::fmt::Arguments;
use std::{fmt, slice};

pub fn copy_str(dest: &mut [u8], src: &[u8]) -> usize {
    let len = min(src.len(), dest.len() - 1);
    dest[..len].copy_from_slice(&src[..len]);
    dest[len] = b'\0';
    len
}

struct BufFmtWriter<'a> {
    buf: &'a mut [u8],
    used: usize,
}

impl<'a> BufFmtWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BufFmtWriter { buf, used: 0 }
    }
}

impl<'a> fmt::Write for BufFmtWriter<'a> {
    // The buffer should always be null terminated
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if self.used >= self.buf.len() - 1 {
            // Silent truncate
            return Ok(());
        }
        self.used += copy_str(&mut self.buf[self.used..], s.as_bytes());
        // Silent truncate
        Ok(())
    }
}

pub fn fmt_to_buf(buf: &mut [u8], args: Arguments) -> usize {
    let mut w = BufFmtWriter::new(buf);
    if let Ok(()) = fmt::write(&mut w, args) {
        w.used
    } else {
        0
    }
}

#[macro_export]
macro_rules! bfmt {
    ($buf:expr, $($args:tt)*) => {
        $crate::fmt_to_buf($buf, format_args!($($args)*));
    };
}

#[macro_export]
macro_rules! bfmt_cstr {
    ($buf:expr, $($args:tt)*) => {{
        let len = $crate::fmt_to_buf($buf, format_args!($($args)*));
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(&$buf[..(len + 1)]) }
    }};
}

// The cstr! macro is inspired by https://github.com/Nugine/const-str

macro_rules! const_assert {
    ($s: expr) => {
        assert!($s)
    };
}

pub struct ToCStr<'a>(pub &'a str);

impl ToCStr<'_> {
    const fn assert_no_nul(&self) {
        let bytes = self.0.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            const_assert!(bytes[i] != 0);
            i += 1;
        }
    }

    pub const fn eval_len(&self) -> usize {
        self.assert_no_nul();
        self.0.as_bytes().len() + 1
    }

    pub const fn eval_bytes<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0; N];
        let mut pos = 0;
        let bytes = self.0.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            const_assert!(bytes[i] != 0);
            buf[pos] = bytes[i];
            pos += 1;
            i += 1;
        }
        pos += 1;
        const_assert!(pos == N);
        buf
    }
}

#[macro_export]
macro_rules! cstr {
    ($s:literal) => {{
        const LEN: usize = $crate::ToCStr($s).eval_len();
        const BUF: [u8; LEN] = $crate::ToCStr($s).eval_bytes();
        unsafe { std::ffi::CStr::from_bytes_with_nul_unchecked(&BUF) }
    }};
}

#[macro_export]
macro_rules! str_ptr {
    ($s:literal) => {{
        cstr!($s).as_ptr()
    }};
}

pub fn ptr_to_str<'a, T>(ptr: *const T) -> &'a str {
    if ptr.is_null() {
        "(null)"
    } else {
        unsafe { CStr::from_ptr(ptr.cast()) }.to_str().unwrap_or("")
    }
}

pub fn errno() -> &'static mut i32 {
    unsafe { &mut *libc::__errno() }
}

pub fn error_str() -> &'static str {
    unsafe { ptr_to_str(libc::strerror(*errno())) }
}

// When len is 0, don't care whether buf is null or not
#[inline]
pub unsafe fn slice_from_ptr<'a, T>(buf: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(buf, len)
    }
}

// When len is 0, don't care whether buf is null or not
#[inline]
pub unsafe fn slice_from_ptr_mut<'a, T>(buf: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        &mut []
    } else {
        slice::from_raw_parts_mut(buf, len)
    }
}

pub trait FlatData {
    fn as_raw_bytes(&self) -> &[u8]
    where
        Self: Sized,
    {
        unsafe {
            let self_ptr = self as *const Self as *const u8;
            slice::from_raw_parts(self_ptr, std::mem::size_of::<Self>())
        }
    }
    fn as_raw_bytes_mut(&mut self) -> &mut [u8]
    where
        Self: Sized,
    {
        unsafe {
            let self_ptr = self as *mut Self as *mut u8;
            slice::from_raw_parts_mut(self_ptr, std::mem::size_of::<Self>())
        }
    }
}
