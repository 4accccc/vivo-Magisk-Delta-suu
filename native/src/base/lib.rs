#![feature(format_args_nl)]

pub use libc;

pub use consts::*;
pub use files::*;
pub use logging::*;
pub use misc::*;
pub use xwrap::*;

mod consts;
mod files;
mod logging;
mod misc;
mod xwrap;

#[cxx::bridge]
pub mod ffi {
    #[derive(Copy, Clone)]
    pub enum LogLevel {
        Error,
        Warn,
        Info,
        Debug,
    }

    extern "Rust" {
        fn log_with_rs(level: LogLevel, msg: &[u8]);
        fn exit_on_error(b: bool);
        fn set_log_level_state(level: LogLevel, enabled: bool);
        fn cmdline_logging();
    }

    #[namespace = "rust"]
    extern "Rust" {
        fn xpipe2(fds: &mut [i32; 2], flags: i32) -> i32;
        fn fd_path(fd: i32, buf: &mut [u8]) -> isize;
    }
}
