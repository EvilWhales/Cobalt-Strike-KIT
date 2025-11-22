#![no_main]
#![no_std]
#![allow(non_upper_case_globals)]
mod beacon;
mod rust_bof;
use beacon::{Beacon, BeaconOutputFn, BeaconPrintfFn, DataP, FormatP};
use core::ffi::{c_char, c_int};
use rust_bof::rust_bof;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn initialize(
    output: BeaconOutputFn,
    printf: BeaconPrintfFn,
    data_extract: extern "C" fn(parser: *mut DataP, alen: c_int) -> *mut c_char,
    data_parse: extern "C" fn(datap: *mut DataP, args: *mut c_char, alen: c_int),
    data_int: extern "C" fn(datap: *mut DataP) -> c_int,
    // Arguments from Beacon
    args: *mut c_char,
    alen: c_int,
) {
    let mut beacon = Beacon::new(
        output,
        printf,
        data_extract,
        data_parse,
        data_int,
        args,
        alen,
    );
    rust_bof(beacon);
}

#[panic_handler]
#[unsafe(no_mangle)]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
