use crate::Beacon;
use core::ffi::c_char;

// This will be the main file we edit to write out BOFs.
pub fn rust_bof(mut beacon: Beacon) {
    let str_arg = beacon.get_arg();
    if str_arg.is_null() {
        beacon.output("Please provide a str:\"arg\"");
    } else {
        beacon.printf("Hello %s from rust bof\0", str_arg as *mut c_char);
    }
}
