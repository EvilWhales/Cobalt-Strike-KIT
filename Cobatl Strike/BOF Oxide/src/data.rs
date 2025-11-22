use core::ffi::{c_char, c_int};

use crate::{BeaconDataExtractFn, BeaconDataIntFn, BeaconDataLengthFn, BeaconDataParseFn, BeaconDataShortFn, BeaconFormatAllocFn, BeaconFormatFreeFn, DataP, FormatP};


pub struct Data {
    beacon_format_alloc: BeaconFormatAllocFn,
    beacon_format_free: BeaconFormatFreeFn,
    beacon_data_parse: BeaconDataParseFn,
    beacon_data_int: BeaconDataIntFn,
    beacon_data_short: BeaconDataShortFn,
    beacon_data_length: BeaconDataLengthFn,
    beacon_data_extract: BeaconDataExtractFn,
    buffer: FormatP,
    parser: DataP,
    args: *mut c_char,
    alen: c_int,
}

impl Data {
    pub fn new(
        beacon_format_alloc: BeaconFormatAllocFn,
        beacon_format_free: BeaconFormatFreeFn,
        beacon_data_parse: BeaconDataParseFn,
        beacon_data_int: BeaconDataIntFn,
        beacon_data_short: BeaconDataShortFn,
        beacon_data_length: BeaconDataLengthFn,
        beacon_data_extract: BeaconDataExtractFn,
        args: *mut c_char,
        alen: c_int,
    ) -> Self {
        let mut buffer = FormatP {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        let mut parser = DataP {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        unsafe {
            (beacon_format_alloc)(&mut buffer, 256);
        }
        unsafe {
            (beacon_data_parse)(&mut parser, args, alen);
        }

        Data {
            beacon_format_alloc,
            beacon_format_free,
            beacon_data_parse,
            beacon_data_int,
            beacon_data_short,
            beacon_data_length,
            beacon_data_extract,
            buffer,
            parser,
            args,
            alen
        }
    }
    pub fn free(&mut self) {
        unsafe { (self.beacon_format_free)(&mut self.buffer) }
    }

    pub fn extract_str(&mut self) -> *const c_char {

        let ip = unsafe {
            let mut size: c_int = 0;

            let str_arg = (self.beacon_data_extract)(&mut self.parser, &mut size);

            str_arg
        };
        
        //let ip = c_char_to_u8(ip as *const u8);
        ip
    }

    pub fn extract_int(&mut self) -> c_int {
        let mut parser = DataP {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        };
        
        let mut size: c_int = 0;

        let int = unsafe {
            (self.beacon_data_int)(&mut parser)
        };

        int
    }
}


pub unsafe fn c_strlen(s: *const c_char) -> usize {
    unsafe {
        let mut count = 0;
        while *s.add(count) != 0 {
            count += 1;
        }
        count
    }
}

// Potentially dangerous
pub fn c_char_to_u8(ptr: *const u8) -> &'static [u8] {
    // Determine the length of the string
    let len = unsafe { c_strlen(ptr as *const i8) };

    // Read the string from the pointer
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };

    slice
}