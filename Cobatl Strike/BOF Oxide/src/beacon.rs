use core::ffi::{c_char, c_int, c_short, c_void};
pub type BeaconOutputFn = extern "C" fn(i32, *const c_char, i32);
pub type BeaconPrintfFn = extern "C" fn(i32, *const c_char, *mut c_char);

pub struct Beacon {
    pub format: FormatP,
    pub data: DataP,
    pub output_addr: BeaconOutputFn,
    pub printf_addr: BeaconPrintfFn,
    pub data_extract: extern "C" fn(parser: *mut DataP, alen: c_int) -> *mut c_char,
    pub data_parse: extern "C" fn(datap: *mut DataP, args: *mut c_char, alen: c_int),
    pub data_int: extern "C" fn(datap: *mut DataP) -> c_int,
    pub args: *const c_char,
    pub alen: c_int,
}

impl Beacon {
    pub fn new(
        output: BeaconOutputFn,
        printf: BeaconPrintfFn,
        data_extract: extern "C" fn(parser: *mut DataP, alen: c_int) -> *mut c_char,
        data_parse: extern "C" fn(datap: *mut DataP, args: *mut c_char, alen: c_int),
        data_int: extern "C" fn(datap: *mut DataP) -> c_int,
        args: *const c_char,
        alen: c_int,
    ) -> Self {
        let mut beacon = Beacon {
            format: FormatP::new(),
            data: DataP::new(),
            output_addr: output,
            printf_addr: printf,
            data_extract: data_extract,
            data_parse: data_parse,
            data_int: data_int,
            args,
            alen,
        };
        beacon.parse_args();

        return beacon;
    }

    pub fn output(&mut self, data: &str) {
        unsafe {
            (self.output_addr)(0, data.as_ptr() as *const c_char, data.len() as i32);
            (self.output_addr)(0, core::ptr::null_mut() as *const c_char, 0 as i32)
        };
    }

    pub fn printf(&mut self, str: &str, arg: *mut c_char) {
        unsafe {
            (self.printf_addr)(0, str.as_ptr() as *const c_char, arg as *mut c_char);
        }
    }
    pub fn get_arg(&mut self) -> *mut c_char {
        unsafe { (self.data_extract)(&mut self.data, 0 as c_int) }
    }

    pub fn get_int(&mut self) -> c_int {
        unsafe { (self.data_int)(&mut self.data) }
    }

    pub fn parse_args(&mut self) {
        unsafe { (self.data_parse)(&mut self.data, self.args as *mut c_char, self.alen) }
    }
}

#[repr(C, align(8))]
pub struct FormatP {
    pub original: *mut c_char,
    pub buffer: *mut c_char,
    pub length: c_int,
    pub size: c_int,
}

impl FormatP {
    pub fn new() -> Self {
        FormatP {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        }
    }
}

#[repr(C)]
pub struct DataP {
    pub original: *mut c_char,
    pub buffer: *mut c_char,
    pub length: c_int,
    pub size: c_int,
}

impl DataP {
    pub fn new() -> Self {
        DataP {
            original: core::ptr::null_mut(),
            buffer: core::ptr::null_mut(),
            length: 0,
            size: 0,
        }
    }
}
