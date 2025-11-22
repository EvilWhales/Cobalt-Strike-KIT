const std = @import("std");

pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "artifact64big",
        .root_source_file = b.path("template.zig"),
        .target = b.resolveTargetQuery(.{ .cpu_arch = .x86_64, .os_tag = .windows }),
        .optimize = .ReleaseSmall,
    });

    const payloadSize = b.option(u32, "payloadSize", "size of shellcode") orelse 350000;

    const options = b.addOptions();
    options.addOption(u32, "payloadSize", payloadSize);

    exe.root_module.addOptions("build_options", options);

    b.installArtifact(exe);
}
