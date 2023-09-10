const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    var sip_module = b.createModule(.{
        .source_file = .{ .path = "siphash.zig" },
    });
    var hsip_module = b.createModule(.{
        .source_file = .{ .path = "halfsiphash.zig" },
    });

    const test_step = b.step("test", "Run library tests");

    const sip_test = b.addTest(.{
        .root_source_file = .{ .path = "tests/test_siphash.zig" },
        .target = target,
        .optimize = optimize,
    });
    const hsip_test = b.addTest(.{
        .root_source_file = .{ .path = "tests/test_halfsiphash.zig" },
        .target = target,
        .optimize = optimize,
    });

    sip_test.addModule("siphash", sip_module);
    hsip_test.addModule("halfsiphash", hsip_module);

    const run_sip_tests = b.addRunArtifact(sip_test);
    test_step.dependOn(&run_sip_tests.step);
    const run_hsip_tests = b.addRunArtifact(hsip_test);
    test_step.dependOn(&run_hsip_tests.step);
}
