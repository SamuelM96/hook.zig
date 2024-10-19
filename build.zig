const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "hook.zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkSystemLibrary("capstone");
    exe.linkLibC();
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_unit_tests.linkSystemLibrary("capstone");
    exe_unit_tests.linkLibC();

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const unit_test_step = b.step("test-unit", "Run unit tests");
    unit_test_step.dependOn(&run_exe_unit_tests.step);

    const run_exe_integration_tests = b.addRunArtifact(exe_unit_tests);

    const c_tests = [_][]const u8{
        "basic-print-loop",
    };

    inline for (c_tests) |test_name| {
        const c_test = b.addExecutable(.{
            .name = test_name,
            .target = target,
            .optimize = optimize,
        });
        const file = std.fmt.comptimePrint("tests/{s}.c", .{test_name});
        c_test.addCSourceFile(.{ .file = .{ .cwd_relative = file }, .flags = &[_][]const u8{"-std=c99"} });
        c_test.linkLibC();
        run_exe_integration_tests.step.dependOn(&b.addInstallArtifact(c_test, .{}).step);
    }

    run_exe_integration_tests.has_side_effects = true;
    const integration_test_step = b.step("test-integration", "Run integration tests");
    integration_test_step.dependOn(&run_exe_integration_tests.step);
}
