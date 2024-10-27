const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const payload = b.addSharedLibrary(.{
        .name = "payload",
        .root_source_file = b.path("src/payload.zig"),
        .target = target,
        .optimize = optimize,
    });
    payload.linkSystemLibrary("luajit-5.1");
    b.installArtifact(payload);

    const exe = b.addExecutable(.{
        .name = "hook.zig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.linkSystemLibrary("dl");
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

    // TODO: Refactor the test builds
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_unit_tests.linkSystemLibrary("dl");
    exe_unit_tests.linkSystemLibrary("capstone");
    exe_unit_tests.linkLibC();

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const unit_test_step = b.step("test-unit", "Run unit tests");
    unit_test_step.dependOn(&run_exe_unit_tests.step);

    var examples_step = b.step("examples", "Build examples exes and libs to try out");

    var exe_dir = try std.fs.cwd().openDir("examples/exe/", .{ .iterate = true });
    defer exe_dir.close();
    var iter = exe_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) {
            continue;
        }
        const c_exe = b.addExecutable(.{
            .name = std.fs.path.stem(entry.name),
            .target = target,
            .optimize = optimize,
        });
        const file = try std.fmt.allocPrint(b.allocator, "examples/exe/{s}", .{entry.name});
        c_exe.addCSourceFile(.{ .file = .{ .cwd_relative = file }, .flags = &[_][]const u8{"-std=c99"} });
        c_exe.linkLibC();
        examples_step.dependOn(&b.addInstallArtifact(c_exe, .{}).step);
    }

    var lib_dir = try std.fs.cwd().openDir("examples/lib/", .{ .iterate = true });
    defer lib_dir.close();
    iter = lib_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) {
            continue;
        }
        const c_lib = b.addSharedLibrary(.{
            .name = std.fs.path.stem(entry.name),
            .target = target,
            .optimize = optimize,
        });
        const file = try std.fmt.allocPrint(b.allocator, "examples/lib/{s}", .{entry.name});
        c_lib.addCSourceFile(.{ .file = .{ .cwd_relative = file }, .flags = &[_][]const u8{ "-std=c99", "-fPIC" } });
        c_lib.linkLibC();
        examples_step.dependOn(&b.addInstallArtifact(c_lib, .{}).step);
    }
}
