const std = @import("std");
const process = @import("process.zig");
const injector = @import("injector.zig");
const c = @cImport({
    // Should I just convert this to Zig? What about cross-platform support?
    @cInclude("capstone/capstone.h");
});

var CSHandle: c.csh = undefined;

// TODO: REPL for live code exec

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    if (args.len != 4) {
        const prog = std.fs.path.basename(args[0]);
        std.log.err("usage: {s} <pid> <library> <code_or_file>", .{prog});
        return;
    }
    const target = process.Process.init(allocator, try std.fmt.parseInt(std.posix.pid_t, args[1], 10));
    defer target.deinit();
    const lib_path = try std.fs.path.resolve(allocator, &.{args[2]});
    defer allocator.free(lib_path);

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return error.CapstoneSetupFail;
    }
    defer _ = c.cs_close(&CSHandle);

    if (!try target.isAlive()) {
        std.log.err("Process doesn't exist!", .{});
        std.posix.exit(1);
    }

    try target.attach();

    const lua_injector = try injector.Injector.init(allocator, &target, lib_path);
    defer lua_injector.deinit() catch |err| {
        std.log.err("Failed to unload injector: {}", .{err});
    };

    lua_injector.injectFile(args[3]) catch {
        try lua_injector.inject(args[3]);
    };

    const hook_me_addr = try target.getFuncFrom("", "hook_me");
    try lua_injector.hook(hook_me_addr);
}

// Do I *need* capstone? It does alleviate the need to write disassemblers for various platforms.
// Being able to disassemble arbitrary chunks of memory at runtime would be handy.
// TODO: Disassemble arbitrary locations in memory
// TODO: Figure out where I want to put. Lite capstone wrapper?
fn disassemble(code: []const u8, address: usize) !void {
    var insn: [*c]c.cs_insn = undefined;
    const count = c.cs_disasm(CSHandle, @ptrCast(code), code.len, address, 0, &insn);
    defer c.cs_free(insn, count);
    if (count > 0) {
        for (0..count) |i| {
            std.log.debug("0x{x}:\t{s}\t{s}", .{ insn[i].address, insn[i].mnemonic, insn[i].op_str });
        }
    } else {
        return error.DisassembleFailed;
    }
}

// FIX: I don't know why, but sometimes tests will just hang. Running the same code outside a test case works...
//
// fn setupTest(allocator: std.mem.Allocator) !process.Process {
//     if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
//         std.log.err("Failed to open Capstone disassembler.", .{});
//         return error.CapstoneSetupFail;
//     }
//
//     const filepath = try std.fs.realpathAlloc(allocator, "./zig-out/bin/basic-print-loop");
//     defer allocator.free(filepath);
//     const header = try process.getELFHeaderFromFile(allocator, filepath);
//
//     var child = std.process.Child.init(&.{
//         filepath,
//     }, allocator);
//
//     try child.spawn();
//     var target = process.Process{ .pid = child.id };
//     try target.attach();
//     try target.continueUntil(header.entry);
//
//     return target;
// }
//
// fn cleanupTest(target: *process.Process) !void {
//     std.log.debug("Closing capstone...", .{});
//     _ = c.cs_close(&CSHandle);
//     std.log.debug("Continuing target {d}...", .{target.pid});
//     try ptrace(PTRACE.CONT, target.pid, 0, 0);
//     try target.detach();
//     std.log.debug("Killing target {d}...", .{target.pid});
//     _ = try target.kill();
// }
//
// test "create rwx page with mmap" {
//     const allocator = std.testing.allocator;
//     var target = try setupTest(allocator);
//
//     const rxw_page = try target.injectMmap(0, std.mem.page_size);
//     std.log.info("RWX Page: 0x{x}", .{rxw_page});
//
//     const mmap_min_addr_file = try std.fs.openFileAbsolute("/proc/sys/vm/mmap_min_addr", .{});
//     defer mmap_min_addr_file.close();
//     var buffer: [64]u8 = undefined;
//     const count = try mmap_min_addr_file.readAll(&buffer);
//     const min_map_addr = try std.fmt.parseInt(usize, std.mem.trim(u8, buffer[0..count], &std.ascii.whitespace), 10);
//
//     try std.testing.expect(rxw_page >= min_map_addr);
//
//     try cleanupTest(&target);
// }
//
// test "load shared object with dlopen()" {
//     const allocator = std.testing.allocator;
//     var target = try setupTest(allocator);
//
//     _ = try target.loadLibrary(allocator, "./zig-out/lib/libpic-hello.so");
//
//     try cleanupTest(&target);
// }
