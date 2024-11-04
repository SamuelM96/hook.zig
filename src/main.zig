const std = @import("std");
const process = @import("process.zig");
const injector = @import("injector.zig");
const c = @cImport({
    // Should I just convert this to Zig? What about cross-platform support?
    @cInclude("capstone/capstone.h");
});

var CSHandle: c.csh = undefined;

// TODO: REPL for live code exec

// HACK: Not a big fan of this approach...
// Must be a better way of handling this state and cleanly exiting
var target: ?process.Process = null;
var lua_injector: ?injector.Injector = null;
fn signalHandler(_: c_int) callconv(.C) void {
    std.log.debug("SIGINT received", .{});
    if (lua_injector) |i| {
        i.deinit() catch |err| {
            std.log.err("Failed to unload injector: {}", .{err});
        };
    }
    if (target) |t| {
        t.deinit();
    }
    std.posix.exit(1);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // TODO: Handle CTRL-C on other platforms
    const sigact = std.os.linux.sigaction(
        std.os.linux.SIG.INT,
        &std.os.linux.Sigaction{
            .handler = .{ .handler = signalHandler },
            .mask = std.os.linux.empty_sigset,
            .flags = 0,
        },
        null,
    );
    if (sigact != 0) {
        return error.SignalHandlerError;
    }

    const args = try std.process.argsAlloc(allocator);
    if (args.len != 4) {
        const prog = std.fs.path.basename(args[0]);
        std.log.err("usage: {s} <pid> <library> <code_or_file>", .{prog});
        return;
    }
    target = process.Process.init(allocator, try std.fmt.parseInt(std.posix.pid_t, args[1], 10));
    const lib_path = try std.fs.path.resolve(allocator, &.{args[2]});
    defer allocator.free(lib_path);

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return error.CapstoneSetupFail;
    }
    defer _ = c.cs_close(&CSHandle);

    if (!try target.?.isAlive()) {
        std.log.err("Process doesn't exist!", .{});
        std.posix.exit(1);
    }

    try target.?.attach();

    lua_injector = try injector.Injector.init(allocator, &target.?, lib_path);
    defer lua_injector.?.deinit() catch |err| {
        std.log.err("Failed to unload injector: {}", .{err});
    };

    lua_injector.?.injectFile(args[3]) catch {
        try lua_injector.?.inject(args[3]);
    };

    std.log.info("Hooking function hook_me()...", .{});
    const hook_me_addr = try target.?.getFuncFrom("", "hook_me");
    const code = "return function() print(\"hooked!\") end";
    try lua_injector.?.hook(hook_me_addr, code);
    std.log.info("Running injector...", .{});
    try lua_injector.?.run();

    // TODO: Message handling
    //
    // I need a way for the payload to communicate back to the host.
    // - Add/remove hooks
    // - Send/receive data
    //
    // There's various IPC options available:
    // - Shared memory + semaphores
    //   - Potential extra option for transferring large amounts of data?
    //   - High performance, but additional complexity due to semaphores
    // - Unix domain sockets or TCP/IP sockets
    //   - Classic, pretty much works everywhere, a lot of info available
    //   - Unix domain sockets are performant
    //   - TCP/IP sockets would work well for remote processes
    // - Named pipes/FIFOs
    //   - Simple
    //   - Local only, mainly aimed at unidirectional communication
    // - Signals
    //   - Not really meant for data transfer and could affect the instrumented process
    // - SysV/POSIX message queues
    //   - Good for structured messages
    //   - Asynchronous
    //   - Could be complex, but probably not more than sockets I'd assume
    //   - Potential overhead due to the message management
    // - D-Bus
    //   - Common message bus system on Linux
    //   - Higher level of abstraction than sockets/shared memory
    //   - Has built-in security features for access control
    //   - Adds complexity
    //   - Abstraction adds performance overhead (context switches a lot)
    //
    // There's probably more options on other platforms, but focusing on Linux for now.
    // What about remote processes too? E.g., injecting into a separate device (mobile, embedded, etc)
    //
    // Sockets seem to be a good way to go. Cross-platform support seems good, and the ability
    // to switch between local and remote connections is nice too. I'd need to build out the
    // abstractions myself.
    //
    // Once the transport mechanism has been decided, there's still the message format.
    // - Any standardised options available?
    // - What metadata to include?
    //   - Version information
    //   - Message type
    //   - Sequence number
    //   - Timestamps?
    // - Message size? Fragmentation? Variable size?
    // - Extensibility? Backwards compatibility?
    // - Encoding? Binary (protobufs? custom?), JSON, XML, etc
    // - Security?
    //   - Access controls: don't want random processes getting access
    //   - Input validation: don't want the target to attack back
    // - Acknowledgement? Synchronisation?
    // - Error handling? Recovery?
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
