const std = @import("std");
const PTRACE = std.os.linux.PTRACE;
const PROT = std.posix.PROT;
const ptrace = std.posix.ptrace;
const pid_t = std.os.linux.pid_t;
const c = @cImport({
    // Should I just convert these to Zig? What about cross-platform support?
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
    @cInclude("linux/mman.h");
    @cInclude("capstone/capstone.h");
});

const CSErrors = error{FailedToDisassemble};
var CSHandle: c.csh = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    if (args.len != 2) {
        std.log.err("usage: {s} <pid>", .{args[0]});
        return;
    }
    const pid = try std.fmt.parseInt(pid_t, args[1], 10);

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return;
    }
    defer _ = c.cs_close(&CSHandle);

    // Signal 0 just tests if the process exists
    std.posix.kill(pid, 0) catch |err| {
        switch (err) {
            std.posix.KillError.ProcessNotFound => std.log.err("Proccess not found!", .{}),
            else => std.log.err("{}", .{err}),
        }
        return;
    };

    try attach(pid);
    defer detach(pid) catch |err| std.log.err("Failed to detach from {d}: {}", .{ pid, err });

    const entry = try getEntryFromMemory(allocator, pid);
    std.log.warn("Entry: 0x{x}", .{entry});

    const rxw_page = try injectMmap(pid, 0, std.mem.page_size, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.info("RWX @ 0x{x}", .{rxw_page});
}

inline fn attach(pid: pid_t) !void {
    std.log.debug("Attaching to {d}...", .{pid});
    try ptrace(PTRACE.ATTACH, pid, 0, 0);
    const result = std.posix.waitpid(pid, 0);
    if (!c.WIFSTOPPED(result.status)) {
        std.log.debug("Error: {}", .{result});
        return error.WaitPidFailed;
    }
}

inline fn detach(pid: pid_t) !void {
    std.log.debug("Detaching from {d}...", .{pid});
    try ptrace(PTRACE.DETACH, pid, 0, 0);
}

inline fn injectMmap(pid: pid_t, addr: usize, length: usize, prot: i64, flags: i64, fd: i64, offset: usize) !usize {
    var regs: c.user_regs_struct = undefined;
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));

    // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    regs.rax = 9; // mmap syscall
    regs.rdi = addr;
    regs.rsi = length;
    regs.rdx = @bitCast(prot);
    regs.r10 = @bitCast(flags);
    regs.r8 = @bitCast(fd);
    regs.r9 = offset;

    std.log.debug("mmap registers: {}", .{regs});

    try injectSyscall(pid, &regs);

    return regs.rax;
}

fn injectSyscall(pid: pid_t, regs: *c.user_regs_struct) !void {
    var orig_regs: c.user_regs_struct = undefined;
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&orig_regs));
    std.log.debug("Original registers: {}", .{orig_regs});

    var inst: usize = undefined;
    try ptrace(PTRACE.PEEKDATA, pid, orig_regs.rip, @intFromPtr(&inst));
    std.log.debug("Saved current instruction: 0x{x}", .{inst});
    std.log.debug("Disassembling: 0x{x}", .{inst});
    var code = std.mem.toBytes(inst);
    std.mem.byteSwapAllFields([code.len]u8, &code);
    disassemble(&code, orig_regs.rip) catch |err| {
        std.log.debug("Error: {}: 0x{x}", .{ err, inst });
    };

    std.log.debug("Setting registers: {}", .{regs});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(regs));

    // TODO: Cross-platform syscall support
    const syscallInst: u16 = 0x050f;
    std.log.debug("Writing syscall instruction: 0x{x}", .{syscallInst});
    try ptrace(PTRACE.POKEDATA, pid, regs.rip, syscallInst);

    std.log.debug("Executing syscall...", .{});
    try ptrace(PTRACE.SINGLESTEP, pid, 0, 0);
    const result = std.posix.waitpid(pid, 0);
    if (!c.WIFSTOPPED(result.status)) {
        std.log.debug("Error: {}", .{result.status});
        return error.WaitPidFailed;
    }
    const signal = c.WSTOPSIG(@as(c_int, @intCast(result.status)));
    std.log.debug("Signal: {}", .{signal});

    std.log.debug("Getting register data...", .{});
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(regs));
    std.log.debug("Data: {}", .{regs});

    std.log.debug("Restoring original instruction: 0x{x}", .{inst});
    try ptrace(PTRACE.POKEDATA, pid, orig_regs.rip, inst);

    std.log.debug("Restoring original registers: {}", .{orig_regs});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&orig_regs));
}

// Do I *need* capstone? It does alleviate the need to write disassemblers for various platforms.
// Being able to disassemble arbitrary chunks of memory at runtime would be handy.
fn disassemble(code: []const u8, address: usize) CSErrors!void {
    var insn: [*c]c.cs_insn = undefined;
    const count = c.cs_disasm(CSHandle, @ptrCast(code), code.len, address, 0, &insn);
    defer c.cs_free(insn, count);
    if (count > 0) {
        for (0..count) |i| {
            std.log.debug("0x{x}:\t{s}\t{s}", .{ insn[i].address, insn[i].mnemonic, insn[i].op_str });
        }
    } else {
        return CSErrors.FailedToDisassemble;
    }
}

fn baseAddress(allocator: std.mem.Allocator, pid: pid_t, filename: []const u8) !usize {
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(maps_path);

    const file = try std.fs.openFileAbsolute(maps_path, .{});
    defer file.close();

    var reader = std.io.bufferedReader(file.reader());
    var stream = reader.reader();
    var buf: [1024]u8 = undefined;

    while (try stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        if (filename.len != 0 and std.mem.indexOf(u8, line, filename) == null) {
            continue;
        }
        const dash_index = std.mem.indexOfScalar(u8, line, '-') orelse return error.InvalidMapsFile;
        return std.fmt.parseInt(usize, line[0..dash_index], 16);
    }

    return error.NotFoundInMapsFile;
}

fn breakUntil(pid: pid_t, addr: usize) !void {
    var inst: u16 = undefined;
    std.log.debug("Patching 0x{x} with a breakpoint...", .{addr});
    try ptrace(PTRACE.PEEKDATA, pid, addr, @intFromPtr(&inst));
    try ptrace(PTRACE.POKEDATA, pid, addr, 0xCC);

    std.log.debug("Continuing until breakpoint @ 0x{x}...", .{addr});
    while (true) {
        try ptrace(PTRACE.CONT, pid, 0, 0);
        const result = std.posix.waitpid(pid, 0);
        const signal = c.WSTOPSIG(@as(c_int, @intCast(result.status)));
        if (c.WIFSTOPPED(result.status) and signal == c.SIGTRAP) {
            break;
        }
    }

    var regs: c.user_regs_struct = undefined;
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
    std.log.debug("Hit breakpoint @ 0x{x}...", .{regs.rip});
    std.log.debug("Restoring previous instruction 0x{x}...", .{inst});
    regs.rip -= 1;
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    try ptrace(PTRACE.POKEDATA, pid, addr, inst);
    return;
}

fn getMinimumMapAddr() !usize {
    const mmap_min_addr_file = try std.fs.openFileAbsolute("/proc/sys/vm/mmap_min_addr", .{});
    defer mmap_min_addr_file.close();
    var buffer: [64]u8 = undefined;
    const count = try mmap_min_addr_file.readAll(&buffer);
    return try std.fmt.parseInt(usize, std.mem.trim(u8, buffer[0..count], &std.ascii.whitespace), 10);
}

fn getEntryFromFile(allocator: std.mem.Allocator, filepath: []const u8) !usize {
    var file = try std.fs.openFileAbsolute(filepath, .{});
    defer file.close();

    const raw = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(raw);

    var stream = std.io.fixedBufferStream(raw);
    const hdr = try std.elf.Header.read(&stream);

    return hdr.entry;
}

fn getEntryFromMemory(allocator: std.mem.Allocator, pid: pid_t) !usize {
    var header: std.elf.Elf64_Ehdr = undefined;
    const base = try baseAddress(allocator, pid, "");
    var i: usize = 0;
    while (i < @sizeOf(@TypeOf(header))) : (i += @sizeOf(usize)) {
        var data: usize = undefined;
        try ptrace(PTRACE.PEEKDATA, pid, base + i, @intFromPtr(&data));
        @memcpy(@as([*]u8, @ptrCast(&header)) + i, &std.mem.toBytes(data));
    }
    return header.e_entry;
}

test "create rwx page with mmap" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return;
    }
    defer _ = c.cs_close(&CSHandle);

    const filepath = try std.fs.realpathAlloc(allocator, "./zig-out/bin/basic-print-loop");
    defer allocator.free(filepath);
    std.log.debug("Getting entry addresss...", .{});
    const entry = try getEntryFromFile(allocator, filepath);
    std.log.info("Entry: 0x{x}", .{entry});

    var target = std.process.Child.init(&.{
        filepath,
    }, allocator);

    try target.spawn();
    std.log.info("PID: {}", .{target.id});

    try attach(target.id);
    try breakUntil(target.id, entry);

    const rxw_page = try injectMmap(target.id, 0, std.mem.page_size, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.info("RWX Page: 0x{x}", .{rxw_page});

    try std.testing.expect(rxw_page >= try getMinimumMapAddr());

    try detach(target.id);
    _ = target.kill() catch {};
}
