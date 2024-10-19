const std = @import("std");
const PTRACE = std.os.linux.PTRACE;
const PROT = std.posix.PROT;
const ptrace = std.posix.ptrace;
const pid_t = std.os.linux.pid_t;
const c = @cImport({
    // Should I just convert these to Zig? What about cross-platform support?
    @cInclude("sys/user.h");
    @cInclude("linux/mman.h");
    @cInclude("capstone/capstone.h");
});

const CSErrors = error{FailedToDisassemble};
var CSHandle: c.csh = undefined;

pub fn main() !void {
    const args = try std.process.argsAlloc(std.heap.page_allocator);
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

    const rxw_page = try injectMmap(pid, 0, std.mem.page_size, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.info("RWX @ 0x{x}", .{rxw_page});
}

inline fn attach(pid: pid_t) !void {
    std.log.debug("Attaching to {d}...", .{pid});
    try ptrace(PTRACE.ATTACH, pid, 0, 0);
    _ = std.posix.waitpid(pid, 0);
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

    disassemble(&std.mem.toBytes(inst), orig_regs.rip) catch |err| {
        std.log.err("{}: {x}", .{ err, inst });
    };

    std.log.debug("Setting registers: {}", .{regs});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(regs));

    // TODO: Cross-platform syscall support
    const syscallInst: u16 = 0x050f;
    std.log.debug("Writing syscall instruction: 0x{x}", .{syscallInst});
    disassemble(&std.mem.toBytes(syscallInst), orig_regs.rip) catch |err| {
        std.log.err("{}: {x}", .{ err, syscallInst });
    };
    try ptrace(PTRACE.POKEDATA, pid, orig_regs.rip, syscallInst);

    std.log.debug("Executing syscall...", .{});
    try ptrace(PTRACE.SINGLESTEP, pid, 0, 0);
    _ = std.posix.waitpid(pid, 0);

    std.log.debug("Getting register data...", .{});
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(regs));

    std.log.debug("Restoring original instruction: 0x{x}", .{inst});
    try ptrace(PTRACE.POKEDATA, pid, orig_regs.rip, inst);

    std.log.debug("Restoring original registers: {}", .{orig_regs});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&orig_regs));
}

// Do I *need* capstone? It does alleviate the need to write disassemblers for various platforms.
// Being able to disassemble arbitrary chunks of memory at runtime would be handy.
fn disassemble(code: []const u8, address: usize) CSErrors!void {
    var insn: [*c]c.cs_insn = undefined;
    const count = c.cs_disasm(CSHandle, @ptrCast(&code), code.len, address, 0, &insn);
    defer c.cs_free(insn, count);
    if (count > 0) {
        for (0..count) |i| {
            std.log.debug("0x{x}:\t{s}\t{s}", .{ insn[i].address, insn[i].mnemonic, insn[i].op_str });
        }
    } else {
        return CSErrors.FailedToDisassemble;
    }
}

test "create rwx page with mmap" {
    // TODO: Add tests
    // Hmmm, what would be the best way to do this... Integration tests with sample programs?
}
