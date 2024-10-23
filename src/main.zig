const std = @import("std");
const PTRACE = std.os.linux.PTRACE;
const PROT = std.posix.PROT;
const ptrace = std.posix.ptrace;
const pid_t = std.os.linux.pid_t;
const c = @cImport({
    // Should I just convert these to Zig? What about cross-platform support?
    @cInclude("dlfcn.h");
    @cInclude("sys/user.h");
    @cInclude("sys/wait.h");
    @cInclude("linux/mman.h");
    @cInclude("capstone/capstone.h");
});

var CSHandle: c.csh = undefined;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    if (args.len != 3) {
        const prog = std.fs.path.basename(args[0]);
        std.log.err("usage: {s} <pid> <library>", .{prog});
        return;
    }
    const pid = try std.fmt.parseInt(pid_t, args[1], 10);
    const lib_path = try std.fs.path.resolve(allocator, &.{args[2]});
    defer allocator.free(lib_path);

    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return error.CapstoneSetupFail;
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

    const base = try baseAddress(allocator, pid, "libc");
    std.log.info("Base: 0x{x}", .{base});

    const header = try getELFHeaderFromRegion(pid, base);
    std.log.info("Entry: 0x{x}", .{header.entry});

    // e_shoff is often the last part of the header, and so can be used to calculate the total size
    // HACK: Technically this is not guaranteed, so worth adding a check and adding the option to determine from the maps file.
    // Matches the result of `ls -l` for now, soooo...
    const elf_size = header.shoff + (header.shentsize * header.shnum);
    std.log.info("ELF size: {d}", .{elf_size});

    const region_path = try getPathForRegion(allocator, pid, base);
    std.log.info("Path: {s}", .{region_path});

    const region_file = try std.fs.openFileAbsolute(region_path, .{});
    const raw_elf = try region_file.readToEndAlloc(allocator, std.math.maxInt(usize));

    const func = "dlopen@@GLIBC_2.34";
    const func_offset = try getFunctionOffset(header, raw_elf, func);
    const func_addr = base + func_offset;
    std.log.info("Located {s} @ offset 0x{x} (0x{x})", .{ func, func_offset, func_addr });

    // const lib_handle = try loadLibrary(allocator, pid, lib_path);
    // std.log.info("Obtained handle: 0x{x}", .{lib_handle});

    // TODO: Abstract out function calling
    // TODO: Call dlclose() on loaded library handle
}

inline fn readData(pid: pid_t, addr: usize, dest: *[]u8) !void {
    const aligned_size: usize = @intFromFloat(@round(@as(f128, @floatFromInt(dest.len)) / @sizeOf(usize)));
    for (0..aligned_size) |i| {
        var datum: usize = undefined;
        const offset = i * @sizeOf(usize);
        try ptrace(PTRACE.PEEKDATA, pid, addr + offset, @intFromPtr(&datum));
        const len = if (dest.len - offset < @sizeOf(usize)) dest.len - offset else @sizeOf(usize);
        std.mem.copyForwards(u8, dest.*[offset..dest.len], std.mem.toBytes(datum)[0..len]);
    }
}
inline fn writeData(pid: pid_t, addr: usize, data: []const u8) !void {
    for (0..data.len, data) |i, datum| {
        try ptrace(PTRACE.POKEDATA, pid, addr + i, datum);
    }
}

inline fn attach(pid: pid_t) !void {
    std.log.debug("Attaching to {d}...", .{pid});
    try ptrace(PTRACE.ATTACH, pid, 0, 0);
    const result = std.posix.waitpid(pid, 0);
    // FIX: Probably need to handle signal-delivery-stop here
    // TODO: Refactor waitpid logic, its handled the same way around the code pretty much
    if (!c.WIFSTOPPED(result.status)) {
        std.log.debug("Error: {}", .{result});
        return error.WaitpidFailed;
    }
}

inline fn detach(pid: pid_t) !void {
    std.log.debug("Detaching from {d}...", .{pid});
    try ptrace(PTRACE.DETACH, pid, 0, 0);
}

// TODO: Alternative: scan for code caves
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
    // HACK: Technically this save/restore logic would be make into an inline wrapper or similar
    // I'll wait until the code gets more complex to avoid premature optimisaton.
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
        return error.WaitpidFailed;
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
// TODO: Disassemble arbitrary locations in memory
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

fn getMappedRegion(allocator: std.mem.Allocator, pid: pid_t, filename: []const u8) ![]u8 {
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(maps_path);

    const file = try std.fs.openFileAbsolute(maps_path, .{});
    defer file.close();

    var reader = std.io.bufferedReader(file.reader());
    var stream = reader.reader();
    var buf: [1024]u8 = undefined;

    var exe_path = filename;
    var start: usize = 0;
    var end: usize = 0;
    while (try stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        if (exe_path.len != 0 and std.mem.indexOf(u8, line, exe_path) == null) {
            if (end != 0) {
                break;
            }
            continue;
        }

        var iter = std.mem.splitScalar(u8, line, ' ');
        const range = iter.next() orelse return error.InvalidMapsFile;
        const dash_index = std.mem.indexOfScalar(u8, range, '-') orelse return error.InvalidMapsFile;
        if (exe_path.len == 0) {
            start = try std.fmt.parseInt(usize, line[0..dash_index], 16);
            while (iter.next()) |data| {
                exe_path = data;
            }
        }
        end = try std.fmt.parseInt(usize, line[dash_index + 1 .. range.len], 16);
    }

    if (end == 0) {
        return error.NotFoundInMapsFile;
    }

    std.log.info("{s} : 0x{x} - 0x{x}", .{ exe_path, start, end });
    const total_size = end - start;
    var region = try allocator.alloc(u8, total_size);
    try readData(pid, start, &region);

    return region;
}

fn getPathForRegion(allocator: std.mem.Allocator, pid: pid_t, base: usize) ![]u8 {
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(maps_path);

    const file = try std.fs.openFileAbsolute(maps_path, .{});
    defer file.close();

    var reader = std.io.bufferedReader(file.reader());
    var stream = reader.reader();
    var buf: [1024]u8 = undefined;

    while (try stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        const dash_index = std.mem.indexOfScalar(u8, line, '-') orelse return error.InvalidMapsFile;
        const region_base: usize = try std.fmt.parseInt(usize, line[0..dash_index], 16);
        if (base == 0 or base == region_base) {
            var exe_path: ?[]const u8 = null;
            var iter = std.mem.splitScalar(u8, line, ' ');
            while (iter.next()) |data| {
                exe_path = data;
            }
            return allocator.dupe(u8, exe_path orelse return error.NotFoundInMapsFile);
        }
    }

    return error.NotFoundInMapsFile;
}

// TODO: Conditional breakpoints
// TODO: Track breakpoints in their own data structure so they can be configured at any point without continuing directly to them
fn continueUntil(pid: pid_t, addr: usize) !void {
    var inst: usize = undefined;
    std.log.debug("Patching 0x{x} with a breakpoint...", .{addr});
    try ptrace(PTRACE.PEEKDATA, pid, addr, @intFromPtr(&inst));
    try ptrace(PTRACE.POKEDATA, pid, addr, 0xCC);

    std.log.debug("Continuing until breakpoint @ 0x{x}...", .{addr});
    var signal = c.SIGCONT;
    while (true) {
        try ptrace(PTRACE.CONT, pid, 0, @intCast(signal));
        const result = std.posix.waitpid(pid, 0);
        const sig_int = @as(c_int, @intCast(result.status));
        signal = c.WSTOPSIG(sig_int);
        if (c.WIFSTOPPED(result.status) and signal == c.SIGTRAP) {
            break;
        } else if (c.WIFSIGNALED(result.status)) {
            // TODO: Provide a debug dump when the target exits unintentionally
            std.log.err("Process {d} terminated due to signal {d}", .{ pid, c.WTERMSIG(sig_int) });
            std.posix.exit(1);
        } else if (c.WIFEXITED(result.status)) {
            std.log.err("Process {d} exited with status {d}", .{ pid, c.WEXITSTATUS(sig_int) });
            std.posix.exit(1);
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

fn getELFHeaderFromFile(allocator: std.mem.Allocator, filepath: []const u8) !std.elf.Header {
    var file = try std.fs.openFileAbsolute(filepath, .{});
    defer file.close();

    const raw = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(raw);

    var stream = std.io.fixedBufferStream(raw);
    return try std.elf.Header.read(&stream);
}

fn getELFHeaderFromRegion(pid: pid_t, base: usize) !std.elf.Header {
    var header: std.elf.Elf64_Ehdr = undefined;
    var i: usize = 0;
    while (i < @sizeOf(@TypeOf(header))) : (i += @sizeOf(usize)) {
        var data: usize = undefined;
        try ptrace(PTRACE.PEEKDATA, pid, base + i, @intFromPtr(&data));
        @memcpy(@as([*]u8, @ptrCast(&header)) + i, &std.mem.toBytes(data));
    }
    return std.elf.Header.parse(@alignCast(&std.mem.toBytes(header)));
}

fn loadLibrary(allocator: std.mem.Allocator, pid: pid_t, lib_path: []const u8) !usize {
    const rwx_area = try injectMmap(pid, 0, lib_path.len + 1, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.debug("Obtained RWX memory @ 0x{x}", .{rwx_area});

    std.log.debug("Writing path of library to inject into process...", .{});
    try writeData(pid, rwx_area, lib_path);

    var orig_regs: c.user_regs_struct = undefined;
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&orig_regs));
    var regs = orig_regs;

    regs.rax = 0;
    regs.rdi = rwx_area;
    regs.rsi = c.RTLD_NOW;

    const libc_addr = try baseAddress(allocator, pid, "libc");
    const dlopen_offset = 0x93300; // TODO: Get dlopen offset at runtime
    const dlopen_addr = libc_addr + dlopen_offset;
    regs.rip = dlopen_addr;
    std.log.debug("dlopen() address found: 0x{x}", .{dlopen_addr});

    std.log.debug("Setting return address to 0x{x}...", .{orig_regs.rip});
    regs.rsp -= 256;
    try ptrace(PTRACE.POKEDATA, pid, regs.rsp, orig_regs.rip);

    std.log.debug("Forcing dlopen() call to load {s}...", .{lib_path});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    try continueUntil(pid, orig_regs.rip);

    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
    const lib_handle: usize = @intCast(regs.rax);
    if (lib_handle == 0) {
        return error.InvalidLibraryHandle;
    }

    std.log.debug("Restoring previous state...", .{});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&orig_regs));

    return lib_handle;
}

fn getFunctionOffset(header: std.elf.Header, elf_file: []const u8, func_name: []const u8) !usize {
    std.log.debug("Getting offset for {s}...", .{func_name});
    var stream = std.io.fixedBufferStream(elf_file);
    var iter = header.section_header_iterator(&stream);
    var symtab_shdr: ?std.elf.Elf64_Shdr = null;
    var strtab_shdr: ?std.elf.Elf64_Shdr = null;
    var idx: usize = 0;
    while (try iter.next()) |shdr| {
        if (shdr.sh_type == std.elf.SHT_SYMTAB) {
            std.log.debug("[{d}] Got .symtab @ 0x{x}", .{ idx, shdr.sh_offset });
            symtab_shdr = shdr;
        }

        // HACK: Will strtab always be after symtab?
        if (shdr.sh_type == std.elf.SHT_STRTAB and symtab_shdr != null and idx == symtab_shdr.?.sh_link) {
            std.log.debug("[{d}] Got .strstab @ 0x{x}", .{ idx, shdr.sh_offset });
            strtab_shdr = shdr;
        }

        idx += 1;
    }

    if (symtab_shdr == null) {
        return error.SymtabNotFound;
    } else if (strtab_shdr == null) {
        return error.StrtabNotFound;
    }

    const symtab_end = symtab_shdr.?.sh_offset + symtab_shdr.?.sh_size;
    const symtab = elf_file[symtab_shdr.?.sh_offset..symtab_end];

    const strtab_end = strtab_shdr.?.sh_offset + strtab_shdr.?.sh_size;
    const strtab = elf_file[strtab_shdr.?.sh_offset..strtab_end];

    const len = symtab_shdr.?.sh_size / @sizeOf(std.elf.Elf64_Sym);
    for (0..len) |i| {
        const offset: usize = i * @sizeOf(std.elf.Elf64_Sym);
        const sym = @as(*const std.elf.Elf64_Sym, @alignCast(@ptrCast(symtab.ptr + offset)));
        const name = std.mem.span(@as([*c]const u8, &strtab[sym.st_name]));
        if (sym.st_type() == std.elf.STT_FUNC) {
            // std.log.debug("{d}: Found {s} @ 0x{x}: {?}", .{ i, name, sym.st_value, sym });
            if (std.mem.eql(u8, name, func_name)) {
                return sym.st_value;
            }
        }
    }

    return error.FuncNotFound;
}

fn setupTest(allocator: std.mem.Allocator) !std.process.Child {
    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &CSHandle) != c.CS_ERR_OK) {
        std.log.err("Failed to open Capstone disassembler.", .{});
        return error.CapstoneSetupFail;
    }

    const filepath = try std.fs.realpathAlloc(allocator, "./zig-out/bin/basic-print-loop");
    defer allocator.free(filepath);
    const header = try getELFHeaderFromFile(allocator, filepath);

    var target = std.process.Child.init(&.{
        filepath,
    }, allocator);

    try target.spawn();
    try attach(target.id);
    try continueUntil(target.id, header.entry);

    return target;
}

fn cleanupTest(target: *std.process.Child) !void {
    std.log.debug("Closing capstone...", .{});
    _ = c.cs_close(&CSHandle);
    std.log.debug("Continuing target {d}...", .{target.id});
    try ptrace(PTRACE.CONT, target.id, 0, 0);
    try detach(target.id);
    std.log.debug("Killing target {d}...", .{target.id});
    _ = try target.kill();
}

test "create rwx page with mmap" {
    const allocator = std.testing.allocator;
    var target = try setupTest(allocator);

    const rxw_page = try injectMmap(target.id, 0, std.mem.page_size, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.info("RWX Page: 0x{x}", .{rxw_page});

    try std.testing.expect(rxw_page >= try getMinimumMapAddr());

    try cleanupTest(&target);
}

// FIX: I don't know why, but sometimes tests will just hang. Running the same code outside a test case works...
test "load shared object with dlopen()" {
    const allocator = std.testing.allocator;
    var target = try setupTest(allocator);

    _ = try loadLibrary(allocator, target.id, "./zig-out/lib/libpic-hello.so");

    try cleanupTest(&target);
}
