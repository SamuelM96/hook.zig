const std = @import("std");
const elf = std.elf;
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
    if (args.len != 4) {
        const prog = std.fs.path.basename(args[0]);
        std.log.err("usage: {s} <pid> <library> <code_or_file>", .{prog});
        return;
    }
    const pid = try std.fmt.parseInt(pid_t, args[1], 10);
    const lib_path = try std.fs.path.resolve(allocator, &.{args[2]});
    defer allocator.free(lib_path);

    var lua_code: []const u8 = undefined;
    if (std.fs.cwd().readFileAlloc(allocator, args[3], std.math.maxInt(usize))) |code| {
        lua_code = std.mem.trim(u8, code, &[_]u8{ ' ', '\n', '\r', '\t' });
        std.log.info("Lua file to inject:\n{s}", .{lua_code});
    } else |_| {
        lua_code = args[3];
        std.log.info("Lua string to inject: {s}", .{lua_code});
    }

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

    std.log.info("Loading {s}...", .{lib_path});
    const lib_handle = try loadLibrary(allocator, pid, lib_path);
    std.log.info("Obtained handle for {s}: 0x{x}", .{ lib_path, lib_handle });

    const lua_load_addr = try getFuncFrom(allocator, pid, lib_path, "load");
    const lua_load_result = try execFunc(pid, lua_load_addr, &[_]usize{});
    std.log.info("load() -> {d}", .{lua_load_result});
    if (lua_load_result == 1) {
        std.log.err("Failed to load luajit runtime", .{});
        std.posix.exit(1);
    }

    const lua_code_addr = try injectMmap(pid, 0, lua_code.len + 1, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.debug("Obtained RWX memory @ 0x{x}", .{lua_code_addr});

    std.log.debug("Writing lua code to inject into process...", .{});
    try writeData(pid, lua_code_addr, lua_code);

    const lua_exec_addr = try getFuncFrom(allocator, pid, lib_path, "exec");
    const lua_exec_result = try execFunc(pid, lua_exec_addr, &[_]usize{lua_code_addr});
    std.log.info("exec(lua_code) -> {d}", .{lua_exec_result});

    const dlclose_addr = try getFuncFrom(allocator, pid, "libc", "dlclose@@GLIBC_2.34");
    std.log.info("Unloading {s}...", .{lib_path});
    const result = try execFunc(pid, dlclose_addr, &[_]usize{lib_handle});
    std.log.info("dlclose(0x{x}) -> {d}", .{ lib_handle, result });

    // TODO: Cache function and base addresses
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
    var regs = try getRegs(pid);

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

test "create rwx page with mmap" {
    const allocator = std.testing.allocator;
    var target = try setupTest(allocator);

    const rxw_page = try injectMmap(target.id, 0, std.mem.page_size, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.info("RWX Page: 0x{x}", .{rxw_page});

    try std.testing.expect(rxw_page >= try getMinimumMapAddr());

    try cleanupTest(&target);
}

fn injectSyscall(pid: pid_t, regs: *c.user_regs_struct) !void {
    // HACK: Technically this save/restore logic could be made into an inline wrapper or similar
    // I'll wait until the code gets more complex to avoid premature optimisaton.
    var orig_regs = try getRegs(pid);
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

    var regs = try getRegs(pid);
    std.log.debug("Hit breakpoint @ 0x{x}...", .{regs.rip});
    std.log.debug("Restoring previous instruction 0x{x}...", .{inst});
    regs.rip -= 1;
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    try ptrace(PTRACE.POKEDATA, pid, addr, inst);
    return;
}

fn execFunc(pid: pid_t, addr: usize, args: []const usize) !usize {
    var orig_regs = try getRegs(pid);
    var regs = orig_regs;
    regs.rip = addr;
    regs.rax = 0;

    std.log.debug("Setting return address to 0x{x}...", .{orig_regs.rip});
    regs.rsp = orig_regs.rsp - 256;
    try ptrace(PTRACE.POKEDATA, pid, regs.rsp, orig_regs.rip);

    for (0..args.len, args) |i, arg| {
        // TODO: Support other ABIs
        switch (i) {
            0 => regs.rdi = arg,
            1 => regs.rsi = arg,
            2 => regs.rdx = arg,
            3 => regs.rcx = arg,
            4 => regs.r8 = arg,
            5 => regs.r9 = arg,
            else => {
                regs.rsp -= @sizeOf(usize);
                try ptrace(PTRACE.POKEDATA, pid, regs.rsp, arg);
            },
        }
    }

    std.log.debug("Calling function @ 0x{x}...", .{addr});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&regs));
    try continueUntil(pid, orig_regs.rip);

    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
    const ret: usize = @intCast(regs.rax);

    std.log.debug("Restoring previous state...", .{});
    try ptrace(PTRACE.SETREGS, pid, 0, @intFromPtr(&orig_regs));

    return ret;
}

fn loadLibrary(allocator: std.mem.Allocator, pid: pid_t, lib_path: []const u8) !usize {
    const rwx_area = try injectMmap(pid, 0, lib_path.len + 1, PROT.READ | PROT.WRITE | PROT.EXEC, c.MAP_PRIVATE | c.MAP_ANONYMOUS, 0, 0);
    std.log.debug("Obtained RWX memory @ 0x{x}", .{rwx_area});

    std.log.debug("Writing path of library to inject into process...", .{});
    try writeData(pid, rwx_area, lib_path);

    const dlopen_name = "dlopen@@GLIBC_2.34";
    const dlopen_addr = try getFuncFrom(allocator, pid, "libc", dlopen_name);

    const lib_handle: usize = try execFunc(pid, dlopen_addr, &[_]usize{ rwx_area, c.RTLD_NOW });
    if (lib_handle == 0) {
        return error.InvalidLibraryHandle;
    }

    return lib_handle;
}

// FIX: I don't know why, but sometimes tests will just hang. Running the same code outside a test case works...
test "load shared object with dlopen()" {
    const allocator = std.testing.allocator;
    var target = try setupTest(allocator);

    _ = try loadLibrary(allocator, target.id, "./zig-out/lib/libpic-hello.so");

    try cleanupTest(&target);
}

fn getBaseAddress(allocator: std.mem.Allocator, pid: pid_t, filename: []const u8) !usize {
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

fn getMinimumMapAddr() !usize {
    const mmap_min_addr_file = try std.fs.openFileAbsolute("/proc/sys/vm/mmap_min_addr", .{});
    defer mmap_min_addr_file.close();
    var buffer: [64]u8 = undefined;
    const count = try mmap_min_addr_file.readAll(&buffer);
    return try std.fmt.parseInt(usize, std.mem.trim(u8, buffer[0..count], &std.ascii.whitespace), 10);
}

fn getELFHeaderFromFile(allocator: std.mem.Allocator, filepath: []const u8) !elf.Header {
    var file = try std.fs.openFileAbsolute(filepath, .{});
    defer file.close();

    const raw = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(raw);

    var stream = std.io.fixedBufferStream(raw);
    return try elf.Header.read(&stream);
}

fn getELFHeaderFromRegion(pid: pid_t, base: usize) !elf.Header {
    var header: elf.Elf64_Ehdr = undefined;
    var i: usize = 0;
    while (i < @sizeOf(@TypeOf(header))) : (i += @sizeOf(usize)) {
        var data: usize = undefined;
        try ptrace(PTRACE.PEEKDATA, pid, base + i, @intFromPtr(&data));
        @memcpy(@as([*]u8, @ptrCast(&header)) + i, &std.mem.toBytes(data));
    }
    return elf.Header.parse(@alignCast(&std.mem.toBytes(header)));
}

fn getFuncFrom(allocator: std.mem.Allocator, pid: pid_t, region_name: []const u8, func_name: []const u8) !usize {
    // TODO: Get base addr and path at the same time
    // Maybe just return a hashmap of the maps file? {base: path, ...}
    const base = try getBaseAddress(allocator, pid, region_name);
    std.log.info("{s} base @ 0x{x}", .{ region_name, base });

    const region_path = try getPathForRegion(allocator, pid, base);
    std.log.info("Path: {s}", .{region_path});

    const region_file = try std.fs.openFileAbsolute(region_path, .{});
    const raw_elf = try region_file.readToEndAlloc(allocator, std.math.maxInt(usize));

    const func_offset = try getFunctionOffset(raw_elf, func_name);
    const func_addr = base + func_offset;
    std.log.info("Located {s} @ offset 0x{x} (0x{x})", .{ func_name, func_offset, func_addr });
    return func_addr;
}

fn getFunctionOffset(elf_file: []const u8, func_name: []const u8) !usize {
    // TODO: Support 32 bit ELFs
    const raw_header = elf_file[0..@sizeOf(elf.Elf64_Ehdr)];
    const header = try elf.Header.parse(@ptrCast(@alignCast(raw_header)));
    std.log.debug("Getting offset for {s}...", .{func_name});

    var stream = std.io.fixedBufferStream(elf_file);
    var iter = header.section_header_iterator(&stream);
    var symtab_shdr: ?elf.Elf64_Shdr = null;
    var strtab_shdr: ?elf.Elf64_Shdr = null;
    var idx: usize = 0;
    while (try iter.next()) |shdr| {
        if (shdr.sh_type == elf.SHT_SYMTAB) {
            std.log.debug("[{d}] Got .symtab @ 0x{x}", .{ idx, shdr.sh_offset });
            symtab_shdr = shdr;
        }

        // HACK: Will strtab always be after symtab?
        if (shdr.sh_type == elf.SHT_STRTAB and symtab_shdr != null and idx == symtab_shdr.?.sh_link) {
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

    const len = symtab_shdr.?.sh_size / @sizeOf(elf.Elf64_Sym);
    for (0..len) |i| {
        const offset: usize = i * @sizeOf(elf.Elf64_Sym);
        const sym = @as(*const elf.Elf64_Sym, @alignCast(@ptrCast(symtab.ptr + offset)));
        const name = std.mem.span(@as([*c]const u8, &strtab[sym.st_name]));
        if (sym.st_type() == elf.STT_FUNC) {
            // std.log.debug("{d}: Found {s} @ 0x{x}: {?}", .{ i, name, sym.st_value, sym });
            if (std.mem.eql(u8, name, func_name)) {
                return sym.st_value;
            }
        }
    }

    return error.FuncNotFound;
}

inline fn getRegs(pid: pid_t) !c.struct_user_regs_struct {
    var regs: c.user_regs_struct = undefined;
    try ptrace(PTRACE.GETREGS, pid, 0, @intFromPtr(&regs));
    return regs;
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
