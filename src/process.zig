const std = @import("std");
const elf = std.elf;
const pid_t = std.posix.pid_t;
const PROT = std.posix.PROT;
const PTRACE = std.os.linux.PTRACE;
const ptrace = std.posix.ptrace;

// TODO: Add other mmap flags
// Main reason for this is, as far as I can tell, the Zig std library
// does not have MAP_ANONYMOUS
const MAP_SHARED = 0x01;
const MAP_PRIVATE = 0x02;
const MAP_SHARED_VALIDATE = 0x03;
const MAP_ANONYMOUS = 0x20;

const RTLD_NOW = 2;

// TODO: Support other platform types
// - Android
// - iOS
// - Windows
// - macOS
// - FreeBSD
// TODO: Support different process injection methods
// - Windows debugging API
// - GDB/LLDB
// - LD_PRELOAD/patching
// TODO: Account for not all architectures supporting PTRACE_SINGLESTEP
// - Can just PEEKDATA & POKEDATA a bunch to set breakpoints
pub const Process = struct {
    pid: pid_t,

    pub inline fn isAlive(self: *const Process) !bool {
        std.posix.kill(self.pid, 0) catch |err| {
            switch (err) {
                std.posix.KillError.ProcessNotFound => return false,
                else => return err,
            }
        };
        return true;
    }

    pub inline fn attach(self: *const Process) !void {
        std.log.debug("Attaching to {d}...", .{self.pid});
        try ptrace(PTRACE.ATTACH, self.pid, 0, 0);
        const result = std.posix.waitpid(self.pid, 0);
        // FIX: Probably need to handle signal-delivery-stop here
        // TODO: Refactor waitpid logic, its handled the same way around the code pretty much
        if (!std.posix.W.IFSTOPPED(result.status)) {
            std.log.debug("Error: {}", .{result});
            return error.WaitpidFailed;
        }
    }

    pub inline fn detach(self: *const Process) !void {
        std.log.debug("Detaching from {d}...", .{self.pid});
        try ptrace(PTRACE.DETACH, self.pid, 0, 0);
    }

    pub inline fn writeData(self: *const Process, addr: usize, data: []const u8) !void {
        for (0..data.len, data) |i, datum| {
            try ptrace(PTRACE.POKEDATA, self.pid, addr + i, datum);
        }
    }

    pub inline fn readData(self: *const Process, addr: usize, dest: []u8) !void {
        const aligned_size: usize = @intFromFloat(@round(@as(f128, @floatFromInt(dest.len)) / @sizeOf(usize)));
        for (0..aligned_size) |i| {
            var datum: usize = undefined;
            const offset = i * @sizeOf(usize);
            try ptrace(PTRACE.PEEKDATA, self.pid, addr + offset, @intFromPtr(&datum));
            const len = if (dest.len - offset < @sizeOf(usize)) dest.len - offset else @sizeOf(usize);
            std.mem.copyForwards(u8, dest[offset..dest.len], std.mem.toBytes(datum)[0..len]);
        }
    }

    pub fn execFunc(self: *const Process, addr: usize, args: []const usize) !usize {
        var orig_regs = try self.getRegs();
        var regs = orig_regs;
        regs.rip = addr;
        regs.rax = 0;

        std.log.debug("Setting return address to 0x{x}...", .{orig_regs.rip});
        regs.rsp = orig_regs.rsp - 256;
        try ptrace(PTRACE.POKEDATA, self.pid, regs.rsp, orig_regs.rip);

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
                    try ptrace(PTRACE.POKEDATA, self.pid, regs.rsp, arg);
                },
            }
        }

        std.log.debug("Calling function @ 0x{x}...", .{addr});
        try ptrace(PTRACE.SETREGS, self.pid, 0, @intFromPtr(&regs));
        try self.continueUntil(orig_regs.rip);

        try ptrace(PTRACE.GETREGS, self.pid, 0, @intFromPtr(&regs));
        const ret: usize = @intCast(regs.rax);

        std.log.debug("Restoring previous state...", .{});
        try ptrace(PTRACE.SETREGS, self.pid, 0, @intFromPtr(&orig_regs));

        return ret;
    }

    // TODO: Conditional breakpoints
    // TODO: Track breakpoints in their own data structure so they can be configured at any point without continuing directly to them
    pub fn continueUntil(self: *const Process, addr: usize) !void {
        var inst: usize = undefined;
        std.log.debug("Patching 0x{x} with a breakpoint...", .{addr});
        try ptrace(PTRACE.PEEKDATA, self.pid, addr, @intFromPtr(&inst));
        try ptrace(PTRACE.POKEDATA, self.pid, addr, 0xCC);

        std.log.debug("Continuing until breakpoint @ 0x{x}...", .{addr});
        var signal: u32 = std.posix.SIG.CONT;
        while (true) {
            try ptrace(PTRACE.CONT, self.pid, 0, @intCast(signal));
            const result = std.posix.waitpid(self.pid, 0);
            signal = std.posix.W.STOPSIG(result.status);
            if (std.posix.W.IFSTOPPED(result.status) and signal == std.posix.SIG.TRAP) {
                break;
            } else if (std.posix.W.IFSIGNALED(result.status)) {
                // TODO: Provide a debug dump when the target exits unintentionally
                std.log.err("Process {d} terminated due to signal {d}", .{ self.pid, std.posix.W.TERMSIG(result.status) });
                std.posix.exit(1);
            } else if (std.posix.W.IFEXITED(result.status)) {
                std.log.err("Process {d} exited with status {d}", .{ self.pid, std.posix.W.EXITSTATUS(result.status) });
                std.posix.exit(1);
            }
        }

        var regs = try self.getRegs();
        std.log.debug("Hit breakpoint @ 0x{x}...", .{regs.rip});
        std.log.debug("Restoring previous instruction 0x{x}...", .{inst});
        regs.rip -= 1;
        try ptrace(PTRACE.SETREGS, self.pid, 0, @intFromPtr(&regs));
        try ptrace(PTRACE.POKEDATA, self.pid, addr, inst);
        return;
    }

    pub inline fn getRegs(self: *const Process) !UserRegs {
        var regs: UserRegs = undefined;
        try ptrace(PTRACE.GETREGS, self.pid, 0, @intFromPtr(&regs));
        return regs;
    }

    // TODO: Track allocated memory so it can be freed
    // TODO: munmap() to free mmap() allocated memory
    // TODO: Alternative: scan for code caves
    // TODO: Alternative: malloc and free (find addresses in memory)
    // TODO: Allocator abstraction around the different methods?
    pub inline fn injectMmap(self: *const Process, addr: usize, length: usize, args: struct { prot: i64 = PROT.READ | PROT.WRITE | PROT.EXEC, flags: i64 = MAP_PRIVATE | MAP_ANONYMOUS, fd: i64 = 0, offset: usize = 0 }) !usize {
        var regs = try self.getRegs();

        // void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
        regs.rax = 9; // mmap syscall
        regs.rdi = addr;
        regs.rsi = length;
        regs.rdx = @bitCast(args.prot);
        regs.r10 = @bitCast(args.flags);
        regs.r8 = @bitCast(args.fd);
        regs.r9 = args.offset;

        std.log.debug("mmap registers: {}", .{regs});

        try self.injectSyscall(&regs);

        return regs.rax;
    }

    pub fn injectSyscall(self: *const Process, regs: *UserRegs) !void {
        // HACK: Technically this save/restore logic could be made into an inline wrapper or similar
        // I'll wait until the code gets more complex to avoid premature optimisaton.
        var orig_regs = try self.getRegs();
        std.log.debug("Original registers: {}", .{orig_regs});

        var inst: usize = undefined;
        try ptrace(PTRACE.PEEKDATA, self.pid, orig_regs.rip, @intFromPtr(&inst));
        std.log.debug("Saved current instruction: 0x{x}", .{inst});
        std.log.debug("Disassembling: 0x{x}", .{inst});
        var code = std.mem.toBytes(inst);
        std.mem.byteSwapAllFields([code.len]u8, &code);
        // disassemble(&code, orig_regs.rip) catch |err| {
        //     std.log.debug("Error: {}: 0x{x}", .{ err, inst });
        // };

        std.log.debug("Setting registers: {}", .{regs});
        try ptrace(PTRACE.SETREGS, self.pid, 0, @intFromPtr(regs));

        // TODO: Cross-platform syscall support
        const syscallInst: u16 = 0x050f;
        std.log.debug("Writing syscall instruction: 0x{x}", .{syscallInst});
        try ptrace(PTRACE.POKEDATA, self.pid, regs.rip, syscallInst);

        std.log.debug("Executing syscall...", .{});
        try ptrace(PTRACE.SINGLESTEP, self.pid, 0, 0);
        const result = std.posix.waitpid(self.pid, 0);
        if (!std.posix.W.IFSTOPPED(result.status)) {
            std.log.debug("Error: {}", .{result.status});
            return error.WaitpidFailed;
        }
        const signal = std.posix.W.STOPSIG(result.status);
        std.log.debug("Signal: {}", .{signal});

        std.log.debug("Getting register data...", .{});
        try ptrace(PTRACE.GETREGS, self.pid, 0, @intFromPtr(regs));
        std.log.debug("Data: {}", .{regs});

        std.log.debug("Restoring original instruction: 0x{x}", .{inst});
        try ptrace(PTRACE.POKEDATA, self.pid, orig_regs.rip, inst);

        std.log.debug("Restoring original registers: {}", .{orig_regs});
        try ptrace(PTRACE.SETREGS, self.pid, 0, @intFromPtr(&orig_regs));
    }

    pub fn loadLibrary(self: *const Process, allocator: std.mem.Allocator, lib_path: []const u8) !usize {
        const rwx_area = try self.injectMmap(0, lib_path.len + 1, .{});
        std.log.debug("Obtained RWX memory @ 0x{x}", .{rwx_area});

        std.log.debug("Writing path of library to inject into process...", .{});
        try self.writeData(rwx_area, lib_path);

        const dlopen_name = "dlopen@@GLIBC_2.34";
        const dlopen_addr = try self.getFuncFrom(allocator, "libc", dlopen_name);

        const lib_handle: usize = try self.execFunc(dlopen_addr, &[_]usize{ rwx_area, RTLD_NOW });
        if (lib_handle == 0) {
            return error.InvalidLibraryHandle;
        }

        return lib_handle;
    }

    pub fn unloadLibrary(self: *const Process, allocator: std.mem.Allocator, handle: usize) !void {
        const dlclose_addr = try self.getFuncFrom(allocator, "libc", "dlclose@@GLIBC_2.34");
        const result = try self.execFunc(dlclose_addr, &[_]usize{handle});
        std.log.debug("dlclose(0x{x}) -> {d}", .{ handle, result });
        if (result != 0) {
            return error.CloseHandleFailed;
        }
    }

    pub fn getBaseAddress(self: *const Process, allocator: std.mem.Allocator, filename: []const u8) !usize {
        const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{self.pid});
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

    pub fn getMappedRegion(self: *const Process, allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
        const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{self.pid});
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
        try self.readData(start, &region);

        return region;
    }

    pub fn getPathForRegion(self: *const Process, allocator: std.mem.Allocator, base: usize) ![]u8 {
        const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{self.pid});
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
    pub fn getFuncFrom(self: *const Process, allocator: std.mem.Allocator, region_name: []const u8, func_name: []const u8) !usize {
        // TODO: Get base addr and path at the same time
        // Maybe just return a hashmap of the maps file? {base: path, ...}
        const base = try self.getBaseAddress(allocator, region_name);
        std.log.info("{s} base @ 0x{x}", .{ region_name, base });

        const region_path = try self.getPathForRegion(allocator, base);
        std.log.info("Path: {s}", .{region_path});

        const region_file = try std.fs.openFileAbsolute(region_path, .{});
        const raw_elf = try region_file.readToEndAlloc(allocator, std.math.maxInt(usize));

        const func_offset = try getFunctionOffset(raw_elf, func_name);
        const func_addr = base + func_offset;
        std.log.info("Located {s} @ offset 0x{x} (0x{x})", .{ func_name, func_offset, func_addr });
        return func_addr;
    }

    pub fn getELFHeaderFromRegion(self: *const Process, base: usize) !elf.Header {
        var header: elf.Elf64_Ehdr = undefined;
        var i: usize = 0;
        while (i < @sizeOf(@TypeOf(header))) : (i += @sizeOf(usize)) {
            var data: usize = undefined;
            try ptrace(PTRACE.PEEKDATA, self.pid, base + i, @intFromPtr(&data));
            @memcpy(@as([*]u8, @ptrCast(&header)) + i, &std.mem.toBytes(data));
        }
        return elf.Header.parse(@alignCast(&std.mem.toBytes(header)));
    }

    pub fn hook(self: *const Process, addr: usize) !void {
        std.log.info("Hooking function @ 0x{x}", .{addr});
        _ = self;

        // - Map function address to callback ID
        // - If hooking exit, set breakpoint at return address
        // - Disassemble iter from the start of the function until we have
        //   enough bytes to load our code in.
        // - Save those bytes based on total length of instructions iterated
        // - Override with trampoline
        //   - Push parameter types
        //   - Push state of registers according to struct layout
        //   - Set RDI to callback ID
        //   - Set RSI to registers struct RSP+offset
        //   - Set RDX to return type enum
        //   - Set RCX to param type enum array RSP+offset
        //   - Push return address (start of function)
        //   - Set RIP to callbackHandler(callback:usize, regs:Registers,
        //       returnType:CType, paramTypes:[]CType)
        //     - Handler can sort out pass original params to callback
        //   - Continue until return address
        // - If callback returns a result, jump to return address
        // - Else, restore prologue & original registers
        //   - Execute till end of prologue
        //   - Set breakpoint at start of function and continue execution
        // - If return address breakpoint is hit, repeat steps but trampoline to
        //   exit hook.
        //   - Remove return breakpoint once finished.
    }
};

// Copied from <sys/user.h>
pub const UserRegs = extern struct {
    r15: usize,
    r14: usize,
    r13: usize,
    r12: usize,
    rbp: usize,
    rbx: usize,
    r11: usize,
    r10: usize,
    r9: usize,
    r8: usize,
    rax: usize,
    rcx: usize,
    rdx: usize,
    rsi: usize,
    rdi: usize,
    orig_rax: usize,
    rip: usize,
    cs: usize,
    eflags: usize,
    rsp: usize,
    ss: usize,
    fs_base: usize,
    gs_base: usize,
    ds: usize,
    es: usize,
    fs: usize,
    gs: usize,
};

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

fn getELFHeaderFromFile(allocator: std.mem.Allocator, filepath: []const u8) !elf.Header {
    var file = try std.fs.openFileAbsolute(filepath, .{});
    defer file.close();

    const raw = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    defer allocator.free(raw);

    var stream = std.io.fixedBufferStream(raw);
    return try elf.Header.read(&stream);
}
