const std = @import("std");
const PROT = std.posix.PROT;
const process = @import("process.zig");
const ptrace = std.posix.ptrace;
const PTRACE = std.os.linux.PTRACE;

// TODO: Support different payload runtimes
// - Raw shellcode (FASM?)
// - TCC for C
// - QuickJS
// - Python
// - Dynamically compile .zig libraries if `zig` is available?
// TODO: Design a common interface for payload libraries
// - If there's a defined C ABI, then it should be possible? All boils down to loading the library in memory and initialising it, then feeding it data to execute.
// TODO: Luajit FFI back to Zig
// TODO: Cache compiled Lua functions
//
// TODO: Function hooking
// - Save prologue (how many bytes?)
// - Save clobbered registers
// - Setup arguments to give registers and what callback
// - Jump to payload to execute callback
// - Execute saved prologue, then jump back to original code to continue
// - For exit override, set breakpoint on return address
// - Track hooks, callbacks, and addresses

pub const Injector = struct {
    allocator: std.mem.Allocator,
    target: *const process.Process,
    payload_handle: usize,
    clean_addr: usize,
    exec_addr: usize,
    hook_addr: usize,
    handle_addr: usize,
    hooked_addresses: std.AutoHashMap(usize, usize),

    pub fn init(allocator: std.mem.Allocator, target: *const process.Process, payload_path: []const u8) !Injector {
        std.log.info("Loading {s}...", .{payload_path});
        const payload_handle = try target.loadLibrary(payload_path);
        std.log.info("Obtained handle for {s}: 0x{x}", .{ payload_path, payload_handle });

        const load_addr = try target.getFuncFrom(payload_path, "load");
        const clean_addr = try target.getFuncFrom(payload_path, "clean");
        const exec_addr = try target.getFuncFrom(payload_path, "exec");
        const hook_addr = try target.getFuncFrom(payload_path, "hook");
        const handle_addr = try target.getFuncFrom(payload_path, "handle");

        const load_result = try target.execFunc(load_addr, &[_]usize{});
        std.log.info("load() -> {d}", .{load_result});
        if (load_result == 1) {
            std.log.err("Failed to load runtime", .{});
            std.posix.exit(1);
        }

        return .{
            .allocator = allocator,
            .target = target,
            .payload_handle = payload_handle,
            .clean_addr = clean_addr,
            .exec_addr = exec_addr,
            .hook_addr = hook_addr,
            .handle_addr = handle_addr,
            .hooked_addresses = std.AutoHashMap(usize, usize).init(allocator),
        };
    }

    pub fn deinit(self: *const Injector) !void {
        std.log.debug("Stopping process {d}...", .{self.target.pid});
        try std.posix.kill(self.target.pid, std.posix.SIG.STOP);
        const res = std.posix.waitpid(self.target.pid, 0);
        if (!std.posix.W.IFSTOPPED(res.status)) {
            std.log.debug("Error: {}", .{res.status});
            return error.WaitpidFailed;
        }
        var iter = self.hooked_addresses.iterator();
        std.log.info("Unhooking {d} functions...", .{self.hooked_addresses.count()});
        while (iter.next()) |entry| {
            const addr = entry.key_ptr.*;
            const inst = entry.value_ptr.*;
            std.log.debug("Unhooking 0x{x}...", .{addr});
            try ptrace(PTRACE.POKEDATA, self.target.pid, addr, inst);
        }
        std.log.debug("Unloading runtime...", .{});
        const clean_result = try self.target.execFunc(self.clean_addr, &[_]usize{});
        std.log.debug("clean() -> {d}", .{clean_result});
        if (clean_result != 0) {
            return error.RuntimeCleanFailed;
        }

        try self.target.unloadLibrary(self.payload_handle);
        std.log.debug("Resuming process {d}...", .{self.target.pid});
        try ptrace(PTRACE.CONT, self.target.pid, 0, 0);
        // TODO: Clean up mmap'd memory
    }

    pub fn inject(self: *const Injector, code: []const u8) !void {
        // TODO: Cache functions
        const code_addr = try self.target.injectMmap(0, code.len + 1, .{});
        std.log.debug("Obtained RWX memory @ 0x{x}", .{code_addr});

        std.log.debug("Writing code to inject into process...", .{});
        try self.target.writeData(code_addr, code);

        std.log.debug("Executing code...", .{});
        const exec_result = try self.target.execFunc(self.exec_addr, &[_]usize{code_addr});
        std.log.debug("exec(code) -> {d}", .{exec_result});
    }

    pub inline fn injectFile(self: *const Injector, path: []const u8) !void {
        if (std.fs.cwd().readFileAlloc(self.allocator, path, std.math.maxInt(usize))) |code| {
            const c = std.mem.trim(u8, code, &[_]u8{ ' ', '\n', '\r', '\t' });
            return self.inject(c);
        } else |err| {
            return err;
        }
    }

    pub fn hook(self: *Injector, addr: usize, code: []const u8) !void {
        std.log.info("Hooking function @ 0x{x}", .{addr});

        const rwx_mem = try self.target.injectMmap(0, code.len + 1, .{});
        try self.target.writeData(rwx_mem, code);
        if (try self.target.execFunc(self.hook_addr, &[_]usize{ addr, rwx_mem }) == 0) {
            var inst: usize = undefined;
            std.log.debug("Patching 0x{x} with a breakpoint...", .{addr});
            try ptrace(PTRACE.PEEKDATA, self.target.pid, addr, @intFromPtr(&inst));
            try ptrace(PTRACE.POKEDATA, self.target.pid, addr, (inst & ~@as(usize, 0xFF)) | 0xCC);
            try self.hooked_addresses.put(addr, inst);
        } else {
            return error.HookFuncFailed;
        }

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

    pub fn run(self: *const Injector) !void {
        // TODO: Move this loop to Process (waitUntilBreakpoint()?)
        var signal: u32 = std.posix.SIG.CONT;
        while (true) {
            try ptrace(PTRACE.CONT, self.target.pid, 0, @intCast(signal));
            const result = std.posix.waitpid(self.target.pid, 0);
            signal = std.posix.W.STOPSIG(result.status);
            if (std.posix.W.IFSTOPPED(result.status) and signal == std.posix.SIG.TRAP) {
                var regs = try self.target.getRegs();
                regs.rip -= 1;
                if (self.hooked_addresses.get(regs.rip)) |inst| {
                    std.log.info("Hit hooked function @ 0x{x}, triggering callback...", .{regs.rip});
                    try ptrace(PTRACE.SETREGS, self.target.pid, 0, @intFromPtr(&regs));
                    try ptrace(PTRACE.POKEDATA, self.target.pid, regs.rip, inst);
                    if (try self.target.execFunc(self.handle_addr, &[_]usize{regs.rip}) != 0) {
                        return error.HandleCallbackFailed;
                    }
                    try ptrace(PTRACE.SINGLESTEP, self.target.pid, 0, 0);
                    const res = std.posix.waitpid(self.target.pid, 0);
                    if (!std.posix.W.IFSTOPPED(res.status)) {
                        std.log.debug("Error: {}", .{res.status});
                        return error.WaitpidFailed;
                    }
                    try ptrace(PTRACE.POKEDATA, self.target.pid, regs.rip, (inst & ~@as(usize, 0xFF)) | 0xCC);
                } else {
                    std.log.err("Stopped on unknown address: 0x{x}. Continuing...", .{regs.rip});
                }
                signal = std.posix.SIG.CONT;
                continue;
            } else if (std.posix.W.IFSIGNALED(result.status)) {
                // TODO: Provide a debug dump when the target exits unintentionally
                std.log.err("Process {d} terminated due to signal {d}", .{ self.target.pid, std.posix.W.TERMSIG(result.status) });
                std.posix.exit(1);
            } else if (std.posix.W.IFEXITED(result.status)) {
                std.log.err("Process {d} exited with status {d}", .{ self.target.pid, std.posix.W.EXITSTATUS(result.status) });
                std.posix.exit(1);
            }
        }
    }
};
