const std = @import("std");
const PROT = std.posix.PROT;
const process = @import("process.zig");

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
    hooks: std.AutoHashMap(usize, usize),

    pub fn init(allocator: std.mem.Allocator, target: *const process.Process, payload_path: []const u8) !Injector {
        std.log.info("Loading {s}...", .{payload_path});
        const payload_handle = try target.loadLibrary(payload_path);
        std.log.info("Obtained handle for {s}: 0x{x}", .{ payload_path, payload_handle });

        const load_addr = try target.getFuncFrom(payload_path, "load");
        const clean_addr = try target.getFuncFrom(payload_path, "clean");
        const exec_addr = try target.getFuncFrom(payload_path, "exec");

        const load_result = try target.execFunc(load_addr, &[_]usize{});
        std.log.info("load() -> {d}", .{load_result});
        if (load_result == 1) {
            std.log.err("Failed to load runtime", .{});
            std.posix.exit(1);
        }

        const hooks = std.AutoHashMap(usize, usize).init(allocator);

        return .{
            .allocator = allocator,
            .target = target,
            .payload_handle = payload_handle,
            .clean_addr = clean_addr,
            .exec_addr = exec_addr,
            .hooks = hooks,
        };
    }

    pub fn deinit(self: *const Injector) !void {
        std.log.debug("Unloading runtime...", .{});
        const clean_result = try self.target.execFunc(self.clean_addr, &[_]usize{});
        std.log.debug("clean() -> {d}", .{clean_result});
        if (clean_result != 0) {
            return error.RuntimeCleanFailed;
        }

        try self.target.unloadLibrary(self.payload_handle);
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

    pub fn hook(self: *const Injector, addr: usize) !void {
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
