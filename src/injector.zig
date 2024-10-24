const std = @import("std");
const PROT = std.posix.PROT;
const process = @import("process.zig");

pub const Injector = struct {
    allocator: std.mem.Allocator,
    target: *const process.Process,
    payload_path: []const u8,
    payload_handle: usize,
    clean_addr: usize,
    exec_addr: usize,

    pub fn init(allocator: std.mem.Allocator, target: *const process.Process, payload_path: []const u8) !Injector {
        std.log.info("Loading {s}...", .{payload_path});
        const payload_handle = try target.loadLibrary(allocator, payload_path);
        std.log.info("Obtained handle for {s}: 0x{x}", .{ payload_path, payload_handle });

        const lua_load_addr = try target.getFuncFrom(allocator, payload_path, "load");
        const lua_clean_addr = try target.getFuncFrom(allocator, payload_path, "clean");
        const lua_exec_addr = try target.getFuncFrom(allocator, payload_path, "exec");

        const lua_load_result = try target.execFunc(lua_load_addr, &[_]usize{});
        std.log.info("load() -> {d}", .{lua_load_result});
        if (lua_load_result == 1) {
            std.log.err("Failed to load luajit runtime", .{});
            std.posix.exit(1);
        }

        return .{
            .allocator = allocator,
            .target = target,
            .payload_path = payload_path,
            .payload_handle = payload_handle,
            .clean_addr = lua_clean_addr,
            .exec_addr = lua_exec_addr,
        };
    }

    pub fn inject(self: *const Injector, code: []const u8) !void {
        // TODO: Cache functions
        const lua_code_addr = try self.target.injectMmap(0, code.len + 1, .{});
        std.log.debug("Obtained RWX memory @ 0x{x}", .{lua_code_addr});

        std.log.debug("Writing lua code to inject into process...", .{});
        try self.target.writeData(lua_code_addr, code);

        std.log.debug("Executing lua code...", .{});
        const lua_exec_result = try self.target.execFunc(self.exec_addr, &[_]usize{lua_code_addr});
        std.log.debug("exec(lua_code) -> {d}", .{lua_exec_result});
    }

    pub inline fn injectFile(self: *const Injector, path: []const u8) !void {
        if (std.fs.cwd().readFileAlloc(self.allocator, path, std.math.maxInt(usize))) |code| {
            const lua_code = std.mem.trim(u8, code, &[_]u8{ ' ', '\n', '\r', '\t' });
            return self.inject(lua_code);
        } else |err| {
            return err;
        }
    }

    pub fn deinit(self: *const Injector) !void {
        std.log.debug("Unloading lua...", .{});
        const lua_clean_result = try self.target.execFunc(self.clean_addr, &[_]usize{});
        std.log.debug("clean() -> {d}", .{lua_clean_result});

        try self.target.unloadLibrary(self.allocator, self.payload_handle);
        // TODO: Clean up mmap'd memory
    }
};
