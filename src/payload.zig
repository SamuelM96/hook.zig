const std = @import("std");
const c = @cImport({
    @cInclude("luajit-2.1/lua.h");
    @cInclude("luajit-2.1/lualib.h");
    @cInclude("luajit-2.1/lauxlib.h");
});

var L: ?*c.lua_State = null;
var hooks: std.AutoHashMap(usize, c_int) = undefined;
// TODO: Combined allocator strategies
// Stack allocator for small allocations?
// Page allocator for larger allocations?
var allocator = std.heap.page_allocator;

export fn load() usize {
    L = c.luaL_newstate();
    if (L == null) {
        std.log.err("Failed to create Lua state", .{});
        return 1;
    }

    c.luaL_openlibs(L);
    hooks = std.AutoHashMap(usize, c_int).init(allocator);

    std.log.info("Loaded luajit runtime!", .{});
    return 0;
}

export fn clean() usize {
    c.lua_close(L);
    return 0;
}

export fn exec(code: [*c]const u8) usize {
    if (L == null and load() > 0) {
        return 1;
    }

    const status = c.luaL_dostring(L, code);
    if (status) {
        var len: usize = undefined;
        const err: [:0]const u8 = c.lua_tolstring(L, -1, &len)[0..len :0];
        std.log.err("Failed to execute code: {s}", .{err});
        return 1;
    }

    return 0;
}

export fn hook(addr: usize, code: [*c]const u8) usize {
    std.log.debug("Installing hook @ 0x{x}...", .{addr});
    if (c.luaL_loadstring(L, code) != c.LUA_OK) {
        var len: usize = undefined;
        const err: [:0]const u8 = c.lua_tolstring(L, -1, &len)[0..len :0];
        std.log.err("Failed to load hooking function: {s}", .{err});
        return 1;
    }
    if (c.lua_pcall(L, 0, 1, 0) != c.LUA_OK) {
        var len: usize = undefined;
        const err: [:0]const u8 = c.lua_tolstring(L, -1, &len)[0..len :0];
        std.log.err("Failed evaluate hooking function: {s}", .{err});
        return 1;
    }
    const func_ref = c.luaL_ref(L, c.LUA_REGISTRYINDEX);
    hooks.put(addr, func_ref) catch |err| {
        std.log.err("failed to register hook: {}", .{err});
        return 1;
    };
    return 0;
}

export fn handle(addr: usize) usize {
    if (hooks.get(addr)) |func_ref| {
        c.lua_rawgeti(L, c.LUA_REGISTRYINDEX, func_ref);
        if (c.lua_pcall(L, 0, 0, 0) != c.LUA_OK) {
            var len: usize = undefined;
            const err: [:0]const u8 = c.lua_tolstring(L, -1, &len)[0..len :0];
            std.log.err("Failed evaluate hooking function: {s}", .{err});
            return 1;
        }
        return 0;
    } else {
        std.log.err("Address not hooked!", .{});
        return 1;
    }
}
