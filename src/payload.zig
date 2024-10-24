const std = @import("std");
const c = @cImport({
    @cInclude("luajit-2.1/lua.h");
    @cInclude("luajit-2.1/lualib.h");
    @cInclude("luajit-2.1/lauxlib.h");
});

var L: ?*c.lua_State = null;

export fn load() usize {
    L = c.luaL_newstate();
    if (L == null) {
        std.log.err("Failed to create Lua state", .{});
        return 1;
    }

    c.luaL_openlibs(L);

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
        var err_len: usize = undefined;
        const err: [*c]const u8 = c.lua_tolstring(L, -1, &err_len);
        std.log.err("Failed to execute code: {s}", .{err[0..err_len]});
        c.lua_close(L);
        return 1;
    }

    return 0;
}
