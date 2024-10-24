#include <stdio.h>
#include <luajit-2.1/lua.h>
#include <luajit-2.1/lualib.h>
#include <luajit-2.1/lauxlib.h>

// gcc -fPIC -shared -o libpayload.so payload.c -lluajit-5.1

lua_State *L = NULL;

__attribute__((visibility("default"))) int load() {
    L = luaL_newstate();
    if (!L) {
        fprintf(stderr, "Failed to create Lua state\n");
        return 1;
    }

    luaL_openlibs(L);

    printf("Loaded luajit runtime!\n");
}

__attribute__((visibility("default"))) void clean() {
    lua_close(L);
}

__attribute__((visibility("default"))) int exec(const char* code) {
    if (!L && load()) {
        return 1;
    }

    int status = luaL_dostring(L, code);
    if (status) {
        fprintf(stderr, "Failed to execute code: %s\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }

    return 0;
}

