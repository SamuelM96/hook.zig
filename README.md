# Hook.zig

Hobby project to explore dynamic instrumentation. The goal is to inject the LuaJIT runtime into a target process to allow function hooking via Lua scripting.

## Install

Only tested on x86-64 Fedora with Zig 0.13.0 at the time of writing.

```bash
sudo dnf install zig capstone-devel
git clone https://github.com/SamuelM96/hook.zig
zig build
```

## Usage

```bash
hook.zig <pid>
```
