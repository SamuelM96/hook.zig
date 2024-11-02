-- This file is for me to explore what I'd like the scripting API to be like

-- Do I need all types?
-- Should I have `char` and `uchar` when there's i8 and u8?
-- Bool? Covered by i8/u8 really
-- Should I use float/double instead of f32/f64?
-- Strings? Wrapper around null terminated *char[]?
---@enum CType primitive types
CTYPES = {
	void = 0,
	ptr = 1,
	i8 = 2,
	i16 = 3,
	i32 = 4,
	i64 = 5,
	u8 = 6,
	u16 = 7,
	u32 = 8,
	u64 = 9,
	f32 = 10,
	f64 = 11,
	f128 = 12,
}

---@class Module
---@field base integer starting address of the module
---@field size integer total size in bytes of the module
---@field path string? path to the module on the filesystem

---@class Function
---@field addr integer absolute address of the function
---@field argument_types CType[] array of the function's argument types in order
---@field return_type CType return type of the function

-- Could I take advantage of FFI for a lot of this? E.g., ffi.cast() for pointers for easy dereferencing
-- ffi.cdef() won't get hook_me() from basic-print-loop.c, and it can't search for functions
-- ffi.load() takes care of loading new modules

-- Return a the module with the matching `name`.
-- If `name` is `nil`, return the list of all loaded modules.
--
---@param name string?
---
---@return Module[] | Module
function GetModules(name)
	return {}
end

-- Gets the address of the export `name` from the chosen module.
-- If `module` is `nil`, it defaults to searching all loaded modules.
-- If `name` is `nil`, it returns all exports.
--
---@param module string?
---@param name string?
---
---@return integer[] | integer
function GetExports(module, name)
	return 0
end

-- Provide ways to:
-- TODO: Call Function objects
-- TODO: Define entry hooks
-- TODO: Define exit hooks
-- TODO: Remove hooks
-- TODO: Get memory ranges
-- TODO: Read/write arbitrary memory locations
-- TODO: Get traceback
