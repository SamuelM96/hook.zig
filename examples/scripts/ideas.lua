-- This file is for me to explore what I'd like the scripting API to be like

-- How can I take advantage of FFI for a lot of this?
-- ffi.cdef() won't get hook_me() from basic-print-loop.c, and it can't search for functions
-- ffi.load() takes care of loading new modules
-- ffi.cast() can be used to read/write arbitrary memory locations, e.g.:
--   local address = 0x12345678
--   local ptr = ffi.cast("char *", address)
--   ptr[0] = 'a'
-- ffi.cast() also handles C types well, so rather than trying to handle parsing them myself,
--   I can offload that work to ffi, e.g., for declaring function pointers with intuitive types
local ffi = require("ffi")

---@class Module
---@field base integer starting address of the module
---@field size integer total size in bytes of the module
---@field path string? path to the module on the filesystem

---@class Function
---@field addr integer absolute address of the function
---@field argument_types string[] array of the function's argument types in order
---@field return_type string return type of the function
Function = {
	_func = nil,
	__call = function(self, ...)
		return self._func(...)
	end,
}
Function.__index = Function

-- Create a new Function object to call native functions.
-- `argument_types` and `return_type` use standard C types, e.g., `int`, `uint64_t`, `char*`, etc
--
---@param addr integer absolute address of the function
---@param argument_types string[] array of the function's argument types in order
---@param return_type string return type of the function
---
---@return Function
function Function.new(addr, argument_types, return_type)
	local self = setmetatable({}, Function)
	self.addr = addr
	self.argument_types = argument_types
	self.return_type = return_type

	local args = ""
	if self.argument_types then
		args = string.format(string.rep("%s,", #self.argument_types):sub(1, -2), table.unpack(self.argument_types))
	end
	local signature = string.format("%s(*)(%s)", self.return_type, args)

	---@diagnostic disable-next-line: param-type-mismatch
	self._func = ffi.cast(signature, self.addr)

	return self
end

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
-- TODO: Define entry hooks
-- TODO: Define exit hooks
-- TODO: Remove hooks
-- TODO: Get memory ranges
-- TODO: Read/write arbitrary memory locations
-- TODO: Get traceback

-- Defining and calling a function
local hook_me = Function.new(0x1001610, { "int" }, "int")
print(string.format("hook_me(123) -> %d", hook_me(123)))
