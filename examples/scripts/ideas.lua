-- This file is for me to explore what I'd like the scripting API to be like

-- Setting entry/exit overrides trigger this, so ignoring it
---@diagnostic disable: duplicate-set-field

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

-- Generate a function signature based on the given C argument and return types.
-- This can be passed to `ffi.cast()` to create direct refernces to native functions.
-- Example:
--   `Signature({"int", "char*"}, "void*")` => `"void*(*)(int, char*)"`
--
---@param argument_types string[] list of argument types
---@param return_type string return type
function Signature(argument_types, return_type)
	local args = "void"
	if argument_types then
		args = string.format(string.rep("%s,", #argument_types):sub(1, -2), table.unpack(argument_types))
	end
	return string.format("%s(*)(%s)", return_type or "void", args)
end

---@class Module
---@field base integer starting address of the module
---@field size integer total size in bytes of the module
---@field path string? path to the module on the filesystem
Module = {}
Module.__index = Module

---@class Function
---@field addr integer absolute address of the function
---@field argument_types string[] array of the function's argument types in order
---@field return_type string return type of the function
---@field entry function? entry hook function
---@field exit function? exit hook function
---@field private _data table
Function = {}

function Function:__call(...)
	return self._data._func(...)
end

function Function:__newindex(key, value)
	local update_func = false
	if key == "entry" or key == "exit" then
		if value == nil or type(value) == "function" then
			-- TODO: Communicate hooking to server
			print("[" .. key .. "] " .. string.format("0x%x", self.addr) .. " -> " .. (value and "func()" or "nil"))
		else
			error("Attempt to assign non-function value to " .. key)
		end
	elseif key == "addr" or key == "argument_types" or key == "return_type" then
		update_func = true
	end
	rawset(self._data, key, value)
	if update_func and self.addr then
		-- TODO: Communicate hook update to server
		local signature = Signature(self.argument_types, self.return_type)
		---@diagnostic disable-next-line: param-type-mismatch
		self._data["_func"] = ffi.cast(signature, self.addr)
	end
end

function Function:__index(key)
	return self._data[key] or Function[key]
end

function Function:original(...)
	-- TODO: Call original, unhooked version
	print("Calling original function @ " .. string.format("0x%x", self.addr))
	return self._data._func(...)
end

function Function:replace(func)
	-- TODO: Replace function
	print("Replacing function @ " .. string.format("0x%x", self.addr))
end

-- Create a new Function object to call native functions.
-- `argument_types` and `return_type` use standard C types, e.g., `int`, `uint64_t`, `char*`, etc
--
---@param addr integer absolute address of the function
---@param argument_types string[] array of the function's argument types in order
---@param return_type string return type of the function
---@param entry function? entry hook function
---@param exit function? exit hook function
---
---@return Function
function Function.new(addr, argument_types, return_type, entry, exit)
	local self = setmetatable({
		_data = {
			_func = nil,
		},
	}, Function)
	self.argument_types = argument_types
	self.return_type = return_type
	self.addr = addr
	self.entry = entry
	self.exit = exit

	return self
end

-- Return the module whose name matches `name`.
-- If `name` is `nil`, return a list of all loaded modules.
--
---@param name string?
---
---@return Module[] | Module
function Module.get(name)
	-- Call out to payload server?
	return setmetatable({}, Module)
end

-- Gets the address of the export `name` from the chosen module.
-- If `name` is `nil`, it returns all exports.
--
---@param name string?
---
---@return integer[] | integer
function Module:exports(name)
	-- Call out to payload server?
	return 0
end

-- Provide ways to:
-- TODO: Read/write registers in hooks
-- TODO: Get memory ranges
-- TODO: Read/write arbitrary memory locations (FFI?)
-- TODO: Get traceback
-- TODO: Interact with other threads
-- TODO: Communicate with host
-- TODO: Hook read/write access
-- TODO: Get module symbols
-- TODO: Get module imports
-- TODO: Change memory protections
-- TODO: Scan memory for patterns
-- TODO: Allocate memory (does FFI handle this well?)
-- TODO: Disassemble arbitrary locations with Capstone
-- TODO: Hexdump data
-- TODO: Create patches
-- TODO: File I/O
-- TODO: Interact with SQLite DBs
-- TODO: Interact with other environments, e.g., Java, ObjC, Python, Ruby, Dotnet, etc

-- Getting a specific module
local base_module = Module.get("basic-print-loop")

-- Getting a specific function from a module
local hook_me_addr = base_module:exports("hook_me")
hook_me_addr = 0x1001610

-- Defining and calling a function
local hook_me = Function.new(hook_me_addr, { "int" }, "int")
print(string.format("hook_me(123) -> %d", hook_me(123)))

-- TODO: Define entry hooks
-- TODO: Define exit hooks
-- Hooking the entry point of a function
-- This involves some meta magic, not sure I'm a fan of the added internal complexity
hook_me.entry = function(i)
	print("Overriding argument in hook_me()...")
	-- Best way to handle overriding arguments?
	-- I can probably get the state of the arguments in Zig after the callback has executed.
	print(i)
	i = 123
end
hook_me.exit = function(ret)
	print(ret)
	-- TODO: Override return value
	return 123
end
-- TODO: Remove hooks
hook_me.entry = nil
hook_me.exit = nil

-- TODO: Replace functions
hook_me.entry = function(i)
	print("Replacing hook_me()...")
	-- call original version?
	print("Original: " .. hook_me:original(123))
	-- Adding a return prevents calling the original function after, effectively replacing it?
	return 42
	-- No return (or return nil) would indicate to execute the function as normal after
	-- What about native functions that return void (AKA nil)?
end
-- Alternatively, be explicit?
hook_me:replace(function(i)
	print("Original: " .. hook_me:original(123))
	return i + 42
end)
