local wireguard = require("wireguard")

local key_pattern = "^[A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/]=%s*$"
local zero_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
local test_device = "wg_lua_t0"

local function is_key(value)
	return type(value) == "string" and #value == 44 and value:match(key_pattern) ~= nil
end

local function assert_error_tuple(...)
	local values = { ... }
	assert.is_nil(values[1])
	assert.is_string(values[2])
	assert.is_number(values[3])
end

local function command_output(command)
	local handle = assert(io.popen(command))
	local output = handle:read("*a")
	handle:close()
	return (output:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function device_names()
	local devices, err, errno = wireguard.list_devices()
	if devices == nil then
		return nil, err, errno
	end
	local names = {}
	for _, name in ipairs(devices) do
		names[name] = true
	end
	return names
end

describe("wireguard Lua binding", function()
	it("exports the expected functions", function()
		local expected = {
			"generate_private_key",
			"generate_preshared_key",
			"public_key",
			"key_is_zero",
			"list_devices",
			"add_device",
			"del_device",
			"get_device",
			"set_device",
		}

		for _, name in ipairs(expected) do
			assert.is_function(wireguard[name])
		end
	end)

	it("generates and derives valid keys", function()
		local private_key = wireguard.generate_private_key()
		local preshared_key = wireguard.generate_preshared_key()
		local public_key = wireguard.public_key(private_key)

		assert.is_true(is_key(private_key))
		assert.is_true(is_key(preshared_key))
		assert.is_true(is_key(public_key))
		assert.is_false(wireguard.key_is_zero(private_key))
		assert.is_false(wireguard.key_is_zero(preshared_key))
		assert.is_false(wireguard.key_is_zero(public_key))
	end)

	it("detects the zero key", function()
		assert.is_true(wireguard.key_is_zero(zero_key))
	end)

	it("raises useful errors for invalid keys", function()
		assert.has_error(function()
			wireguard.public_key("not-a-key")
		end, "invalid WireGuard base64 key")

		assert.has_error(function()
			wireguard.key_is_zero("not-a-key")
		end, "invalid WireGuard base64 key")
	end)

	it("lists devices or returns an error tuple", function()
		local devices, err, errno = wireguard.list_devices()
		if devices == nil then
			assert_error_tuple(devices, err, errno)
		else
			assert.is_table(devices)
		end
	end)
end)

describe("wireguard device lifecycle", function()
	before_each(function()
		wireguard.del_device(test_device)
	end)

	after_each(function()
		wireguard.del_device(test_device)
	end)

	it("adds, configures, reads, and deletes a WireGuard device", function()
		assert_error_tuple(wireguard.get_device(test_device))

		assert.is_true(wireguard.add_device(test_device))

		local names, err, errno = device_names()
		if names == nil then
			assert_error_tuple(nil, err, errno)
		else
			assert.is_true(names[test_device])
		end

		local device = wireguard.get_device(test_device)
		assert.is_table(device)
		assert.are.equal(test_device, device.name)
		assert.are.equal(0, os.execute("ip link set dev " .. test_device .. " up"))

		local private_key = wireguard.generate_private_key()
		assert.is_true(wireguard.set_device({
			name = test_device,
			private_key = private_key,
			listen_port = 51820,
			replace_peers = true,
		}))

		device = wireguard.get_device(test_device)
		assert.is_table(device)
		assert.are.equal(test_device, device.name)
		assert.are.equal("51820", command_output("wg show " .. test_device .. " listen-port"))
		assert.are.equal(wireguard.public_key(private_key), command_output("wg show " .. test_device .. " public-key"))

		assert.is_true(wireguard.del_device(test_device))
		assert_error_tuple(wireguard.get_device(test_device))
	end)
end)
