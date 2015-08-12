local load_balance = {}

local DEFAULT_CONNECT_TIMEDOUT = 5000  --ms
local DEFAULT_SEND_TIMEDOUT = 5000   --ms
local DEFAULT_READ_TIMEDOUT = 5000   --ms
local DEFAULT_MAX_HEAD_SIZE = 512
local DEFAULT_MAX_BODY_SIZE = 4096
local DEFAULT_KEEPALIVE_TIMEDOUT = 0 --no timedout
local DEFAULT_POOL_SIZE = 50 
local DEFAULT_FAILED_TIME = 60  --seconds
local DEFAULT_MAX_TRIES = 3

local backend_status = {}
------------------------------------------------------------


--[[
conf_tb is config table, example

	["server"] = {
		{
			["host"] = "192.168.1.23", --string
			["port"] = 80,  --number
			["weight"] = 3, -- number >=0
			["connect_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_CONNECT_TIMEDOUT)
			["send_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_SEND_TIMEDOUT)
			["read_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_READ_TIMEDOUT)
			["pool_name"] = nil, --"127.0.0.1:80", --string or nil(defaul is host:port)
			["pool_size"] = 50, --number or nil(default DEFAULT_POOL_SIZE)
			["keepalive_timeout"] = nil, --number(ms,>0; =0unlimited) or nil(default DEFAULT_KEEPALIVE_TIMEDOUT)
			["max_head_size"] = 512, --number(>0), or nil(default DEFAULT_MAX_HEAD_SIZE)
			["max_body_size"] = 2048, --number(>0), or nil(default DEFAULT_MAX_BODY_SIZE)
		},
		{
			["host"] = "192.168.1.24", 
			["port"] = 80,
			["weight"] = 1, 
			["connect_timeout"] = 5000, 
			["send_timeout"] = 5000,
			["read_timeout"] = 5000, 
			["pool_name"] = nil,
			["pool_size"] = 50, 
			["keepalive_timeout"] = nil, 
			["max_head_size"] = 512,
			["max_body_size"] = 2048, 
		},
	},
	["backend_name"] = "user_backend",
	["failed_time"] = 60, -- number, second, max abandon time when marked down, nil(default DEFAULT_FAILED_TIME)
	["max_tries"] = 3, -- number >= 1, max try times to connect, nil(default DEFAULT_MAX_TRIES)
--]]

load_balance.check_config = function(conf_tb)
	if conf_tb["is_checked"] then
		return true,"checked"
	end
	
	if type(conf_tb["server"]) ~= "table" then
		return false, "no server table"
	end
	
	local n = table.getn(conf_tb["server"])
	if n == 0 then
		return false, "no server array"
	end
	
	for i=1,n do
		local server = conf_tb["server"][i]
		if type(server["host"]) ~= "string" or server["host"] == "" then
			return false, 'wrong server["host"]'
		end
		
		if type(server["port"]) ~= "number" or server["port"] < 0 or server["port"] > 65535 then
			return false, 'wrong server["port"]'
		end
		
		if type(server["weight"]) ~= "number" or server["weight"] < 1 then
			return false, 'wrong server["weight"]'
		end
		
		if server["connect_timeout"] == nil then
			server["connect_timeout"] = DEFAULT_CONNECT_TIMEDOUT
		elseif type(server["connect_timeout"]) ~= "number" or server["connect_timeout"] <= 0 then
			return false, 'wrong server["connect_timeout"]'
		end
		
		if server["send_timeout"] == nil then
			server["send_timeout"] = DEFAULT_SEND_TIMEDOUT
		elseif type(server["send_timeout"]) ~= "number" or server["send_timeout"] <= 0 then
			return false, 'wrong server["send_timeout"]'
		end
		
		if server["read_timeout"] == nil then
			server["read_timeout"] = DEFAULT_READ_TIMEDOUT
		elseif type(server["read_timeout"]) ~= "number" or server["read_timeout"] <= 0 then
			return false, 'wrong server["read_timeout"]'
		end
		
		if server["pool_name"] == nil then
			server["pool_name"] = server["host"] .. ":" .. server["port"]
		elseif type(server["pool_name"]) ~= "string" or server["pool_name"] == "" then
			return false, 'wrong server["pool_name"]'
		end
		
		if server["pool_size"] == nil then
			server["pool_size"] = DEFAULT_POOL_SIZE
		elseif type(server["pool_size"]) ~= "number" or server["pool_size"] <= 0 then
			return false, 'wrong server["pool_size"]'
		end
		
		if server["keepalive_timeout"] == nil then
			server["keepalive_timeout"] = DEFAULT_KEEPALIVE_TIMEDOUT
		elseif type(server["keepalive_timeout"]) ~= "number" or server["keepalive_timeout"] < 0 then
			return false, 'wrong server["keepalive_timeout"]'
		end
		
		if server["max_head_size"] == nil then
			server["max_head_size"] = DEFAULT_MAX_HEAD_SIZE
		elseif type(server["max_head_size"]) ~= "number" or server["max_head_size"] < 64 then
			return false, 'wrong server["max_head_size"]'
		end
		
		if server["max_body_size"] == nil then
			server["max_body_size"] = DEFAULT_MAX_BODY_SIZE
		elseif type(server["max_body_size"]) ~= "number" or server["max_body_size"] < 64 then
			return false, 'wrong server["max_body_size"]'
		end
	end
	
	if conf_tb["failed_time"] == nil then
		conf_tb["failed_time"] = DEFAULT_FAILED_TIME
	elseif type(conf_tb["failed_time"]) ~= "number" or conf_tb["failed_time"] <=0 then
		return false, 'wrong conf_tb["failed_time"]'
	end
	
	if conf_tb["max_tries"] == nil then
		conf_tb["max_tries"] = DEFAULT_MAX_TRIES
	elseif type(conf_tb["max_tries"]) ~= "number" or conf_tb["max_tries"] <=0 then
		return false, 'wrong conf_tb["max_tries"]'
	end
	
	local backend_name = conf_tb["backend_name"]
	if type(backend_name) ~= "string" or backend_name == "" then
		return false, 'wrong conf_tb["backend_name"]'
	end
	if backend_status[backend_name] then
		return false, 'duplicated backend_name ' .. backend_name
	end

	backend_status[backend_name] = {}
	backend_status[backend_name]["ok_flag"] = true
	for i=1,n do
		local tb = {}
		tb["ok"] = backend_status[backend_name]["ok_flag"]
		tb["hits"] = 0
		tb["ok_tm"] = 0
		table.insert(backend_status[backend_name],tb)
	end
	
	backend_status[backend_name]["n"] = n
	backend_status[backend_name]["i"] = 1
	backend_status[backend_name]["n_down"] = 0
	
	conf_tb["is_checked"] = true
	
	return true, "ok"
end

load_balance.check_config_all = function(conf_all)
	for k,_ in pairs(conf_all) do
		local ok, errmsg = load_balance.check_config(conf_all[k])
		if not ok then
			error("check_config_all: " .. errmsg)
		end
	end
end


--
load_balance.calculate_server = function(conf_tb)
	--if not backend_status[conf_tb["backend_name"]] then
	--	return nil,""
	--end
	
	local pos = nil
	
	local status_tb = backend_status[conf_tb["backend_name"]]
	local n = status_tb["n"]
	local i = status_tb["i"]

	while true do
		--when all status_tb[i]["ok"] is down, then dead loop, but load_balance.set_status() will reset, so dead loop not happen
		if status_tb[i]["ok"] ~= status_tb["ok_flag"] and status_tb[i]["ok_tm"] < ngx.time() then
			status_tb[i]["ok"] = status_tb["ok_flag"]
			status_tb["n_down"] = status_tb["n_down"] - 1
		end
		
		if status_tb[i]["ok"] == status_tb["ok_flag"] then
			pos = i
			status_tb[i]["hits"] = status_tb[i]["hits"] + 1
			if status_tb[i]["hits"] >= conf_tb["server"][i]["weight"] then
				status_tb[i]["hits"] = 0
				i = i + 1
				if i > n then
					i = 1
				end
			end
			
			break
		end
		
		i = i + 1
		if i > n then
			i = 1
		end
	end
	
	status_tb["i"] = i
	
	return pos
end

load_balance.set_status = function(conf_tb, pos, is_ok)
	--if all failure
	local status_tb = backend_status[conf_tb["backend_name"]]
	if is_ok then
		if status_tb[pos]["ok"] ~= status_tb["ok_flag"] then
			status_tb[pos]["ok"] = status_tb["ok_flag"]
			status_tb["n_down"] = status_tb["n_down"] - 1
		end
		return
	end
	
	--not ok
	if status_tb[pos]["ok"] == status_tb["ok_flag"] then
		status_tb[pos]["ok"] = not status_tb["ok_flag"]
		status_tb[pos]["ok_tm"] = ngx.time() + conf_tb["failed_time"]
		status_tb["n_down"] = status_tb["n_down"] + 1
		if status_tb["n_down"] >= status_tb["n"] then --all failed, reset
			status_tb["ok_flag"] = not status_tb["ok_flag"]
			status_tb["n_down"] = 0
		end
		status_tb["i"] = status_tb["i"] + 1
		if status_tb["i"] > status_tb["n"] then
			status_tb["i"] = 1
		end
	end
end

load_balance.get_status = function(backend_name)
	return backend_name and backend_status[backend_name] or backend_status
end


return load_balance