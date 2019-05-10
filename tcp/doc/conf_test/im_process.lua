local bit = require "bit"
local netutil = require "netutil"

local login = false
local logined_uid = nil

local response_pkg = function(resp_data_tb)
	local resp_body = cjson.encode(resp_data_tb)
	local data_len = string.len(resp_body) + 4
	local data_len_h = netutil.htonl(data_len)
	local resp_data = netutil.packint32(data_len_h) .. resp_body
	local send_bytes, err = ngx.print(resp_data)
	return (err == nil and send_bytes == data_len)
end

local notify_pkg = function(to, resp_data_tb)
	local resp_body = cjson.encode(resp_data_tb)
	local data_len = string.len(resp_body) + 4
	local data_len_h = netutil.htonl(data_len)
	local resp_data = netutil.packint32(data_len_h) .. resp_body
	local send_bytes, err = ngx.clients.send(to, resp_data)
	return err
end

local ngx_return_error = function(status, reason)
	--status : 406, 500
	--reason: string
	local resp_data_tb = {
		["type"] = "error",
		["status"] = status,
		["reason"] = reason,
	}
	nlog.warn("pkg: [error] " .. tostring(status) .. ": " .. reason)
	response_pkg(resp_data_tb)
	ngx.exit()
end

-----------login----------------------
local token_check = function(token, uid)
	if string.find(token, uid) then
		return true
	end
	return false
end

local f_ack_login = function(status, reason)
	--status : number, 0ok, 1failed
	--reason: string/nil
	local resp_data_tb = {
		["type"] = "ack_login",
		["status"] = status,
		["reason"] = reason,
	}
	nlog.debug("pkg: [ack_login] " .. tostring(status) .. ": " .. tostring(reason))
	local ok = response_pkg(resp_data_tb)
	return ok
end

local f_req_login = function(req_tb)
	if login then
		f_ack_login(1, "alrealy logined")
		ngx.exit()
	end
	local token = req_tb["token"]
	local uid = req_tb["uid"]
	if type(token) ~= "string" or type(uid) ~= "uid" then
		f_single_m2(1, "err token/uid")
		ngx.exit()
	end
	local token = tostring(req_tb["token"])
	if not token_check(token, uid) then
		f_ack_login(1, "token check failed")
		ngx.exit()
	end
	if f_ack_login(0, nil) then
		login = true
		logined_uid = uid
		ngx.clients.set(logined_uid) --最好是不会被垃圾回收的变量
	else
		ngx.exit()
	end
end

-------logout--------------
local f_ack_out = function(status)
	--status : number, 0
	local resp_data_tb = {
		["type"] = "ack_logout",
		["status"] = status,
	}
	nlog.debug("pkg: [ack_logout] " .. tostring(status))
	local ok = response_pkg(resp_data_tb)
	return ok
end

local f_req_out = function(req_tb)
	f_ack_out(0)
	ngx.clients.del(uid)
	login = false
	logined_uid = nil
	ngx.exit()
end

------f_single_m1---------
local f_single_m2 = function(status, reason)
	--status : number, 0ok, 1failed
	--reason: string/nil
	local resp_data_tb = {
		["type"] = "single_m2",
		["status"] = status,
		["reason"] = reason,
	}
	nlog.debug("pkg: [single_m2] " .. tostring(status) .. ": " .. tostring(reason))
	local ok = response_pkg(resp_data_tb)
	return ok
end

local f_single_m3 = function(to, msg_id, msg)
	--to : string 
	--msg_id : number 
	--msg : string 
	local resp_data_tb = {
		["type"] = "single_m3",
		["msg_id"] = msg_id,
		["from"] = logined_uid,
		["msg"] = msg,
	}
	local err = notify_pkg(to, resp_data_tb)
	return err
end

local f_single_m1 = function(req_tb)
	if not login then
		f_single_m2(1, "not login")
		ngx.exit()
	end
	
	local msg_id = req_tb["msg_id"]
	local to = req_tb["to"]
	local msg = req_tb["msg"]
	if type(msg_id) ~= "number" or type(to) ~= "string" or type(msg) ~= "string" then
		f_single_m2(1, "err msg_id/to/msg")
		ngx.exit()
	end
	
	--f_single_m2(0, nil) --等对方确认收到再反馈
	
	local err = f_single_m3(to, msg_id, msg)
	if err then
		f_single_m2(1, err)
		return
	end
	
	--wait 'to' confirm, as single_m4
end

-------f_single_m4---------
local f_single_m5 = function(from, msg_id, status, reason)
	--from : string 
	--msg_id : number 
	--status : number 
	--reason : string/nil 
	
	local resp_data_tb = {
		["type"] = "single_m5",
		["msg_id"] = msg_id,
		["to"] = logined_uid,
		["status"] = status,
		["reason"] = reason,
	}
	local err = notify_pkg(from, resp_data_tb)
	return err
end

local f_single_m4 = function(req_tb)
	if not login then
		f_single_m2(1, "not login")
		ngx.exit()
	end
	local msg_id = req_tb["msg_id"]
	local from = req_tb["from"]
	local status = req_tb["status"]
	local reason = req_tb["reason"]
	if type(msg_id) ~= "number" or type(from) ~= "string" or ( status ~= 0 and status ~= 1 ) then
		f_single_m2(1, "err msg_id/from/status")
		ngx.exit()
	end
	
	local err = f_single_m5(from, msg_id, status, reason)
	if err then
		
	end
end
---------------------------
local type_func = {
	["req_login"] = f_req_login,
	["req_logout"] = f_req_logout,
	["single_m1"] = f_single_m1,
	["single_m4"] = f_single_m4,
}

---------------------------

while true do
	local head_data,err = ngx.receive(4, nil)
	if not head_data then
		ngx_return_error(406, "unexpected package " .. tostring(err))
	end
	
	local total_len = netutil.unpackint32(string.sub(head_data,1,4))
	if total_len <= 4 and total_len > 1024 then
		ngx_return_error(406, "unexpected package total_len " .. tostring(total_len))
	end
	
	local data,err = ngx:receive(total_len - 4, nil)
	if not data then
		ngx_return_error(406, "unexpected package  " .. tostring(err))
	end
	
	local req_body = cjson_safe.decode(data)
	if not req_body then
		ngx_return_error(406, "invalid json " .. tostring(data))
	end
	
	local msg_type = req_tb["type"]
	if not type_func[msg_type] then
		ngx_return_error(406, "invalid msg_type " .. tostring(msg_type))
	end
	
	type_func[msg_type](req_tb)
	
	ngx.wait_next_request()
end

