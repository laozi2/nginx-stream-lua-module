local cjson = require "cjson"
local cjson_safe = require "cjson.safe"

local http_config = {
	["host"] = "127.0.0.1", --string
	["port"] = 443, --number
	["connect_timeout"] = 5000,  --number(ms,>0) or nil
	["send_timeout"] = 5000,  --number(ms,>0) or nil
	["read_timeout"] = 5000,  --number(ms,>0) or nil
	["pool_name"] = nil, --"127.0.0.1:80", --string or nil
	["pool_size"] = 50, --number or nil,default 50
	["keepalive_timeout"] = nil, --number(ms,>0; =0unlimited) or nil,default 0
	["max_head_size"] = 512, --number(>0), or nil default 512
	["max_body_size"] = 2048, --number(>0), or nil default 4k
}

local requst_tb = {
	["method"] = "GET", --GET POST HEAD
	["uri"] = "/testa", --string
	["args"] = {  --table or nil
		["a"] = "a?dsaf& +x", --key,value must string
		--["sleep"] = "5",
	},
	["headers"] = { --table or nil
		--not allow to set Content-Length,Transfer-Encoding,Connection
		["X-IS-IP"] = "127.0.0.1",
		["Host"] = "api-sandbox.xxxx.net",
	},
	["body"] = nil, -- POST:string or GET/HEAD:nil
}

local test_http = function()
	local httpsock = http.new()
	
	local ret,errmsg = httpsock:init(http_config)
	nlog.info(tostring(ret).." "..tostring(errmsg))
	if not ret then
		return
	end
	
	ret,errmsg = httpsock:sslhandshake(ssl1,false)
	nlog.info(tostring(ret).." "..tostring(errmsg))
	if not ret then	
		httpsock:done()
		return
	end
	
	local ret_table,errmsg = httpsock:http_request(requst_tb)
	nlog.info(type(ret_table).." "..tostring(errmsg))
	if type(ret_table) == "table" then
		nlog.info(cjson.encode(ret_table))
	end
	
	--ret,errmsg = httpsock:send_request(requst_tb)
	--nlog.info(tostring(ret).." "..tostring(errmsg))
	--if not ret then
	--	httpsock:done(true)
	--	return
	--end
	--
	--local ret_table,errmsg = httpsock:receive_response()
	--nlog.info(type(ret_table).." "..tostring(errmsg))
	--if type(ret_table) == "table" then
	--	nlog.info(cjson.encode(ret_table))
	--end
	
	httpsock:done()
end



while true do
	local data,r2,r3 = ngx.receive(10,nil)
	--ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
	if not data then
		ngx.say("exit")
		ngx.exit()
	end

	--ngx.sleep(5)
	
	test_http()

	--collectgarbage()
	ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
	
	ngx.wait_next_request()
end