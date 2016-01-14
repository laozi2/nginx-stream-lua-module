local cjson = require "cjson"
local cjson_safe = require "cjson.safe"

local requst_tb = {
	["method"] = "GET", --GET POST HEAD
	["uri"] = "/testa", --string
	["args"] = {  --table or nil
		["a"] = "1", --key,value must string
		["b"] = "2",
	},
	["headers"] = { --table or nil
		--not allow to set Content-Length,Transfer-Encoding,Connection
		["X-IS-IP"] = "127.0.0.1",
		["Host"] = "api.xxxxxx.net",
	},
	["body"] = nil, -- POST:string or GET/HEAD:nil
}

local test_http = function()
	local httpsock = http_lb.new()
	
	local ret,errmsg = httpsock:init(upstream_conf["user_backend"])
	nlog.info(tostring(ret).." "..tostring(errmsg))
	if not ret then
		return
	end
	
	local ret_table,errmsg = httpsock:http_request(requst_tb)
	nlog.info(type(ret_table).." "..tostring(errmsg))
	if type(ret_table) == "table" then
		nlog.info(cjson.encode(ret_table))
	end
	
	httpsock:done()
end



while true do
	local data,r2,r3 = ngx.receive(10,6)
	ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
	if not data then
		ngx.say("exit")
		ngx.exit()
	end

	--ngx.sleep(5)
	
	test_http()

	--collectgarbage()
	
	ngx.wait_next_request()
end