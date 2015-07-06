local client_sock = ngx.socket.tcp()
client_sock:settimeout(5000,1000,3000)

local DB_MAX_IDLE_TIME = 
local DB_POOL_SIZE = 

local req_data = "GET /hello HTTP/1.1\r\nUser-Agent: TestLua\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n"

local test_http = function(u)
	local ret,err = u:connect("127.0.0.1",8080)
	local reuse = u:getreusedtimes()
	nlog.info("connect : "..tostring(ret).." "..tostring(err).." "..tostring(reuse))
	if not ret then 
		return
	end

	ret,err = u:send(req_data)
	nlog.info("send : "..tostring(ret).." "..tostring(err))

	local ret_table,err = u:receive_http(512,1024*10)
	nlog.info(type(ret_table).." "..tostring(err))
	if type(ret_table) == "table" then
		if type(ret_table["body"]) == "table" then
			ret_table["body"] = table.concat(ret_table["body"])
		end
		local ret_js = cjson.encode(ret_table)
		nlog.info(ret_js)
	end
	u:setkeepalive()
end



while true do
	local data,r2,r3 = ngx.receive(10,6)
	ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
	if not data then
		ngx.say("exit")
		ngx.exit()
	end

	--ngx.sleep(5)
	
	test_http(client_sock)

	--collectgarbage()
	
	ngx.wait_next_request()
end