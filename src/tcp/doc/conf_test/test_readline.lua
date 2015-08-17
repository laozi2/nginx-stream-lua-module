local client_sock = ngx.socket.tcp()
client_sock:settimeout(5000,1000,3000)


--[[
TODO:
	调整输入输出，和错误信息
	string.find 不用每次都从头开始找，这对于超长字符串可以提高效率
	调整每次读取的长度，和单行最大允许长度
--]]
local read_line = function(u,data_tb)
	if not data_tb["str"] then
		nlog.warn("str is nil")
		return nil
	end
	while true do
		local i,j = string.find(data_tb["str"], "(.-)\r\n")
		if i then
			local line = string.sub(data_tb["str"], i, j - 2)
			data_tb["str"] = string.sub(data_tb["str"], j + 1)
			return line
		end
		
		local data,err = u:receive(256,1)
		nlog.debug("receive : "..tostring(data).." "..tostring(err))
		if not data then
			data_tb["str"] = nil
			return nil
		end
		
		data_tb["str"] = data_tb["str"] .. data
		if #data_tb["str"] > 10240 then
			nlog.warn("str > 10240")
			data_tb["str"] = nil
			return nil
		end
	end
end



local test_readline = function(u,n)
	local ret,err = u:connect("127.0.0.1",6688,"127.0.0.1_6688");
	nlog.debug("connect : "..tostring(ret).." "..tostring(err))
	if not ret then
		return
	end

	ret,err = u:send("hello")
	nlog.debug("send : "..tostring(ret).." "..tostring(err))
	if not ret then
		return
	end
	
	local data_tb = {}
	data_tb["str"] = ""
	for i=1,n do
		local line = read_line(u,data_tb)
		nlog.debug('['..tostring(line)..']')
	end

	u:setkeepalive()
end


local i = 0
while true do
	local data,r2,r3 = ngx.receive(10,1)
	if not data then
		ngx.say("exit")
		ngx.exit()
	end

	test_readline(client_sock,2)

	ngx.say(collectgarbage("count"))
	ngx.wait_next_request()
end

