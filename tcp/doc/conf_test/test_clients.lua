--local bit = require("bit")
--local netutil = require("netutil")

local i = 0
local saved = false
local save_client = function(uid)
    --if saved then
    --   return
	--end
	local err = ngx.clients.set(uid)
    if err then
       nlog.error(err)
       return 
    end
    nlog.info("set ok")
    saved = true
end
local exists = function(uid)
   local exists = ngx.clients.exists(uid)
    nlog.info("exists: " .. tostring(exists))
end
local del = function(uid)
  local ret = ngx.clients.del(uid)
  nlog.info("del: " .. tostring(ret))
end
local send = function(uid, msg)
	local n, err = ngx.clients.send(uid, msg)
     nlog.info("send: " .. tostring(n) .. "," .. tostring(err))
end
while true do
	local data,r2,r3 = ngx.receive(10,1)
    if string.find(data, "check") then
		exists("uid1")	
	elseif string.find(data, "error") then
		f() -- will abort
    elseif string.find(data, "send_to") then
        send("uid1", "fromother:ssssssssss")
	else
		save_client("uid1")	
	end
	ngx.say(collectgarbage("count"))
    --save_client("uid1")
    --save_client("uid2")
    --exists("uid1")
    --exists("uid2")
	--del("uid1")
	--del("uid2")
	--exists("uid1")
	ngx.wait_next_request()
end

--[[
测试:
打开客户端A，连接:
打开客户端B，连接:
观察日志

验证: 协程被动退出后对应设置的对象是否自动删除
1. B: 发送 "check"
2. A: 发送 "xxxxxxxx"
3. B: 发送 "check"
4. A: 发送 "error"
5. B: 发送 "check"
6. A: 连接并发送 "xxxxxxxx", 然后断开
7. B: 发送 "check"

验证: 发消息
1. B: 发送 "send_to", (A断开, 发送失败, 看日志)
1. A: 发送 "xxxxxxxx"
2. B: 发送 "send_to", A收到数据
--]]
