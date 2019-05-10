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
����:
�򿪿ͻ���A������:
�򿪿ͻ���B������:
�۲���־

��֤: Э�̱����˳����Ӧ���õĶ����Ƿ��Զ�ɾ��
1. B: ���� "check"
2. A: ���� "xxxxxxxx"
3. B: ���� "check"
4. A: ���� "error"
5. B: ���� "check"
6. A: ���Ӳ����� "xxxxxxxx", Ȼ��Ͽ�
7. B: ���� "check"

��֤: ����Ϣ
1. B: ���� "send_to", (A�Ͽ�, ����ʧ��, ����־)
1. A: ���� "xxxxxxxx"
2. B: ���� "send_to", A�յ�����
--]]
