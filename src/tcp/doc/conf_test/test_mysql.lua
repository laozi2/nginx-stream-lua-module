--local mysql = require("mysql")
--local db_ml = require("db_ml")
--local cjson = require("cjson")

--db config
local db_user = {}
db_user.host = "127.0.0.1"
db_user.port = "3306"
db_user.database = "webusers"
db_user.user = "tmptest"
db_user.password = "tmptestQ"
db_user.max_packet_size = 1024 * 1024
db_user.pool = "db_webusers_pool" --db_<db name>_pool

--mysql module args
local db_arg = {}
db_arg.db_param = db_user

local sql = "select * from ts_user_id where user_id=2002848"

while true do
	local data,r2,r3 = ngx.receive(10,5)
	
	--ngx.say(collectgarbage("count"))
	ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
	if not data then
		ngx.say("exit")
		ngx.exit()
	end
	
	local ml = db_ml:new()
	ml:init(db_arg.db_param)
	local res,err, errno, sqlstate = ml:query(sql)
	ml:done()

	if not res then
		ngx.print("bad result: err[" .. tostring(err).."],errno["..tostring(errno).."],sqlstate["..tostring(sqlstate).."]")
	else
		local msg = cjson.encode(res)
		ngx.print(msg)
	end

	--collectgarbage()
	
	ngx.wait_next_request()
end

