--db_ml module
--need mysql.lua,nlog.lua

local _M = {_VERSION = '0'}
local mt = {__index = _M}

local LOCK_EXPTIME = 5
local LOCK_TIMEOUT = 5
local DEFAULT_CONNECT_TIMEOUT = 5000
local DEFAULT_SEND_TIMEOUT = 5000
local DEFAULT_READ_TIMEOUT = 5000
local DEFAULT_KEEPALIVE_TIMEDOUT = 0 --no timedout
local DEFAULT_POOL_SIZE = 10

function _M.new()
    local db, err = mysql:new()
    --if not db then
    --    local error_string = "failed to instantiate mysql: " .. tostring(err)
    --    nlog.derror(error_string)
        --ngx.log(ngx.ERR,error_string)
    --    tcp_return(error_string)
    --end
    
    return setmetatable({db = db}, mt)
end


--[[
    opts:
    {
        --for mysql lib
        "host":"10.0.3.136", --string
        "port":3306,  --number
        "database":"db_user", --string
        "user":"tmptest", --string
        "password":"tmptestQ", --string
        "max_packet_size":1024 * 1024,--number or nil(default 1024 * 1024) 
        "pool":"db_user_pool_master",--string or nil(default user:database:host:port)
        
        --for db_ml lib
        "connect_timeout":5000, --number(ms,>0) or nil(default DEFAULT_CONNECT_TIMEOUT)
        "send_timeout":5000, --number(ms,>0) or nil(default DEFAULT_SEND_TIMEOUT)
        "read_timeout":5000, --number(ms,>0) or nil(default DEFAULT_READ_TIMEOUT)
        "pool_size":50, --number or nil,default 50
        "keepalive_timeout":60000, --number(ms,>0; =0unlimited) or nil,default 0
    }
--]]
function _M.init(self, opts)
    local db = self.db
    if not db then
        return nil, "not initialized"
    end
    
    db:set_timeout(opts.connect_timeout or DEFAULT_CONNECT_TIMEOUT, opts.send_timeout or DEFAULT_SEND_TIMEOUT, opts.read_timeout or DEFAULT_READ_TIMEOUT)

    local res, err, errno, sqlstate = db:connect(opts)
    if not res then
        nlog.derror("connect failed: "..tostring(err))
        return nil, err
    end
    
    self.keepalive_timeout = opts.keepalive_timeout or DEFAULT_KEEPALIVE_TIMEDOUT
    self.pool_size = opts.pool_size or DEFAULT_POOL_SIZE
    self.db_host = opts.host

    return 1,"ok"
end

function _M.query(self, sql)
    local db = self.db
    if not db then
        return nil, "not initialized"
    end
    
    local start = ngx.now()
    local res, err, errno, sqlstate = db:query(sql)
    self.elapsed_sql = ngx.now() - start
    
    nlog.sql(self.db_host, string.format("%.3f", self.elapsed_sql), sql)

    if not res then 
        nlog.derror("bad result: " .. err .. ":" .. sql)
    end

    return res,err, errno, sqlstate
end

function _M.done(self, close)
    local db = self.db
    if not db then
        return nil, "not initialized"
    end

    if close then
        return db:close() --1, or nil,closed/ot initialized
    end
    
    return db:set_keepalive(self.keepalive_timeout,self.pool_size)  --1, or nil,closed
end

return _M
