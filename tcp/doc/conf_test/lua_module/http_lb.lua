-----------------------------------------
--Module: http module, load_balance version
--Author: xxh
--Date: 
-----------------------------------------

local nlog = require("nlog")
local load_balance = require("load_balance")
local tcp = ngx.socket.tcp

module("http_lb", package.seeall)

_M["_VERSION"] = '0'
local mt = {__index = _M}

-- constants

local POOL_NAME_INDEX = 2 --same as SOCKET_KEY_INDEX

local USER_AGENT = "resty-agent"
local CRLF = "\r\n"
local STATE_CONNECTED = 1
local STATE_REQUEST_SENT = 2

local use_log = true

--[[
    use http1.1, the common header : 
    Host
    *Connection
    User-Agent
    *Content-Length
    Content-Type
    *Transfer-Encoding
    Expect
    Accept-Encoding
    Keep-Alive
    X-Forwarded-For
    X-Real-IP
    Accept
    Accept-Language
    Date
    Cookie
--]]
--[[
req_tb: 
    {
        "method":"GET", --GET POST HEAD
        "uri":"/hello", --string
        "args":{  --table or nil
                "a":"1", --key,value must string
                "b":"2",
            },
        "headers":{ --table or nil
                "X-IS-IP":"127.0.0.1",
                --not allow to set Content-Length,Transfer-Encoding,Connection
            },
        "body":"", -- POST:string or GET/HEAD:nil
    }
return 0 ok , -1 error
--]]

local _make_request = function(req_tb)
    local args = ""
    if req_tb["args"] then
        local sep = "?"
        for k,v in pairs(req_tb["args"]) do
            args = args .. sep .. k .. "=" .. ngx.escape_uri(v)
            if sep == "?" then sep = "&" end
        end
    end
    
    local content_length = 0
    
    if req_tb["method"] == "POST" then
        if not req_tb["body"] then
            return nil
        end
        content_length = string.len(req_tb["body"])
    end
    
    if not req_tb["headers"] then
        req_tb["headers"] = {}
    end
    
    req_tb["headers"]["Content-Length"] = content_length
    req_tb["headers"]["Transfer-Encoding"] = nil
    req_tb["headers"]["User-Agent"] = USER_AGENT
    req_tb["headers"]["Connection"] = nil
    
    local headers = ""
    for k,v in pairs(req_tb["headers"]) do
        headers = headers .. k .. ": " .. v .. CRLF
    end
    
    --GET /hello HTTP/1.1\r\nUser-Agent: TestLua\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n
    local req_str = req_tb["method"] .. " " .. req_tb["uri"] .. args .. " HTTP/1.1" .. CRLF .. headers .. CRLF
    if req_tb["method"] == "POST" then
        return req_str .. req_tb["body"]
    end
    return req_str
end


----------------------------------------
--ok, or throw error
function new()
    local sock = tcp()
    ----sock never be null if returned
    --if not sock then
    --    return nil, err
    --end
    return setmetatable({ ["sock"] = sock , ["tries"] = 0 }, mt)
end

--[[
    opts:
    ["server"] = {
        {
            ["host"] = "192.168.1.23", --string
            ["port"] = 80,  --number
            ["weight"] = 3, -- number >=0
            ["connect_timeout"] = 5000,  --number(ms,>0) or nil
            ["send_timeout"] = 5000,  --number(ms,>0) or nil
            ["read_timeout"] = 5000,  --number(ms,>0) or nil
            ["pool_name"] = nil, --"127.0.0.1:80", --string or nil
            ["pool_size"] = 50, --number or nil,default 50
            ["keepalive_timeout"] = nil, --number(ms,>0; =0unlimited) or nil,default 0
            ["max_head_size"] = 512, --number(>0), or nil default 512
            ["max_body_size"] = 2048, --number(>0), or nil default 4k
        },
        {
            ["host"] = "192.168.1.24", 
            ["port"] = 80,
            ["weight"] = 1, -- >=0
            ["connect_timeout"] = 5000,  --number(ms,>0) or nil
            ["send_timeout"] = 5000,  --number(ms,>0) or nil
            ["read_timeout"] = 5000,  --number(ms,>0) or nil
            ["pool_name"] = nil, --"127.0.0.1:80", --string or nil
            ["pool_size"] = 50, --number or nil,default 50
            ["keepalive_timeout"] = nil, --number(ms,>0; =0unlimited) or nil,default 0
            ["max_head_size"] = 512, --number(>0), or nil default 512
            ["max_body_size"] = 2048, --number(>0), or nil default 4k
        },
    },
    ["failed_time"] = 60, -- number, second, max abandon time when marked down
    ["try_times"] = 3, -- number >= 1
    ["failed_connect"] = true, -- bool
    ["failed_send"] = true, -- bool
    ["failed_read"] = false, -- bool
    
    return (nil,errmsg) or (1,"ok")
--]]

function init(self, opts)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    local ok, errmsg = load_balance.check_config(opts)
    if not ok then
        return nil, errmsg
    end
    
    self.tries = self.tries + 1
    if self.tries > opts["max_tries"] then
        return nil, "exceed max tries"
    end
    
    local conf_pos = load_balance.calculate_server(opts)
    
    sock:settimeout(opts["server"][conf_pos]["connect_timeout"],opts["server"][conf_pos]["send_timeout"],opts["server"][conf_pos]["read_timeout"])
    
    local retcode,errmsg = sock:connect(opts["server"][conf_pos]["host"],opts["server"][conf_pos]["port"],opts["server"][conf_pos]["pool_name"])
    if not retcode then
        if use_log then
            nlog.derror("connect " .. opts["server"][conf_pos]["pool_name"] .. " failed : "..tostring(errmsg))
        end
        load_balance.set_status(opts, conf_pos, false)
        return self.init(self, opts)  --use tail recursion, no stack overflow
    end

    self.tries = 0
    load_balance.set_status(opts, conf_pos, true)

    self.state = STATE_CONNECTED
    self.keepalive_timeout = opts["server"][conf_pos]["keepalive_timeout"]
    self.pool_size = opts["server"][conf_pos]["pool_size"]
    self.max_head_size = opts["server"][conf_pos]["max_head_size"]
    self.max_body_size = opts["server"][conf_pos]["max_body_size"]
    return 1,"ok"
end

function done(self, close)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot be reused in the current connection state: "
                    .. (self.state or "nil")
    end

    self.state = nil

    if close then
        return sock:close() --1, or nil,closed
    end
    
    return sock:setkeepalive(self.keepalive_timeout,self.pool_size)  --1, or nil,closed
end

function send_request(self, req_tb)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot send query in the current context: "
                    .. (self.state or "nil")
    end
    
    local req_str = _make_request(req_tb)
    if not req_str then
        return nil, "wrong request"
    end
    
    local byte_sent,errmsg = sock:send(req_str)
    
    if byte_sent then
        self.state = STATE_REQUEST_SENT
    end

    return byte_sent,errmsg
end

function receive_response(self)

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    if self.state ~= STATE_REQUEST_SENT then
        return nil, "cannot send query in the current context: "
                    .. (self.state or "nil")
    end

    local ret_table,errmsg = sock:receive_http(self.max_head_size,self.max_body_size)
    
    self.state = STATE_CONNECTED
    
    if ret_table and type(ret_table["body"]) == "table" then
        ret_table["body"] = table.concat(ret_table["body"])
    end
    
    if errmsg then
        if use_log then
            nlog.derror("receive_http failed : "..tostring(errmsg))
        end
    end
    
    return ret_table,errmsg
end

function http_request(self, req_tb)
    local start = ngx.now()
    local ret,errmsg = self:send_request(req_tb)
    if not ret then
        self:done(true)
        local elapsed = string.format("%.3f", ngx.now() - start)
        if use_log then
            nlog.http((self.sock and self.sock[POOL_NAME_INDEX]), req_tb.uri, elapsed, "[send_request error: " .. tostring(errmsg) .. "]")
        end
        return nil,errmsg
    end
    
    local ret_table,errmsg = self:receive_response()
    
    local elapsed = string.format("%.3f", ngx.now() - start)
    if errmsg then
        nlog.http((self.sock and self.sock[POOL_NAME_INDEX]), req_tb.uri, elapsed, "[receive_response error: " .. tostring(errmsg) .. "]")
        return nil, errmsg
    end
    nlog.http((self.sock and self.sock[POOL_NAME_INDEX]), req_tb.uri, elapsed, nil)

    return ret_table
end