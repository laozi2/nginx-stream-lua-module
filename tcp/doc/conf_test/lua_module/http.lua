-----------------------------------------
--Module: http module
--Author: xxh
--Date: 
-----------------------------------------

local nlog = require("nlog")
local tcp = ngx.socket.tcp
module("http", package.seeall)

_M["_VERSION"] = '0'
local mt = {__index = _M}

-- constants

local POOL_NAME_INDEX = 2 --same as SOCKET_KEY_INDEX

local USER_AGENT = "resty-agent"
local CRLF = "\r\n"
local STATE_CONNECTED = 1
local STATE_REQUEST_SENT = 2
local DEFAULT_MAX_HEAD_SIZE = 512
local DEFAULT_MAX_BODY_SIZE = 4096
local DEFAULT_KEEPALIVE_TIMEDOUT = 0 --no timedout
local DEFAULT_POOL_SIZE = 50

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
                "a":"1", --key,value must string, value must not be escaped.
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
    return setmetatable({ sock = sock }, mt)
end

--[[
    opts:
    {
        "host":"127.0.0.1", --string
        "port":80, --number
        "connect_timeout":5000,  --number(ms,>0) or nil
        "send_timeout":5000,  --number(ms,>0) or nil
        "read_timeout":5000,  --number(ms,>0) or nil
        "pool_name":"127.0.0.1:80", --string or nil(set by host:port)
        "pool_size":50, --number or nil,default 50
        "keepalive_timeout":60000, --number(ms,>0; =0unlimited) or nil,default 0
        "max_head_size":512, --number(>0), or nil default 512
        "max_body_size":4096, --number(>0), or nil default 4k
    }
    
    return (nil,errmsg) or (1,"ok")
--]]
function init(self, opts)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end
    
    sock:settimeout(opts.connect_timeout,opts.send_timeout,opts.read_timeout)

    if opts.pool_name == nil then
        opts.pool_name = opts.host .. ":" .. opts.port
    end
    
    local retcode,errmsg = sock:connect(opts.host,opts.port,opts.pool_name)
    if not retcode then
        if use_log then
            nlog.derror("connect failed : "..tostring(errmsg))
        end
        return nil,errmsg
    end
    
    self.state = STATE_CONNECTED
    self.keepalive_timeout = opts.keepalive_timeout or DEFAULT_KEEPALIVE_TIMEDOUT
    self.pool_size = opts.pool_size or DEFAULT_POOL_SIZE
    self.max_head_size = opts.max_head_size or DEFAULT_MAX_HEAD_SIZE
    self.max_body_size = opts.max_body_size or DEFAULT_MAX_BODY_SIZE
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