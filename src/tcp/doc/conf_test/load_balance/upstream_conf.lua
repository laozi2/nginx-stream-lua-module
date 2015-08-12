local upstream_conf = {}


upstream_conf["user_backend"] = {
	["server"] = {
		{
			["host"] = "192.168.1.23", --string
			["port"] = 80,  --number
			["weight"] = 3, -- number >=0
			["connect_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_CONNECT_TIMEDOUT)
			["send_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_SEND_TIMEDOUT)
			["read_timeout"] = 5000,  --number(ms,>0) or nil(default DEFAULT_READ_TIMEDOUT)
			["pool_name"] = nil, --"127.0.0.1:80", --string or nil(defaul is host:port)
			["pool_size"] = 50, --number or nil(default DEFAULT_POOL_SIZE)
			["keepalive_timeout"] = nil, --number(ms,>0; =0unlimited) or nil(default DEFAULT_KEEPALIVE_TIMEDOUT)
			["max_head_size"] = 512, --number(>0), or nil(default DEFAULT_MAX_HEAD_SIZE)
			["max_body_size"] = 2048, --number(>0), or nil(default DEFAULT_MAX_BODY_SIZE)
		},
		{
			["host"] = "192.168.1.24", 
			["port"] = 80,
			["weight"] = 1, 
			["connect_timeout"] = 5000, 
			["send_timeout"] = 5000,
			["read_timeout"] = 5000, 
			["pool_name"] = nil,
			["pool_size"] = 50, 
			["keepalive_timeout"] = nil, 
			["max_head_size"] = 512,
			["max_body_size"] = 2048, 
		},
	},
	["backend_name"] = "user_backend",
	["failed_time"] = 60, -- number, second, max abandon time when marked down, nil(default DEFAULT_FAILED_TIME)
	["max_tries"] = 3, -- number >= 1, max try times to connect, nil(default DEFAULT_MAX_TRIES)
}




return upstream_conf