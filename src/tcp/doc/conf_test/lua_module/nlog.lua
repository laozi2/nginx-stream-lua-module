-----------------------------------------
--Module: nlog
--Author: xxh
--Date: 
-----------------------------------------

local strchar = string.char
local stringlen = string.len
local stringformat = string.format
local stringbyte = string.byte
local tableinsert = table.insert
local tableconcat = table.concat
local ngxlocaltime = ngx.localtime
local ngxnlog = ngx.nlog
local tonumber = tonumber
local tostring = tostring

module("nlog")

--[[
function list :
	nlog.init({}) --only use in init_by_lua
		example: 
			nlog.init({
				["sock"] = {"127.0.0.1:5003","127.0.0.1:5151"},
				["dsock"] = {"127.0.0.1:5004","127.0.0.1:5151"},
				["hsock"] = {"127.0.0.1:5005","127.0.0.1:5151"},
			})

	nlog.error(str)
	nlog.warn(str)
	nlog.info(str)
	nlog.debug(str)
	
	nlog.derror(str)
	nlog.dwarn(str)
	nlog.dinfo(str)
	nlog.ddebug(str)
	
	nlog.herror(str)
	nlog.hwarn(str)
	nlog.hinfo(str)
	nlog.hdebug(str)
	
	nlog.sql(host, elapsed, sql)
	nlog.http(host, uri, elapsed, errmsg)

--]]
----------------------------------

local csock = nil
local dsock = nil
local hsock = nil

init = function(conf_tb)
    csock = ngxnlog(conf_tb["csock"][1],conf_tb["csock"][2])
    dsock = ngxnlog(conf_tb["dsock"][1],conf_tb["dsock"][2])
    hsock = ngxnlog(conf_tb["hsock"][1],conf_tb["hsock"][2])
end

-----------------------
error = function(str)
    local msg = strchar(0x1b) .. "[1;33m" .. ngxlocaltime() .. " ERROR ".. str 
             .. strchar(0x1b) .. "[0m\n"
    csock:send(msg) 
end

warn = function(str)
    local msg = strchar(0x1b) .. "[1;35m" .. ngxlocaltime() .. " WARN ".. str 
             .. strchar(0x1b) .. "[0m\n"
    csock:send(msg)
end

info = function(str)
    local msg = strchar(0x1b) .. "[1;32m" .. ngxlocaltime() .. " INFO ".. str 
            .. strchar(0x1b) .. "[0m\n"
    csock:send(msg)
end

debug = function(str)
    local msg = strchar(0x1b) .. "[0;00m" .. ngxlocaltime() .. " DEBUG ".. str 
            .. strchar(0x1b) .. "[0m\n"
    csock:send(msg) 
end


-----------------------------

derror = function(str)
    local msg = strchar(0x1b) .. "[1;33m" .. ngxlocaltime() .. " ERROR ".. str 
            .. strchar(0x1b) .. "[0m\n"
    dsock:send(msg) 
end

dwarn = function(str)
    local msg = strchar(0x1b) .. "[1;35m" .. ngxlocaltime() .. " WARN ".. str 
            .. strchar(0x1b) .. "[0m\n"
    dsock:send(msg)
end

dinfo = function(str)
    local msg = strchar(0x1b) .. "[1;32m" .. ngxlocaltime() .. " INFO ".. str 
            .. strchar(0x1b) .. "[0m\n"
    dsock:send(msg)
end

ddebug = function(str)
    local msg = strchar(0x1b) .. "[0;00m" .. ngxlocaltime() .. " DEBUG ".. str 
            .. strchar(0x1b) .. "[0m\n"
    dsock:send(msg) 
end

-------------------------------
local tohex = function(str)
    local len = stringlen(str)
    local tb = {}
    for i = 1, len do
        tableinsert(tb,stringformat("%02X",stringbyte(str,i)))
    end
    
    return tableconcat(tb)
end


herror = function(str)
    local msg = strchar(0x1b) .. "[1;33m" .. ngxlocaltime() .. " ERROR ".. tohex(str) 
            .. strchar(0x1b) .. "[0m\n"
    hsock:send(msg) 
end

hwarn = function(str)
    local msg = strchar(0x1b) .. "[1;35m" .. ngxlocaltime() .. " WARN ".. tohex(str) 
            .. strchar(0x1b) .. "[0m\n"
    hsock:send(msg)
end

hinfo = function(str)
    local msg = strchar(0x1b) .. "[1;32m" .. ngxlocaltime() .. " INFO ".. tohex(str) 
            .. strchar(0x1b) .. "[0m\n"
    hsock:send(msg)
end

hdebug = function(str)
    local msg = strchar(0x1b) .. "[0;00m" .. ngxlocaltime() .. " DEBUG ".. tohex(str) 
            .. strchar(0x1b) .. "[0m\n"
    hsock:send(msg) 
end

--------------------------
sql = function(host, elapsed, sql)
    elapsed = tonumber(elapsed)
    if elapsed < 0.01 then
        --elapsed = tostring(elapsed)
    elseif elapsed < 0.1 then
        elapsed = strchar(0x1b) .. "[1;32m" .. elapsed .. strchar(0x1b) .. "[0m"
    elseif elapsed < 0.5 then
        elapsed = strchar(0x1b) .. "[1;35m" .. elapsed .. strchar(0x1b) .. "[0m"
    else
        elapsed = strchar(0x1b) .. "[1;33m" .. elapsed .. strchar(0x1b) .. "[0m"
    end
    
    local msg = ngxlocaltime() .." " .. tostring(host) .. " " .. elapsed .. " [sql] " 
          .. tostring(sql) .. "\n"

    hsock:send(msg)
end

http = function(host, uri, elapsed, errmsg)
    elapsed = tonumber(elapsed)
    if elapsed < 0.01 then
        --elapsed = tostring(elapsed)
    elseif elapsed < 0.1 then
        elapsed = strchar(0x1b) .. "[1;32m" .. elapsed .. strchar(0x1b) .. "[0m"
    elseif elapsed < 0.5 then
        elapsed = strchar(0x1b) .. "[1;35m" .. elapsed .. strchar(0x1b) .. "[0m"
    else
        elapsed = strchar(0x1b) .. "[1;33m" .. elapsed .. strchar(0x1b) .. "[0m"
    end
    
    local msg = ngxlocaltime() .. " " .. tostring(host) .. " " .. elapsed .. " [http] " .. tostring(uri) .. " "
          .. (errmsg and strchar(0x1b) .. "[1;33m" .. errmsg .. strchar(0x1b) .. "[0m" or "") .. "\n"

    hsock:send(msg)
end

