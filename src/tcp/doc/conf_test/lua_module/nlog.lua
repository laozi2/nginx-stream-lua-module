--nlog_utils.lua log for lua file
local nlog = {}

nlog.fatal = function(str)
    local msg = string.char(0x1b) .. "[0;32m" .. ngx.localtime() .. " ERROR " .. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg) 
end

nlog.error = function(str)
    local msg = string.char(0x1b) .. "[1;33m" .. ngx.localtime() .. " ERROR ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg) 
end

nlog.warn = function(str)
    local msg = string.char(0x1b) .. "[1;35m" .. ngx.localtime() .. " WARN ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg)
end

nlog.info = function(str)
    local msg = string.char(0x1b) .. "[1;32m" .. ngx.localtime() .. " INFO ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg)
end

nlog.debug = function(str)
    local msg = string.char(0x1b) .. "[0;00m" .. ngx.localtime() .. " DEBUG ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg) 
end

nlog.trace = function(str)
    local msg = string.char(0x1b) .. "[0;00m" .. ngx.localtime() .. " DEBUG ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    sock:send(msg) 
end

nlog.tohex = function(str)
    local i = 1
    local len = string.len(str)
    local outstring = ""
    while i <= len and i < 4096 do
        outstring = outstring .. string.format("%02X",tostring(string.byte(str,i)))
        i = i + 1
    end
    return outstring
end

nlog.hfatal = function(str)
    local msg = string.char(0x1b) .. "[0;32m" .. ngx.localtime() .. " ERROR " .. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg) 
end

nlog.herror = function(str)
    local msg = string.char(0x1b) .. "[1;33m" .. ngx.localtime() .. " ERROR ".. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg) 
end

nlog.hwarn = function(str)
    local msg = string.char(0x1b) .. "[1;35m" .. ngx.localtime() .. " WARN ".. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg)
end

nlog.hinfo = function(str)
    local msg = string.char(0x1b) .. "[1;32m" .. ngx.localtime() .. " INFO ".. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg)
end

nlog.hdebug = function(str)
    local msg = string.char(0x1b) .. "[0;00m" .. ngx.localtime() .. " DEBUG ".. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg) 
end

nlog.htrace = function(str)
    local msg = string.char(0x1b) .. "[0;00m" .. ngx.localtime() .. " DEBUG ".. nlog.tohex(str) 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    hsock:send(msg) 
end


nlog.dfatal = function(str)
    local msg = string.char(0x1b) .. "[0;32m" .. ngx.localtime() .. " ERROR " .. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    dsock:send(msg) 
end

nlog.derror = function(str)
    local msg = string.char(0x1b) .. "[1;33m" .. ngx.localtime() .. " ERROR ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    dsock:send(msg) 
end

nlog.dwarn = function(str)
    local msg = string.char(0x1b) .. "[1;35m" .. ngx.localtime() .. " WARN ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    dsock:send(msg)
end

nlog.dinfo = function(str)
    local msg = string.char(0x1b) .. "[1;32m" .. ngx.localtime() .. " INFO ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    dsock:send(msg)
end

nlog.ddebug = function(str)
    local msg = string.char(0x1b) .. "[0;00m" .. ngx.localtime() .. " DEBUG ".. str 
            .. " \"" ..  --[[ngx.var.request ..--]] "\"" .. string.char(0x1b) .. "[0m\n"
    dsock:send(msg) 
end

nlog.kdebug = function(str)
    ksock:send(ngx.localtime() .. str .."\n")
end

nlog.sql = function(host, elapsed, sql)
    elapsed = tonumber(elapsed)
    if elapsed < 0.01 then
        --elapsed = tostring(elapsed)
    elseif elapsed < 0.1 then
        elapsed = string.char(0x1b) .. "[1;32m" .. elapsed .. string.char(0x1b) .. "[0m"
    elseif elapsed < 0.5 then
        elapsed = string.char(0x1b) .. "[1;35m" .. elapsed .. string.char(0x1b) .. "[0m"
    else
        elapsed = string.char(0x1b) .. "[1;33m" .. elapsed .. string.char(0x1b) .. "[0m"
    end
    
    local msg = ngx.localtime() .." " .. tostring(host) .. " " .. elapsed .. " [sql] " 
          .. tostring(sql) .. " " .. --[[ngx.var.request ..--]] "\n"

    hsock:send(msg)
end

nlog.http = function(host, uri, elapsed, errmsg)
    elapsed = tonumber(elapsed)
    if elapsed < 0.01 then
        --elapsed = tostring(elapsed)
    elseif elapsed < 0.1 then
        elapsed = string.char(0x1b) .. "[1;32m" .. elapsed .. string.char(0x1b) .. "[0m"
    elseif elapsed < 0.5 then
        elapsed = string.char(0x1b) .. "[1;35m" .. elapsed .. string.char(0x1b) .. "[0m"
    else
        elapsed = string.char(0x1b) .. "[1;33m" .. elapsed .. string.char(0x1b) .. "[0m"
    end
    
    local msg = ngx.localtime() .. " " .. tostring(host) .. " " .. elapsed .. " [http] " .. tostring(uri) .. " "
          .. (errmsg and string.char(0x1b) .. "[1;33m" .. errmsg .. string.char(0x1b) .. "[0m" or "") .. "\n"

    hsock:send(msg)
end

return nlog
