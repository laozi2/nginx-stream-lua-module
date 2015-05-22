nginx tcp lua module
=========================
A tcp module with lua support for nginx.

Most code are copied from ngx-lua-module & nginx-tcp-lua-module. Thanks for there great job.

Tested with nginx-1.4.1.

2015/05/19

config file example
--------------------
    tcp {
        #...

        lua_package_path '/usr/local/nginx_tcp/conf/?.lua;/usr/local/nginx_tcp/conf/lua_module/?.lua;;';
        lua_package_cpath '/usr/local/nginx_tcp/conf/lua_module/?.so;;';

        lua_shared_dict db_lock 100m;

        init_by_lua_file 'conf/init_by_lua.lua';

        server {
             listen 6666;

             protocol tcp_lua;

             process_by_lua_file 'conf/test.lua';

             lua_socket_connect_timeout 10s;
             lua_check_client_abort on; #default off

             resolver 114.114.114.114;
        }
     }

`init_by_lua.lua`

    --------------common-----------------------
    cjson = require "cjson"
    cjson_safe = require "cjson.safe"
    bit = require "bit"
    luuid = require "luuid"
    netutil = require "netutil"
    mysql = require "mysql"
    db_ml = require "db_ml"
    --...



`test.lua`


    local client_sock = ngx.socket.tcp()
    client_sock:settimeout(5000,1000,3000)

    local data = "hello world 1234567890"
    local data_len = string.len(data)
    local data_len_h = netutil.htonl(data_len)
    local req_data = netutil.packint32(data_len_h) .. data


    local upstream_test = function(u)
        local ret,err = u:connect("127.0.0.1",8000,"127.0.0.1_8000_1");
        local reuse = u:getreusedtimes()
        ngx.log(ngx.INFO,"connect : "..tostring(ret).." "..tostring(err).." "..tostring(reuse))
        if not ret then 
             return
        end

        ret,err = u:send(req_data)
        ngx.log(ngx.INFO,"send : "..tostring(ret).." "..tostring(err))
        if not ret then
            return
        end

        local data,err = u:receive(4,nil)
        if use_log then ngx.log(ngx.INFO,"receive : "..tostring(data).." "..tostring(err)) end
        if not data then
            return
        end

        local totoal_len = netutil.unpackint32(string.sub(data,1,4))
        ngx.log(ngx.INFO,"totoal_len : "..tostring(totoal_len))

        local data,err = u:receive(totoal_len - 4,nil)
        ngx.log(ngx.INFO,"receive again: ["..tostring(data).."] "..tostring(err))
        if not data then
             return
        end

        if totoal_len - 4 ~= #data then
             ngx.log(ngx.INFO,"receive len not match")
             return
        end
        u:setkeepalive()
    end


    local test_shm = function()
         local key = "x"
         local value = "hello world"
         local dogs = ngx.shared.db_lock
         local shm_value = dogs:get(key)

         if not shm_value then
             local succ, err, forcible = dogs:set(key,value,10000)
             ngx.log(ngx.INFO,tostring(succ)..","..tostring(err)..","..tostring(forcible))
         end

         local shm_value = dogs:get(key)
         ngx.log(ngx.INFO,tostring(shm_value))
    end


    while true do
         local data,r2,r3 = ngx.receive(10,6)

         ngx.say("receive ret "..tostring(data).." "..tostring(r2).." "..tostring(r3) .. ","..collectgarbage("count"))
         if not data then
              ngx.say("exit")
              ngx.exit()
         end

       --ngx.sleep(5)

       --upstream_test(client_sock)

       test_shm()

       --collectgarbage()

        ngx.wait_next_request()
    end

Note:
>*  为尽可能减少资源消耗，提升效率，将请求的作用域划分为：以基于连接的会话 `connection_session` ， 和基于协议的请求 `light_session`. 二者区别在于： `connection_session` 在协程内运行lua脚本的正常(`ngx.exit()`,或程序执行完)或异常退出，将删除该协程，同时做一次强制垃圾收集，断开客户端连接，释放会话内存池和链接内存池。 `light_session` 仅打印日志，进入请求的keepalive状态，等待下一次请求。 函数 `ngx.wait_next_request()` 将结束当前`light_session`并等待下次请求。 因此推荐编程框架为
>>      while true do
>>             --...
>>          ngx.wait_next_request()
>>      end

Directives
------------------

###`lua_package_cpath`

>* Syntax:  
>>*     **`lua_package_cpath`** *lua-style-cpath-str*
>>*     **Default :**  *The content of LUA_CPATH environment variable or Lua's compiled-in defaults.*
>>*     **Context :**  tcp

>* For example:
>>     lua_package_cpath '/bar/baz/?.so;/blah/blah/?.so;;';

>* Note:
>>*    lua调用so库的访问路径

###`lua_package_path`

>* Syntax:  
>>*     **`lua_package_path`** *lua-style-path-str*
>>*     **Default :**  *The content of LUA_PATH environ variable or Lua's compiled-in defaults.*
>>*     **Context :**  tcp

>* For example:
>>     lua_package_path '/foo/bar/?.lua;/blah/?.lua;;';

>* Note:
>>*    lua调用其他lua模块的访问路径

###`lua_code_cache`

>* Syntax:  
>>*     **`lua_code_cache`** on | off;
>>*     **Default :**  on;
>>*     **Context :**  tcp,server

>* For example:
>>     lua_code_cache on;

>* Note:
>>*    是否缓存lua代码

###`init_by_lua`

>* Syntax:  
>>*     **`init_by_lua`** *path-to-lua-script-file*;
>>*     **Default :**  -
>>*     **Context :**  tcp

>* For example:
>>     init_by_lua 'a = require("a")';

>* Note:
>>*    Runs the Lua code specified by the argument <lua-script-str> on the global Lua VM level when the Nginx master process (if any) is loading the Nginx config file. 
>>*    As http lua.



###`init_by_lua_file`

>* Syntax:  
>>*     **`init_by_lua_file`** *lua-script-str*;
>>*     **Default :**  -
>>*     **Context :**  tcp

>* For example:
>>     init_by_lua_file 'conf/init_by_lua.lua';

>* Note:
>>*    As http lua.


###`process_by_lua_file`

>* Syntax:  
>>*     **`process_by_lua_file`** *path-to-lua-script-file*;
>>*     **Default :**  -
>>*     **Context :**  server

>* For example:
>>     process_by_lua_file 'conf/test.lua';

>* Note:
>>*    执行请求的lua文件

###`process_by_lua`

>* Syntax:  
>>*     **`process_by_lua`** *lua-script-str*;
>>*     **Default :**  -
>>*     **Context :**  server

>* For example:
>>     process_by_lua 'ngx.exit()';

>* Note:
>>*    执行请求的lua代码

###`lua_socket_connect_timeout`

>* Syntax:  
>>*     **`lua_socket_connect_timeout`** *time*;
>>*     **Default :**  60s;
>>*     **Context :**  tcp,server

>* For example:
>>     lua_socket_connect_timeout 5;

>* Note:
>>*    作为客户端连接上游的超时时间

###`lua_socket_send_lowat`

>* Syntax:  
>>*     **`lua_socket_send_lowat`** *size*;
>>*     **Default :**  0;
>>*     **Context :**  tcp,server

>* For example:
>>     lua_socket_send_lowat 0;

>* Note:
>>*    Controls the lowat (low water) value for the cosocket send buffer. 

###`lua_socket_pool_size`

>* Syntax:  
>>*     **`lua_socket_pool_size`** *size*;
>>*     **Default :**  30;
>>*     **Context :**  tcp,server

>* For example:
>>     lua_socket_pool_size 10;

>* Note:
>>*    Specifies the size limit (in terms of connection count) for every cosocket connection pool associated with every remote server (i.e., identified by either the host-port pair). 
>>*    When the connection pool exceeds the available size limit, the least recently used (idle) connection already in the pool will be closed to make room for the current connection.
>>*    Note that the cosocket connection pool is per nginx worker process rather than per nginx server instance, so size limit specified here also applies to every single nginx worker process.

###`lua_check_client_abort`

>* Syntax:  
>>*     **`lua_check_client_abort`** on|off;
>>*     **Default :**  off;
>>*     **Context :**  tcp,server

>* For example:
>>     lua_check_client_abort on;

>* Note:
>>*    This directive controls whether to check for premature client connection abortion. 

###`lua_shared_dict`

>* Syntax:  
>>*     **`lua_shared_dict`** *name* *size*;
>>*     **Default :**  -
>>*     **Context :**  tcp

>* For example:
>>     lua_shared_dict dogs 10m;

>* Note:
>>*    Declares a shared memory zone, <name>, to serve as storage for the shm based Lua dictionary ngx.shared.<name>.
>>*    Shared memory zones are always shared by all the nginx worker processes in the current nginx server instance.
>>*    The <size> argument accepts size units such as k and m.  **At least 8k**;

Nginx log level constants
------------------------
    ngx.STDERR
    ngx.EMERG
    ngx.ALERT
    ngx.CRIT
    ngx.ERR
    ngx.WARN
    ngx.NOTICE
    ngx.INFO
    ngx.DEBUG


Nginx API for Lua
-----------------

### `ngx.log` 

>* **syntax**: ngx.log(log_level, ...)
>* **context**: `process_by_lua*`

### `ngx.print` 

>* **syntax**: send_bytes, err = ngx.print(...) 
>* **context**: `process_by_lua*`
>* **example**:
>>     ngx.print("hello world",21,nil,true,false,{"a","b"})   --output: hello world21niltruefalseab

>* **note**: 
>>*    args can be string,number,bool,array type of table,lightuserdata,nil
>>*    send_bytes will be (*number*(>0),'ok')  or (nil,*errormsg*).
>>*    This method is a synchronous operation and is 100% nonblocking. But if AGAIN encountered while sending data this data will return immediately.

### `ngx.say` 

>* **syntax**: ok, err = ngx.say(...) 
>* **context**: `process_by_lua*`
>* **note**: Just as ngx.print but also emit a trailing newline. 

### `ngx.exit` 

>* **syntax**: ok, err = ngx.exit()
>* **context**: `process_by_lua*`
>* **note**: this function will exit current session. and delete lua thread and disconnect the client.

### `ngx.receive` 

>* **syntax**: data, err, partial = ngx.receive(*totoal-size*, *at-least-size*) 
>* **context**: `process_by_lua*`
>* **example**:
>>     local data,err,partial = ngx.receive(100,50)

>* **note**: 
>>*   Receives data from the connected socket according to the size. This method is a synchronous operation and is 100% nonblocking. 
>>*   totoal-size: > 0, at-least-size: [1,totoal-size] or nil. 
>>*   In case of success, it returns the data received; in case of error, it returns nil with a string describing the error and the partial data received so far. 
>>*   该实现去掉了 http ngx_lua 的模式匹配功能，以弱化的“至少多少个字节就可以返回”的功能来代替。 这样把解析字符类协议的工作完全放到lua代码里。

### `ngx.sleep` 

>* **syntax**: ngx.sleep(seconds) 
>* **context**: `process_by_lua*`
>* **example**:
>>     ngx.sleep(10.234)

>* **note**: Sleeps for the specified seconds without blocking. One can specify time resolution up to 0.001 seconds (i.e., one milliseconds).  Behind the scene, this method makes use of the Nginx timers. 

### `ngx.wait_next_request` 

>* **syntax**: `ngx.wait_next_request()`
>* **context**: `process_by_lua*`
>* **note**: finalize current light_session and wait next request, client connection will be keepalive.

### `ngx.utctime`

>* **context**: str = ngx.utctime()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns the current time stamp (in the format yyyy-mm-dd hh:mm:ss) of the nginx cached time (no syscall involved unlike Lua's os.date function). This is the UTC time. 

### `ngx.localtime`

>* **context**: str = ngx.localtime()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns the current time stamp (in the format yyyy-mm-dd hh:mm:ss) of the nginx cached time (no syscall involved unlike Lua's os.date function). This is the local time. 

### `ngx.time`

>* **context**: secs = ngx.time()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns the elapsed seconds from the epoch for the current time stamp from the nginx cached time (no syscall involved unlike Lua's date library). Updates of the Nginx time cache an be forced by calling ngx.update_time first. 


### `ngx.now`

>* **context**: secs = ngx.now()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns a floating-point number for the elapsed time in seconds (including milliseconds as the decimal part) from the epoch for the current time stamp from the nginx cached time (no syscall involved unlike Lua's date library). 

### `ngx.today`

>* **context**: str = ngx.today()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns current date (in the format yyyy-mm-dd) from the nginx cached time (no syscall involved unlike Lua's date library). 

### `ngx.tcp_time`

>* **context**: str = ngx.tcp_time(sec)
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Returns a formated string can be used as the http header time (for example, being used in Last-Modified header). The parameter sec is the time stamp in seconds (like those returned from ngx.time). 
>* example
>>     ngx.say(ngx.tcp_time(1290079655))
>>        -- yields "Thu, 18 Nov 2010 11:27:35 GMT"

### `ngx.parse_tcp_time`

>* **context**: sec = ngx.parse_tcp_time(str)
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Parse the http time string (as returned by ngx.tcp_time) into seconds. Returns the seconds or nil if the input string is in bad forms. 
>* example
>>     local time = ngx.parse_tcp_time("Thu, 18 Nov 2010 11:27:35 GMT")
>>     if time == nil then
>>         --...
>>     end

### `ngx.update_time`

>* **context**: ngx.update_time()
>* **context**: `process_by_lua*`,`init_by_lua*`
>* **Note**: Forcibly updates the Nginx current time cache. This call involves a syscall and thus has some overhead, so do not abuse it. 


### `ngx.shared.DICT`

>* **context**: `process_by_lua*`,`init_by_lua*`
>*  **Note**: totally the seem as http [http://wiki.nginx.org/HttpLuaModule#ngx.shared.DICT](http://wiki.nginx.org/HttpLuaModule#ngx.shared.DICT)


### `ngx.socket.tcp`
>* **syntax**: tcpsock = ngx.socket.tcp()
>* **context**: `process_by_lua*`
>* **note**:
>>*   The `connect_timeout`,`read_timeout`,`send_timeout` of tcpsock will default set by config command.
>>*    Just like http  [http://wiki.nginx.org/HttpLuaModule#ngx.socket.tcp](http://wiki.nginx.org/HttpLuaModule#ngx.socket.tcp) Creates and returns a TCP socket object (also known as one type of the "cosocket" objects). The following methods are supported on this object: 
>>>     connect
>>>     send
>>>     receive
>>>     close
>>>     settimeout
>>>     setoption
>>>     setkeepalive
>>>     getreusedtimes

Install
------------------
    wget http://luajit.org/download/LuaJIT-2.0.0.tar.gz
    tar -xvfz LuaJIT-2.0.0.tar.gz
    cd LuaJIT-2.0.0
    make &&  make install

    wget 'http://nginx.org/download/nginx-1.4.1.tar.gz'
    tar -xzvf nginx-1.4.1.tar.gz
    cd nginx-1.4.1/

    # tell nginx's build system where to find luajit:
    export LUAJIT_LIB=/usr/local/lib
    export LUAJIT_INC=/usr/local/include/luajit-2.0

    # or tell where to find Lua
    #export LUA_LIB=/path/to/lua/lib
    #export LUA_INC=/path/to/lua/include
    
    # Here we assume Nginx is to be installed under /usr/local/nginx/.
    ./configure --prefix=/usr/local/nginx \
            --with-debug \
            --with-tcp \
            --add-module=src/tcp/ngx_tcp_log_module \
            --add-module=src/tcp/ngx_tcp_lua_module

    make && make install