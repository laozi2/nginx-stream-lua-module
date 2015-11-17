##lua api 使用说明


### `ngx.say`, `ngx.print`
*   语法:   send_bytes, err = ngx.print(...) 
>*   参数为任意个以下类型的值: table,string,nil,number,boolean, `ngx.null`. table为前面类型组成的数组，顺序拼接

*   返回值: 

>*   luaL_error, lua脚本出错退出, 有错误信息
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足
>>* ...

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>* 参数类型错误

>* 两个返回值: **nil, *errmsg*** ; 发送错误
>>* 发送socket无效 : "closed"
>>* 没有数据要发送 : "will send nothing"
>>* 发送失败: "EAGAIN error", "closed",...

>* 两个返回值: ***number(>0)*, nil**
>>* 发送除了number个字节数，可能少于要发送的字节数

*   注意： 

>*     该函数的实现暂未采用异步等待发完的处理，而是直接send(). **建议一次发送数据量不要过大**。
>*     之所以失败第一个返回值是nil不是0是因为考虑以后发送超时，仍然返回已发送字节数，并且返回错误信息


### `ngx.receive`
* 语法:  data, err, partial = ngx.receive(*totoal-size*, *at-least-size*)
>*  参数1 totoal-size 大于0的数字
>*  参数2 at-least-size 至少多少个就可以返回，取值范围[1,totoal-size], 或者为nil,表示默认为totoal-size

* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 1 or 2 arguments"
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足: "out of memory"

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>*  参数1不是数字： "expecting number parameter!"
>>*  参数1小于等于0: "bad argument <= 0"
>>*  参数2不在特定范围内: "bad pattern argument beyond [1,$2]"

>*  data, err, partial
>>* 如果超时，客户端断开，接收出错等： data为nil, err为字符串, partial为出错前接收到的数据
>>* 正常情况，data为接收到字符串，err,partial为nil


### `ngx.wait_next_request`

* 语法: `ngx.wait_next_request()`

* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 0 arguments 
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"


### `ngx.exit`

* 语法: `ngx.exit()`

* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 0 arguments 
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"


### `ngx.sleep`

* 语法: ngx.sleep(*time-of-seconds*)
>*   参数time-of-seconds, 秒，可以为小数

* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 1 arguments 
>>* 没有session，不在 `protocol_by_lua指令中`, "no session found"

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>* 参数1小于等于0， "bad argument <= 0"


### `ngx.socket.tcp`

*  语法: `tcpsock = ngx.socket.tcp()`

*  返回值: 
>*  luaL_error, lua脚本出错退出, 有错误信息
>>*  参数个数不对 "expecting zero arguments, but got %d"
>>*  没有session，不在 `protocol_by_lua指令中`, "no session found"
>>*  lua内存不足: "out of memory"


>*  tcpsock
>>*  正常一定返回tcpsock对象，其实是个table,[1]=upstream的userdata,[2]=pool key

* 注意:
>* 创建好socket后： `connect_timeout`默认为指令`lua_socket_connect_timeout`的值, `send_timeout`,`read_timeout` 默认为指令`send_timeout`,`read_timeout`的值。 可以在任意时刻使用 sock:settimeout()设置。
>* 后续使用的该返回的对象调函数，这里将对象名字为 tcpsock


### `tcpsock:connect`

* 语法 : ok, err = tcpsock:connect(host, port, pool_name)
>*  参数1 host: 域名或者ip,字符串
>*  参数2 port: 端口，数字 [0,65536]
>*  参数3 pool_name ： 连接池名字，字符串，或者不传参(注意：不是传nil),默认为 host:port


* 返回值:
>*  luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对，"ngx.socket connect: expecting 3 or 4 arguments (including the object), but seen %d"
>>* 没有session，不在 `protocol_by_lua指令中`, "no session found"
>>* 内存不足: "out of memory"

>* luaL_argerror, 参数错误
>>* 参数1的类型： "bad argument, string expected"
>>* 参数2的类型和范围: "bad port number, need [0,65536]"
>>* 参数3的类型，有但不是string : "bad argument, string expected"

>* ok,err
>>* 成功,返回1个值，数字1
>>* 失败,返回2个值，nil,errmsg.

*  注意:
>*  在已连接状态的tcpsock上再次connect，将先断开该连接


### `tcpsock:receive`

* 语法 : data, err, partial = tcpsock:receive(*totoal-size*, *at-least-size*)
>*  参数1 totoal-size 大于0的数字
>*  参数2 at-least-size 至少多少个就可以返回，取值范围[1,totoal-size], 或者为nil,表示默认为totoal-size

* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 1 or 2 arguments"
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足: "out of memory"

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>*  参数1不是数字： "expecting number parameter!"
>>*  参数1小于等于0: "bad argument <= 0"
>>*  参数2不在特定范围内: "bad pattern argument beyond [1,$2]"

>*  data, err, partial
>>* 如果超时，客户端断开，接收出错等： data为nil, err为字符串, partial为出错前接收到的数据
>>* 正常情况，data为接收到字符串，err,partial为nil

### `tcpsock:send`

* 语法: byte_sent,errmsg,`partial_sent_byte` = tcpsock:send(...)
>*  任意个参数，类型为number,string, table; table为数组，包含类型number,string,table,顺序拼接

* 返回值:
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "expecting 2 arguments (including the object),but got %d"
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足: "out of memory"

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>* 参数类型不对

>*  byte_sent,error,`partial_sent_byte`
>>* 如果发送成功: byte_sent为实际发出的字节数，等于要发送的字节数
>>* 如果发送失败: byte_send为nil, errmsg为错误信息，字符串，`partial_sent_byte`为失败前已经发送的字节数



### `tcpsock:close`

* 语法: retcode,errmsg = tcpsock:close()

* 返回值:
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数不对 "ngx.socket close: expecting 1 argument", 这里指没有对象调用。
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"

>* retcode,errmsg
>>*  如果close成功: 返回数字1
>>*  如果已经close了，返回nil, "closed"


### `tcpsock:settimeout`

* 语法: tcpsock:settimeout(*connect_timeout*,*send_timeout*,*read_timeout*)
>* 单位毫秒，只有大于0的数字才能被设置, 反之不报错


* 返回值: 
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数少于1,包括对象 : "expecting at least 1 arguments (including the object) but got %d"


### `tcpsock:getreusedtimes`

* 语法: reusedtime,errmsg = tcpsock:getreusedtimes()

* 返回值:
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数错误: "expecting 1 argument (including the object), but got %d"

>* reusedtime,errmsg
>>* socket已经关闭，返回 nil,"closed"
>>* 成功返回数字.

### `tcpsock:setkeepalive`

* 语法: retcode,errmsg = tcpsock:setkeepalive(*timeout*,*pool_size*)
>*  timeout: 毫秒,数字:0表示无限时间;或者nil: 默认60秒
>*  pool_size : 数字，>=0, 或者为nil:默认30. 仅当该连接池不存在的情况，已存在的无效

* 返回值:
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数错误: "expecting 1 to 3 arguments (including the object), but got %d"
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足: "out of memory"

>* retcode,errmsg
>>* 错误: nil, error string : "key not found","closed","invalid connection","failed to handle read event", "zero pool size", "connection in dubious state",
>>* 成功: 数字1

### `tcpsock:receive_http`

* 语法: rettb,errmsg = tcpsock:receive_http(*max_head_size*,*max_body_size*)
>*  参数1 max_head_size， number>0, 需合理设置
>*  参数2 max_body_size， number>0, 需合理设置

* 返回值
>* luaL_error, lua脚本出错退出, 有错误信息
>>* 参数个数错误: "expecting 3 arguments (including the object), but got %d"
>>* 没有session，不在 `protocol_by_lua`指令中, "no session found"
>>* 内存不足: "out of memory"

>* luaL_argerror, 参数错误，lua脚本出错退出, 有参数错误信息
>>* 参数2,3不是数字，"expecting number parameter!", 不是大于0 "bad argument <= 0"

>* rettb,errmsg
>>* rettb: table, 边解析边放入table,出错可能导致table里解析到的http内容不完整。
>>* 当成功时: errmsg是nil, 否则为string
>>* table { info(string),code(数字),headers为字典类型table,body为数组类型的table}
