nginx tcp core module
=========================
A tcp module for nginx.

Tested with nginx-1.4.1.

2015/05/19


Install
--------------------



config file example
--------------------
    tcp {

        #connection_pool_size 1k;   #main/srv/take one/default 0.5k
        session_pool_size 1k;  #main/srv/take one/default 1k
        client_max_body_size 1k;   #main/srv/take one/default 1k;

        read_timeout 60s;    #main/srv/take one/default 60s
        #send_timeout 60s;    #main/srv/take one/default 60s
        #keepalive_timeout 60; #main/srv/take one/no set,no keepalive_timeout 

        #error_log  logs/error_tcp.log debug_tcp;  #main/srv/take one more/default null
        error_log logs/error_tcp.log info;

        log_format token '$remote_addr $time_iso8601 $msec $request_time $connection $connection_requests $bytes_sent $protocol';
        #default log_format combined '$remote_addr $time_iso8601 $msec $request_time $connection $connection_requests $protocol';


        server {
            listen 6666;

            protocol demo;

            #access_log off;
            access_log logs/access_tcp.log token;  #default access_log logs/access_tcp.log;
            access_nlog 0.0.0.0:5002 0.0.0.0:5151;

            allow 127.0.0.1;
            deny all;
        }

    }


Directives
------------------

###`listen`

>* Syntax:  
>>*     **`listen`** [ip:]*port* [backlog=number] [rcvbuf=size] [sndbuf=size] [deferred] [bind] [so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]];
>>*     **Default :**  listen *:0;
>>*     **Context :**  server

>* For example:
>>     listen 127.0.0.1:110;
>>     listen *:110;
>>     listen 110;     # same as *:110

>* Note:
>>*    为了禁止一个端口处理不同协议，同一个端口只属于一个server. 同一个server 可以有多个端口.
>>*    目前仅支持 ipv4 ,不支持ipv6, unix_domain, 不支持 ssl


###`protocol` 

>* Syntax:  
>>*     **`protocol`** *protocol_name*;
>>*     **Default :** -
>>*     **Context :**  server

>* For example:
>>     protocol demo;

>* Note:
>>*     protocol 为已实现的流处理模块. 一个server里必须仅有一个protocol配置.


###`read_timeout` 

>* Syntax:  
>>*     **`read_timeout`** *time*;
>>*     **Default :** 60s;
>>*     **Context :**  tcp,server

>* For example:
>>     read_timeout 60s;

>* Note:
>>*   读完整个协议数据的时间，具体由各个协议实现。


###`send_timeout` 

>* Syntax:  
>>*     **`send_timeout`** *time*;
>>*     **Default :** 60s;
>>*     **Context :**  tcp,server

>* Example:
>>     send_timeout 60s;

>* Note:
>>*   一次发送数据流的时间，具体由各个协议实现。


###`keepalive_timeout` 

>* Syntax:  
>>*     **`keepalive_timeout`** *time*;
>>*     **Default :** -
>>*     **Context :**  tcp,server

>* Example:
>>     keepalive_timeout 6000s;

>* Note:
>>*    一个连接上的请求结束后，服务端保留这个连接的时间，不设置就不主动断开客服端。

### `connection_pool_size`

>* Syntax:  
>>*     **`connection_pool_size`** *size*;
>>*     **Default :** 0.5k;
>>*     **Context :** tcp,server

>* Example:
>>     connection_pool_size 1k;

>* Note:
>>*    Allows accurate tuning of per-connection memory allocations.


### `session_pool_size`

>* Syntax:  
>>*     **`session_pool_size`** *size*;
>>*     **Default :** 1k;
>>*     **Context :**  tcp,server

>* Example:
>>     session_pool_size 1k;

>* Note:
>>*    一个会话的内存池大小。该内存池用户存放会话上下文和接收发送的数据。为了既能充分利用内存池，又不用频繁分配内存，大小应略大于平均数据包长度。具体的精确优化配置根据不同协议模块而定。


### `client_max_body_size`

>* Syntax:  
>>*     **`client_max_body_size`** *size*;
>>*     **Default :** 1k;
>>*     **Context :**  tcp,server

>* Example:
>>     client_max_body_size 1k;

>* Note:
>>*     协议允许的最大数据长度。由协议模块实现。

### `error_log`

>* Syntax:  
>>*    **`error_log`**  *file* | stderr | [debug | info | notice | warn | error | crit | alert | emerg];
>>*     **Default :**  error_log logs/error.log error;
>>*     **Context :**  main,tcp,server

>* Example:
>>     error_log logs/error.log error;

>* Note:
>>*     类似于http模块的error_log指令， 在main配置为debug时，tcp,server 日志级别可配置debug_tcp

### `nlog`
>>*    **`nlog`** *`local_ip`*:*`local_port`*  *`remote_ip`*:*`remote_prot`*;
>>*     **Default :** -
>>*     **Context :**  main,tcp,server

>* Example:
>>     nlog 0.0.0.0:5001 0.0.0.0:5151;

>* Note:
>>*     通过udp发送日志到日志服务器，该指令前必须配置`error_log`指令。通过对源码的patch, nlog也支持core,http的`error_log`的udp日志.


### `log_format`

>* Syntax:  
>>*    **`log_format`** *name* *string* ...;
>>*     **Default :** `'$remote_addr $time_iso8601 $msec $request_time $connection $connection_requests $protocol'`;
>>*     **Context :**  tcp,server

>* Example:
>>     log_format token '$remote_addr $time_iso8601 $msec $request_time $connection $connection_requests $bytes_sent $protocol';

>* Note:
>>*     指定日志格式
>>*     $remote_addr : client ip address
>>*     $time_local : local time in the Common Log Format, "28/Sep/1970:12:00:00 +0600"
>>*     $time_iso8601 : local time in the ISO 8601 standard format, "1970-09-28T12:00:00+06:00"
>>*     $msec : time in seconds with a milliseconds resolution at the time of the log write 
>>*     $request_time : request processing time in seconds with a milliseconds resolution; time elapsed between the first bytes were read from the client and the log write after the last bytes were sent to the client 
>>*     $connection : connection serial number 
>>*     $connection_requests : the current number of requests made through a connection (1.1.18) 
>>*     $bytes_sent : the number of bytes sent to a client 
>>*     $protocol : the current protocol name


### `access_log`

>* Syntax:  
>>*    **`access_log`** access_log *path* | off  [*format*];
>>*     **Default :**  `access_log logs/access_tcp.log combined;`
>>*     **Context :**  tcp,server

>* Example:
>>     access_log logs/access_tcp.log token; 

>* Note:
>>*     配置日志


### `access_nlog`

>* Syntax:  
>>*    **`access_nlog`** *`local_ip`*:*`local_port`*  *`remote_ip`*:*`remote_prot`*;
>>*     **Default :**  -
>>*     **Context :**  tcp,server

>* Example:
>>     access_nlog 127.0.0.1:5002 127.0.0.1:5151;

>* Note:
>>*     通过udp发送日志到日志服务器，必须配置access_log之后。


### `allow`

>* Syntax:  
>>*    **`allow`** *ip* | all;
>>*     **Default :**  -
>>*     **Context :**  tcp,server

>* Example:
>>     allow 127.0.0.1;
>>     allow 127.0.0.0/24;
>>     allow all;

>* Note:
>>*     允许ip访问。

### `deny`

>* Syntax:  
>>*    **`deny`** *ip* | all;
>>*     **Default :**  -
>>*     **Context :**  tcp,server

>* Example:
>>     deny 127.0.0.1;
>>     deny 127.0.0.0/24;
>>     deny all;

>* Note:
>>*     禁止ip访问。 allow 和 deny 可以配置任意个，The rules are checked in sequence until the first match is found. 

### `resolver`

>* Syntax:  
>>*    **`resolver`** *address* [valid=*time*]
>>*     **Default :**  -
>>*     **Context :**  tcp,server

>* Example:
>>     resolver 114.114.114.114;

>* Note:
>>*     Configures name servers used to resolve names of upstream servers into addresses


### `resolver_timeout`

>* Syntax:  
>>*    **`resolver_timeout`**  *time*
>>*     **Default :**  30s;
>>*     **Context :**  tcp,server

>* Example:
>>     resolver_timeout 10s;

>* Note:
>>*     Configures name servers used to resolve names of upstream servers into addresses