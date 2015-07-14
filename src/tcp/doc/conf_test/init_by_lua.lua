
--------------common-----------------------
cjson = require "cjson"
cjson_safe = require "cjson.safe"
bit = require "bit"
luuid = require "luuid"
netutil = require "netutil"
mysql = require "mysql"
db_ml = require "db_ml"
http = require "http"

nlog = require "nlog"
socket = require("socket")
sock = socket.udp()
sock:setoption("reuseaddr",true)
sock:setsockname("127.0.0.1",5003)
sock:setpeername("127.0.0.1",5151)

dsocket = require("socket")
dsock = dsocket.udp()
dsock:setoption("reuseaddr",true)
dsock:setsockname("127.0.0.1",5004)
dsock:setpeername("127.0.0.1",5151)

hsocket = require("socket")
hsock = hsocket.udp()
hsock:setoption("reuseaddr",true)
hsock:setsockname("127.0.0.1",5005)
hsock:setpeername("127.0.0.1",5151)

gsocket = require("socket")
gsock = gsocket.udp()
gsock:setoption("reuseaddr",true)
gsock:setsockname("127.0.0.1",5007)
gsock:setpeername("127.0.0.1",5161)

ksocket = require("socket")
ksock = ksocket.udp()
ksock:setoption("reuseaddr",true)
ksock:setsockname("127.0.0.1",5007)
ksock:setpeername("127.0.0.1",5162)

