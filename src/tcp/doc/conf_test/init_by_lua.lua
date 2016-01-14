
--------------common-----------------------
--cjson = require "cjson"  --do not use .so here
--cjson_safe = require "cjson.safe"
bit = require "bit"
--luuid = require "luuid"
--netutil = require "netutil"


--nlog-----------
require("nlog")
nlog.init({
	["csock"] = {"127.0.0.1:5003","127.0.0.1:5151"},
	["dsock"] = {"127.0.0.1:5004","127.0.0.1:5151"},
	["hsock"] = {"127.0.0.1:5005","127.0.0.1:5151"},
})

---http-------
require("http")

---mysql------
require("db_ml")

-----http load balance---
upstream_conf = require "upstream_conf"
require("load_balance")
load_balance.check_config_all(upstream_conf)
require("http_lb")

ssl1 = ngx.new_ssl_ctx({
    ssl_protocols = {
            "SSLv3",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
        },
    ssl_ciphers = "HIGH:!aNULL:!MD5",
    ssl_verify_depth = 1,
    ssl_trusted_certificate = "",
    ssl_crl = "",
})


