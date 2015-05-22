# yum -y install  -y pcre* openssl*
export LUAJIT_LIB=/usr/local/lib
export LUAJIT_INC=/usr/local/include/luajit-2.0
./configure --prefix=/usr/local/nginx_tcp \
			--with-debug \
			--without-http_gzip_module \
			--with-http_stub_status_module \
			--with-tcp \
			--add-module=src/tcp/ngx_tcp_log_module \
			--add-module=src/tcp/ngx_tcp_demo_module \
			--add-module=src/tcp/ngx_tcp_lua_module
