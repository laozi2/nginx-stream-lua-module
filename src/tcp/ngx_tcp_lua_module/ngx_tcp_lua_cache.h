#ifndef NGX_TCP_LUA_CACHE_H
#define NGX_TCP_LUA_CACHE_H

#include "ngx_tcp_lua_common.h"


ngx_int_t ngx_tcp_lua_cache_loadfile(lua_State *L, const u_char *script,
        const u_char *cache_key, char **err, unsigned enabled);
ngx_int_t ngx_tcp_lua_cache_loadbuffer(lua_State *L, const u_char *src, size_t src_len,
        const u_char *cache_key, const char *name, char **err, unsigned enabled);


#endif 


