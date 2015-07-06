#ifndef NGX_TCP_LUA_REQ_H
#define NGX_TCP_LUA_REQ_H

#include "ngx_tcp_lua_common.h"

void ngx_tcp_lua_inject_req_api(lua_State *L);

void ngx_tcp_lua_req_resume(ngx_tcp_session_t *s);

void ngx_tcp_lua_check_client_abort_handler(ngx_tcp_session_t *s);

#endif 
