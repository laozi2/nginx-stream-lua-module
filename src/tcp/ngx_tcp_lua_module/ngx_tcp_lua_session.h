
#ifndef _NGX_TCP_LUA_SESSION_H_INCLUDED_
#define _NGX_TCP_LUA_SESSION_H_INCLUDED_


#include "ngx_tcp_lua_common.h"


void ngx_tcp_lua_close_session(ngx_tcp_session_t *s);
ngx_int_t ngx_tcp_lua_init_light_session(ngx_tcp_session_t* s);
void ngx_tcp_lua_finalize_light_session(ngx_tcp_session_t* s);

void ngx_tcp_lua_log_session(ngx_tcp_session_t* s);

#endif /*_NGX_TCP_LUA_SESSION_H_INCLUDED_*/
