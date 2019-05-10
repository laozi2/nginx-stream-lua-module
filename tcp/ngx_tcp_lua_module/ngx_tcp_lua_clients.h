
/*

 */


#ifndef _NGX_TCP_LUA_CLIENTS_H_INCLUDED_
#define _NGX_TCP_LUA_CLIENTS_H_INCLUDED_


#include "ngx_tcp_lua_common.h"


typedef struct ngx_tcp_lua_client_s {
    ngx_tcp_session_t              *session;
} ngx_tcp_lua_client_t;

void ngx_tcp_lua_inject_clients_api(lua_State *L);
void ngx_tcp_lua_clients_cleanup(lua_State *L, void *data);

#endif /* _NGX_TCP_LUA_CLIENTS_H_INCLUDED_ */
