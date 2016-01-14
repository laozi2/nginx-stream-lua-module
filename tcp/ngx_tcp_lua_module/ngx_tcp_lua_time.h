
/*
 * Copyright (C) Xiaozhe Wang (chaoslawful)
 * Copyright (C) Yichun Zhang (agentzh)
 */


#ifndef _NGX_TCP_LUA_TIME_H_INCLUDED_
#define _NGX_TCP_LUA_TIME_H_INCLUDED_


#include "ngx_tcp_lua_common.h"


void ngx_tcp_lua_inject_time_api(lua_State *L);
void ngx_tcp_lua_inject_req_time_api(lua_State *L);


#endif /* _NGX_HTTP_LUA_TIME_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
