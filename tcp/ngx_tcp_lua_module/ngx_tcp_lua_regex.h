
/*
 * Copyright 
 */


#ifndef _NGX_TCP_LUA_REGEX_H_INCLUDED_
#define _NGX_TCP_LUA_REGEX_H_INCLUDED_


#include "ngx_tcp_lua_common.h"


#if (NGX_PCRE)
void ngx_tcp_lua_inject_regex_api(lua_State *L);
#endif


#endif /* _NGX_TCP_LUA_REGEX_H_INCLUDED_ */

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
