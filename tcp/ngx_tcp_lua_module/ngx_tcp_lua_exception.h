
#ifndef NGX_TCP_LUA_EXCEPTION_H
#define NGX_TCP_LUA_EXCEPTION_H

#include <setjmp.h>
#include "ngx_tcp_lua_common.h"

#define NGX_LUA_EXCEPTION_TRY if (setjmp(ngx_tcp_lua_exception) == 0)
#define NGX_LUA_EXCEPTION_CATCH else
#define NGX_LUA_EXCEPTION_THROW(x) longjmp(ngx_tcp_lua_exception, (x))

extern jmp_buf ngx_tcp_lua_exception;

int ngx_tcp_lua_atpanic(lua_State *L);

#endif /* NGX_TCP_LUA_EXCEPTION_H */

