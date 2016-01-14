

#include "ngx_tcp_lua_exception.h"
#include "ngx_tcp_lua_util.h"


/*  longjmp mark for restoring nginx execution after Lua VM crashing */
jmp_buf ngx_tcp_lua_exception;

/**
 * Override default Lua panic handler, output VM crash reason to nginx error
 * log, and restore execution to the nearest jmp-mark.
 * 
 * @param L Lua state pointer
 * @retval Long jump to the nearest jmp-mark, never returns.
 * @note nginx request pointer should be stored in Lua thread's globals table
 * in order to make logging working.
 * */
int
ngx_tcp_lua_atpanic(lua_State *L)
{
    return 1;
}

