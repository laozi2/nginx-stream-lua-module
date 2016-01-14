
/*
 * Copyright (C) Yichun Zhang (agentzh)
 */

#include "ngx_tcp_lua_initby.h"
#include "ngx_tcp_lua_util.h"


ngx_int_t
ngx_tcp_lua_init_by_inline(ngx_log_t *log, ngx_tcp_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    //in case of no config Lua
    if (NULL == L) {
        return NGX_OK;
    }

    status = luaL_loadbuffer(L, (char *) lmcf->init_src.data,
                             lmcf->init_src.len, "=init_by_lua")
             || ngx_tcp_lua_do_call(log, L);

    return ngx_tcp_lua_report(log, L, status, "init_by_lua");
}


ngx_int_t
ngx_tcp_lua_init_by_file(ngx_log_t *log, ngx_tcp_lua_main_conf_t *lmcf,
    lua_State *L)
{
    int         status;

    //in case of no config Lua
    if (NULL == L) {
        return NGX_OK;
    }

    status = luaL_loadfile(L, (char *) lmcf->init_src.data)
             || ngx_tcp_lua_do_call(log, L);

    return ngx_tcp_lua_report(log, L, status, "init_by_lua_file");
}

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
