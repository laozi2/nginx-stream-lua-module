#ifndef NGX_TCP_LUA_UTIL_H
#define NGX_TCP_LUA_UTIL_H


#include "ngx_tcp_lua_common.h"


/* char whose address we'll use as key in Lua vm registry for
 * user code cache table */
extern char ngx_tcp_lua_code_cache_key;

/* char whose address we'll use as key in Lua vm registry for
 * all the "ngx.ctx" tables */
extern char ngx_tcp_lua_ctx_tables_key;

/* char whose address we'll use as key in Lua vm registry for
 * regex cache table  */
extern char ngx_tcp_lua_regex_cache_key;

/* char whose address we'll use as key in Lua vm registry for
 * socket connection pool table */
extern char ngx_tcp_lua_socket_pool_key;

/* char whose address we'll use as key for the nginx request pointer */
extern char ngx_tcp_lua_request_key;

/* char whose address we'll use as key for the nginx config logger */
extern char ngx_tcp_lua_cf_log_key;

/* char whose address we use as the key in Lua vm registry for
 * regex cache table  */
extern char ngx_tcp_lua_regex_cache_key;



lua_State *ngx_tcp_lua_new_state(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf);
lua_State *ngx_tcp_lua_new_thread(ngx_tcp_session_t *s, lua_State *L, int *ref);
void ngx_tcp_lua_request_cleanup(void *data);
void ngx_tcp_lua_del_thread(ngx_tcp_session_t *r, lua_State *L, int ref);
ngx_int_t ngx_tcp_lua_run_thread(lua_State *L, ngx_tcp_session_t *s,
        ngx_tcp_lua_ctx_t *ctx, int nret);
void ngx_tcp_lua_wev_handler(ngx_tcp_session_t *s);

u_char *ngx_tcp_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len);

size_t ngx_tcp_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i, unsigned strict);
u_char *ngx_tcp_lua_copy_str_in_table(lua_State *L, int index, u_char *dst);

ngx_int_t ngx_tcp_lua_report(ngx_log_t *log, lua_State *L, int status,
    const char *prefix);

int ngx_tcp_lua_do_call(ngx_log_t *log, lua_State *L);

int ngx_tcp_lua_traceback(lua_State *L);

void ngx_tcp_lua_stack_dump(lua_State* L,const char* prefix);

static ngx_inline ngx_tcp_session_t *
ngx_tcp_lua_get_session(lua_State *L)
{
    ngx_tcp_session_t    *s;

    //lua_getglobal(L, &ngx_tcp_lua_request_key);
    lua_pushlightuserdata(L, &ngx_tcp_lua_request_key);
    lua_rawget(L, LUA_GLOBALSINDEX);
    s = lua_touserdata(L, -1);
    lua_pop(L, 1);

    return s;
}


#endif
