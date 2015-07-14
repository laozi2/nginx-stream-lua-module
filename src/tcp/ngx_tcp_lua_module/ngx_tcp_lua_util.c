
#include "ngx_md5.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_req.h"
#include "ngx_tcp_lua_string.h"
#include "ngx_tcp_lua_socket.h"
#include "ngx_tcp_lua_exception.h"
#include "ngx_tcp_lua_log.h"
#include "ngx_tcp_lua_time.h"
#include "ngx_tcp_lua_session.h"
#include "ngx_tcp_lua_sleep.h"
#include "ngx_tcp_lua_shdict.h"



char ngx_tcp_lua_code_cache_key;
char ngx_tcp_lua_ctx_tables_key;
char ngx_tcp_lua_regex_cache_key;
char ngx_tcp_lua_socket_pool_key;
char ngx_tcp_lua_request_key;


/*  coroutine anchoring table key in Lua vm registry */
static char ngx_tcp_lua_coroutines_key;

#ifndef LUA_PATH_SEP
#define LUA_PATH_SEP ";"
#endif

#define AUX_MARK "\1"

void ngx_tcp_lua_create_new_global_table(lua_State *L, int narr, int nrec);
static void ngx_tcp_lua_inject_ngx_api(ngx_conf_t *cf, lua_State *L);
void ngx_tcp_lua_inject_core_consts(lua_State *L);


static void
ngx_tcp_lua_set_path(ngx_conf_t *cf, lua_State *L, int tab_idx,
        const char *fieldname, const char *path, const char *default_path)
{
    const char          *tmp_path;
    const char          *prefix;

    /* XXX here we use some hack to simplify string manipulation */
    tmp_path = luaL_gsub(L, path, LUA_PATH_SEP LUA_PATH_SEP,
            LUA_PATH_SEP AUX_MARK LUA_PATH_SEP);

    lua_pushlstring(L, (char *) cf->cycle->prefix.data, cf->cycle->prefix.len);
    prefix = lua_tostring(L, -1);
    tmp_path = luaL_gsub(L, tmp_path, "$prefix", prefix);
    tmp_path = luaL_gsub(L, tmp_path, "${prefix}", prefix);
    lua_pop(L, 3);

    tmp_path = luaL_gsub(L, tmp_path, AUX_MARK, default_path);

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, cf->log, 0,
            "lua setting lua package.%s to \"%s\"", fieldname, tmp_path);

    lua_remove(L, -2);

    /* fix negative index as there's new data on stack */
    tab_idx = (tab_idx < 0) ? (tab_idx - 1) : tab_idx;
    lua_setfield(L, tab_idx, fieldname);
}


static void
ngx_tcp_lua_init_registry(ngx_conf_t *cf, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, cf->log, 0,
            "lua initializing lua registry");

    /* {{{ register a table to anchor lua coroutines reliably:
     * {([int]ref) = [cort]} */
    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* create the registry entry for the Lua request ctx data table */
    lua_pushlightuserdata(L, &ngx_tcp_lua_ctx_tables_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);

    /* create the registry entry for the Lua socket connection pool table */
    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);

    /* {{{ register table to cache user code:
     * {([string]cache_key) = [code closure]} */
    lua_pushlightuserdata(L, &ngx_tcp_lua_code_cache_key);
    lua_newtable(L);
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

}


static void
ngx_tcp_lua_init_globals(ngx_conf_t *cf, lua_State *L)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, cf->log, 0,
            "lua initializing lua globals");

    /* {{{ remove unsupported globals */
    lua_pushnil(L);
    lua_setfield(L, LUA_GLOBALSINDEX, "coroutine");
    /* }}} */


    ngx_tcp_lua_inject_ngx_api(cf, L);
}


static void
ngx_tcp_lua_inject_ngx_api(ngx_conf_t *cf, lua_State *L)
{
    ngx_tcp_lua_main_conf_t   *lmcf;

    lmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_lua_module);

    lua_createtable(L, 0 /* narr */, 89 /* nrec */);    /* ngx.* */

    ngx_tcp_lua_inject_core_consts(L);

    ngx_tcp_lua_inject_log_api(L);
    
    ngx_tcp_lua_inject_req_api(L);

    ngx_tcp_lua_inject_socket_api(cf->log, L);

    ngx_tcp_lua_inject_string_api(L);

    ngx_tcp_lua_inject_time_api(L);

    ngx_tcp_lua_inject_sleep_api(L);

    ngx_tcp_lua_inject_req_time_api(L);

    ngx_tcp_lua_inject_shdict_api(lmcf, L);

    lua_getglobal(L, "package"); /* ngx package */
    lua_getfield(L, -1, "loaded"); /* ngx package loaded */
    lua_pushvalue(L, -3); /* ngx package loaded ngx */
    lua_setfield(L, -2, "ngx"); /* ngx package loaded */
    lua_pop(L, 2);

    lua_setglobal(L, "ngx");
}


lua_State *
ngx_tcp_lua_new_state(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf)
{
    lua_State       *L;
    const char      *old_path;
    const char      *new_path;
    size_t           old_path_len;
    const char      *old_cpath;
    const char      *new_cpath;
    size_t           old_cpath_len;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, cf->log, 0, "lua creating new vm state");

    L = luaL_newstate();
    if (L == NULL) {
        return NULL;
    }

    luaL_openlibs(L);

    lua_getglobal(L, "package");

    if (!lua_istable(L, -1)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "the \"package\" table does not exist");
        return NULL;
    }

#ifdef LUA_DEFAULT_PATH
#   define LUA_DEFAULT_PATH_LEN (sizeof(LUA_DEFAULT_PATH) - 1)
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, cf->log, 0,
            "lua prepending default package.path with %s", LUA_DEFAULT_PATH);

    lua_pushliteral(L, LUA_DEFAULT_PATH ";"); /* package default */
    lua_getfield(L, -2, "path"); /* package default old */
    old_path = lua_tolstring(L, -1, &old_path_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "path"); /* package */
#endif

#ifdef LUA_DEFAULT_CPATH
#   define LUA_DEFAULT_CPATH_LEN (sizeof(LUA_DEFAULT_CPATH) - 1)
    ngx_log_debug1(NGX_LOG_DEBUG_TCP, cf->log, 0,
            "lua prepending default package.cpath with %s", LUA_DEFAULT_CPATH);

    lua_pushliteral(L, LUA_DEFAULT_CPATH ";"); /* package default */
    lua_getfield(L, -2, "cpath"); /* package default old */
    old_cpath = lua_tolstring(L, -1, &old_cpath_len);
    lua_concat(L, 2); /* package new */
    lua_setfield(L, -2, "cpath"); /* package */
#endif

    if (lmcf->lua_path.len != 0) {
        lua_getfield(L, -1, "path"); /* get original package.path */
        old_path = lua_tolstring(L, -1, &old_path_len);

        lua_pushlstring(L, (char *) lmcf->lua_path.data, lmcf->lua_path.len);
        new_path = lua_tostring(L, -1);

        ngx_tcp_lua_set_path(cf, L, -3, "path", new_path, old_path);

        lua_pop(L, 2);
    }

    if (lmcf->lua_cpath.len != 0) {
        lua_getfield(L, -1, "cpath"); /* get original package.cpath */
        old_cpath = lua_tolstring(L, -1, &old_cpath_len);

        lua_pushlstring(L, (char *) lmcf->lua_cpath.data, lmcf->lua_cpath.len);
        new_cpath = lua_tostring(L, -1);

        ngx_tcp_lua_set_path(cf, L, -3, "cpath", new_cpath, old_cpath);

        lua_pop(L, 2);
    }

    lua_remove(L, -1); /* remove the "package" table */

    ngx_tcp_lua_init_registry(cf, L);
    ngx_tcp_lua_init_globals(cf, L);

    return L;
}


lua_State *
ngx_tcp_lua_new_thread(ngx_tcp_session_t *s, lua_State *L, int *ref)
{
    int              top;
    lua_State       *co;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "lua creating new thread");

    top = lua_gettop(L);

    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    co = lua_newthread(L);

    if (co) {
        /*  {{{ inherit coroutine's globals to main thread's globals table
         *  for print() function will try to find tostring() in current
         *  globals table.
         */
        /*  new globals table for coroutine */
        ngx_tcp_lua_create_new_global_table(co, 0, 0);

        lua_createtable(co, 0, 1);
        lua_pushvalue(co, LUA_GLOBALSINDEX);
        lua_setfield(co, -2, "__index");
        lua_setmetatable(co, -2);

        lua_replace(co, LUA_GLOBALSINDEX);
        /*  }}} */

        *ref = luaL_ref(L, -2);

        if (*ref == LUA_NOREF) {
            lua_settop(L, top);  /* restore main thread stack */
            return NULL;
        }
    }

    /*  pop coroutine reference on main thread's stack after anchoring it
     *  in registry */
    lua_pop(L, 1);

    return co;

}

void
ngx_tcp_lua_request_cleanup(void *data)
{
    ngx_tcp_session_t          *s = data;
    ngx_tcp_lua_main_conf_t    *lmcf;
    ngx_tcp_lua_ctx_t          *ctx;
    lua_State                   *L;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "lua request cleanup");

    ctx = s->ctx;

    /*  force coroutine handling the request quit */

    //add here
    ngx_tcp_lua_sleep_cleanup(ctx);
    
    if (ctx->cc_ref == LUA_NOREF) {
        return;
    }

    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

    L = lmcf->lua;
    
    ngx_tcp_lua_del_thread(s, L, ctx->cc_ref);
    
    //force collect garbage
    lua_gc(L, LUA_GCCOLLECT, 0);
    
    //int count = lua_gc(L, LUA_GCCOUNT, 0);
    //dd("ngx_tcp_lua_del_thread %d\n",count);
}


void
ngx_tcp_lua_del_thread(ngx_tcp_session_t *s, lua_State *L, int ref)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "lua deleting thread");

    lua_pushlightuserdata(L, &ngx_tcp_lua_coroutines_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    /* release reference to coroutine */
    luaL_unref(L, -1, ref);
    lua_pop(L, 1);
}


ngx_int_t
ngx_tcp_lua_run_thread(lua_State *L, ngx_tcp_session_t *s,
        ngx_tcp_lua_ctx_t *ctx, int nret)
{
    int                      rv;
    int                      cc_ref;
    lua_State               *cc;
    const char              *err, *msg;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
            "lua run thread");

    /* set Lua VM panic handler */
    lua_atpanic(L, ngx_tcp_lua_atpanic);

    //dd("ctx = %p", ctx);

    cc = ctx->co;
    cc_ref = ctx->cc_ref;

    //rv = lua_resume(cc, 0);
    //dd("%d",rv);

    NGX_LUA_EXCEPTION_TRY {

        dd("calling lua_resume: vm %p, nret %d", cc, (int) nret);

        /*  run code */
        rv = lua_resume(cc, nret);

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                "lua resume returned %d", rv);

        switch (rv) {
            case LUA_YIELD:
                /*  yielded, let event handler do the rest job */
                /*  FIXME: add io cmd dispatcher here */

                ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                        "lua thread yielded");

                if (ctx->exited) {
                    return NGX_OK; //NGX_DONE
                }
                
                //lua_settop(cc, 0);
                return NGX_AGAIN;

            case 0:
                ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                        "lua thread ended normally");

                return NGX_OK;

            case LUA_ERRRUN:
                err = "runtime error";
                break;

            case LUA_ERRSYNTAX:
                err = "syntax error";
                break;

            case LUA_ERRMEM:
                err = "memory allocation error";
                break;

            case LUA_ERRERR:
                err = "error handler error";
                break;

            default:
                err = "unknown error";
                break;
        }

        if (lua_isstring(cc, -1)) {
            dd("user custom error msg");
            msg = lua_tostring(cc, -1);

        } else {
            msg = "unknown reason";
        }

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "lua handler aborted: %s: %s", err, msg);

        return NGX_ERROR;
    
    } NGX_LUA_EXCEPTION_CATCH {

        dd("nginx execution restored");

    }

    return NGX_ERROR;

}


void 
ngx_tcp_lua_wev_handler(ngx_tcp_session_t *s) 
{
    int                                 nret = 0;
    ngx_int_t                           rc;
    ngx_event_t                         *wev;
    ngx_connection_t                    *c;
    ngx_tcp_lua_ctx_t                   *ctx;
    ngx_tcp_lua_main_conf_t             *lmcf;
    ngx_tcp_lua_socket_upstream_t       *u;

    c = s->connection;
    wev = c->write;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, wev->log, 0,
                   "tcp lua wev handler: %d", c->fd);

    //if (ngx_handle_write_event(wev, 0) != NGX_OK) {
    //    ngx_tcp_lua_close_session(s);
    //}

    ctx = s->ctx;

    u = ctx->data;
    //if (!ctx->socket_busy && ctx->socket_ready) {
    if (u->prepare_retvals) {

        dd("resuming socket api");

        dd("setting socket_ready to 0");

        //ctx->socket_ready = 0;

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua tcp socket calling prepare retvals handler %p",
                       u->prepare_retvals);

        nret = u->prepare_retvals(s, u, ctx->co);
        if (nret == NGX_AGAIN) {
            return;
        }
        
        u->prepare_retvals = NULL;
    } 

    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

    dd("about to run thread for %p ", s);

    rc = ngx_tcp_lua_run_thread(lmcf->lua, s, ctx, nret);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
            "lua run thread returned %d", rc);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR || rc == NGX_OK) {
        ngx_tcp_lua_close_session(s);
        return;
    }

    return;

}


/**
 * Create new table and set _G field to itself.
 *
 * After:
 *         | new table | <- top
 *         |    ...    |
 * */
void
ngx_tcp_lua_create_new_global_table(lua_State *L, int narr, int nrec)
{
    lua_createtable(L, narr, nrec + 1);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");
}


u_char *
ngx_tcp_lua_digest_hex(u_char *dest, const u_char *buf, int buf_len)
{
    ngx_md5_t                     md5;
    u_char                        md5_buf[MD5_DIGEST_LENGTH];

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, buf, buf_len);
    ngx_md5_final(md5_buf, &md5);

    return ngx_hex_dump(dest, md5_buf, sizeof(md5_buf));
}


void
ngx_tcp_lua_inject_core_consts(lua_State *L)
{
    /* {{{ core constants */
    lua_pushinteger(L, NGX_OK);
    lua_setfield(L, -2, "OK");

    lua_pushinteger(L, NGX_AGAIN);
    lua_setfield(L, -2, "AGAIN");

    lua_pushinteger(L, NGX_DONE);
    lua_setfield(L, -2, "DONE");

    lua_pushinteger(L, NGX_DECLINED);
    lua_setfield(L, -2, "DECLINED");

    lua_pushinteger(L, NGX_ERROR);
    lua_setfield(L, -2, "ERROR");

    lua_pushlightuserdata(L, NULL);
    lua_setfield(L, -2, "null");
    /* }}} */
}



size_t
ngx_tcp_lua_calc_strlen_in_table(lua_State *L, int index, int arg_i,
    unsigned strict)
{
    double              key;
    int                 max;
    int                 i;
    int                 type;
    size_t              size;
    size_t              len;
    const char         *msg;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    dd("table index: %d", index);

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        dd("key type: %s", luaL_typename(L, -2));

        if (lua_type(L, -2) == LUA_TNUMBER) {

            key = lua_tonumber(L, -2);

            dd("key value: %d", (int) key);

            if (floor(key) == key && key >= 1) {
                if (key > max) {
                    max = (int) key;
                }

                lua_pop(L, 1); /* stack: table key */
                continue;
            }
        }

        /* not an array (non positive integer key) */
        lua_pop(L, 2); /* stack: table */

        luaL_argerror(L, arg_i, "non-array table found");
        return 0;
    }

    size = 0;

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, -1, &len);
                size += len;
                break;

            case LUA_TNIL:

                if (strict) {
                    goto bad_type;
                }

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (strict) {
                    goto bad_type;
                }

                if (lua_toboolean(L, -1)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_tcp_lua_calc_strlen_in_table(L, -1, arg_i, strict);
                break;

            case LUA_TLIGHTUSERDATA:

                if (strict) {
                    goto bad_type;
                }

                if (lua_touserdata(L, -1) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

bad_type:

                msg = lua_pushfstring(L, "bad data type %s found",
                        lua_typename(L, type));
                return luaL_argerror(L, arg_i, msg);
        }

        lua_pop(L, 1); /* stack: table */
    }

    return size;
}


u_char *
ngx_tcp_lua_copy_str_in_table(lua_State *L, int index, u_char *dst)
{
    double               key;
    int                  max;
    int                  i;
    int                  type;
    size_t               len;
    u_char              *p;

    if (index < 0) {
        index = lua_gettop(L) + index + 1;
    }

    max = 0;

    lua_pushnil(L); /* stack: table key */
    while (lua_next(L, index) != 0) { /* stack: table key value */
        key = lua_tonumber(L, -2);
        if (key > max) {
            max = (int) key;

        }

        lua_pop(L, 1); /* stack: table key */
    }

    for (i = 1; i <= max; i++) {
        lua_rawgeti(L, index, i); /* stack: table value */
        type = lua_type(L, -1);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = (u_char *) lua_tolstring(L, -1, &len);
                dst = ngx_copy(dst, p, len);
                break;

            case LUA_TNIL:
                *dst++ = 'n';
                *dst++ = 'i';
                *dst++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, -1)) {
                    *dst++ = 't';
                    *dst++ = 'r';
                    *dst++ = 'u';
                    *dst++ = 'e';

                } else {
                    *dst++ = 'f';
                    *dst++ = 'a';
                    *dst++ = 'l';
                    *dst++ = 's';
                    *dst++ = 'e';
                }

                break;

            case LUA_TTABLE:
                dst = ngx_tcp_lua_copy_str_in_table(L, -1, dst);
                break;

            case LUA_TLIGHTUSERDATA:

                *dst++ = 'n';
                *dst++ = 'u';
                *dst++ = 'l';
                *dst++ = 'l';
                break;

            default:
                luaL_error(L, "impossible to reach here");
                return NULL;
        }

        lua_pop(L, 1); /* stack: table */
    }

    return dst;
}

ngx_int_t
ngx_tcp_lua_report(ngx_log_t *log, lua_State *L, int status,
    const char *prefix)
{
    const char      *msg;

    if (status && !lua_isnil(L, -1)) {
        msg = lua_tostring(L, -1);
        if (msg == NULL) {
            msg = "unknown error";
        }

        ngx_log_error(NGX_LOG_ERR, log, 0, "%s error: %s", prefix, msg);
        lua_pop(L, 1);
    }

    /* force a full garbage-collection cycle */
    lua_gc(L, LUA_GCCOLLECT, 0);

    return status == 0 ? NGX_OK : NGX_ERROR;
}


int
ngx_tcp_lua_do_call(ngx_log_t *log, lua_State *L)
{
    int                 status, base;
    //ngx_pool_t         *old_pool;

    base = lua_gettop(L);  /* function index */
    lua_pushcfunction(L, ngx_tcp_lua_traceback);  /* push traceback function */
    lua_insert(L, base);  /* put it under chunk and args */

    //old_pool = ngx_tcp_lua_pcre_malloc_init(ngx_cycle->pool);
    status = lua_pcall(L, 0, 0, base);
    //ngx_tcp_lua_pcre_malloc_done(old_pool);

    lua_remove(L, base);

    return status;
}

int
ngx_tcp_lua_traceback(lua_State *L)
{
    if (!lua_isstring(L, 1)) { /* 'message' not a string? */
        return 1;  /* keep it intact */
    }

    lua_getglobal(L, "debug");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return 1;
    }

    lua_getfield(L, -1, "traceback");
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        return 1;
    }

    lua_pushvalue(L, 1);  /* pass error message */
    lua_pushinteger(L, 2);  /* skip this function and traceback */
    lua_call(L, 2, 1);  /* call debug.traceback */
    return 1;
}

//tmp
void 
ngx_tcp_lua_stack_dump(lua_State* L,const char* prefix)
{
    int i;
    if(prefix){
        printf("%s: ",prefix);
    }

    int top = lua_gettop(L);
    if(top < 1){
        printf("stack is empty\n");
        return;
    }
    
    printf("bottom----->top\n\t");
    for(i=1;i<=top;i++){
        int t = lua_type(L,i);
        switch(t){
        
        case LUA_TSTRING:
            printf("%d/%d[%s]",i,i-top-1,lua_tostring(L,i));
            break;
        
        case LUA_TBOOLEAN:
            printf(lua_toboolean(L,i)?"%d/%d[true]":"false",i,i-top-1);
            break;
            
        case LUA_TNUMBER:
            printf("%d/%d[%g]",i,i-top-1,lua_tonumber(L,i));
            break;
            
        default:
            printf("%d/%d[%s]",i,i-top-1,lua_typename(L,t));
            break;
        }
        
        printf("    ");
    }
    
    printf("\n");
}