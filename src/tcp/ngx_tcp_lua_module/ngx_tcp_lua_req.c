
#include "ngx_tcp_lua_common.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_req.h"
#include "ngx_tcp_lua_session.h"

#define NGX_TCP_LUA_REQ_FT_ERROR        0x0001
#define NGX_TCP_LUA_REQ_FT_TIMEOUT      0x0002
#define NGX_TCP_LUA_REQ_FT_CLOSED       0x0004
#define NGX_TCP_LUA_REQ_FT_NOMEM        0x0008


static int ngx_tcp_lua_ngx_print(lua_State *L);
static int ngx_tcp_lua_ngx_say(lua_State *L);
static int ngx_tcp_lua_ngx_echo(lua_State *L, unsigned newline);
static int ngx_tcp_lua_ngx_wait_next_request(lua_State *L);
static int ngx_tcp_lua_ngx_exit(lua_State *L);
static int ngx_tcp_lua_ngx_receive(lua_State *L);

static void ngx_tcp_lua_req_read_handler(ngx_tcp_session_t *s); 
static ngx_int_t ngx_tcp_lua_req_read(ngx_tcp_session_t *s, ngx_tcp_lua_ctx_t *ctx);
static int ngx_tcp_lua_req_tcp_receive_retval_handler(ngx_tcp_session_t *s, lua_State *L);
static int ngx_tcp_lua_req_error_retval_handler(ngx_tcp_session_t *s, lua_State *L);
static void ngx_tcp_lua_check_client_abort_handler(ngx_tcp_session_t *s);
static void ngx_tcp_lua_req_keepalive_handler(ngx_tcp_session_t *s);

void
ngx_tcp_lua_inject_req_api(lua_State *L)
{
    lua_pushcfunction(L, ngx_tcp_lua_ngx_say);
    lua_setfield(L, -2, "say");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_print);
    lua_setfield(L, -2, "print");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_wait_next_request);
    lua_setfield(L, -2, "wait_next_request");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_exit);
    lua_setfield(L, -2, "exit");

    lua_pushcfunction(L, ngx_tcp_lua_ngx_receive);
    lua_setfield(L, -2, "receive");
}


static int
ngx_tcp_lua_ngx_print(lua_State *L)
{
    dd("calling lua print");
    return ngx_tcp_lua_ngx_echo(L, 0);
}


static int
ngx_tcp_lua_ngx_say(lua_State *L)
{
    dd("calling");
    return ngx_tcp_lua_ngx_echo(L, 1);
}

static int
ngx_tcp_lua_ngx_echo(lua_State *L, unsigned newline)
{
    ngx_tcp_session_t          *s;
    ngx_tcp_lua_ctx_t          *ctx;
    const char                 *p;
    size_t                      len;
    size_t                      size;
    ngx_buf_t                  *b;
    int                         i;
    int                         nargs;
    int                         type;
    const char                 *msg;
    ngx_int_t                   n;

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ctx = s->ctx;   //ctx impossible NULL

    if (ctx->socket_invalid) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to send data on a closed/invalid socket");

        //lua_pushnil(L);
        lua_pushnumber(L, (lua_Number) 0);
        lua_pushliteral(L, "closed");
        return 2;
    }

    nargs = lua_gettop(L);
    size = 0;

    for (i = 1; i <= nargs; i++) {

        type = lua_type(L, i);

        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:

                lua_tolstring(L, i, &len);
                size += len;
                break;

            case LUA_TNIL:

                size += sizeof("nil") - 1;
                break;

            case LUA_TBOOLEAN:

                if (lua_toboolean(L, i)) {
                    size += sizeof("true") - 1;

                } else {
                    size += sizeof("false") - 1;
                }

                break;

            case LUA_TTABLE:

                size += ngx_tcp_lua_calc_strlen_in_table(L, i, i, 0);
                break;

            case LUA_TLIGHTUSERDATA:

                dd("userdata: %p", lua_touserdata(L, i));

                if (lua_touserdata(L, i) == NULL) {
                    size += sizeof("null") - 1;
                    break;
                }

                continue;

            default:

                msg = lua_pushfstring(L, "string, number, boolean, nil, "
                                      "ngx.null, or array table expected, "
                                      "but got %s", lua_typename(L, type));

                return luaL_argerror(L, i, msg);
        }
    }

    if (newline) {
        size += sizeof("\n") - 1;
    }

    if (size == 0) {
        /* do nothing for empty strings */
        return 0;
    }

    b = ctx->buf_out;
    if (b == NULL) {
        b = ngx_create_temp_buf(s->pool, size);
        
        if (b == NULL) {
            return luaL_error(L, "out of memory");
        }
        
        ctx->buf_out = b;
    }
    else if (b->start == NULL || (size_t)(b->end - b->start) < size) {
        b->start = ngx_palloc(s->pool, size);
        if (b->start == NULL) {
            return luaL_error(L, "out of memory");
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
        b->temporary = 1;
        //others are 0 or NULL
    }
    else {
        b->pos = b->start;
        b->last = b->start;
    }

    for (i = 1; i <= nargs; i++) {
        type = lua_type(L, i);
        switch (type) {
            case LUA_TNUMBER:
            case LUA_TSTRING:
                p = lua_tolstring(L, i, &len);
                b->last = ngx_copy(b->last, (u_char *) p, len);
                break;

            case LUA_TNIL:
                *b->last++ = 'n';
                *b->last++ = 'i';
                *b->last++ = 'l';
                break;

            case LUA_TBOOLEAN:
                if (lua_toboolean(L, i)) {
                    *b->last++ = 't';
                    *b->last++ = 'r';
                    *b->last++ = 'u';
                    *b->last++ = 'e';

                } else {
                    *b->last++ = 'f';
                    *b->last++ = 'a';
                    *b->last++ = 'l';
                    *b->last++ = 's';
                    *b->last++ = 'e';
                }

                break;

            case LUA_TTABLE:
                b->last = ngx_tcp_lua_copy_str_in_table(L, i, b->last);
                break;

            case LUA_TLIGHTUSERDATA:
                *b->last++ = 'n';
                *b->last++ = 'u';
                *b->last++ = 'l';
                *b->last++ = 'l';
                break;

            default:
                return luaL_error(L, "impossible to reach here");
        }
    }

    if (newline) {
        *b->last++ = '\n';
    }

#if 0
    if (b->last != b->end) {
        return luaL_error(L, "buffer error: %p != %p", b->last, b->end);
    }
#endif

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   newline ? "lua say response" : "lua print response");

    size = b->last - b->pos;

    n = s->connection->send(s->connection, b->pos, size);

    if (n > 0) {
        //b->pos += n;
        lua_pushnumber(L, (lua_Number) n);

        //ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
        //               "lua socket receive done in a single run");
        lua_pushliteral(L, "ok");
    }
    else if (n == NGX_AGAIN){
        //lua_pushnumber(L, (lua_Number) 0);
        lua_pushnil(L);
        lua_pushliteral(L, "EAGAIN error");
    }
    else {
        //NGX_ERROR
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_ERROR;
        ctx->socket_invalid = 1;
        ctx->socket_errno = ngx_socket_errno;
        ngx_tcp_lua_req_error_retval_handler(s, L);
        //lua_pushnumber(L, (lua_Number) 0);
        //lua_pushliteral(L, "socket error");
    }
    
    if (ngx_pfree(s->pool, b->start) == NGX_OK) {
        b->start = NULL;
    }
    else {
        b->pos = b->start;
        b->last = b->start;
    }

    return 2;
}


static int
ngx_tcp_lua_ngx_receive(lua_State *L)
{
    ngx_tcp_session_t      *s;
    ngx_tcp_lua_ctx_t      *ctx;
    ngx_buf_t              *b;
    int                     n;
    ngx_int_t               rc;
    lua_Integer             bytes;
    lua_Integer             bytes_atleast = 0;
    
    n = lua_gettop(L);
    if (n != 1 && n != 2) {
        return luaL_error(L, "expecting 1 or 2 arguments ", n);
    }
    
    if (0 == lua_isnumber(L, 1)) {
        return luaL_argerror(L, 1, "expecting number parameter!");
    }

    bytes = lua_tointeger(L, 1);
    if (bytes <= 0) {
        return luaL_argerror(L, 1, "bad argument < 0");
    }

    if (1 == lua_isnumber(L, 2)) {
        bytes_atleast = lua_tointeger(L, 2);
        if (bytes_atleast < 1 || bytes_atleast > bytes) {
            return luaL_argerror(L, 2, "bad pattern argument beyond [1,$2]");
        }
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ctx = s->ctx;

    if (ctx->socket_invalid) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to receive data on a closed/invalid socket");

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    ctx->length = (size_t) bytes;
    ctx->bytes_atleast = bytes_atleast ? bytes_atleast : bytes;
    ctx->ft_type = 0;

    b = ctx->buf_in;

    if (b == NULL) {
        b = ngx_create_temp_buf(s->pool, bytes);
        
        if (b == NULL) {
            return luaL_error(L, "out of memory");
        }
        
        ctx->buf_in = b;
    }
    else if (b->start == NULL || b->end - b->start < bytes) {
        b->start = ngx_palloc(s->pool, bytes);
        if (b->start == NULL) {
            return luaL_error(L, "out of memory");
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + bytes;
        b->temporary = 1;
        //others are 0 or NULL
    }
    else {
        b->pos = b->start;
        b->last = b->start;
    }

    rc = ngx_tcp_lua_req_read(s, ctx);

    if (rc == NGX_ERROR || rc == NGX_OK) {

        return ngx_tcp_lua_req_tcp_receive_retval_handler(s, L);
    }

    /* rc == NGX_AGAIN */

    s->read_event_handler = ngx_tcp_lua_req_read_handler;

    return lua_yield(L, 0);
}

static void 
ngx_tcp_lua_req_read_handler(ngx_tcp_session_t *s) 
{
    ngx_connection_t                    *c;
    ngx_tcp_lua_ctx_t                   *ctx;
    ngx_int_t                            rc;
    
    c = s->connection;
    ctx = s->ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua req read handler");
    
    //ctx->buf_in is not NULL;
    rc = ngx_tcp_lua_req_read(s, ctx);
    
    if (rc == NGX_AGAIN) {
        return;
    }
    
    //rc == NGX_ERROR || rc == NGX_OK
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    
    s->read_event_handler = ngx_tcp_lua_check_client_abort_handler;
    //s->write_event_handler = ngx_tcp_session_empty_handler;
    
    ctx->prepare_retvals = ngx_tcp_lua_req_tcp_receive_retval_handler;
    ngx_tcp_lua_req_resume(s);
}

static ngx_int_t
ngx_tcp_lua_req_read(ngx_tcp_session_t *s, ngx_tcp_lua_ctx_t *ctx)
{
    ngx_connection_t            *c;
    ngx_tcp_core_srv_conf_t     *cscf;
    ngx_buf_t                   *b;
    ngx_event_t                 *rev;
    size_t                       size;
    ssize_t                      n;

    c = s->connection;
    rev = c->read;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "lua socket read timed out");
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_TIMEOUT;
        return NGX_ERROR;
    }
    
    b = ctx->buf_in;
    
    size = ctx->length - (b->last - b->pos);
    if (size <= 0) {
        //log
        return NGX_OK;
    }
    
    n = c->recv(c, b->last, size);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                "lua socket recv returned %d",(int) n);

    if (n == NGX_AGAIN) {
        dd("socket recv busy");
        if (!rev->timer_set) {
            cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
            ngx_add_timer(rev, cscf->read_timeout);
        }
        
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ctx->ft_type |= NGX_TCP_LUA_REQ_FT_ERROR;
            ctx->socket_invalid = 1;
            ctx->socket_errno = ngx_socket_errno;
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (n == 0) {
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_CLOSED;
        ctx->socket_invalid = 1;
        //ctx->socket_errno = ngx_socket_errno;
        
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                    "lua socket closed");

        return NGX_ERROR;
    }

    if (n == NGX_ERROR) {
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_ERROR;
        ctx->socket_invalid = 1;
        ctx->socket_errno = ngx_socket_errno;
        
        return NGX_ERROR;
    }
    
    b->last += n;
    
    if ((size_t)(b->last - b->pos) >= ctx->bytes_atleast) {
        return NGX_OK;
    }
    
    return NGX_AGAIN;
}

static int
ngx_tcp_lua_req_tcp_receive_retval_handler(ngx_tcp_session_t *s, lua_State *L)
{
    int                          n = 0;
    ngx_tcp_lua_ctx_t           *ctx;
    size_t                       size;
    ngx_buf_t                   *b;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket receive return value handler");
    ctx = s->ctx;
    
    if (ctx->ft_type) {
        //n=2, nil nil/error_string
        n += ngx_tcp_lua_req_error_retval_handler(s, L);
    }
    
    b = ctx->buf_in;
    
    if (b) {
        size = b->last - b->pos;
        if (size > 0) {
            lua_pushlstring(L, (char *) b->pos, size);
            n += 1;
        }
        else {
            //log
        }
        
        if (ngx_pfree(s->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }
        else {
            b->pos = b->start;
            b->last = b->start;
        }
    }
    else {
        //log
    }
    
    ctx->length = 0;

    return n;
}


static int
ngx_tcp_lua_req_error_retval_handler(ngx_tcp_session_t *s, lua_State *L)
{
    u_char                   errstr[NGX_MAX_ERROR_STR];
    u_char                  *p;
    ngx_tcp_lua_ctx_t       *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket error retval handler");

    //ngx_tcp_lua_socket_finalize(s, u);

    ctx = s->ctx;

    lua_pushnil(L);

    if (ctx->ft_type & NGX_TCP_LUA_REQ_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (ctx->ft_type & NGX_TCP_LUA_REQ_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (ctx->ft_type & NGX_TCP_LUA_REQ_FT_NOMEM) {
        lua_pushliteral(L, "out of memory");

    } else {

        if (ctx->socket_errno) {

            p = ngx_strerror(ctx->socket_errno, errstr, sizeof(errstr));

            /* for compatibility with LuaSocket */
            ngx_strlow(errstr, errstr, p - errstr);
            lua_pushlstring(L, (char *) errstr, p - errstr);

        } else {
            lua_pushliteral(L, "error");
        }
    }

    return 2;
}

void 
ngx_tcp_lua_req_resume(ngx_tcp_session_t *s) 
{
    int                                  nret = 0;
    ngx_int_t                            rc;
    ngx_connection_t                    *c;
    ngx_tcp_lua_ctx_t                   *ctx;
    ngx_tcp_lua_main_conf_t             *lmcf;

    c = s->connection;

    ctx = s->ctx;

    if (ctx->prepare_retvals) {
    
        nret = ctx->prepare_retvals(s,ctx->co);
        ctx->prepare_retvals = NULL;
        
    }
    
    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

    dd("about to run thread for %p ", s);

    rc = ngx_tcp_lua_run_thread(lmcf->lua, s, ctx, nret);

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
            "lua run thread returned %d", rc);

    if (rc == NGX_ERROR || rc == NGX_OK) {
        //ngx_tcp_finalize_session(s);
        ngx_tcp_lua_close_session(s);
        return;
    }
    
    //NGX_AGAIN
    return;
}

static void
ngx_tcp_lua_check_client_abort_handler(ngx_tcp_session_t *s)
{
    ngx_connection_t       *c;
    ngx_tcp_lua_ctx_t      *ctx;
    ngx_tcp_lua_srv_conf_t *lscf;
    
    c = s->connection;
    ctx = s->ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua socket check client abort handler");

    if (ctx->socket_invalid) {
        return;
    }
    
    ngx_tcp_test_reading(s);
    
    if (c->error) {
        ctx->ft_type |= NGX_TCP_LUA_REQ_FT_ERROR;
        ctx->socket_errno = ngx_socket_errno;
        ctx->socket_invalid = 1;
        
#if 1
        lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);

        if (lscf->check_client_abort) {
            ngx_tcp_lua_close_session(s);
        }
#endif
    }
}

static int 
ngx_tcp_lua_ngx_wait_next_request(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_connection_t                   *c;
    int                                 n;
    ngx_tcp_core_srv_conf_t            *cscf;
    ngx_tcp_lua_ctx_t                  *ctx;

    n = lua_gettop(L);
    if (n != 0) {
        //return luaL_error(L, "expecting 1 arguments "
        //                  "(including the object), but got %d", n);
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    c = s->connection;

    ngx_tcp_lua_finalize_light_session(s);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua req calling wait_next_request() method");

    ctx = s->ctx;

    if (ctx->socket_invalid) {
        c->close = 1;
        goto yield;
    }
    
    ngx_tcp_test_reading(s);
    
    if (c->error) {
        c->close = 1;
        goto yield;
    }
    
    if (c->read->ready) {
        if(ngx_tcp_lua_init_light_session(s) != NGX_OK){
            c->close = 1;
            goto yield;
        }

        c->log->action = "continue with new session";
        
        return 0;
    }


yield:
    if (c->close) {
        ctx->exited = 1;
        return lua_yield(L, 0);
    }

    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);

    c->log->action = "lua_req_keepalive";
    c->idle = 1;
    ngx_reusable_connection(c, 1);

    s->write_event_handler = ngx_tcp_session_empty_handler;
    s->read_event_handler = ngx_tcp_lua_req_keepalive_handler;

    if (!c->read->timer_set && cscf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        ngx_add_timer(c->read, cscf->keepalive_timeout);
    }

    //lua_pushliteral(L, "closed");
    return lua_yield(L, 0);
}



static void
ngx_tcp_lua_req_keepalive_handler(ngx_tcp_session_t *s)
{
    ngx_connection_t            *c;
    ngx_event_t                 *rev;

    c = s->connection;
    rev = c->read;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_tcp_lua_close_session(s);
        return;
    }

    if (c->close) {
        ngx_tcp_lua_close_session(s);
        return;
    }
    
    //have data or close event
    //tmp
    ngx_tcp_test_reading(s);
    
    if (!c->read->ready) {
        if (!c->error) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0, "weird, no event call this function");
        }
        ngx_tcp_lua_close_session(s);
        return;
    }
    
    c->idle = 0;
    ngx_reusable_connection(c, 0);
    
    //s->write_event_handler = ngx_tcp_session_empty_handler;
    s->read_event_handler = ngx_tcp_lua_check_client_abort_handler;;
    
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (ngx_tcp_lua_init_light_session(s) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->action = "start new session";

    ngx_tcp_lua_req_resume(s);
}


static int
ngx_tcp_lua_ngx_exit(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_ctx_t                  *ctx;

    if (lua_gettop(L) != 0) {
        //return luaL_error(L, "expecting 1 arguments "
        //                  "(including the object), but got %d", n);
    }

    s = ngx_tcp_lua_get_session(L); 
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ctx = s->ctx;
    
    ctx->exited = 1;

    return lua_yield(L, 0);
}