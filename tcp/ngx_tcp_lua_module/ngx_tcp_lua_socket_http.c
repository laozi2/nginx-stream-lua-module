#include "ngx_tcp_lua_socket_tcp.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_session.h"


#define NGX_TCP_LUA_SOCKET_ERR_STATUSLINE 0x01
#define NGX_TCP_LUA_SOCKET_ERR_HEADERS    0x02
#define NGX_TCP_LUA_SOCKET_ERR_BODY       0x04
#define NGX_TCP_LUA_SOCKET_ERR_BIGHEADER  0x08
#define NGX_TCP_LUA_SOCKET_ERR_BIGBODY    0x10

#define NGX_TCP_HTTP_PARSE_HEADER_DONE         1
#define NGX_TCP_HTTP_PARSE_INVALID_HEADER      13

typedef enum {
    sw_tlsh_begin = 0,
    sw_tlsh_status_line,
    sw_tlsh_headers,
    sw_tlsh_body,
    sw_tlsh_done
} ngx_tcp_lua_http_ctx_state;


typedef struct {
    ngx_uint_t           http_version;
    ngx_uint_t           code;
    ngx_uint_t           count;
    u_char              *start;
    u_char              *end;
} ngx_tcp_http_status_t;

typedef struct {
    ngx_uint_t           state;
    off_t                size;
}ngx_tcp_http_chunked_t;

typedef struct {
    ngx_int_t                        max_header_size;
    ngx_int_t                        max_body_size;

    off_t                            content_length_n;

    ngx_uint_t                       state;//for all read http
    ngx_tcp_http_status_t            status;//for http parse
    u_char                          *header_name_start;
    u_char                          *header_name_end;
    u_char                          *header_start;
    u_char                          *header_end;
    
    ngx_buf_t                       *buf;
    
    ngx_tcp_http_chunked_t           chunk;
    
    int                              error_code;
    
    int                              saved_top;
    
    ngx_tcp_lua_http_ctx_state       ctx_state;

    unsigned                         chunked:1;
    unsigned                         wait_body_data:1;
    unsigned                         invalid_header:1;
} ngx_tcp_lua_http_parse_ctx_t;


static ngx_int_t ngx_tcp_lua_socket_read_http(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_socket_read_http_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static ngx_int_t ngx_tcp_lua_http_input_filter(ngx_tcp_lua_http_parse_ctx_t *http_ctx,
    ngx_buf_t *b, lua_State *L);
static ngx_int_t ngx_tcp_parse_http_status_line(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_tcp_http_status_t *status);
static ngx_int_t ngx_tcp_process_http_header(ngx_tcp_lua_http_parse_ctx_t *r,
    ngx_buf_t *b, lua_State *L);
static ngx_int_t ngx_tcp_parse_http_header_line(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores);
static ngx_int_t ngx_tcp_process_http_body(ngx_tcp_lua_http_parse_ctx_t *r,
    ngx_buf_t *b, lua_State *L);
ngx_int_t ngx_lua_parse_http_chunked(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_tcp_http_chunked_t *ctx);
static int ngx_tcp_lua_socket_tcp_receive_http_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
    
int
ngx_tcp_lua_socket_tcp_receive_http(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_socket_upstream_t      *u;
    ngx_int_t                           rc;
    ngx_tcp_lua_ctx_t                  *ctx;
    ngx_tcp_lua_http_parse_ctx_t       *http_ctx;
    int                                 n;
    lua_Integer                         max_header_size;
    lua_Integer                         max_body_size;

    n = lua_gettop(L);
    //receive(max_header_size,max_body_size)
    if (n != 3) {
        return luaL_error(L, "expecting 3 arguments "
                          "(including the object), but got %d", n);
    }
    
    if (0 == lua_isnumber(L, 2)) {
        return luaL_argerror(L, 2, "expecting number parameter!");
    }
    
    max_header_size = lua_tointeger(L, 2);
    if (max_header_size <= 0) {
        return luaL_argerror(L, 2, "bad argument <= 0");
    }
    
    if (0 == lua_isnumber(L, 3)) {
        return luaL_argerror(L, 3, "expecting number parameter!");
    }
    
    max_body_size = lua_tointeger(L, 3);
    if (max_body_size <= 0) {
        return luaL_argerror(L, 3, "bad argument <= 0");
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket calling receive_http() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    //lua_pop(L,2);

    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to receive data on a closed socket: u:%p, c:%p, "
                      "ft:%ui eof:%ud",
                      u, u ? u->peer.connection : NULL, u ? u->ft_type : 0,
                      u ? u->eof : 0);

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket read timeout: %M", u->read_timeout);

    //u->input_filter = ngx_tcp_lua_socket_read_http_statusline;
    //u->input_filter_ctx = u;
    //u->length = (size_t) bytes;
    //u->rest = u->length;
    //u->bytes_atleast = bytes_atleast ? bytes_atleast : bytes;

    http_ctx = ngx_pcalloc(s->pool,sizeof(ngx_tcp_lua_http_parse_ctx_t));
    if (http_ctx == NULL) {
        return luaL_error(L, "out of memory");
    }
    http_ctx->max_header_size = (ngx_int_t)max_header_size;
    http_ctx->max_body_size = (ngx_int_t)max_body_size;
    http_ctx->ctx_state = sw_tlsh_begin;
    http_ctx->content_length_n = -1;
    http_ctx->saved_top = lua_gettop(L);
    /* set by pcalloc
     *    http_ctx->state = 0;//
     *    http_ctx->http_status = {};//
     *    http_ctx->header_name_start = NULL;
     *    http_ctx->header_name_end = NULL;
     *    http_ctx->header_start = NULL;
     *    http_ctx->header_end = NULL;
     *    http_ctx->buf = NULL;
     *    http_ctx->chunk = {};
     *    http_ctx->error_code = 0;
     *    http_ctx->chunked = 0;
     *    http_ctx->wait_body_data = 0;
    */
    
    u->buf_in = (ngx_buf_t*)http_ctx;

    u->waiting = 0;
    u->ft_type = 0;
    
    lua_newtable(L);

    rc = ngx_tcp_lua_socket_read_http(s, u , L);

    if (rc == NGX_ERROR) {
        dd("read failed: %d", (int) u->ft_type);

        return ngx_tcp_lua_socket_tcp_receive_http_retval_handler(s, u, L);
    }

    if (rc == NGX_OK) {

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket receive done in a single run");

        return ngx_tcp_lua_socket_tcp_receive_http_retval_handler(s, u, L);
    }

    /* rc == NGX_AGAIN */

    u->read_event_handler = ngx_tcp_lua_socket_read_http_handler;
    //u->write_event_handler = ngx_tcp_lua_socket_dummy_handler; //no need

    /* set s->write_event_handler to go on session process */
    s->write_event_handler = ngx_tcp_lua_wev_handler;
    
    u->waiting = 1;
    u->prepare_retvals = ngx_tcp_lua_socket_tcp_receive_http_retval_handler;

    ctx = s->ctx;
    ctx->data = u;

    return lua_yield(L, lua_gettop(L));
}


static void
ngx_tcp_lua_socket_read_http_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;
    ngx_tcp_lua_ctx_t           *ctx;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket read handler");

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "lua socket read timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    ctx = s->ctx;
    (void) ngx_tcp_lua_socket_read_http(s, u, ctx->co);
}


static ngx_int_t
ngx_tcp_lua_socket_read_http(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_buf_t                   *b;
    ngx_tcp_lua_http_parse_ctx_t* http_ctx;
    ngx_event_t                 *rev;
    size_t                       size;
    ssize_t                      n;

    c = u->peer.connection;
    rev = c->read;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua socket read data: waiting: %d", (int) u->waiting);

    http_ctx = (ngx_tcp_lua_http_parse_ctx_t*)u->buf_in;
    
    if (http_ctx->ctx_state == sw_tlsh_begin) {
        http_ctx->buf = ngx_create_temp_buf(s->pool, http_ctx->max_header_size);
        if (http_ctx->buf == NULL) {
            ngx_tcp_lua_socket_handle_error(s, u,
                                            NGX_TCP_LUA_SOCKET_FT_NOMEM);
            return NGX_ERROR;
        }
        http_ctx->ctx_state = sw_tlsh_status_line;
    }
    
    b = http_ctx->buf;

    while (1) {
    
        size = b->end - b->last;
    
        n = c->recv(c, b->last, size);
    
        dd("read event ready: %d", (int) c->read->ready);

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                    "lua socket recv returned %d: \"%p\"",
                    (int) n, s);
    
        if (n == NGX_AGAIN) {
            dd("socket recv busy");
            if (!rev->timer_set) {
                ngx_add_timer(rev, u->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_lua_socket_handle_error(s, u,
                                            NGX_TCP_LUA_SOCKET_FT_ERROR);
                return NGX_ERROR;
            }
    
            return NGX_AGAIN;
        }
    
        if (n == 0) {
            u->eof = 1;
            u->ft_type |= NGX_TCP_LUA_SOCKET_FT_CLOSED;
            //it means server closed while not read enough data.
            ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                        "lua socket closed");
            c->error = 1;
            ngx_tcp_lua_socket_handle_error(s, u,
                                            NGX_TCP_LUA_SOCKET_FT_ERROR);
    
            return NGX_ERROR;
        }
    
        if (n == NGX_ERROR) {
            c->error = 1;
            ngx_tcp_lua_socket_handle_error(s, u,
                                            NGX_TCP_LUA_SOCKET_FT_ERROR);
            return NGX_ERROR;
        }

        b->last += n;
        
        rc = ngx_tcp_lua_http_input_filter(http_ctx, b, L);
        
        if (rc == NGX_OK) {
            break;
        }
        
        if (rc == NGX_ERROR) {
            ngx_tcp_lua_socket_handle_error(s, u,
                                            NGX_TCP_LUA_SOCKET_FT_ERROR);
            return NGX_ERROR;
        }
        
        // rc == NGX_AGAIN
        //continue;
    }
    
    ngx_log_debug3(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                        "lua socket receive done: wait:%d, eof:%d, "
                        "uri:\"%p\"", (int) u->waiting, (int) u->eof,
                        s);
    ngx_tcp_lua_socket_handle_success(s, u);
    return NGX_OK;
}

static ngx_int_t
ngx_tcp_lua_http_input_filter(ngx_tcp_lua_http_parse_ctx_t *http_ctx,
    ngx_buf_t *b, lua_State *L)
{
    ngx_tcp_lua_http_ctx_state     ctx_state;
    ngx_int_t                      err;
    ngx_int_t                      rc;
    
    ctx_state = http_ctx->ctx_state;
    err = 0;
    
    while (err == 0) {
        
        switch (ctx_state) {
            
            case sw_tlsh_status_line :
                
                rc = ngx_tcp_parse_http_status_line(http_ctx, b, &http_ctx->status);

                if (rc == NGX_OK) {
                    lua_pushinteger(L, (lua_Integer)http_ctx->status.code);
                    lua_setfield(L, -2, "code");
                
                    lua_pushlstring(L, (const char*)http_ctx->status.start, http_ctx->status.end - http_ctx->status.start);
                    lua_setfield(L, -2, "info");
                
                    lua_newtable(L);//for headers
                    //lua_setfield(L, -2, "headers");
                    ctx_state = sw_tlsh_headers;
                
                    break;
                }
                
                if (rc == NGX_AGAIN) {
                    if (b->last == b->end) {
                        //ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        //     "upstream sent too big header");
                        http_ctx->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGHEADER;
                        err = 1;
                    }
                    else {
                        err = 2;
                    }
                    
                    break;
                }
                
                //rc == NGX_ERROR
                //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                //            "upstream sent no valid HTTP/1.0 header");
                http_ctx->error_code = NGX_TCP_LUA_SOCKET_ERR_STATUSLINE;
                err = 1;
                
                break;
        
            case sw_tlsh_headers :
                rc = ngx_tcp_process_http_header(http_ctx, b , L);
            
                if (rc == NGX_OK) {
                    lua_setfield(L, -2, "headers");
                    if (http_ctx->chunked || http_ctx->content_length_n > 0) {
                        lua_newtable(L);//for body
                        ctx_state = sw_tlsh_body;
                    }
                    
                    else if (http_ctx->content_length_n == -1) {
                        //no chunked or content_length
                        //http_ctx->error_code = NGX_TCP_LUA_SOCKET_ERR_HEADERS;
                
                        //err = 1;
                        //for HEAD no content_length or chunked
                        ctx_state = sw_tlsh_done;
                    }
                    else {
                        //content_length_n == 0
                        ctx_state = sw_tlsh_done;
                    }
                    
                    break;
                }
            
                if (rc == NGX_AGAIN) {
                    if (b->last == b->end) {
                        lua_setfield(L, -2, "headers");
                        //ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        //     "upstream sent too big header");
                        http_ctx->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGHEADER;
                        
                        err = 1;
                    }
                    else {
                        err = 2;
                    }
                
                    break;
                }
                
                //rc == NGX_ERROR
                lua_setfield(L, -2, "headers");

                //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                //            "upstream sent no valid HTTP/1.0 header");
                http_ctx->error_code = NGX_TCP_LUA_SOCKET_ERR_HEADERS;
                err = 1;
                
                break;
            
            case sw_tlsh_body : 
                rc = ngx_tcp_process_http_body(http_ctx, b ,L);
            
                if (rc == NGX_OK) {
                    lua_setfield(L, -2, "body");
                    ctx_state = sw_tlsh_done;
                    break;
                }
                
                if (rc == NGX_AGAIN) {
                    err = 2;
                    break;
                }
                
                //rc = NGX_ERROR
                lua_setfield(L, -2, "body");
                err = 1;
                break;
                
            case sw_tlsh_done :
                err = -1;
                break;

            default : //unknow, impossible
                err = 1;
                break;
        }
    }
    
    http_ctx->ctx_state = ctx_state;
    
    if (err == 1) {
        return NGX_ERROR;
    }
    
    if (err == 2) {
        return NGX_AGAIN;
    }
    
    return NGX_OK;
}

static int
ngx_tcp_lua_socket_tcp_receive_http_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    //u_char           errstr[NGX_MAX_ERROR_STR];
    //u_char          *p;
    ngx_tcp_lua_http_parse_ctx_t    *http_ctx;
    
    http_ctx = (ngx_tcp_lua_http_parse_ctx_t*)u->buf_in;
    
    //当网络错误时不会设置headers/body的table到返回的table里
#if 1

    if (lua_gettop(L) - http_ctx->saved_top > 2) {
        lua_pushliteral(L, "wrong lua stack");
        return lua_gettop(L) - http_ctx->saved_top + 1;
    }
    if (lua_gettop(L) - http_ctx->saved_top == 2) {
        if (0 == lua_istable(L,-1)) {
            lua_pushliteral(L, "lua stack -1 is not table");
            return 3;
        }
        if (http_ctx->ctx_state != sw_tlsh_headers && 
            http_ctx->ctx_state != sw_tlsh_body ) {
            lua_pushliteral(L, "wrong ctx_state");
            return 3;
        }
    }
#endif

    if (lua_gettop(L) - http_ctx->saved_top == 2) {
        if (http_ctx->ctx_state == sw_tlsh_headers) {
            lua_setfield(L, -2, "headers");
        }
        else {
            lua_setfield(L, -2, "body");
        }
    }

    if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "out of memory");

    } else {

        //if (u->socket_errno) {
        //    p = ngx_strerror(u->socket_errno, errstr, sizeof(errstr));
        //    /* for compatibility with LuaSocket */
        //    ngx_strlow(errstr, errstr, p - errstr);
        //    lua_pushlstring(L, (char *) errstr, p - errstr);
        //
        //} else {
        //    lua_pushliteral(L, "error");
        //}
        
        switch (http_ctx->error_code) {
        
            case 0 :
                lua_pushnil(L);
                break;
            
            case NGX_TCP_LUA_SOCKET_ERR_STATUSLINE :
                lua_pushliteral(L, "err status line");
                break;
            
            case NGX_TCP_LUA_SOCKET_ERR_HEADERS :
                lua_pushliteral(L, "err headers");
                break;
            
            case NGX_TCP_LUA_SOCKET_ERR_BODY :
                lua_pushliteral(L, "err body");
                break;
            
            case NGX_TCP_LUA_SOCKET_ERR_BIGHEADER :
                lua_pushliteral(L, "err header too big");
                break;
                
            case NGX_TCP_LUA_SOCKET_ERR_BIGBODY :
                lua_pushliteral(L, "err body too big");
                break;
                
            default :
                lua_pushliteral(L, "err unknown");
                break;
        }

    }

    u->buf_in = NULL;

    return 2;
}

static ngx_int_t
ngx_tcp_process_http_header(ngx_tcp_lua_http_parse_ctx_t *r,
    ngx_buf_t *b, lua_State *L)
{
    ngx_int_t                       rc;
    size_t                          header_name_len;                        
    size_t                          header_len;                        

    for ( ;; ) {

        rc = ngx_tcp_parse_http_header_line(r, b, 1);

        if (rc == NGX_OK) {

            /* a header line has been parsed successfully */

            header_name_len = r->header_name_end - r->header_name_start;
            header_len = r->header_end - r->header_start;

            lua_pushlstring(L, (const char*)r->header_name_start, header_name_len);
            lua_pushlstring(L, (const char*)r->header_start, header_len);
            lua_rawset(L, -3);
            
            if (0 == ngx_strncasecmp(r->header_name_start, (u_char *) "content-length", header_name_len)
                || 0 == ngx_strncasecmp(r->header_name_start, (u_char *) "content_length", header_name_len) ) {
                r->content_length_n = ngx_atoof(r->header_start, header_len);
            }
            
            if ( (0 == ngx_strncasecmp(r->header_name_start, (u_char *) "transfer-encoding", header_name_len)
                || 0 == ngx_strncasecmp(r->header_name_start, (u_char *) "transfer-encoding", header_name_len) )
                &&  ngx_strlcasestrn(r->header_start, r->header_end, (u_char *) "chunked", 7 - 1) != NULL ) {
                r->chunked = 1;
            }

            continue;
        }

        if (rc == NGX_TCP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            //ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            //               "http proxy header done");

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        //rc = NGX_HTTP_PARSE_INVALID_HEADER
        /* there was error while a header line parsing */

        //ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
        //              "upstream sent invalid header");
        r->error_code = NGX_TCP_LUA_SOCKET_ERR_HEADERS;
        return NGX_ERROR;
    }
}

static ngx_int_t
ngx_tcp_process_http_body(ngx_tcp_lua_http_parse_ctx_t *r,
    ngx_buf_t *b, lua_State *L)
{
    ngx_int_t        rc;
    size_t           copy_len;
    
    if (r->chunked == 1) {
        //still has body unread
        if (r->wait_body_data && r->chunk.size > 0) {
            if (b->last - b->pos >= r->chunk.size) {
                lua_pushlstring(L, (const char*)b->pos, r->chunk.size);
                lua_rawseti(L, -2, luaL_getn(L, -2) + 1);

                b->pos += r->chunk.size;
                r->max_body_size -= r->chunk.size;
                r->chunk.size = 0;

                if (r->max_body_size < 0) {
                    r->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGBODY;
                    
                    return NGX_ERROR;
                }
                
                r->wait_body_data = 0;
            }
            else {
                if (b->last == b->end) {
                    copy_len = b->last - b->pos;
                    lua_pushlstring(L, (const char*)b->pos, copy_len);
                    lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
                    r->chunk.size -= copy_len;
                    r->max_body_size -= copy_len;
                    b->pos = b->last = b->start;

                    if (r->max_body_size < 0) {
                        r->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGBODY;
                    
                        return NGX_ERROR;
                    }
                }
                return NGX_AGAIN;
            }
        }
        
        for ( ;; ) {
        
            rc = ngx_lua_parse_http_chunked(r, b, &r->chunk);
            
            if (rc == NGX_OK) {
                if (b->last - b->pos >= r->chunk.size) {
                    lua_pushlstring(L, (const char*)b->pos, r->chunk.size);
                    lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
                    b->pos += r->chunk.size;
                    
                    r->max_body_size -= r->chunk.size;
                    r->chunk.size = 0;
                    
                    if (r->max_body_size < 0) {
                        r->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGBODY;
                    
                        return NGX_ERROR;
                    }
                }
                else {
                    if (b->last == b->end) {
                        copy_len = b->last - b->pos;
                        lua_pushlstring(L, (const char*)b->pos, copy_len);
                        lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
                        r->chunk.size -= copy_len;
                        r->max_body_size -= copy_len;
                        b->pos = b->last = b->start;
                        
                        if (r->max_body_size < 0) {
                            r->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGBODY;
                        
                            return NGX_ERROR;
                        }
                    }
                    
                    r->wait_body_data = 1;
                    
                    return NGX_AGAIN;
                }
                
                continue;
            }
            
            if (rc == NGX_AGAIN) {
                if (b->last == b->end) {
                    b->pos = b->last = b->start;
                }
                return NGX_AGAIN;
            }
             
            if (rc == NGX_DONE) {
                return NGX_OK;
            }
            
            r->error_code = NGX_TCP_LUA_SOCKET_ERR_BODY;
            return NGX_ERROR;
        }
        
    }
    
    else if (r->content_length_n > 0) {
        if (b->last - b->pos >= r->content_length_n) {
            lua_pushlstring(L, (const char*)b->pos, b->last - b->pos);
            lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
            b->pos += r->content_length_n;
            
            //no check max_body_size here due to alrealy read it
            return NGX_OK;
        }
        
        if (b->last == b->end) {
            lua_pushlstring(L, (const char*)b->pos, b->last - b->pos);
            lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
            r->content_length_n -= b->last - b->pos;// content_length_n impossible redue to 0
            r->max_body_size -= b->last - b->pos;
            b->pos = b->last = b->start;
            
            if (r->max_body_size < 0) {
                r->error_code = NGX_TCP_LUA_SOCKET_ERR_BIGBODY;
                        
                return NGX_ERROR;
            }
        }
        
        return NGX_AGAIN;
    }
    
    else if (r->content_length_n == 0) {
        return NGX_OK;
    }

    r->error_code = NGX_TCP_LUA_SOCKET_ERR_HEADERS;
    return NGX_ERROR;
}

//--------------------------------------------------------

static ngx_int_t
ngx_tcp_parse_http_status_line(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_tcp_http_status_t *status)
{
    u_char   ch;
    u_char  *p;
    enum {
        sw_start = 0,
        sw_H,
        sw_HT,
        sw_HTT,
        sw_HTTP,
        sw_first_major_digit,
        sw_major_digit,
        sw_first_minor_digit,
        sw_minor_digit,
        sw_status,
        sw_space_after_status,
        sw_status_text,
        sw_almost_done
    } state;

    state = r->state;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* "HTTP/" */
        case sw_start:
            switch (ch) {
            case 'H':
                state = sw_H;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_H:
            switch (ch) {
            case 'T':
                state = sw_HT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HT:
            switch (ch) {
            case 'T':
                state = sw_HTT;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTT:
            switch (ch) {
            case 'P':
                state = sw_HTTP;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        case sw_HTTP:
            switch (ch) {
            case '/':
                state = sw_first_major_digit;
                break;
            default:
                return NGX_ERROR;
            }
            break;

        /* the first digit of major HTTP version */
        case sw_first_major_digit:
            if (ch < '1' || ch > '9') {
                return NGX_ERROR;
            }

            //r->http_major = ch - '0';
            state = sw_major_digit;
            break;

        /* the major HTTP version or dot */
        case sw_major_digit:
            if (ch == '.') {
                state = sw_first_minor_digit;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            //r->http_major = r->http_major * 10 + ch - '0';
            break;

        /* the first digit of minor HTTP version */
        case sw_first_minor_digit:
            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            //r->http_minor = ch - '0';
            state = sw_minor_digit;
            break;

        /* the minor HTTP version or the end of the request line */
        case sw_minor_digit:
            if (ch == ' ') {
                state = sw_status;
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            //r->http_minor = r->http_minor * 10 + ch - '0';
            break;

        /* HTTP status code */
        case sw_status:
            if (ch == ' ') {
                break;
            }

            if (ch < '0' || ch > '9') {
                return NGX_ERROR;
            }

            status->code = status->code * 10 + ch - '0';

            if (++status->count == 3) {
                state = sw_space_after_status;
                status->start = p - 2;
            }

            break;

        /* space or end of line */
        case sw_space_after_status:
            switch (ch) {
            case ' ':
                state = sw_status_text;
                break;
            case '.':                    /* IIS may send 403.1, 403.2, etc */
                state = sw_status_text;
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
            break;

        /* any text until end of line */
        case sw_status_text:
            switch (ch) {
            case CR:
                state = sw_almost_done;

                break;
            case LF:
                goto done;
            }
            break;

        /* end of status line */
        case sw_almost_done:
            status->end = p - 1;
            switch (ch) {
            case LF:
                goto done;
            default:
                return NGX_ERROR;
            }
        }
    }

    b->pos = p;
    r->state = state;

    return NGX_AGAIN;

done:

    b->pos = p + 1;

    if (status->end == NULL) {
        status->end = p;
    }

    //status->http_version = r->http_major * 1000 + r->http_minor;
    r->state = sw_start;

    return NGX_OK;
}


static ngx_int_t
ngx_tcp_parse_http_header_line(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_uint_t allow_underscores)
{
    u_char      ch, *p;
    //ngx_uint_t  hash, i;
    enum {
        sw_start = 0,
        sw_name,
        sw_space_before_value,
        sw_value,
        sw_space_after_value,
        sw_ignore_line,
        sw_almost_done,
        sw_header_almost_done
    } state;

    /* the last '\0' is not needed because string is zero terminated */

    //static u_char  lowcase[] =
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
    //    "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
    //    "\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    //    "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    state = r->state;
    //hash = r->header_hash;
    //i = r->lowcase_index;

    for (p = b->pos; p < b->last; p++) {
        ch = *p;

        switch (state) {

        /* first char */
        case sw_start:
            r->header_name_start = p;
            r->invalid_header = 0;

            switch (ch) {
            case CR:
                r->header_end = p;
                state = sw_header_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto header_done;
            default:
                state = sw_name;

                //c = lowcase[ch];

                //if (c) {
                    //hash = ngx_hash(0, c);
                    //r->lowcase_header[0] = c;
                    //i = 1;
                    //break;
                //}

                if (ch == '\0') {
                    return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
                }

                r->invalid_header = 1;

                break;

            }
            break;

        /* header name */
        case sw_name:
            //c = lowcase[ch];

            //if (c) {
            //    hash = ngx_hash(hash, c);
            //    r->lowcase_header[i++] = c;
            //    i &= (NGX_HTTP_LC_HEADER_LEN - 1);
            //    break;
            //}

            if (ch == '_') {
                if (allow_underscores) {
                    //hash = ngx_hash(hash, ch);
                    //r->lowcase_header[i++] = ch;
                    //i &= (NGX_HTTP_LC_HEADER_LEN - 1);

                } else {
                    r->invalid_header = 1;
                }

                break;
            }

            if (ch == ':') {
                r->header_name_end = p;
                state = sw_space_before_value;
                break;
            }

            if (ch == CR) {
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            }

            if (ch == LF) {
                r->header_name_end = p;
                r->header_start = p;
                r->header_end = p;
                goto done;
            }

            /* IIS may send the duplicate "HTTP/1.1 ..." lines */
            if (ch == '/'
                //&& r->upstream
                && p - r->header_name_start == 4
                && ngx_strncmp(r->header_name_start, "HTTP", 4) == 0)
            {
                state = sw_ignore_line;
                break;
            }

            if (ch == '\0') {
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            }

            r->invalid_header = 1;

            break;

        /* space* before header value */
        case sw_space_before_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                r->header_start = p;
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_start = p;
                r->header_end = p;
                goto done;
            case '\0':
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            default:
                r->header_start = p;
                state = sw_value;
                break;
            }
            break;

        /* header value */
        case sw_value:
            switch (ch) {
            case ' ':
                r->header_end = p;
                state = sw_space_after_value;
                break;
            case CR:
                r->header_end = p;
                state = sw_almost_done;
                break;
            case LF:
                r->header_end = p;
                goto done;
            case '\0':
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* space* before end of header line */
        case sw_space_after_value:
            switch (ch) {
            case ' ':
                break;
            case CR:
                state = sw_almost_done;
                break;
            case LF:
                goto done;
            case '\0':
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            default:
                state = sw_value;
                break;
            }
            break;

        /* ignore header line */
        case sw_ignore_line:
            switch (ch) {
            case LF:
                state = sw_start;
                break;
            default:
                break;
            }
            break;

        /* end of header line */
        case sw_almost_done:
            switch (ch) {
            case LF:
                goto done;
            case CR:
                break;
            default:
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            }
            break;

        /* end of header */
        case sw_header_almost_done:
            switch (ch) {
            case LF:
                goto header_done;
            default:
                return NGX_TCP_HTTP_PARSE_INVALID_HEADER;
            }
        }
    }

    b->pos = p;
    r->state = state;
    //r->header_hash = hash;
    //r->lowcase_index = i;

    return NGX_AGAIN;

done:

    b->pos = p + 1;
    r->state = sw_start;
    //r->header_hash = hash;
    //r->lowcase_index = i;

    return NGX_OK;

header_done:

    b->pos = p + 1;
    r->state = sw_start;

    return NGX_TCP_HTTP_PARSE_HEADER_DONE;
}


ngx_int_t
ngx_lua_parse_http_chunked(ngx_tcp_lua_http_parse_ctx_t *r, ngx_buf_t *b,
    ngx_tcp_http_chunked_t *ctx)
{
    u_char     *pos, ch, c;
    ngx_int_t   rc;
    
    enum {
        sw_chunk_start = 0,
        sw_chunk_size,
        sw_chunk_extension,
        sw_chunk_extension_almost_done,
        sw_chunk_data,
        sw_after_data,
        sw_after_data_almost_done,
        sw_last_chunk_extension,
        sw_last_chunk_extension_almost_done,
        sw_trailer,
        sw_trailer_almost_done,
        sw_trailer_header,
        sw_trailer_header_almost_done
    } state;

    state = ctx->state;

    if (state == sw_chunk_data && ctx->size == 0) {
        state = sw_after_data;
    }

    rc = NGX_AGAIN;

    for (pos = b->pos; pos < b->last; pos++) {

        ch = *pos;

        //ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
         //              "http chunked byte: %02Xd s:%d", ch, state);

        switch (state) {

        case sw_chunk_start:
            if (ch >= '0' && ch <= '9') {
                state = sw_chunk_size;
                ctx->size = ch - '0';
                break;
            }

            c = (u_char) (ch | 0x20);

            if (c >= 'a' && c <= 'f') {
                state = sw_chunk_size;
                ctx->size = c - 'a' + 10;
                break;
            }

            goto invalid;

        case sw_chunk_size:
            if (ch >= '0' && ch <= '9') {
                ctx->size = ctx->size * 16 + (ch - '0');
                break;
            }

            c = (u_char) (ch | 0x20);

            if (c >= 'a' && c <= 'f') {
                ctx->size = ctx->size * 16 + (c - 'a' + 10);
                break;
            }

            if (ctx->size == 0) {

                switch (ch) {
                case CR:
                    state = sw_last_chunk_extension_almost_done;
                    break;
                case LF:
                    state = sw_trailer;
                    break;
                case ';':
                case ' ':
                case '\t':
                    state = sw_last_chunk_extension;
                    break;
                default:
                    goto invalid;
                }

                break;
            }

            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
                break;
            case ';':
            case ' ':
            case '\t':
                state = sw_chunk_extension;
                break;
            default:
                goto invalid;
            }

            break;

        case sw_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_chunk_data;
            }
            break;

        case sw_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_chunk_data;
                break;
            }
            goto invalid;

        case sw_chunk_data:
            rc = NGX_OK;
            goto data;

        case sw_after_data:
            switch (ch) {
            case CR:
                state = sw_after_data_almost_done;
                break;
            case LF:
                state = sw_chunk_start;
            }
            break;

        case sw_after_data_almost_done:
            if (ch == LF) {
                state = sw_chunk_start;
                break;
            }
            goto invalid;

        case sw_last_chunk_extension:
            switch (ch) {
            case CR:
                state = sw_last_chunk_extension_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;

        case sw_last_chunk_extension_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;

        case sw_trailer:
            switch (ch) {
            case CR:
                state = sw_trailer_almost_done;
                break;
            case LF:
                goto done;
            default:
                state = sw_trailer_header;
            }
            break;

        case sw_trailer_almost_done:
            if (ch == LF) {
                goto done;
            }
            goto invalid;

        case sw_trailer_header:
            switch (ch) {
            case CR:
                state = sw_trailer_header_almost_done;
                break;
            case LF:
                state = sw_trailer;
            }
            break;

        case sw_trailer_header_almost_done:
            if (ch == LF) {
                state = sw_trailer;
                break;
            }
            goto invalid;

        }
    }

data:

    ctx->state = state;
    b->pos = pos;

    //switch (state) {
    //
    //case sw_chunk_start:
    //    ctx->length = 3 /* "0" LF LF */;
    //    break;
    //case sw_chunk_size:
    //    ctx->length = 2 /* LF LF */
    //                  + (ctx->size ? ctx->size + 4 /* LF "0" LF LF */ : 0);
    //    break;
    //case sw_chunk_extension:
    //case sw_chunk_extension_almost_done:
    //    ctx->length = 1 /* LF */ + ctx->size + 4 /* LF "0" LF LF */;
    //    break;
    //case sw_chunk_data:
    //    ctx->length = ctx->size + 4 /* LF "0" LF LF */;
    //    break;
    //case sw_after_data:
    //case sw_after_data_almost_done:
    //    ctx->length = 4 /* LF "0" LF LF */;
    //    break;
    //case sw_last_chunk_extension:
    //case sw_last_chunk_extension_almost_done:
    //    ctx->length = 2 /* LF LF */;
    //    break;
    //case sw_trailer:
    //case sw_trailer_almost_done:
    //    ctx->length = 1 /* LF */;
    //    break;
    //case sw_trailer_header:
    //case sw_trailer_header_almost_done:
    //    ctx->length = 2 /* LF LF */;
    //    break;
    //
    //}

    //if (ctx->size < 0 || ctx->length < 0) {
    if (ctx->size < 0) {
        goto invalid;
    }

    return rc;

done:

    ctx->state = 0;
    b->pos = pos + 1;

    return NGX_DONE;

invalid:

    return NGX_ERROR;
}