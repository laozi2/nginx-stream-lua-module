

#include "ngx_tcp_lua_socket_tcp.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_session.h"
#include "ngx_tcp_lua_ssl.h"



static char ngx_tcp_lua_tcp_socket_metatable_key;
static char ngx_tcp_lua_upstream_udata_metatable_key;

static int ngx_tcp_lua_socket_error_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static int ngx_tcp_lua_socket_tcp(lua_State *L);
static int ngx_tcp_lua_socket_tcp_connect(lua_State *L);
static void ngx_tcp_lua_socket_resolve_handler(ngx_resolver_ctx_t *ctx);
static int ngx_tcp_lua_socket_resolve_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static int ngx_tcp_lua_socket_tcp_connect_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static int ngx_tcp_lua_socket_tcp_receive(lua_State *L);
static ngx_int_t ngx_tcp_lua_socket_read_chunk(void *data, ssize_t bytes);
//static ngx_int_t ngx_tcp_lua_socket_read_all(void *data, ssize_t bytes);
//static ngx_int_t ngx_tcp_lua_socket_read_line(void *data, ssize_t bytes);
static ngx_int_t ngx_tcp_lua_socket_read(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static int ngx_tcp_lua_socket_tcp_send(lua_State *L);
static int ngx_tcp_lua_socket_tcp_send_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static int ngx_tcp_lua_socket_tcp_close(lua_State *L);
static int ngx_tcp_lua_socket_tcp_setoption(lua_State *L);
static int ngx_tcp_lua_socket_tcp_settimeout(lua_State *L);
//static int ngx_tcp_lua_req_wait_next_request(lua_State *L);
//static int ngx_tcp_lua_req_exit(lua_State *L);
static int ngx_tcp_lua_socket_tcp_getreusedtimes(lua_State *L);
static int ngx_tcp_lua_socket_tcp_setkeepalive(lua_State *L);
static void ngx_tcp_lua_socket_tcp_handler(ngx_event_t *ev);
static ngx_int_t ngx_tcp_lua_socket_tcp_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_tcp_lua_socket_read_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static void ngx_tcp_lua_socket_send_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static ngx_int_t ngx_tcp_lua_socket_send(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static int ngx_tcp_lua_socket_tcp_receive_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_socket_connected_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static void ngx_tcp_lua_socket_finalize(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
static ngx_int_t ngx_tcp_lua_socket_test_connect(ngx_connection_t *c);
//static int ngx_tcp_lua_socket_tcp_receiveuntil(lua_State *L);
//static int ngx_tcp_lua_socket_receiveuntil_iterator(lua_State *L);
//static ngx_int_t ngx_tcp_lua_socket_compile_pattern(u_char *data, size_t len,
//    ngx_tcp_lua_socket_compiled_pattern_t *cp, ngx_log_t *log);
//static ngx_int_t ngx_tcp_lua_socket_read_until(void *data, ssize_t bytes);
//static int ngx_tcp_lua_socket_cleanup_compiled_pattern(lua_State *L);
//static int ngx_tcp_lua_req_socket(lua_State *L);
//static void ngx_tcp_lua_req_socket_rev_handler(ngx_tcp_session_t *s);
//static int ngx_tcp_lua_socket_downstream_destroy(lua_State *L);
//static void ngx_tcp_lua_req_socket_cleanup(void *data);
static void ngx_tcp_lua_socket_dummy_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u);
//static ngx_int_t ngx_tcp_lua_socket_add_input_buffer(ngx_tcp_session_t *s,
//    ngx_tcp_lua_socket_upstream_t *u);
//static ngx_int_t ngx_tcp_lua_socket_add_pending_data(ngx_tcp_session_t *s,
//    ngx_tcp_lua_socket_upstream_t *u, u_char *pos, size_t len, u_char *pat,
//    int prefix, int old_state);
//static ngx_int_t ngx_tcp_lua_socket_insert_buffer(ngx_tcp_session_t *s,
//    ngx_tcp_lua_socket_upstream_t *u, u_char *pat, size_t prefix);
//static ngx_int_t ngx_tcp_lua_socket_push_input_data(ngx_tcp_session_t *s,
//    ngx_tcp_lua_ctx_t *ctx, ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_socket_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_tcp_lua_socket_keepalive_rev_handler(ngx_event_t *ev);
static ngx_int_t ngx_tcp_lua_socket_keepalive_close_handler(ngx_event_t *ev);
static void ngx_tcp_lua_socket_free_pool(ngx_log_t *log, ngx_tcp_lua_socket_pool_t *spool);
static void ngx_tcp_lua_socket_cleanup(void *data);
static int ngx_tcp_lua_socket_upstream_destroy(lua_State *L);
static ngx_int_t ngx_tcp_lua_get_keepalive_peer(ngx_tcp_session_t *s, lua_State *L,
    int key_index, ngx_tcp_lua_socket_upstream_t *u);
static void ngx_tcp_lua_socket_close_connection(ngx_connection_t *c);

#if (NGX_TCP_SSL)
static int ngx_tcp_lua_socket_tcp_sslhandshake(lua_State *L);
static int ngx_tcp_lua_ssl_handshake_retval_handler(ngx_tcp_session_t *r,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L);
static void ngx_tcp_lua_ssl_handshake_handler(ngx_connection_t *c);
#endif

void
ngx_tcp_lua_inject_socket_api(ngx_log_t *log, lua_State *L)
{
//    ngx_int_t         rc;

    lua_createtable(L, 0, 1 /* nrec */);    /* ngx.socket */

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp);
    lua_setfield(L, -2, "tcp");

    //{
    //    const char    buf[] = "local sock = ngx.socket.tcp()"
    //               " local ok, err = sock:connect(...)"
    //               " if ok then return sock else return nil, err end";
    //
    //    rc = luaL_loadbuffer(L, buf, sizeof(buf) - 1, "ngx.socket.connect");
    //}
    //
    //if (rc != NGX_OK) {
    //    ngx_log_error(NGX_LOG_CRIT, log, 0,
    //                  "failed to load Lua code for ngx.socket.connect(): %i",
    //                  rc);
    //
    //} else {
    //    lua_setfield(L, -2, "connect");
    //}

    lua_setfield(L, -2, "socket");

    ///* {{{req socket object metatable */
    //lua_pushlightuserdata(L, &ngx_tcp_lua_req_socket_metatable_key);
    //lua_createtable(L, 0 /* narr */, 3 /* nrec */);
    //
    //lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receive);
    //lua_setfield(L, -2, "receive");
    //
    ////lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receiveuntil);
    ////lua_setfield(L, -2, "receiveuntil");
    //
    //lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_settimeout);
    //lua_setfield(L, -2, "settimeout"); /* ngx socket mt */
    //
    //lua_pushvalue(L, -1);
    //lua_setfield(L, -2, "__index");
    //
    //lua_rawset(L, LUA_REGISTRYINDEX);
    ///* }}} */

    /* {{{tcp object metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_tcp_socket_metatable_key);
    lua_createtable(L, 0 /* narr */, 12 /* nrec */);

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_connect);
    lua_setfield(L, -2, "connect");
    
#if (NGX_TCP_SSL)
    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_sslhandshake);
    lua_setfield(L, -2, "sslhandshake");
#endif

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receive);
    lua_setfield(L, -2, "receive");

    //lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receiveuntil);
    //lua_setfield(L, -2, "receiveuntil");
    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_receive_http);
    lua_setfield(L, -2, "receive_http");

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_send);
    lua_setfield(L, -2, "send");

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_close);
    lua_setfield(L, -2, "close");

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_setoption);
    lua_setfield(L, -2, "setoption");

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_settimeout);
    lua_setfield(L, -2, "settimeout"); 

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_getreusedtimes);
    lua_setfield(L, -2, "getreusedtimes");

    lua_pushcfunction(L, ngx_tcp_lua_socket_tcp_setkeepalive);
    lua_setfield(L, -2, "setkeepalive");

    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */

    /* {{{upstream userdata metatable */
    lua_pushlightuserdata(L, &ngx_tcp_lua_upstream_udata_metatable_key);
    lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    lua_pushcfunction(L, ngx_tcp_lua_socket_upstream_destroy);
    lua_setfield(L, -2, "__gc");
    lua_rawset(L, LUA_REGISTRYINDEX);
    /* }}} */
}


static int
ngx_tcp_lua_socket_tcp(lua_State *L)
{
    ngx_tcp_session_t             *s;
    ngx_tcp_lua_socket_upstream_t *u;
    ngx_tcp_lua_srv_conf_t        *lscf;
    ngx_tcp_core_srv_conf_t       *cscf;

    if (lua_gettop(L) != 0) {
        return luaL_error(L, "expecting zero arguments, but got %d",
                lua_gettop(L));
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    lua_createtable(L, 2 /* narr */, 1 /* nrec */);
    lua_pushlightuserdata(L, &ngx_tcp_lua_tcp_socket_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    u = lua_newuserdata(L, sizeof(ngx_tcp_lua_socket_upstream_t));
    if (u == NULL) {
        return luaL_error(L, "out of memory");
    }

    //lua_createtable(L, 0 /* narr */, 1 /* nrec */); /* metatable */
    //lua_pushcfunction(L, ngx_tcp_lua_socket_upstream_destroy);
    //lua_setfield(L, -2, "__gc");
    //lua_setmetatable(L, -2);

    lua_pushlightuserdata(L, &ngx_tcp_lua_upstream_udata_metatable_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_setmetatable(L, -2);

    lua_rawseti(L, 1, SOCKET_CTX_INDEX);

    ngx_memzero(u, sizeof(ngx_tcp_lua_socket_upstream_t));

    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    u->connect_timeout = lscf->connect_timeout;
    u->send_timeout = cscf->send_timeout;
    u->read_timeout = cscf->read_timeout;

    return 1;
}


static int
ngx_tcp_lua_socket_tcp_connect(lua_State *L)
{
    ngx_tcp_session_t           *s;
    ngx_tcp_lua_ctx_t           *ctx;
    ngx_str_t                    host;
    int                          port;
    ngx_resolver_ctx_t          *rctx, temp;
    int                          saved_top;
    int                          n;
    u_char                      *p;
    size_t                       len;
    ngx_url_t                    url;
    ngx_int_t                    rc;
    ngx_peer_connection_t       *pc;
    ngx_tcp_lua_srv_conf_t      *lscf;
    ngx_tcp_core_srv_conf_t     *cscf;
    ngx_msec_t                   connect_timeout,send_timeout,read_timeout;

    ngx_tcp_lua_socket_upstream_t          *u;

    n = lua_gettop(L);
    
    //connect("ip(string)",port(number),pool_name(string))
    if (n != 3 && n != 4) {
        return luaL_error(L, "ngx.socket connect: expecting 3 or 4 arguments "
                          "(including the object), but seen %d", n);
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ctx = s->ctx;

    luaL_checktype(L, 1, LUA_TTABLE);

    p = (u_char *) luaL_checklstring(L, 2, &len);
    if (p == NULL) {
        return luaL_argerror(L, 2, "bad argument, string expected");
    }

    host.data = ngx_palloc(s->pool, len + 1);
    if (host.data == NULL) {
        return luaL_error(L, "out of memory");
    }

    host.len = len;

    ngx_memcpy(host.data, p, len);
    host.data[len] = '\0';

    port = luaL_checkinteger(L, 3);
    
    if (port < 0 || port > 65536) {
        //lua_pushnil(L);
        //lua_pushfstring(L, "bad port number: %d", port);
        //return 2;
        return luaL_argerror(L, 3, "bad port number, need [0,65536]");
    }

    if (n == 4) {
        if (0 == lua_isstring(L, 4)) {
            //lua_pop(L,1);
            return luaL_argerror(L, 4, "bad argument, string expected");
        }
    }
    else { //n == 3
        lua_pushliteral(L, ":");
        lua_insert(L, 3);
        lua_concat(L, 3);
    }

    dd("socket key: %s", lua_tostring(L, -1));

    /* the key's index is -1 */

    lua_pushvalue(L, -1);
    lua_rawseti(L, 1, SOCKET_KEY_INDEX);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (NULL == u) {
        lua_pushnil(L);
        lua_pushliteral(L, "upsteam socket is null");
        return 2;
    }

    if (u->peer.connection) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket reconnect without shutting down");

        ngx_tcp_lua_socket_finalize(s, u);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua reuse socket upstream ctx");

    //save u config
    connect_timeout = u->connect_timeout;
    send_timeout = u->send_timeout;
    read_timeout = u->read_timeout;
    
    //clear u
    ngx_memzero(u, sizeof(ngx_tcp_lua_socket_upstream_t));
    
    //restore u config
    u->connect_timeout = connect_timeout;
    u->send_timeout = send_timeout;
    u->read_timeout = read_timeout;
    
    u->session = s; /* set the controlling request */
    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);
    u->conf = lscf;

    pc = &u->peer;
    pc->log = s->connection->log;
    pc->log_error = NGX_ERROR_ERR;

    dd("lua peer connection log: %p", pc->log);

    //s->connection->single_connection = 0;

    rc = ngx_tcp_lua_get_keepalive_peer(s, L, -1, u);

    if (rc == NGX_OK) {
        lua_pushinteger(L, 1);
        return 1;
    }

    if (rc == NGX_ERROR) {
        lua_pushnil(L);
        lua_pushliteral(L, "error in get keepalive peer");
        return 2;
    }

    /* rc == NGX_DECLINED */

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = host.len;
    url.url.data = host.data;
    url.default_port = port;
    url.no_resolve = 1;

    if (ngx_parse_url(s->pool, &url) != NGX_OK) {
        lua_pushnil(L);

        if (url.err) {
            lua_pushfstring(L, "failed to parse host name \"%s\": %s",
                            host.data, url.err);

        } else {
            lua_pushfstring(L, "failed to parse host name \"%s\"", host.data);
        }

        return 2;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket connect timeout: %M", u->connect_timeout);

    u->resolved = ngx_pcalloc(s->pool, sizeof(ngx_tcp_upstream_resolved_t));
    if (u->resolved == NULL) {
        return luaL_error(L, "out of memory");
    }

    if (url.addrs && url.addrs[0].sockaddr) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket network address given directly");

        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->naddrs = 1;
        u->resolved->host = url.addrs[0].name;

    } else {
        u->resolved->host = host;
        u->resolved->port = (in_port_t) port;
    }

    if (u->resolved->sockaddr) {
        rc = ngx_tcp_lua_socket_resolve_retval_handler(s, u, L);
        if (rc == NGX_AGAIN) {
            return lua_yield(L, 0);
        }

        return rc;
    }

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    temp.name = host;
    rctx = ngx_resolve_start(cscf->resolver, &temp);
    if (rctx == NULL) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushliteral(L, "failed to start the resolver");
        return 2;
    }

    if (rctx == NGX_NO_RESOLVER) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushfstring(L, "no resolver defined to resolve \"%s\"", host.data);
        return 2;
    }

    rctx->name = host;
    rctx->type = NGX_RESOLVE_A;
    rctx->handler = ngx_tcp_lua_socket_resolve_handler;
    rctx->data = u;
    rctx->timeout = cscf->resolver_timeout;

    u->resolved->ctx = rctx;

    saved_top = lua_gettop(L);

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket fail to run resolver immediately");

        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;

        u->resolved->ctx = NULL;
        lua_pushnil(L);
        lua_pushfstring(L, "%s could not be resolved", host.data);

        return 2;
    }

    if (u->waiting == 1) {
        /* resolved and in connecting */
        return lua_yield(L, 0);
    }

    n = lua_gettop(L) - saved_top;
    if (n) {
        /* errors occurred during resolving or connecting
         * or already connected */
        return n;
    }

    /* still resolving */

    u->waiting = 1;
    //u->prepare_retvals = ngx_tcp_lua_socket_resolve_retval_handler;

    ctx->data = u;
    //ctx->socket_busy = 1;
    //ctx->socket_ready = 0;

    /* set s->write_event_handler to go on session process */
    s->write_event_handler = ngx_tcp_lua_wev_handler;

    return lua_yield(L, 0);
}

static void
ngx_tcp_lua_socket_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_upstream_resolved_t        *ur;
    ngx_tcp_lua_ctx_t                  *lctx;
    lua_State                          *L;
    ngx_tcp_lua_socket_upstream_t      *u;
    u_char                             *p;
    size_t                              len;
    struct sockaddr_in                 *sin;
    ngx_uint_t                          i;

    u = ctx->data;
    s = u->session;
    ur = u->resolved;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket resolve handler");

    lctx = s->ctx;

    L = lctx->co;

    dd("setting socket_ready to 1");

    if (ctx->state) {
        ngx_log_debug2(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket resolver error: %s (waiting: %d)",
                       ngx_resolver_strerror(ctx->state), (int) u->waiting);

        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushlstring(L, (char *) ctx->name.data, ctx->name.len);
        lua_pushfstring(L, " could not be resolved (%d: %s)",
                        (int) ctx->state,
                        ngx_resolver_strerror(ctx->state));
        lua_concat(L, 2);

        u->prepare_retvals = ngx_tcp_lua_socket_error_retval_handler;
        goto done;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    in_addr_t   addr;
    ngx_uint_t  i;

    for (i = 0; i < ctx->naddrs; i++) {
        dd("addr i: %d %p", (int) i,  &ctx->addrs[i]);

        addr = ntohl(ctx->addrs[i]);

        ngx_log_debug4(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "name was resolved to %ud.%ud.%ud.%ud",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }
    }
#endif

    if (ur->naddrs == 0) {

        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushliteral(L, "name cannot be resolved to a address");

        u->prepare_retvals = ngx_tcp_lua_socket_error_retval_handler;
        goto done;
    }

    if (ur->naddrs == 1) {
        i = 0;

    } else {
        i = ngx_random() % ur->naddrs;
    }

    dd("selected addr index: %d", (int) i);

    len = NGX_INET_ADDRSTRLEN + sizeof(":65536") - 1;

    p = ngx_pnalloc(s->pool, len + sizeof(struct sockaddr_in));
    if (p == NULL) {

        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_RESOLVER;
        lua_pushnil(L);
        lua_pushliteral(L, "out of memory");

        u->prepare_retvals = ngx_tcp_lua_socket_error_retval_handler;
        goto done;
    }

    sin = (struct sockaddr_in *) &p[len];
    ngx_memzero(sin, sizeof(struct sockaddr_in));

    len = ngx_inet_ntop(AF_INET, &ur->addrs[i], p, NGX_INET_ADDRSTRLEN);
    len = ngx_sprintf(&p[len], ":%d", ur->port) - p;

    sin->sin_family = AF_INET;
    sin->sin_port = htons(ur->port);
    sin->sin_addr.s_addr = ur->addrs[i];

    ur->sockaddr = (struct sockaddr *) sin;
    ur->socklen = sizeof(struct sockaddr_in);

    ur->host.data = p;
    ur->host.len = len;
    ur->naddrs = 1;

    u->prepare_retvals = ngx_tcp_lua_socket_resolve_retval_handler;

done:
    ur->ctx = NULL;

    ngx_resolve_name_done(ctx);

    if (u->waiting) {
        u->waiting = 0;
        s->write_event_handler(s);

    } else {
        if (u->prepare_retvals) {
            (void) u->prepare_retvals(s, u, L);
        }
    }
}

static int
ngx_tcp_lua_socket_resolve_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    ngx_tcp_lua_ctx_t               *ctx;
    ngx_peer_connection_t           *pc;
    ngx_connection_t                *c;
    ngx_tcp_upstream_resolved_t     *ur;
    ngx_int_t                        rc;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket resolve retval handler");

    //impossible
    //if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_RESOLVER) {
    //    return 2;
    //}

    pc = &u->peer;

    ur = u->resolved;

    if (ur->sockaddr) {
        pc->sockaddr = ur->sockaddr;
        pc->socklen = ur->socklen;
        pc->name = &ur->host;

    } else {
        lua_pushnil(L);
        lua_pushliteral(L, "resolver not working");
        return 2;
    }

    u->resolved = NULL;//XXX

    pc->get = ngx_tcp_lua_socket_tcp_get_peer;

    rc = ngx_event_connect_peer(pc);

    //if (u->cleanup == NULL) {
        u->cleanup = ngx_tcp_lua_socket_cleanup;
    //}

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua tcp socket connect: %i", rc);

    if (rc == NGX_ERROR) {
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_ERROR;
        lua_pushnil(L);
        lua_pushliteral(L, "connect peer error");
        return 2;
    }

    //if (rc == NGX_BUSY) {
    //    u->ft_type |= NGX_TCP_LUA_SOCKET_FT_ERROR;
    //    lua_pushnil(L);
    //    lua_pushliteral(L, "no live connection");
    //    return 2;
    //}

    if (rc == NGX_DECLINED) {
        dd("socket errno: %d", (int) ngx_socket_errno);
        u->ft_type |= NGX_TCP_LUA_SOCKET_FT_ERROR;
        u->socket_errno = ngx_socket_errno;
        return ngx_tcp_lua_socket_error_retval_handler(s, u, L);
    }

    /* rc == NGX_OK || rc == NGX_AGAIN */

    c = pc->connection;

    c->data = u;

    c->write->handler = ngx_tcp_lua_socket_tcp_handler;
    c->read->handler = ngx_tcp_lua_socket_tcp_handler;

    u->write_event_handler = ngx_tcp_lua_socket_connected_handler;
    u->read_event_handler = ngx_tcp_lua_socket_connected_handler;

    c->sendfile &= s->connection->sendfile;

    c->pool = NULL; //s->pool;

    //below are set by ngx_event_connect_peer 
    //c->log = s->connection->log; 
    //c->read->log = c->log;
    //c->write->log = c->log;

    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */

    //u->writer.out = NULL;
    //u->writer.last = &u->writer.out;
    //u->writer.connection = c;
    //u->writer.limit = 0;
    //u->request_sent = 0;

    ctx = s->ctx;

    ctx->data = u;

    if (rc == NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket connected: fd:%d", (int) c->fd);

        /* We should delete the current write/read event
         * here because the socket object may not be used immediately
         * on the Lua land, thus causing hot spin around level triggered
         * event poll and wasting CPU cycles. */

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_tcp_lua_socket_handle_error(s, u,
                                             NGX_TCP_LUA_SOCKET_FT_ERROR);
            lua_pushnil(L);
            lua_pushliteral(L, "failed to handle write event");

            return 2;
        }

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_tcp_lua_socket_handle_error(s, u,
                                             NGX_TCP_LUA_SOCKET_FT_ERROR);
            lua_pushnil(L);
            lua_pushliteral(L, "failed to handle write event");

            return 2;
        }

        dd("setting socket_ready to 1");

        u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
        u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;

        lua_pushinteger(L, 1);
        return 1;
    }

    /* rc == NGX_AGAIN */

    ngx_add_timer(c->write, u->connect_timeout);

    u->waiting = 1;
    //u->prepare_retvals = ngx_tcp_lua_socket_tcp_connect_retval_handler;

    /* set s->write_event_handler to go on session process */
    s->write_event_handler = ngx_tcp_lua_wev_handler;

    return NGX_AGAIN;
}


static int
ngx_tcp_lua_socket_error_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    u_char           errstr[NGX_MAX_ERROR_STR];
    u_char          *p;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket error retval handler");

    if (u->ft_type & (NGX_TCP_LUA_SOCKET_FT_RESOLVER | NGX_TCP_LUA_SOCKET_FT_SSL)) {
        return 2;
    }

    lua_pushnil(L);

    if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_TIMEOUT) {
        lua_pushliteral(L, "timeout");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_CLOSED) {
        lua_pushliteral(L, "closed");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_BUFTOOSMALL) {
        lua_pushliteral(L, "buffer too small");

    } else if (u->ft_type & NGX_TCP_LUA_SOCKET_FT_NOMEM) {
        lua_pushliteral(L, "out of memory");

    } else {

        if (u->socket_errno) {
//#if (nginx_version >= 1000000)
            p = ngx_strerror(u->socket_errno, errstr, sizeof(errstr));
//#else
//            p = ngx_strerror_r(u->socket_errno, errstr, sizeof(errstr));
//#endif
            /* for compatibility with LuaSocket */
            ngx_strlow(errstr, errstr, p - errstr);
            lua_pushlstring(L, (char *) errstr, p - errstr);

        } else {
            lua_pushliteral(L, "error");
        }
    }

    return 2;
}


static int
ngx_tcp_lua_socket_tcp_connect_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    if (u->ft_type) {
        return ngx_tcp_lua_socket_error_retval_handler(s, u, L);
    }

    lua_pushinteger(L, 1);
    return 1;
}


static int
ngx_tcp_lua_socket_tcp_receive(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_socket_upstream_t      *u;
    ngx_int_t                           rc;
    ngx_tcp_lua_ctx_t                  *ctx;
    ngx_buf_t                          *b;
    int                                 n;
    lua_Integer                         bytes;
    lua_Integer                         bytes_atleast = 0;
//    ngx_msec_t                          timeout = 0;
//    ngx_tcp_core_srv_conf_t            *cscf;

    n = lua_gettop(L);
    //receive(len,at least len)
    if (n != 2 && n != 3) {
        return luaL_error(L, "expecting 2 or 3 arguments "
                          "(including the object), but got %d", n);
    }
    
    if (0 == lua_isnumber(L, 2)) {
        return luaL_argerror(L, 2, "expecting number parameter!");
    }
    
    bytes = lua_tointeger(L, 2);
    if (bytes <= 0) {
        return luaL_argerror(L, 2, "bad argument <= 0");
    }
    
    if (n >= 3 && 1 == lua_isnumber(L, 3)) {
        bytes_atleast = lua_tointeger(L, 3);
        if (bytes_atleast < 1 || bytes_atleast > bytes) {
            return luaL_argerror(L, 3, "bad pattern argument beyond [1,$2]");
        }
    }
    
    //if (n >= 4 && 1 == lua_isnumber(L, 4)) {
    //    timeout = (ngx_msec_t) lua_tointeger(L, 4);
    //}

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket calling receive() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    //lua_pop(L,1);

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
    
    //if (timeout > 0) {
    //    u->read_timeout = timeout;
    //
    //} else {
    //    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    //    u->read_timeout = cscf->read_timeout;
    //}

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket read timeout: %M", u->read_timeout);

    u->input_filter = ngx_tcp_lua_socket_read_chunk;
    u->input_filter_ctx = u;
    u->length = (size_t) bytes;
    u->rest = u->length;
    u->bytes_atleast = bytes_atleast ? bytes_atleast : bytes;

    ctx = s->ctx;
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
    
    u->buf_in = b;
    u->waiting = 0;
    u->ft_type = 0;

    dd("tcp receive: buf_in: %p", u->buf_in);

    rc = ngx_tcp_lua_socket_read(s, u);

    if (rc == NGX_ERROR) {
        dd("read failed: %d", (int) u->ft_type);

        return ngx_tcp_lua_socket_tcp_receive_retval_handler(s, u, L);
    }

    if (rc == NGX_OK) {

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket receive done in a single run");

        return ngx_tcp_lua_socket_tcp_receive_retval_handler(s, u, L);
    }

    /* rc == NGX_AGAIN */

    u->read_event_handler = ngx_tcp_lua_socket_read_handler;
    //u->write_event_handler = ngx_tcp_lua_socket_dummy_handler; //no need

    /* set s->write_event_handler to go on session process */
    s->write_event_handler = ngx_tcp_lua_wev_handler;
    
    u->waiting = 1;
    u->prepare_retvals = ngx_tcp_lua_socket_tcp_receive_retval_handler;

    ctx->data = u;

    return lua_yield(L, 0);
}




static ngx_int_t
ngx_tcp_lua_socket_read_chunk(void *data, ssize_t bytes)
{
    ngx_tcp_lua_socket_upstream_t      *u = data;

    ngx_buf_t                   *b;

    b = u->buf_in;
    
    if (bytes >= (ssize_t) u->rest) {
        b->last += u->rest;
        u->rest = 0;
        
        return NGX_OK;
    }
    
    /* bytes < u->rest */
    b->last += bytes;
    u->rest -= bytes;
    
    if ((size_t)(b->last - b->pos) >= u->bytes_atleast) {
        return NGX_OK;
    }
    
    return NGX_AGAIN;
}

static ngx_int_t
ngx_tcp_lua_socket_read(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;
    ngx_buf_t                   *b;
    ngx_event_t                 *rev;
    size_t                       size;
    ssize_t                      n;

    c = u->peer.connection;
    rev = c->read;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua socket read data: waiting: %d", (int) u->waiting);

    b = u->buf_in;
    
    //if (u->rest == 0) {
    //    return NGX_OK;
    //}
    
    while (u->rest) {
    
        size = u->rest;
    
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
        
        rc = u->input_filter(u->input_filter_ctx, n);
        
        if (rc == NGX_OK) {
            break;
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


static int
ngx_tcp_lua_socket_tcp_send(lua_State *L)
{
    ngx_int_t                            rc;
    ngx_tcp_session_t                   *s;
    u_char                              *p;
    size_t                               len;
    ngx_tcp_lua_ctx_t                   *ctx;
    ngx_tcp_lua_socket_upstream_t       *u;
    int                                  type;
    const char                          *msg;
    ngx_buf_t                           *b;
    int                                  n;
    //ngx_tcp_core_srv_conf_t             *cscf;
    //ngx_msec_t                           timeout = 0;

    /* TODO: add support for the optional "i" and "j" arguments */

    n = lua_gettop(L);
    //send(data)
    if (n != 2) {
        return luaL_error(L, "expecting 2 arguments (including the object), "
                          "but got %d", n);
    }
    
    //if (n >= 3 && 1 == lua_isnumber(L, 3)) {
    //    timeout = (ngx_msec_t) lua_tointeger(L, 3);
    //}

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to send data on a closed socket: u:%p, c:%p, "
                      "ft:%ui eof:%ud",
                      u, u ? u->peer.connection : NULL, u ? u->ft_type : 0,
                      u ? u->eof : 0);

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }
    
    //if (timeout > 0) {
    //    u->send_timeout = timeout;
    //
    //} else {
    //    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    //    u->send_timeout = cscf->send_timeout;
    //}

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket send timeout: %M", u->send_timeout);

    type = lua_type(L, 2);
    switch (type) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            lua_tolstring(L, 2, &len);
            break;

        case LUA_TTABLE:
            len = ngx_tcp_lua_calc_strlen_in_table(L, 2, 2, 1 /* strict */);
            break;

        default:
            msg = lua_pushfstring(L, "string, number, boolean, nil, "
                    "or array table expected, got %s",
                    lua_typename(L, type));

            return luaL_argerror(L, 2, msg);
    }

    ctx = s->ctx;

    b = ctx->buf_out;

    if (b == NULL) {
        b = ngx_create_temp_buf(s->pool, len);
        
        if (b == NULL) {
            return luaL_error(L, "out of memory");
        }
        
        ctx->buf_out = b;
    }
    else if (b->start == NULL || (size_t)(b->end - b->start) < len) {
        b->start = ngx_palloc(s->pool, len);
        if (b->start == NULL) {
            return luaL_error(L, "out of memory");
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + len;
        b->temporary = 1;
        //others are 0 or NULL
    }
    else {
        b->pos = b->start;
        b->last = b->start;
    }
    
    u->buf_out = b;

    switch (type) {
        case LUA_TNUMBER:
        case LUA_TSTRING:
            p = (u_char *) lua_tolstring(L, 2, &len);
            b->last = ngx_copy(b->last, (u_char *) p, len);
            break;

        case LUA_TTABLE:
            b->last = ngx_tcp_lua_copy_str_in_table(L, 2, b->last);
            break;

        default:
            return luaL_error(L, "impossible to reach here");
    }

    u->length = len;
    u->ft_type = 0;

#if 1
    u->waiting = 0;
#endif

    rc = ngx_tcp_lua_socket_send(s, u);

    dd("socket send returned %d", (int) rc);

    if (rc == NGX_ERROR) {
        //return ngx_tcp_lua_socket_error_retval_handler(s, u, L);
        return ngx_tcp_lua_socket_tcp_send_retval_handler(s, u, L);
    }

    if (rc == NGX_OK) {
        //lua_pushinteger(L, len);
        //return 1;
        return ngx_tcp_lua_socket_tcp_send_retval_handler(s, u, L);
    }

    /* rc == NGX_AGAIN */
    /* set s->write_event_handler to go on session process */
    s->write_event_handler = ngx_tcp_lua_wev_handler;

    u->waiting = 1;
    u->prepare_retvals = ngx_tcp_lua_socket_tcp_send_retval_handler;

    ctx->data = u;
    //ctx->socket_busy = 1;
    //ctx->socket_ready = 0;

    return lua_yield(L, 0);
}


static int
ngx_tcp_lua_socket_tcp_send_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    int                          n = 0;
    ngx_buf_t                   *b;
    size_t                       sent_length;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket send return value handler");

    b = ((ngx_tcp_lua_ctx_t*)(s->ctx))->buf_out;

    if (u->ft_type) {
        n += ngx_tcp_lua_socket_error_retval_handler(s, u, L);
        sent_length = b ? b->pos - b->start : 0;
        lua_pushinteger(L, sent_length);
    }
    else {
        lua_pushinteger(L, u->length);
        n += 1;
    }
    
    
    if (b == NULL) {
        return n;
    }
    
    if (ngx_pfree(s->pool, b->start) == NGX_OK) {
        b->start = NULL;
    }
    else {
        b->pos = b->start;
        b->last = b->start;
    }

    u->buf_out = NULL;
    u->length = 0;
    
    return n;
}


static int
ngx_tcp_lua_socket_tcp_receive_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    int                          n = 0;
    size_t                       size;
    ngx_buf_t                   *b;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket receive return value handler");

    if (u->ft_type) {
        //n=2, nil nil/error_string
        n += ngx_tcp_lua_socket_error_retval_handler(s, u, L);
    }
    
    b = u->buf_in;
    
    if (b) {
        size = b->last - b->pos;
        if (size > 0) {
            lua_pushlstring(L, (char *) b->pos, size);
            n += 1;
        }
        else {
            //log
        }
    }
    else {
        //log
    }

    b = ((ngx_tcp_lua_ctx_t*)(s->ctx))->buf_in;

    if (b) {
        if (ngx_pfree(s->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }
        else {
            b->pos = b->start;
            b->last = b->start;
        }
    }
    
    u->buf_in = NULL;
    u->length = 0;
    u->rest = 0;

    return n;
}


static int
ngx_tcp_lua_socket_tcp_close(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_socket_upstream_t      *u;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "ngx.socket close: expecting 1 argument "
                          "(including the object) but seen %d", lua_gettop(L));
    }

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    ngx_tcp_lua_socket_finalize(s, u);

    lua_pushinteger(L, 1);
    return 1;
}


static int
ngx_tcp_lua_socket_tcp_setoption(lua_State *L)
{
    /* TODO */
    return 0;
}


static int
ngx_tcp_lua_socket_tcp_settimeout(lua_State *L)
{
    int                     n;
    ngx_int_t               connect_timeout;
    ngx_int_t               send_timeout;
    ngx_int_t               read_timeout;

    ngx_tcp_lua_socket_upstream_t  *u;

    n = lua_gettop(L);

    //(connect_timeout,send_timeout,read_timeout)
    if (n < 1) {
        return luaL_error(L, "expecting at least 1 arguments (including the object) but got %d",
                          lua_gettop(L));
    }
    
    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    if (!u) {
        return 0;
    }

    connect_timeout = (ngx_int_t) lua_tonumber(L, 2);
    send_timeout = (ngx_int_t) lua_tonumber(L, 3);
    read_timeout = (ngx_int_t) lua_tonumber(L, 4);
    
    if (connect_timeout > 0) {
        u->connect_timeout = (ngx_msec_t) connect_timeout;
    }
    
    if (send_timeout > 0) {
        u->send_timeout = (ngx_msec_t) send_timeout;
    }
    
    if (read_timeout > 0) {
        u->read_timeout = (ngx_msec_t) read_timeout;
    }
    
    return 0;
}


static void
ngx_tcp_lua_socket_tcp_handler(ngx_event_t *ev)
{
    ngx_connection_t                *c;
    ngx_tcp_session_t              *s;
    //ngx_tcp_log_ctx_t              *ctx;
    ngx_tcp_lua_socket_upstream_t  *u;

    c = ev->data;
    u = c->data;
    s = u->session;
    c = s->connection;

    ngx_log_debug2(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket handler for \"%p\", wev %d", s, (int) ev->write);

    if (ev->write) {
        u->write_event_handler(s, u);

    } else {
        u->read_event_handler(s, u);
    }
}


static ngx_int_t
ngx_tcp_lua_socket_tcp_get_peer(ngx_peer_connection_t *pc, void *data)
{
    /* empty */
    return NGX_OK;
}


static void
ngx_tcp_lua_socket_read_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket read handler");

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "lua socket read timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    if (u->buf_in && u->buf_in->start != NULL) {
        (void) ngx_tcp_lua_socket_read(s, u);
    }
}


static void
ngx_tcp_lua_socket_send_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket send handler");

    if (c->write->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "lua socket write timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    if (u->buf_out && u->buf_out->start != NULL) {
        (void) ngx_tcp_lua_socket_send(s, u);
    }
}

static ngx_int_t
ngx_tcp_lua_socket_send(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;
    ngx_buf_t                   *b;
    ngx_event_t                 *wev;
    size_t                       size;
    ngx_int_t                    n;

    c = u->peer.connection;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket send data: %p", u);

    dd("lua connection log: %p", c->log);
    
    b = u->buf_out;
    
    //if (b == NULL){
    //    return NGX_OK;
    //}
    
    size = b->last - b->pos;
    if (size <= 0) {
        //nothing to send
        return NGX_OK;
    }
    
    n = c->send(c, b->pos, size);
    
    if (n == NGX_ERROR) {
        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
        return NGX_ERROR;
    }

    if (n > 0) {
        b->pos += n;
        
        if(b->pos >= b->last){
            //send done
            
            ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
            "lua socket sent all the data: buffered 0x%d", (int) size);

            u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
                return NGX_ERROR;
            }

            ngx_tcp_lua_socket_handle_success(s, u);
            return NGX_OK;
        }
        
    }
    
    //n < size or NGX_AGAIN
    
    u->write_event_handler = ngx_tcp_lua_socket_send_handler;
    //u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;

    wev = c->write;
    if (!wev->timer_set) {
        ngx_add_timer(wev, u->send_timeout);
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
        
        return NGX_ERROR;
    }
    
    return NGX_AGAIN;
}


void
ngx_tcp_lua_socket_handle_success(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_connection_t            *c;

    c = u->peer.connection;
    
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

#if 1
    u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
    u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;
#endif

    if (u->waiting) {
        u->waiting = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket waking up the current request");

        s->write_event_handler(s);
    }
}


void
ngx_tcp_lua_socket_handle_error(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, ngx_uint_t ft_type)
{
    //ngx_connection_t            *c;
    ngx_tcp_lua_socket_pool_t   *spool;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket handle error");

    u->ft_type |= ft_type;

    //c = u->peer.connection;

    //clean u->peer.connection when any error occours, even timeout event
    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua close socket connection");

        ngx_tcp_lua_socket_close_connection(u->peer.connection);//ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;

        if (u->reused) {
            spool = u->socket_pool;

            if (spool) {
                spool->active_connections--;

                if (spool->active_connections == 0) {
                    ngx_tcp_lua_socket_free_pool(s->connection->log, spool);
                }
            }
        }
    }

    if (u->waiting) {
        u->waiting = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket waking up the current request");

        //need set u->prepare_retvals before call this function if expect Lua return value
        s->write_event_handler(s);
    }
}


static void
ngx_tcp_lua_socket_connected_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_int_t                    rc;
    ngx_connection_t            *c;

    c = u->peer.connection;

    u->prepare_retvals = ngx_tcp_lua_socket_tcp_connect_retval_handler;

    if (c->write->timedout) {

        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "lua socket connect timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    rc = ngx_tcp_lua_socket_test_connect(c);
    if (rc != NGX_OK) {
        if (rc > 0) {
            u->socket_errno = (ngx_err_t) rc;
        }

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket connected");

    /* We should delete the current write/read event
     * here because the socket object may not be used immediately
     * on the Lua land, thus causing hot spin around level triggered
     * event poll and wasting CPU cycles. */

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_ERROR);
        return;
    }

    u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
    u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket waking up the current request");

    s->write_event_handler(s);
}


static void
ngx_tcp_lua_socket_cleanup(void *data)
{
    ngx_tcp_lua_socket_upstream_t  *u = data;

    ngx_tcp_session_t  *s;

    s = u->session;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "cleanup lua socket upstream request: \"%p\"", s);

    ngx_tcp_lua_socket_finalize(s, u);
}


static void
ngx_tcp_lua_socket_finalize(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_tcp_lua_socket_pool_t          *spool;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua finalize socket");
    
    if (u->buf_in || u->buf_out) {
        //u->buf_in = NULL;
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "buf_in/buf_out not null when finalize");
    }

    if (u->cleanup) {
        u->cleanup = NULL;
    }

    if (u->resolved && u->resolved->ctx) {
    //    ngx_resolve_name_done(u->resolved->ctx);
    //    u->resolved->ctx = NULL;
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "resolved->ctx not null when finalize");
    }

    if (u->peer.free) {
        u->peer.free(&u->peer, u->peer.data, 0);
    }

    if (u->peer.connection) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua close socket connection");

        ngx_tcp_lua_socket_close_connection(u->peer.connection);//ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;

        if (!u->reused) {
            return;
        }

        spool = u->socket_pool;
        if (spool == NULL) {
            return;
        }

        spool->active_connections--;

        if (spool->active_connections == 0) {
            ngx_tcp_lua_socket_free_pool(s->connection->log, spool);
        }
    }
}


static ngx_int_t
ngx_tcp_lua_socket_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof) {
            (void) ngx_connection_error(c, c->write->kq_errno,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return err;
        }
    }

    return NGX_OK;
}

static int
ngx_tcp_lua_socket_tcp_getreusedtimes(lua_State *L)
{
    ngx_tcp_lua_socket_upstream_t      *u;

    if (lua_gettop(L) != 1) {
        return luaL_error(L, "expecting 1 argument "
                          "(including the object), but got %d", lua_gettop(L));
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);

    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    lua_pushinteger(L, u->reused);
    return 1;
}


static int
ngx_tcp_lua_socket_tcp_setkeepalive(lua_State *L)
{
    ngx_tcp_lua_main_conf_t            *lmcf;
    ngx_tcp_lua_srv_conf_t             *lscf;
    ngx_tcp_lua_socket_upstream_t      *u;
    ngx_connection_t                   *c;
    ngx_tcp_lua_socket_pool_t          *spool;
    size_t                              size;
    ngx_str_t                           key;
    ngx_uint_t                          i;
    ngx_queue_t                        *q;
    ngx_peer_connection_t              *pc;
    u_char                             *p;
    ngx_tcp_session_t                  *s;
    ngx_msec_t                          timeout;
    ngx_uint_t                          pool_size;
    int                                 n;
    ngx_int_t                           rc;
    ngx_tcp_lua_socket_pool_item_t     *items, *item;
   // ngx_buf_t                          *b;

    n = lua_gettop(L);

    if (n < 1 || n > 3) {
        return luaL_error(L, "expecting 1 to 3 arguments "
                          "(including the object), but got %d", n);
    }

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_rawgeti(L, 1, SOCKET_KEY_INDEX);
    key.data = (u_char *) lua_tolstring(L, -1, &key.len);
    if (key.data == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "key not found");
        return 2;
    }

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    lua_pop(L, 1);

    /* stack: obj cache key */

    pc = &u->peer;
    c = pc->connection;

    if (u == NULL || c == NULL || u->ft_type || u->eof) {
        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }

    //b = &u->buffer;
    //b = u->buf_in;
    //
    //if (b->start && ngx_buf_size(b)) {
    //    lua_pushnil(L);
    //    lua_pushliteral(L, "unread data in buffer");
    //    return 2;
    //}

    if (c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "invalid connection");
        return 2;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        lua_pushnil(L);
        lua_pushliteral(L, "failed to handle read event");
        return 2;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "lua socket set keepalive: saving connection %p", c);

    dd("saving connection to key %s", lua_tostring(L, -1));

    lua_pushvalue(L, -1);
    lua_rawget(L, -3);
    spool = lua_touserdata(L, -1);
    lua_pop(L, 1);

    /* stack: obj timeout? size? cache key */

    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);

    if (spool == NULL) {
        /* create a new socket pool for the current peer key */

        if (n == 3) {
            pool_size = luaL_checkinteger(L, 3);

        } else {
            pool_size = lscf->pool_size;
        }

        if (pool_size == 0) {
            lua_pushnil(L);
            lua_pushliteral(L, "zero pool size");
            return 2;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket connection pool size: %ui", pool_size);

        size = sizeof(ngx_tcp_lua_socket_pool_t) + key.len
                + sizeof(ngx_tcp_lua_socket_pool_item_t)
                * pool_size;

        spool = lua_newuserdata(L, size);
        if (spool == NULL) {
            return luaL_error(L, "out of memory");
        }

        ngx_log_debug1(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "lua socket keepalive create connection pool for key "
                       "\"%s\"", lua_tostring(L, -2));

        lua_rawset(L, -3);

        lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);

        spool->conf = lmcf;
        spool->active_connections = 0;

        ngx_queue_init(&spool->cache);
        ngx_queue_init(&spool->free);

        p = ngx_copy(spool->key, key.data, key.len);
        *p++ = '\0';

        items = (ngx_tcp_lua_socket_pool_item_t *) p;

        for (i = 0; i < pool_size; i++) {
            ngx_queue_insert_head(&spool->free, &items[i].queue);
            items[i].socket_pool = spool;
        }
    }

    if (ngx_queue_empty(&spool->free)) {

        q = ngx_queue_last(&spool->cache);
        ngx_queue_remove(q);
        spool->active_connections--;

        item = ngx_queue_data(q, ngx_tcp_lua_socket_pool_item_t, queue);

        ngx_tcp_lua_socket_close_connection(item->connection);//ngx_close_connection(item->connection);

    } else {
        q = ngx_queue_head(&spool->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_tcp_lua_socket_pool_item_t, queue);
    }

    item->connection = c;
    ngx_queue_insert_head(&spool->cache, q);

    if (!u->reused) {
        spool->active_connections++;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "lua socket clear current socket connection");

    pc->connection = NULL;

#if 0
    if (u->cleanup) {
        //*u->cleanup = NULL;
        u->cleanup = NULL;
    }
#endif

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (n >= 2) {
        timeout = (ngx_msec_t) luaL_checkinteger(L, 2);

    } else {
        //timeout = lscf->keepalive_timeout;
        timeout = 60000;
    }

#if (NGX_DEBUG)
    if (timeout == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket keepalive timeout: unlimited");
    }
#endif

    if (timeout) {
        ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                       "lua socket keepalive timeout: %M ms", timeout);

        ngx_add_timer(c->read, timeout);
    }

    c->write->handler = ngx_tcp_lua_socket_keepalive_dummy_handler;
    c->read->handler = ngx_tcp_lua_socket_keepalive_rev_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
    item->reused = u->reused;

    //if (c->read->ready) {
        rc = ngx_tcp_lua_socket_keepalive_close_handler(c->read);
        if (rc != NGX_OK) {
            lua_pushnil(L);
            lua_pushliteral(L, "connection in dubious state");
            return 2;
        }
    //}


#if 1
    ngx_tcp_lua_socket_finalize(s, u);
#endif

    lua_pushinteger(L, 1);
    return 1;
}


static ngx_int_t
ngx_tcp_lua_get_keepalive_peer(ngx_tcp_session_t *s, lua_State *L,
    int key_index, ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_tcp_lua_socket_pool_item_t     *item;
    ngx_tcp_lua_socket_pool_t          *spool;
    ngx_queue_t                         *q;
    int                                  top;
    ngx_peer_connection_t               *pc;
    ngx_connection_t                    *c;

    top = lua_gettop(L);

    if (key_index < 0) {
        key_index = top + key_index + 1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket pool get keepalive peer");

    pc = &u->peer;

    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX); /* table */
    lua_pushvalue(L, key_index); /* key */
    lua_rawget(L, -2);

    spool = lua_touserdata(L, -1);
    if (spool == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "lua socket keepalive connection pool not found");
        lua_settop(L, top);
        return NGX_DECLINED;
    }

    u->socket_pool = spool;

    if (!ngx_queue_empty(&spool->cache)) {
        q = ngx_queue_head(&spool->cache);

        item = ngx_queue_data(q, ngx_tcp_lua_socket_pool_item_t, queue);
        c = item->connection;

        ngx_queue_remove(q);
        ngx_queue_insert_head(&spool->free, q);

        ngx_log_debug2(NGX_LOG_DEBUG_TCP, pc->log, 0,
                       "lua socket get keepalive peer: using connection %p, "
                       "fd:%d", c, c->fd);

        c->idle = 0;
        c->log = pc->log;
        c->read->log = pc->log;
        c->write->log = pc->log;
        c->data = u;

#if 1
        c->write->handler = ngx_tcp_lua_socket_tcp_handler;
        c->read->handler = ngx_tcp_lua_socket_tcp_handler;
#endif

        if (c->read->timer_set) {
            ngx_del_timer(c->read);
        }

        pc->connection = c;
        pc->cached = 1;

        u->reused = item->reused + 1;

#if 1
        u->write_event_handler = ngx_tcp_lua_socket_dummy_handler;
        u->read_event_handler = ngx_tcp_lua_socket_dummy_handler;
#endif

        if (u->cleanup == NULL) {
            u->cleanup = ngx_tcp_lua_socket_cleanup;
        }

        lua_settop(L, top);

        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, pc->log, 0,
                   "lua socket keepalive: connection pool empty");

    lua_settop(L, top);

    return NGX_DECLINED;
}


static void
ngx_tcp_lua_socket_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_tcp_lua_socket_keepalive_rev_handler(ngx_event_t *ev)
{
    (void) ngx_tcp_lua_socket_keepalive_close_handler(ev);
}


static ngx_int_t
ngx_tcp_lua_socket_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_tcp_lua_socket_pool_item_t     *item;
    ngx_tcp_lua_socket_pool_t          *spool;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    c = ev->data;

    if (c->close) {
        goto close;
    }

    if (c->read->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                       "lua socket keepalive max idle timeout");

        goto close;
    }

    dd("read event ready: %d", (int) c->read->ready);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, ev->log, 0,
                   "lua socket keepalive close handler check stale events");

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        /* stale event */

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return NGX_OK;
    }

close:

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "lua socket keepalive close handler: fd:%d", c->fd);

    item = c->data;
    spool = item->socket_pool;

    ngx_tcp_lua_socket_close_connection(c);//ngx_close_connection(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&spool->free, &item->queue);
    spool->active_connections--;

    dd("keepalive: active connections: %u",
            (unsigned) spool->active_connections);

    if (spool->active_connections == 0) {
        ngx_tcp_lua_socket_free_pool(ev->log, spool);
    }

    return NGX_DECLINED;
}


static void
ngx_tcp_lua_socket_free_pool(ngx_log_t *log, ngx_tcp_lua_socket_pool_t *spool)
{
    lua_State                           *L;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, log, 0,
                   "lua socket keepalive: free connection pool for \"%s\"",
                   spool->key);

    L = spool->conf->lua;

    lua_pushlightuserdata(L, &ngx_tcp_lua_socket_pool_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    lua_pushstring(L, (char *) spool->key);
    lua_pushnil(L);
    lua_rawset(L, -3);
    lua_pop(L, 1);
}


static int
ngx_tcp_lua_socket_upstream_destroy(lua_State *L)
{
    ngx_tcp_lua_socket_upstream_t          *u;

    dd("upstream destroy triggered by Lua GC");

    u = lua_touserdata(L, 1);
    if (u == NULL) {
        return 0;
    }

    if (u->cleanup) {
        //ngx_tcp_lua_socket_cleanup(u); /* it will clear u->cleanup */
        u->cleanup(u); /* it will clear u->cleanup */
    }

    return 0;
}


static void
ngx_tcp_lua_socket_dummy_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket dummy handler");
}

static void
ngx_tcp_lua_socket_close_connection(ngx_connection_t *c)
{
#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        (void) ngx_ssl_shutdown(c);
    }

#endif

    if (c->pool) {
        ngx_destroy_pool(c->pool);
        c->pool = NULL;
    }

    ngx_close_connection(c);
}


#if (NGX_TCP_SSL)

static int
ngx_tcp_lua_socket_tcp_sslhandshake(lua_State *L)
{
    ngx_tcp_session_t                  *s;
    ngx_tcp_lua_socket_upstream_t      *u;
    ngx_int_t                           rc;
    ngx_tcp_lua_ctx_t                  *ctx;
    ngx_tcp_lua_ssl_ctx_t              *ssl_ctx;
    ngx_connection_t                   *c;
    int                                 n,top;

    n = lua_gettop(L);
    //sslhandshake(sslctx,verify?)
    if (n != 2 && n != 3) {
        return luaL_error(L, "expecting 2 or 3 arguments "
                          "(including the object), but got %d", n);
    }
    
    s = ngx_tcp_lua_get_session(L);
    if (s == NULL) { //init_by_lua no session
        return luaL_error(L, "no session found");
    }

    ctx = s->ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "lua socket calling sslhandshake() method");

    luaL_checktype(L, 1, LUA_TTABLE);

    lua_rawgeti(L, 1, SOCKET_CTX_INDEX);
    u = lua_touserdata(L, -1);
    //lua_pop(L,1);
    
    if (u == NULL || u->peer.connection == NULL || u->ft_type || u->eof) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "attempt to sslhandshake on a closed socket: u:%p, c:%p, "
                      "ft:%ui eof:%ud",
                      u, u ? u->peer.connection : NULL, u ? u->ft_type : 0,
                      u ? u->eof : 0);

        lua_pushnil(L);
        lua_pushliteral(L, "closed");
        return 2;
    }
    
    ssl_ctx = lua_touserdata(L, 2);
    if (NULL == ssl_ctx || NULL == ssl_ctx->ssl.ctx) {
        return luaL_argerror(L, 2, "expecting ssl_ctx by new_ssl_ctx parameter!");
    }
    
    if (n == 3) {
        u->ssl_verify = lua_toboolean(L, 3);
    }
    else {
        u->ssl_verify = 0;
    }

    c = u->peer.connection;

    if (c->ssl && c->ssl->handshaked) {
        lua_pushinteger(L, 1);
        return 1;
    }

    /* we need separate pool here to be able to cache SSL connections */
    if (c->pool == NULL) {
        c->pool = ngx_create_pool(128, c->log);
        if (c->pool == NULL) {
            return luaL_error(L, "out of memory");
        }
    }

    if (ngx_ssl_create_connection(&ssl_ctx->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        lua_pushnil(L);
        lua_pushliteral(L, "failed to create ssl connection");
        return 2;
    }

    rc = ngx_ssl_handshake(c);

    dd("ngx_ssl_handshake returned %d", (int) rc);

    if (rc == NGX_AGAIN) {

        if (c->write->timer_set) {
            ngx_del_timer(c->write);
        }

        ngx_add_timer(c->read, u->connect_timeout);

        c->ssl->handler = ngx_tcp_lua_ssl_handshake_handler;

        /* set s->write_event_handler to go on session process */
        s->write_event_handler = ngx_tcp_lua_wev_handler;
    
        u->waiting = 1;
        u->prepare_retvals = ngx_tcp_lua_ssl_handshake_retval_handler;

        ctx->data = u;

        return lua_yield(L, 0);    
    }
    
    //NGX_OK or NGX_ERROR
    top = lua_gettop(L);
    ngx_tcp_lua_ssl_handshake_handler(c);
    return lua_gettop(L) - top;
}


static void
ngx_tcp_lua_ssl_handshake_handler(ngx_connection_t* c)
{
    ngx_int_t                      rc;
    ngx_tcp_lua_ctx_t             *lctx;
    lua_State                     *L;
    const char                    *err;
    int                            ssl_verify_failed = 0;
    ngx_tcp_session_t              *s;
    ngx_tcp_lua_socket_upstream_t  *u;

    u = c->data;
    s = u->session;
    
    lctx = s->ctx;
    L = lctx->co;

    c->write->handler = ngx_tcp_lua_socket_tcp_handler;
    c->read->handler = ngx_tcp_lua_socket_tcp_handler;
    
    //timedout will close connection
    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                     "lua socket handshake timed out");

        ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_TIMEOUT);
        return;
    }
    
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    
    if (c->ssl->handshaked) {
        if (u->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                lua_pushnil(L);
                err = lua_pushfstring(L, "%d: %s", (int) rc,
                                      X509_verify_cert_error_string(rc));

                ngx_log_debug1(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                        "lua ssl certificate verify error: (%s)", err);

                ssl_verify_failed = 1;
                goto failed;
            }
        }
        //no need ssl_verify or X509_V_OK
        if (u->waiting) {
            return ngx_tcp_lua_socket_handle_success(s, u);
        }
        
        lua_pushinteger(L, 1);
        return;
    }
    
failed: 
    if (u->waiting) {
        return ngx_tcp_lua_socket_handle_error(s, u, NGX_TCP_LUA_SOCKET_FT_SSL);
    }

    if (ssl_verify_failed == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "handshake failed");
    }
    return;
}


static int
ngx_tcp_lua_ssl_handshake_retval_handler(ngx_tcp_session_t *s,
    ngx_tcp_lua_socket_upstream_t *u, lua_State *L)
{
    if (u->ft_type) {
        return ngx_tcp_lua_socket_error_retval_handler(s, u, L);
    }
    
    lua_pushinteger(L, 1);
    return 1;
}

#endif  /* NGX_TCP_SSL */
