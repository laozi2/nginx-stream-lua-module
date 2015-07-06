
//#ifndef DDEBUG
//#define DDEBUG 1
//#endif

#include "ngx_tcp_lua_common.h"
#include "ngx_tcp_lua_cache.h"
#include "ngx_tcp_lua_util.h"
#include "ngx_tcp_lua_session.h"
#include "ngx_tcp_lua_shdict.h"
#include "ngx_tcp_lua_initby.h"
#include "ngx_tcp_lua_req.h"

static void ngx_tcp_lua_init_connection_handler(ngx_event_t *rev);
static ngx_int_t ngx_tcp_lua_init_session(ngx_tcp_session_t* s);
static void ngx_tcp_lua_start_session(ngx_tcp_session_t *s); 

void *ngx_tcp_lua_create_main_conf(ngx_conf_t *cf);
char *ngx_tcp_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_tcp_lua_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_lua_merge_srv_conf(ngx_conf_t *cf, void *parent,
            void *child);
char *ngx_tcp_lua_package_cpath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_tcp_lua_package_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_tcp_lua_process_by_lua_file(ngx_conf_t *cf, 
            ngx_command_t *cmd, void *conf);
char * ngx_tcp_lua_process_by_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_tcp_lua_init(ngx_conf_t *cf);
char *ngx_tcp_lua_init_vm(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf);
static void ngx_tcp_lua_cleanup_vm(void *data);
u_char *ngx_tcp_lua_rebase_path(ngx_pool_t *pool, u_char *src, size_t len);
ngx_int_t ngx_tcp_lua_process_by_chunk(lua_State *L, ngx_tcp_session_t *s);
static char *ngx_tcp_lua_lowat_check(ngx_conf_t *cf, void *post, void *data);
char *ngx_tcp_lua_code_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_tcp_lua_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *ngx_tcp_lua_init_by_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_tcp_protocol_t  ngx_tcp_lua_protocol = {

    ngx_string("tcp_lua"),
//   { 0, 0, 0, 0 },
//   NGX_TCP_LUA_PROTOCOL,

    ngx_tcp_lua_init_connection_handler,
    NGX_TCP_PROTOCOL_UNSET
};


static ngx_conf_post_t  ngx_tcp_lua_lowat_post =
    { ngx_tcp_lua_lowat_check };


static ngx_command_t  ngx_tcp_lua_commands[] = {

    { ngx_string("lua_package_cpath"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_package_cpath,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_package_path"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_package_path,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_code_cache"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_tcp_lua_code_cache,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, enable_code_cache),
      NULL },

    { ngx_string("process_by_lua_file"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_process_by_lua_file,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, lua_src),
      NULL },

    { ngx_string("process_by_lua"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_process_by_lua,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, lua_src),
      NULL },

    { ngx_string("lua_socket_connect_timeout"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("lua_socket_send_lowat"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, send_lowat),
      &ngx_tcp_lua_lowat_post },

    { ngx_string("lua_socket_pool_size"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, pool_size),
      NULL },

    { ngx_string("lua_check_client_abort"),
      NGX_TCP_MAIN_CONF|NGX_TCP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_TCP_SRV_CONF_OFFSET,
      offsetof(ngx_tcp_lua_srv_conf_t, check_client_abort),
      NULL },

    { ngx_string("lua_shared_dict"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_tcp_lua_shared_dict,
      0,
      0,
      NULL },

    { ngx_string("init_by_lua"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_init_by_lua,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_tcp_lua_init_by_inline },

    { ngx_string("init_by_lua_file"),
      NGX_TCP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_tcp_lua_init_by_lua,
      NGX_TCP_MAIN_CONF_OFFSET,
      0,
      (void *) ngx_tcp_lua_init_by_file },

    ngx_null_command
};

static ngx_tcp_module_t  ngx_tcp_lua_module_ctx = {
    &ngx_tcp_lua_protocol,              /* protocol */
    ngx_tcp_lua_init,                   /*  postconfiguration */

    ngx_tcp_lua_create_main_conf,       /*  create main configuration */
    ngx_tcp_lua_init_main_conf,         /*  init main configuration */

    ngx_tcp_lua_create_srv_conf,            /* create server configuration */
    ngx_tcp_lua_merge_srv_conf              /* merge server configuration */
};


ngx_module_t  ngx_tcp_lua_module = {
    NGX_MODULE_V1,
    &ngx_tcp_lua_module_ctx,             /* module context */
    ngx_tcp_lua_commands,                /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


//-------handlers-----------
/*readable, close, timedout*/
static void
ngx_tcp_lua_init_connection_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    
    c = rev->data;
    s = c->data;
    
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_tcp_init_connection_handler");
    
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_close_connection(c);
        return;
    }

    if (c->close) {
        ngx_tcp_close_connection(c);
        return;
    }
    
    ngx_reusable_connection(c, 0);
    
    if(ngx_tcp_lua_init_session(s) != NGX_OK){
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->action = "ngx_tcp_lua_start_session";

    s->read_event_handler = ngx_tcp_lua_check_client_abort_handler;
    s->write_event_handler = ngx_tcp_session_empty_handler;
    rev->handler= ngx_tcp_session_handler;
    c->write->handler= ngx_tcp_session_handler;

    if (rev->timer_set) {
        ngx_del_timer(rev);
    }
    
    ngx_tcp_lua_start_session(s);
}

static ngx_int_t
ngx_tcp_lua_init_session(ngx_tcp_session_t* s)
{
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_connection_t         *c;
    
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    c = s->connection;
    
    //assert(s->pool == NULL);
    s->pool = ngx_create_pool(cscf->session_pool_size, c->log);
    if (NULL == s->pool) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                    "ngx_tcp_lua_init_session : ngx_create_pool failed");
        return NGX_ERROR;
    }

    //assert(s->ctx == NULL);
    s->ctx = ngx_pcalloc(c->pool, sizeof(ngx_tcp_lua_ctx_t)); //s->pool
    if(NULL == s->ctx){
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "ngx_tcp_lua_init_session : ngx_pcalloc failed");
        
        ngx_destroy_pool(s->pool);

        return NGX_ERROR;
    }
    
    //set by ngx_pcalloc

    if (ngx_tcp_lua_init_light_session(s) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                        "ngx_tcp_lua_init_light_session failed");

        ngx_destroy_pool(s->pool);
        
        return NGX_ERROR;
    }
          
    return NGX_OK;
}


static void 
ngx_tcp_lua_start_session(ngx_tcp_session_t *s) 
{
    ngx_connection_t            *c;
    ngx_tcp_lua_srv_conf_t          *lscf;
    ngx_tcp_lua_main_conf_t     *lmcf;
    
    lua_State                       *L;
    ngx_int_t                        rc;
    u_char                          *script_path;
    char                            *err;

    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp lua init and load src");

    lscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_lua_module);
    lmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_lua_module);    
    L = lmcf->lua;

    if (lscf->lua_src_inline) {
        /*  load Lua inline script (w/ cache) sp = 1 */
        rc = ngx_tcp_lua_cache_loadbuffer(L, lscf->lua_src.data,
                lscf->lua_src.len, lscf->lua_src_key,
                "process_by_lua", &err, lscf->enable_code_cache ? 1 : 0); 
        
        if (rc != NGX_OK) {
            if (err == NULL) {
                err = "unknown error";
            }
        
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "failed to load Lua inlined code: %s", err);

            ngx_tcp_lua_close_session(s);
        
            return;
        }
    } else {
        /*  load Lua script file (w/ cache)        sp = 1 */
        script_path = ngx_tcp_lua_rebase_path(s->pool, lscf->lua_src.data,
                lscf->lua_src.len);
        
        if (script_path == NULL) {

            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "failed to load Lua inlined code: script_path is NULL");

            ngx_tcp_lua_close_session(s);
            return;
        }
        
        rc = ngx_tcp_lua_cache_loadfile(L, script_path, lscf->lua_src_key,
                &err, lscf->enable_code_cache ? 1 : 0);

        if (rc != NGX_OK) {
            if (err == NULL) {
                err = "unknown error";
            }

            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "failed to load Lua code: %s", err);

            ngx_tcp_lua_close_session(s);

            return;
        }
    }
    
    /*  make sure we have a valid code chunk */
    assert(lua_isfunction(L, -1));
    
    c->log->action = "ngx_tcp_lua_process_by_chunk";

    rc = ngx_tcp_lua_process_by_chunk(L, s);
    
    //rc will be NGX_OK NGX_ERROR NGX_AGAIN
    if (rc == NGX_ERROR || rc == NGX_OK) {
        ngx_tcp_lua_close_session(s);
        return;
    }

    //NGX_AGAIN
}

void *
ngx_tcp_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_lua_main_conf_t    *lmcf;

    lmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_lua_main_conf_t));
    if (lmcf == NULL) {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      lmcf->lua = NULL;
     *      lmcf->lua_path = { 0, NULL };
     *      lmcf->lua_cpath = { 0, NULL };
     *      lmcf->init_handler = NULL;
     *      lmcf->init_src = { 0, NULL };
     *      lmcf->shm_zones = NULL;
     *      lmcf->shm_zones_inited = 0;
     *      lmcf->requires_shm = 0;
     */

    lmcf->pool = cf->pool;

    return lmcf;
}


char *
ngx_tcp_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static void *
ngx_tcp_lua_create_srv_conf(ngx_conf_t *cf) 
{
    ngx_tcp_lua_srv_conf_t  *lscf;

    lscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_lua_srv_conf_t));
    if (lscf == NULL) {
        return NULL;
    }

    lscf->enable_code_cache = NGX_CONF_UNSET;

    lscf->send_lowat = NGX_CONF_UNSET_SIZE;
    lscf->pool_size = NGX_CONF_UNSET_UINT;
    lscf->check_client_abort = NGX_CONF_UNSET;

    //lscf->read_timeout = NGX_CONF_UNSET_UINT;
    //lscf->send_timeout = NGX_CONF_UNSET_UINT;
    lscf->connect_timeout = NGX_CONF_UNSET_UINT;

    lscf->lua_src_inline = 0;

    return lscf;
}


static char *
ngx_tcp_lua_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) 
{
    ngx_tcp_lua_srv_conf_t *prev = parent;
    ngx_tcp_lua_srv_conf_t *conf = child;

    if (conf->lua_src.len == 0) {
        conf->lua_src = prev->lua_src;
        conf->lua_src_key = prev->lua_src_key;
    }
    
    ngx_conf_merge_value(conf->enable_code_cache, prev->enable_code_cache, 1);

    ngx_conf_merge_size_value(conf->send_lowat,
                              prev->send_lowat, 0);

    ngx_conf_merge_msec_value(conf->connect_timeout,
                              prev->connect_timeout, 60000);

//    ngx_conf_merge_msec_value(conf->send_timeout,
//                              prev->send_timeout, 60000);
//
//    ngx_conf_merge_msec_value(conf->read_timeout,
//                              prev->read_timeout, 60000);
                             
    ngx_conf_merge_uint_value(conf->pool_size, prev->pool_size, 30);

    ngx_conf_merge_value(conf->check_client_abort, prev->check_client_abort, 0);

    return NGX_CONF_OK;
}


char *
ngx_tcp_lua_package_cpath(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_lua_main_conf_t  *lmcf = conf;
    ngx_str_t                *value;

    if (lmcf->lua_cpath.len != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lmcf->lua_cpath.len = value[1].len;
    lmcf->lua_cpath.data = value[1].data;

    return NGX_CONF_OK;
}


char *
ngx_tcp_lua_package_path(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_lua_main_conf_t *lmcf = conf;
    ngx_str_t                *value;

    if (lmcf->lua_path.len != 0) {
        return "is duplicate";
    }

    value = cf->args->elts;

    lmcf->lua_path.len = value[1].len;
    lmcf->lua_path.data = value[1].data;

    return NGX_CONF_OK;
}


static char *
ngx_tcp_lua_process_by_lua_file(ngx_conf_t *cf, 
            ngx_command_t *cmd, void *conf)
{
    char  *p = conf;

    ngx_str_t        *field, *value;

    field = (ngx_str_t *) (p + cmd->offset);

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[1];

    return NGX_CONF_OK;
}


char *
ngx_tcp_lua_process_by_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                      *p;
    ngx_str_t                   *value;
    ngx_tcp_lua_srv_conf_t     *lscf = conf;

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                "Invalid location config: no runnable Lua code");
        return NGX_CONF_ERROR;
    }
    
    lscf->lua_src = value[1];

    /* Don't eval nginx variables for inline lua code */

    p = ngx_palloc(cf->pool, NGX_TCP_LUA_INLINE_KEY_LEN + 1);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    lscf->lua_src_key = p;

    p = ngx_copy(p, NGX_TCP_LUA_INLINE_TAG, NGX_TCP_LUA_INLINE_TAG_LEN);
    p = ngx_tcp_lua_digest_hex(p, value[1].data, value[1].len);
    *p = '\0';

    lscf->lua_src_inline = 1;
    
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_tcp_lua_init(ngx_conf_t *cf)
{
    ngx_tcp_lua_main_conf_t   *lmcf;
    //ngx_tcp_lua_srv_conf_t    *lscf;
    //ngx_tcp_core_srv_conf_t   *cscf;

    if(ngx_tcp_lua_protocol.set == NGX_TCP_PROTOCOL_UNSET){
        return NGX_OK;
    }

    //cscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_core_module);
    //lscf = ngx_tcp_conf_get_module_srv_conf(cf, ngx_tcp_lua_module);
    
    //lscf->read_timeout = cscf->read_timeout;
    //lscf->send_timeout = cscf->send_timeout;

    lmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_lua_module);

    if (lmcf->lua == NULL) {
    
        if (ngx_tcp_lua_init_vm(cf, lmcf) != NGX_CONF_OK) {
            ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                               "failed to initialize Lua VM");
            return NGX_ERROR;
        }

    }

    if (!lmcf->requires_shm && lmcf->init_handler) {
        if (lmcf->init_handler(cf->log, lmcf, lmcf->lua) != NGX_OK) {
            /* an error happened */
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


char *
ngx_tcp_lua_init_vm(ngx_conf_t *cf, ngx_tcp_lua_main_conf_t *lmcf)
{
    ngx_pool_cleanup_t              *cln;

    /* add new cleanup handler to config mem pool */
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    /* create new Lua VM instance */
    lmcf->lua = ngx_tcp_lua_new_state(cf, lmcf);
    if (lmcf->lua == NULL) {
        return NGX_CONF_ERROR;
    }

    /* register cleanup handler for Lua VM */
    cln->handler = ngx_tcp_lua_cleanup_vm;
    cln->data = lmcf->lua;

    return NGX_CONF_OK;
}


static void
ngx_tcp_lua_cleanup_vm(void *data)
{
    lua_State *L = data;

    if (L != NULL) {
        lua_close(L);
    }
}


u_char *
ngx_tcp_lua_rebase_path(ngx_pool_t *pool, u_char *src, size_t len)
{
    u_char            *p, *dst;

    if (len == 0) {
        return NULL;
    }

    if (src[0] == '/') {
        /* being an absolute path already */
        dst = ngx_palloc(pool, len + 1);
        if (dst == NULL) {
            return NULL;
        }

        p = ngx_copy(dst, src, len);

        *p = '\0';

        return dst;
    }

    dst = ngx_palloc(pool, ngx_cycle->prefix.len + len + 1);
    if (dst == NULL) {
        return NULL;
    }

    p = ngx_copy(dst, ngx_cycle->prefix.data, ngx_cycle->prefix.len);
    p = ngx_copy(p, src, len);

    *p = '\0';

    return dst;
}


ngx_int_t
ngx_tcp_lua_process_by_chunk(lua_State *L, ngx_tcp_session_t *s)
{
    int                      cc_ref;
    lua_State               *cc;
    ngx_tcp_lua_ctx_t      *ctx;
    ngx_tcp_cleanup_t      *cln;

    dd("content by chunk");

    ctx = s->ctx; //ctx impossible NULL

    ctx->cc_ref = LUA_NOREF;

    /*  {{{ new coroutine to handle request */
    cc = ngx_tcp_lua_new_thread(s, L, &cc_ref);

    if (cc == NULL) {
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                "(lua-content-by-chunk) failed to create new coroutine "
                "to handle request");

        return NGX_ERROR;
    }

    /*  move code closure to new coroutine */
    lua_xmove(L, cc, 1);

    /*  set closure's env table to new coroutine's globals table */
    lua_pushvalue(cc, LUA_GLOBALSINDEX);
    lua_setfenv(cc, -2);

    /*  save nginx request in coroutine globals table */
    lua_pushlightuserdata(cc, &ngx_tcp_lua_request_key);
    lua_pushlightuserdata(cc, s);
    lua_rawset(cc, LUA_GLOBALSINDEX);
    /*  }}} */

    ctx->co = cc;
    ctx->cc_ref = cc_ref;

    /*  {{{ register request cleanup hooks */
    //if (ctx->cleanup == NULL) {
        cln = ngx_tcp_cleanup_add(s, 0 , s->connection->pool);
        if (cln == NULL) {
            return NGX_ERROR;
        }

        cln->handler = ngx_tcp_lua_request_cleanup;
        cln->data = s;
    //}
    /*  }}} */

    return ngx_tcp_lua_run_thread(L, s, ctx, 0);

}


static char *
ngx_tcp_lua_lowat_check(ngx_conf_t *cf, void *post, void *data)
{
#if (NGX_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= ngx_freebsd_net_inet_tcp_sendspace) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"fastcgi_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           ngx_freebsd_net_inet_tcp_sendspace);

        return NGX_CONF_ERROR;
    }

#elif !(NGX_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"fastcgi_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return NGX_CONF_OK;
}


char *
ngx_tcp_lua_code_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char             *p = conf;
    ngx_flag_t       *fp;
    char             *ret;

    ret = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (ret != NGX_CONF_OK) {
        return ret;
    }

    fp = (ngx_flag_t *) (p + cmd->offset);

    if (!*fp) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                "lua_code_cache is off; this will hurt performance");
    }

    return NGX_CONF_OK;
}

char *
ngx_tcp_lua_shared_dict(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_tcp_lua_main_conf_t    *lmcf = conf;

    ngx_str_t                  *value, name;
    ngx_shm_zone_t             *zone;
    ngx_shm_zone_t            **zp;
    ngx_tcp_lua_shdict_ctx_t  *ctx;
    ssize_t                     size;

    if (lmcf->shm_zones == NULL) {
        lmcf->shm_zones = ngx_palloc(cf->pool, sizeof(ngx_array_t));
        if (lmcf->shm_zones == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_array_init(lmcf->shm_zones, cf->pool, 2,
                           sizeof(ngx_shm_zone_t *))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    ctx = NULL;

    if (value[1].len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua shared dict name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name = value[1];

    size = ngx_parse_size(&value[2]);

    if (size <= 8191) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid lua shared dict size \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_lua_shdict_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->name = name;
    ctx->main_conf = lmcf;
    ctx->log = &cf->cycle->new_log;

    zone = ngx_shared_memory_add(cf, &name, (size_t) size,
                                 &ngx_tcp_lua_module);
    if (zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (zone->data) {
        ctx = zone->data;

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "lua_shared_dict \"%V\" is already defined as "
                           "\"%V\"", &name, &ctx->name);
        return NGX_CONF_ERROR;
    }

    zone->init = ngx_tcp_lua_shdict_init_zone;
    zone->data = ctx;

    zp = ngx_array_push(lmcf->shm_zones);
    if (zp == NULL) {
        return NGX_CONF_ERROR;
    }

    *zp = zone;

    lmcf->requires_shm = 1;

    return NGX_CONF_OK;
}

char *
ngx_tcp_lua_init_by_lua(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                      *name;
    ngx_str_t                   *value;
    ngx_tcp_lua_main_conf_t     *lmcf = conf;

    dd("enter");

    /*  must specifiy a content handler */
    if (cmd->post == NULL) {
        return NGX_CONF_ERROR;
    }

    if (lmcf->init_handler) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len == 0) {
        /*  Oops...Invalid location conf */
        ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                           "invalid location config: no runnable Lua code");
        return NGX_CONF_ERROR;
    }

    lmcf->init_handler = (ngx_tcp_lua_conf_handler_pt) cmd->post;

    if (cmd->post == ngx_tcp_lua_init_by_file) {
        name = ngx_tcp_lua_rebase_path(cf->pool, value[1].data,
                                        value[1].len);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }

        lmcf->init_src.data = name;
        lmcf->init_src.len = ngx_strlen(name);

    } else {
        lmcf->init_src = value[1];
    }

    return NGX_CONF_OK;
}


