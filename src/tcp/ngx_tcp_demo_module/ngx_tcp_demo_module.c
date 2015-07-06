
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>

#define NGX_TCP_DEMO_PROTOCOL  0
#define NGX_TCP_DEMO_HEADER_LEN 4
#define NGX_TCP_DEMO_MIN_LEN    4  //4head



typedef void (*ngx_tcp_demo_post_handler_pt)(ngx_tcp_session_t *r);

typedef struct {
    size_t                         body_len;
    ngx_buf_t                     *buffer_in;//only for buffer client data
    ngx_buf_t                     *buffer_out;
    ngx_tcp_demo_post_handler_pt   post_handler;
}ngx_tcp_demo_session_ctx_t;

typedef struct {
    ngx_uint_t    signature;//no meaning
} ngx_tcp_demo_main_conf_t;

typedef struct {
    ngx_str_t    echo_str;
} ngx_tcp_demo_srv_conf_t;


static ngx_int_t ngx_tcp_demoe_postconfiguration(ngx_conf_t *cf);
static void *ngx_tcp_demo_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_demo_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_tcp_demo_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_demo_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_tcp_demo_echo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void ngx_tcp_demo_init_connection_handler(ngx_event_t *rev);
static void ngx_tcp_demo_process_header_handler(ngx_event_t *rev);
static void ngx_tcp_demo_process_body_handler(ngx_event_t *rev);

static void ngx_tcp_demo_process_session(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_demo_init_session(ngx_tcp_session_t* s);

//static void ngx_tcp_demo_read_handler(ngx_event_t *wev);
static void ngx_tcp_demo_send_handler(ngx_event_t *wev);
static void ngx_tcp_demo_send(ngx_tcp_session_t* s,ngx_tcp_demo_post_handler_pt post_handler);

static void ngx_tcp_demo_close_session(ngx_tcp_session_t *s);
static void ngx_tcp_demo_reset_session(ngx_tcp_session_t *s);
static void ngx_tcp_demo_finalize_session(ngx_tcp_session_t* s);
static void ngx_tcp_demo_keepalive_handler(ngx_event_t *rev);
static void ngx_tcp_demo_log_session(ngx_tcp_session_t* s);


static ngx_tcp_protocol_t  ngx_tcp_demo_protocol = {
    ngx_string("demo"),
//    { 110, 0, 0, 0 },
//    NGX_TCP_DEMO_PROTOCOL,

    ngx_tcp_demo_init_connection_handler,
    NGX_TCP_PROTOCOL_UNSET
};

static ngx_command_t  ngx_tcp_demo_commands[] = {

  { ngx_string("demo_echo"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_demo_echo,
      NGX_TCP_SRV_CONF_OFFSET,
      0,
      NULL },
    
    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_demo_module_ctx = {
    &ngx_tcp_demo_protocol,               /* protocol */
    ngx_tcp_demoe_postconfiguration,      /* postconfiguration */

    ngx_tcp_demo_create_main_conf,        /* create main configuration */
    ngx_tcp_demo_init_main_conf,          /* init main configuration */

    ngx_tcp_demo_create_srv_conf,         /* create server configuration */
    ngx_tcp_demo_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_tcp_demo_module = {
    NGX_MODULE_V1,
    &ngx_tcp_demo_module_ctx,             /* module context */
    ngx_tcp_demo_commands,                /* module directives */
    NGX_TCP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

//--------------configure--------------------

static ngx_int_t
ngx_tcp_demoe_postconfiguration(ngx_conf_t *cf)
{
    return NGX_OK;
}

static void*
ngx_tcp_demo_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_demo_main_conf_t   *pdmcf;

    pdmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_demo_main_conf_t));
    if (pdmcf == NULL) {
        return NULL;
    }
    
    pdmcf->signature = NGX_CONF_UNSET_UINT;
    
    return pdmcf;
}

static char *
ngx_tcp_demo_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}

static void *
ngx_tcp_demo_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_demo_srv_conf_t  *pscf;

    pscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_demo_srv_conf_t));
    if (pscf == NULL) {
        return NULL;
    }
    
    ngx_str_null(&pscf->echo_str);

    return pscf;
}

static char *
ngx_tcp_demo_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
//    ngx_tcp_demo_srv_conf_t *prev = parent;
//    ngx_tcp_demo_srv_conf_t *conf = child;

    return NGX_CONF_OK;
}

static char *
ngx_tcp_demo_echo(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_tcp_demo_srv_conf_t         *pdscf;
    ngx_str_t                       *value;
    
    pdscf = conf;
    value = cf->args->elts;

    pdscf->echo_str.data = value[1].data;
    pdscf->echo_str.len = value[1].len;

    return NGX_CONF_OK;
}


//-----------------handler--------------------------
static void
ngx_tcp_demo_init_connection_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    
    c = rev->data;
    s = c->data;
    
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_demo_init_connection_handler");
    
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
    
    size = NGX_TCP_DEMO_HEADER_LEN;
    
    b = c->buffer;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_tcp_close_connection(c);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
        if (c->listening->deferred_accept)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out in deferred accept");
            ngx_tcp_close_connection(c);
            return;
        }
#endif

        if (!rev->timer_set) {
            ngx_add_timer(rev, c->listening->post_accept_timeout);
            ngx_reusable_connection(c, 1);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_close_connection(c);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_tcp_close_connection(c);
        return;
    }

    b->last += n;


    ngx_reusable_connection(c, 0);
    
    if(ngx_tcp_demo_init_session(s) != NGX_OK){
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->action = "reading client header";
    
    c->write->handler = ngx_tcp_empty_handler;
    rev->handler = ngx_tcp_demo_process_header_handler;
    ngx_tcp_demo_process_header_handler(rev);
    
}

static ngx_int_t
ngx_tcp_demo_init_session(ngx_tcp_session_t* s)
{
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_pool_t               *pool;
    ngx_connection_t         *c;
    ngx_time_t               *tp;
    ngx_tcp_demo_session_ctx_t *session_ctx;
    
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    c = s->connection;

    c->requests++;
    
    pool = s->pool;
    if(NULL == pool){
        pool = ngx_create_pool(cscf->session_pool_size, c->log);
        if (NULL == pool) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                         "ngx_demo_init_session : ngx_create_pool failed");
            return NGX_ERROR;
        }
            
        s->pool = pool;
    }
    
    session_ctx = ngx_pcalloc(s->pool, sizeof(ngx_tcp_demo_session_ctx_t));
    if(NULL == session_ctx){
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                         "ngx_demo_init_session : ngx_pcalloc failed");
        
        ngx_destroy_pool(s->pool);
        
        return NGX_ERROR;
    }
    
    
    //set by ngx_pcalloc
    //session_ctx->buffer_in = NULL;
    //session_ctx->buffer_out = NULL;
    //session_ctx->post_handler = NULL;
    
    s->ctx = session_ctx;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, 1);
    s->stat_reading = 1;
    (void) ngx_atomic_fetch_add(ngx_stat_requests, 1);
#endif

    tp = ngx_timeofday();
    s->start_sec = tp->sec;
    s->start_msec = tp->msec;
    
    return NGX_OK;
}

static void
ngx_tcp_demo_process_header_handler(ngx_event_t *rev)
{
    size_t                       size;
    ssize_t                      n;
    ngx_buf_t                   *b;
    ngx_connection_t            *c;
    ngx_tcp_session_t           *s;
    ngx_tcp_demo_session_ctx_t  *ctx;
    ngx_tcp_core_srv_conf_t     *cscf;
    
    c = rev->data;
    s = c->data;
    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_demo_process_header_handler");
    
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    b = c->buffer;
    size = b->last - b->pos;
    
    if(size < NGX_TCP_DEMO_HEADER_LEN){
        n = c->recv(c, b->last, NGX_TCP_DEMO_HEADER_LEN - size);
        
        if(n == NGX_AGAIN){
            if (!rev->timer_set) {
                ngx_add_timer(rev, cscf->read_timeout);
            }
        
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_demo_close_session(s);
                return;
            }
            return;
        }
        
        if (n == NGX_ERROR) {
            ngx_tcp_demo_close_session(s);
            return;
        }
        
        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed connection");
            ngx_tcp_demo_close_session(s);
            return;
        }
        
        b->last += n;
        
        if(b->last - b->pos < NGX_TCP_DEMO_HEADER_LEN){
            if (!rev->timer_set) {
                ngx_add_timer(rev, cscf->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_demo_close_session(s);
                return;
            }
            return;
        }
    }

    size = (size_t)ntohl(*(uint32_t*)(b->pos));

    if(size < NGX_TCP_DEMO_MIN_LEN || size > cscf->client_max_body_size){ //4
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "body_len %z", size);
        ngx_tcp_demo_close_session(s);
        return;
    }

    ctx = s->ctx;
    ctx->body_len = size;
        
    b = ngx_create_temp_buf(s->pool, size);
    if(NULL == b){
        ngx_tcp_demo_close_session(s);
        return;
    }
        
    ctx->buffer_in = b;
    
    c->log->action = "reading client body";
    
    rev->handler = ngx_tcp_demo_process_body_handler;
    ngx_tcp_demo_process_body_handler(rev);
}

static void 
ngx_tcp_demo_process_body_handler(ngx_event_t *rev)
{
    ssize_t                       n;
    ngx_buf_t                    *b;
    ngx_connection_t             *c;
    ngx_tcp_session_t            *s;
    ngx_tcp_demo_session_ctx_t   *ctx;
    ngx_tcp_core_srv_conf_t      *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_demo_process_body_handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    ctx = s->ctx;
    b = ctx->buffer_in;
    
    if(b->last - b->pos < (signed)ctx->body_len){
        n = c->recv(c, b->last, b->end - b->last);
        
        if(n == NGX_AGAIN){
            if (!rev->timer_set) {
                cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
                ngx_add_timer(rev, cscf->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_demo_close_session(s);
                return;
            }
            return;
        }
        
        if (n == NGX_ERROR) {
            ngx_tcp_demo_close_session(s);
            return;
        }
        
        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed connection");
            ngx_tcp_demo_close_session(s);
            return;
        }
        
        b->last += n;
        
        if(b->last - b->pos < (signed)ctx->body_len){
            if (!rev->timer_set) {
                cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
                ngx_add_timer(rev, cscf->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_demo_close_session(s);
                return;
            }
            return;
        }
    }

    //read done
    c->log->action = "process client by protocol";
    
    rev->handler = ngx_tcp_block_reading;
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    ngx_tcp_demo_process_session(s);
}



static void
ngx_tcp_demo_process_session(ngx_tcp_session_t *s)
{
    ngx_str_t                   echo_str = ngx_string("hello world");
    ngx_tcp_demo_session_ctx_t *ctx;
    ngx_tcp_demo_srv_conf_t    *dscf;
    ngx_connection_t           *c;
    int                        size;
    
    ctx = s->ctx;
    c = s->connection;
    dscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_demo_module);
    
    if (dscf->echo_str.len > 0) {
        echo_str.data = dscf->echo_str.data;
        echo_str.len = dscf->echo_str.len;
    }
    else if (ctx->body_len > 0) {
        echo_str.data = ctx->buffer_in->pos;
        echo_str.len = ctx->buffer_in->last - ctx->buffer_in->pos;
    }
    else {
        //echo_str = ngx_string("hello world");
    }
    
    size = echo_str.len + 4;
    ctx->buffer_out = ngx_create_temp_buf(s->pool, size);
    if (ctx->buffer_out == NULL) {
        ngx_log_error(NGX_LOG_WARN, c->log,0,"protocol error,disconnect it");
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    uint32_t n_net = htonl(size);
    memcpy(ctx->buffer_out->last,&n_net,4);
    ctx->buffer_out->last += 4;
    memcpy(ctx->buffer_out->last,echo_str.data,echo_str.len);
    ctx->buffer_out->last += echo_str.len;
    
    ngx_tcp_demo_send(s,NULL);
}

static void
ngx_tcp_demo_close_session(ngx_tcp_session_t *s)
{
    ngx_connection_t  *c;

#if (NGX_STAT_STUB)
    if (s->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (s->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }
#endif


    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_demo_close_session");
    
    ngx_destroy_pool(s->pool);
    ngx_tcp_close_connection(c);
}

static void
ngx_tcp_demo_reset_session(ngx_tcp_session_t *s)
{
    ngx_connection_t          *c;
    ngx_buf_t                 *b;
    
    //write log, when free s->pool,consider unsend write buf
    
    c = s->connection;
    
    b = c->buffer;
    if(b){
        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;

        } else {
            b->pos = b->start;
            b->last = b->start;
        }
    }
    
    ngx_reset_pool(s->pool);
    
    s->ctx = NULL;
    
    //s->start_sec = 0;
    //s->start_msec = 0;
    //s->blocked = 0;
    //s->quit = 0;
}

static void
ngx_tcp_demo_finalize_session(ngx_tcp_session_t* s)
{
    ngx_connection_t   *c;
    ngx_event_t        *rev;
    ngx_tcp_core_srv_conf_t   *cscf;

    c = s->connection;
    c->log->action = "finalize session";

    ngx_tcp_demo_log_session(s);
    
    rev = c->read;
    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
    
    ngx_log_error(NGX_LOG_DEBUG, c->log,0,"ngx_tcp_demo_finalize_session");

#if (NGX_STAT_STUB)

    if (s->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
        s->stat_reading = 0;
    }

    if (s->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
        s->stat_writing = 0;
    }

#endif

    //do not care send done or not
    
    ngx_tcp_demo_reset_session(s);
    //c->write->handler = ngx_tcp_empty_handler;
    
    c->log->action = "keepalive";
    c->idle = 1;
    ngx_reusable_connection(c, 1);
    rev->handler = ngx_tcp_demo_keepalive_handler;
    
    ngx_tcp_test_reading(s);
    
    if(c->error){
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    //char tmp[1] = {0};
    //ssize_t n = recv(c->fd, tmp, 1, MSG_PEEK);
    //if(n < 0){
    //    rev->ready = 0;
    //}
    if(rev->ready){
        ngx_post_event(rev, &ngx_posted_events);
        return;
    }
    
    if (cscf->keepalive_timeout != NGX_CONF_UNSET_MSEC) {
        ngx_add_timer(rev, cscf->keepalive_timeout);
    }

}

static void 
ngx_tcp_demo_keepalive_handler(ngx_event_t *rev)
{    
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_tcp_core_srv_conf_t   *cscf;
    
    c = rev->data;
    s = c->data;
    
    
    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
    
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp keepalive handler");
    
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        ngx_tcp_demo_close_session(s);
        return;
    }

    if (c->close) {
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    size = NGX_TCP_DEMO_HEADER_LEN;
    
    b = c->buffer;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_tcp_demo_close_session(s);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_tcp_demo_close_session(s);
            return;
        }

        b->pos = b->start;
        b->last = b->start;
        b->end = b->last + size;
    }

    n = c->recv(c, b->last, size);

    if (n == NGX_AGAIN) {

#if (NGX_HAVE_DEFERRED_ACCEPT && defined TCP_DEFER_ACCEPT)
        if (c->listening->deferred_accept)
        {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out in deferred accept");
            ngx_tcp_demo_close_session(s);
            return;
        }
#endif
        
        if (!rev->timer_set) {
            ngx_add_timer(rev, cscf->read_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_demo_close_session(s);
            return;
        }

        /*
         * We are trying to not hold c->buffer's memory for an idle connection.
         */

        if (ngx_pfree(c->pool, b->start) == NGX_OK) {
            b->start = NULL;
        }

        return;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_demo_close_session(s);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_tcp_demo_close_session(s);
        return;
    }

    b->last += n;

    c->idle = 0;
    ngx_reusable_connection(c, 0);
    
    if(ngx_tcp_demo_init_session(s) != NGX_OK){
        ngx_tcp_demo_close_session(s);
        return;
    }

    c->log->action = "reading client header";
    
    c->write->handler = ngx_tcp_empty_handler;
    rev->handler = ngx_tcp_demo_process_header_handler;
    ngx_tcp_demo_process_header_handler(rev);
}

/*
static void
ngx_tcp_demo_read_handler(ngx_event_t *rev)
{

}
*/

static void
ngx_tcp_demo_send(ngx_tcp_session_t* s,ngx_tcp_demo_post_handler_pt post_handler)
{
    ngx_connection_t          *c;
    ngx_tcp_demo_session_ctx_t        *ctx;
    
    c = s->connection;
    ctx = s->ctx;
    
    if(post_handler){
        ctx->post_handler = post_handler;
    }
    else{
        ctx->post_handler = ngx_tcp_demo_finalize_session;
    }
    
    c->log->action = "sending respone";
    c->write->handler = ngx_tcp_demo_send_handler;
    ngx_tcp_demo_send_handler(c->write);
}

static void
ngx_tcp_demo_send_handler(ngx_event_t *wev)
{
    ngx_int_t                  n;
    size_t                     size;
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    ngx_tcp_demo_session_ctx_t* ctx;
    ngx_buf_t                 *b;
    ngx_tcp_core_srv_conf_t   *cscf;

    c = wev->data;
    s = c->data;
    ctx = s->ctx; //ctx must not NULL
    b = ctx->buffer_out;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    if(NULL == b){
        //nothing to send
        goto done;
    }
    
    size = b->last - b->pos;
    if(size <= 0){
        //send done or nothing to send
        goto done;
    }

    n = c->send(c, b->pos, size);

    if (n > 0) {
        b->pos += n;
        
        //n < size
        if(b->pos < b->last){
            if (!wev->timer_set) {
                cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
                ngx_add_timer(wev, cscf->send_timeout);
            }

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_tcp_demo_close_session(s);    
            }
            return;
        }
        
        //send done means session is done.
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "ngx_tcp_demo_send_handler done");
        goto done;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_demo_close_session(s);
        return;
    }
    
    if(n == NGX_AGAIN){
        if (!wev->timer_set) {
            cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
            ngx_add_timer(wev, cscf->send_timeout);
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_tcp_demo_close_session(s);
            return;
        }
        
        return;
    }
    
    /*0 == n*/
   //log impossiable here
   
done:

    if (wev->timer_set) {
        ngx_del_timer(wev);
    }
    
    wev->handler = ngx_tcp_empty_handler;

    ctx->post_handler(s);
}


static void 
ngx_tcp_demo_log_session(ngx_tcp_session_t* s)
{
    ngx_time_t         *tp;
    ngx_msec_int_t      ms;
    ngx_connection_t   *c;

    if(s->log_handler){
        s->log_handler(s);
        return;
    }

    c = s->connection;

    ngx_time_update();//tmp
    tp = ngx_timeofday();

    ms = (ngx_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    ms = ngx_max(ms, 0);

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "request time %T.%03M", ms / 1000, ms % 1000);
}