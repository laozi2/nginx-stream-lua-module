
/*
 * Copyright (C) 
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#include <ngx_tcp.h>
#include "ngx_tcp_token_cache_module.h"

#define NGX_TCP_TOKEN_CACHE_PROTOCOL   0
#define NGX_TCP_TOKEN_CACHE_HEADER_LEN 4
#define NGX_TCP_TOKEN_CACHE_MIN_LEN    8  //4head+4cmd

typedef struct {

    ngx_msec_t                  time_interval;
    size_t                      shm_size;
    ngx_shm_t                   token_shm;
    ngx_tcp_token_slab_pool_t*  token_slab_pool;
    
} ngx_tcp_token_cache_main_conf_t;

typedef struct {
    ngx_uint_t     signature;
} ngx_tcp_token_cache_srv_conf_t;

ngx_tcp_token_slab_pool_t*  ngx_token_slab_pool = NULL;

static ngx_int_t ngx_tcp_token_cache_postconfiguration(ngx_conf_t *cf);
static void *ngx_tcp_token_cache_create_main_conf(ngx_conf_t *cf);
static char *ngx_tcp_token_cache_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_tcp_token_cache_create_srv_conf(ngx_conf_t *cf);
static char *ngx_tcp_token_cache_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_tcp_token_shm_const_size(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
    
static void ngx_tcp_token_cache_master_exit(ngx_cycle_t *cycle);
    
    
static void ngx_tcp_token_cache_init_connection_handler(ngx_event_t *rev);
static void ngx_tcp_token_cache_process_header_handler(ngx_event_t *rev);
static void ngx_tcp_token_cache_process_body_handler(ngx_event_t *rev);

static void ngx_tcp_token_cache_process_session(ngx_tcp_session_t *s);
static ngx_int_t ngx_tcp_token_cache_init_session(ngx_tcp_session_t* s);

//static void ngx_tcp_token_cache_read_handler(ngx_event_t *wev);
static void ngx_tcp_token_cache_send_handler(ngx_event_t *wev);
static void ngx_tcp_token_cache_send(ngx_tcp_session_t* s,ngx_tcp_token_cache_post_handler_pt post_handler);

static void ngx_tcp_token_cache_close_session(ngx_tcp_session_t *s);
static void ngx_tcp_token_cache_reset_session(ngx_tcp_session_t *s);
static void ngx_tcp_token_cache_finalize_session(ngx_tcp_session_t* s);
static void ngx_tcp_token_cache_keepalive_handler(ngx_event_t *rev);
static void ngx_tcp_token_cache_log_session(ngx_tcp_session_t* s);

static ngx_int_t ngx_tcp_token_slab_init(ngx_conf_t *cf,ngx_shm_t* shm,ngx_tcp_token_slab_pool_t** p_pool,ssize_t element_size);

static ngx_str_t token_cache_shm_name = ngx_string("token_cache_shm");

static ngx_tcp_protocol_t  ngx_tcp_token_cache_protocol = {
    ngx_string("token_cache"),
//    { 110, 0, 0, 0 },
//    NGX_TCP_TOKEN_CACHE_PROTOCOL,

    ngx_tcp_token_cache_init_connection_handler,
    NGX_TCP_PROTOCOL_UNSET
};

static ngx_command_t  ngx_tcp_token_cache_commands[] = {

  { ngx_string("token_shm_const_size"),
      NGX_TCP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_tcp_token_shm_const_size,
      0,
      0,
      NULL },
    
    ngx_null_command
};


static ngx_tcp_module_t  ngx_tcp_token_cache_module_ctx = {
    &ngx_tcp_token_cache_protocol,                     /* protocol */
    ngx_tcp_token_cache_postconfiguration,             /*  postconfiguration */

    ngx_tcp_token_cache_create_main_conf,              /* create main configuration */
    ngx_tcp_token_cache_init_main_conf,                /* init main configuration */

    ngx_tcp_token_cache_create_srv_conf,               /* create server configuration */
    ngx_tcp_token_cache_merge_srv_conf                 /* merge server configuration */
};


ngx_module_t  ngx_tcp_token_cache_module = {
    NGX_MODULE_V1,
    &ngx_tcp_token_cache_module_ctx,       /* module context */
    ngx_tcp_token_cache_commands,          /* module directives */
    NGX_TCP_MODULE,                        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    ngx_tcp_token_cache_master_exit,       /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_tcp_token_cache_create_main_conf(ngx_conf_t *cf)
{
    ngx_tcp_token_cache_main_conf_t *ptcmcf;
    
    ptcmcf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_token_cache_main_conf_t));
    if (ptcmcf == NULL) {
        return NULL;
    }
    
    ptcmcf->shm_size = NGX_CONF_UNSET_SIZE;
    ptcmcf->token_slab_pool = NULL;
    //ptcmcf->token_shm
    
    return ptcmcf;
}

static char *
ngx_tcp_token_cache_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static void *
ngx_tcp_token_cache_create_srv_conf(ngx_conf_t *cf)
{
    ngx_tcp_token_cache_srv_conf_t  *ptcscf;//point token_cache srv conf

    ptcscf = ngx_pcalloc(cf->pool, sizeof(ngx_tcp_token_cache_srv_conf_t));
    if (ptcscf == NULL) {
        return NULL;
    }
    
    //ptcscf->signature = 0;

    return ptcscf;
}


static char *
ngx_tcp_token_cache_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    //ngx_tcp_token_cache_srv_conf_t *prev = parent;
    //ngx_tcp_token_cache_srv_conf_t *conf = child;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_tcp_token_cache_postconfiguration(ngx_conf_t *cf)
{
    ngx_tcp_token_cache_main_conf_t  *old_tcmcf,*tcmcf;
    ngx_cycle_t                      *old_cycle;
    ngx_shm_t                        *token_shm;
    ssize_t                          element_size;
    
    
    ngx_uint_t                       i;
    ngx_shm_zone_t                  *shm_zone;
    ngx_list_part_t                 *part;

    if(ngx_tcp_token_cache_protocol.set == NGX_TCP_PROTOCOL_UNSET){
        return NGX_OK;
    }

#if !(NGX_HAVE_ATOMIC_OPS)
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"module 'token_cache' need feture NGX_HAVE_ATOMIC_OPS");

    return NGX_ERROR;
#endif

    tcmcf = ngx_tcp_conf_get_module_main_conf(cf, ngx_tcp_token_cache_module);
    
    if(tcmcf->shm_size == NGX_CONF_UNSET_SIZE){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"module 'token_cache' need command 'token_shm_const_size'");

        return NGX_ERROR;
    }
    
    //check wether token_cache_shm_name used by other module
    //code can '//' or not because duplication of name do not matter.
    part = &cf->cycle->shared_memory.part;
    shm_zone = part->elts;
    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        if (token_cache_shm_name.len != shm_zone[i].shm.name.len) {
            continue;
        }

        if (ngx_strncmp(token_cache_shm_name.data, shm_zone[i].shm.name.data, token_cache_shm_name.len)
            != 0)
        {
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"shm name \"%V\" is reserved by ngx_tcp_token_cache_module",&token_cache_shm_name);

        return NGX_ERROR;
    }

    //[nginx -t][nginx -s xxx][nginx again], will ngx_shm_alloc another shm,
    //next 3 line code can '//' or not
    if( ngx_process == NGX_PROCESS_SIGNALLER || ngx_test_config ){
        return NGX_OK;
    }
    
    //
    old_cycle = cf->cycle->old_cycle;
    token_shm = &tcmcf->token_shm;

    if(ngx_is_init_cycle(old_cycle)){
        //create shm
        token_shm->name = token_cache_shm_name;
        token_shm->size = tcmcf->shm_size;
        token_shm->log = cf->cycle->log;
        token_shm->exists = 0;//it seems no use
        
        if(ngx_shm_alloc(token_shm) != NGX_OK){
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"ngx_shm_alloc failed");

            return NGX_ERROR;
        }
        
        element_size = sizeof(void*) + sizeof(struct ngx_tcp_token_info_s);//44/52 need config,must > 8,and muti of 4
        if(NGX_ERROR == ngx_tcp_token_slab_init(cf,token_shm,&tcmcf->token_slab_pool,element_size)){
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"ngx_tcp_token_slab_init failed");

            return NGX_ERROR;
        }
        
        ngx_stat_token_req_cur_sec = &tcmcf->token_slab_pool->token_status.ngx_stat_token_req_cur_sec0;
        ngx_token_slab_pool = tcmcf->token_slab_pool;

        return NGX_OK;
    }
    
    old_tcmcf = ngx_tcp_cycle_get_module_main_conf(old_cycle,ngx_tcp_token_cache_module);

    if(old_tcmcf->shm_size != tcmcf->shm_size){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "token_shm_const_size \"%z\" is const", old_tcmcf->shm_size);

        return NGX_ERROR;
    }
    
    token_shm->addr = old_tcmcf->token_shm.addr;
    token_shm->name = token_cache_shm_name;
    token_shm->size = tcmcf->shm_size;
    token_shm->log = cf->cycle->log;
    token_shm->exists = 1;//it seems no use
    
    tcmcf->token_slab_pool = old_tcmcf->token_slab_pool;//?
    
    ngx_stat_token_req_cur_sec = &tcmcf->token_slab_pool->token_status.ngx_stat_token_req_cur_sec0;
    ngx_token_slab_pool = tcmcf->token_slab_pool;
    
    return NGX_OK;
}


static char *
ngx_tcp_token_shm_const_size(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ssize_t                          size;
    ngx_str_t                       *value;
    ngx_tcp_token_cache_main_conf_t *ptcmcf;
    
    ptcmcf = conf;
    
    value = cf->args->elts;
    size = ngx_parse_size(&value[1]);

    if (size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid zone size \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "zone \"%V\" is too small", &value[1]);
        return NGX_CONF_ERROR;
    }
    
    
    ptcmcf->shm_size = size;
    return NGX_CONF_OK;
}


static void
ngx_tcp_token_cache_master_exit(ngx_cycle_t *cycle)
{
    //will free automaticly where process exit
    
    //ngx_tcp_token_cache_main_conf_t* ptcmcf;
    
    //ptcmcf = ngx_tcp_conf_get_module_main_conf(cycle->ctx, ngx_tcp_token_cache_module);
    
    
    //ngx_shm_free(&ptcmcf->token_shm);
}

static ngx_int_t
ngx_tcp_token_slab_init(ngx_conf_t *cf,ngx_shm_t* shm,ngx_tcp_token_slab_pool_t** p_pool,ssize_t element_size)
{
    u_char           *p,*file;
    size_t           size;
    ngx_uint_t       elements;
    ngx_uint_t       i;
    ngx_tcp_token_info_t *next;
    ngx_tcp_token_slab_pool_t *pool;
    
    
    ngx_memzero(shm->addr,shm->size);

    pool = (ngx_tcp_token_slab_pool_t *) shm->addr;
    pool->start = (char*)shm->addr;
    pool->end = (char*)pool->start + shm->size;
    
    p = (u_char *) pool + sizeof(ngx_tcp_token_slab_pool_t);
    p = ngx_align_ptr(p, NGX_ALIGNMENT);
    
    size = (u_char*)pool->end - p;
    elements = (size/element_size) - 8;//8 for safe
    
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,"token_shm_const_size can storage %d tokens,per token size %z",elements,element_size);

    
    pool->hash_slots = (void**)p;
    pool->hash_slots_n = elements;
    
    p = (u_char*)pool->hash_slots + elements * sizeof(void*);
    pool->tokens = (ngx_tcp_token_info_t*)p;
    pool->tokens_n = elements;
  
    i = pool->tokens_n;
    next = NULL;
    do {
        i--;
    
        pool->tokens[i].next = next;
        next = &pool->tokens[i];
    } while (i);

    pool->free_token = next;
    pool->free_token_n = pool->tokens_n;
 
#if (NGX_HAVE_ATOMIC_OPS)

    file = NULL;

#else

    //file = ngx_pnalloc(cf->cycle->pool, cf->cycle->lock_file.len + shm->name.len);
    //if (file == NULL) {
    //    return NGX_ERROR;
    //}
    //
    //(void) ngx_sprintf(file, "%V%V%Z", &cf->cycle->lock_file, &shm->name);
    
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"need NGX_HAVE_ATOMIC_OPS");
    
    return NGX_ERROR;

#endif
    if (ngx_shmtx_create(&pool->mutex, &pool->lock, file) != NGX_OK) {
        return NGX_ERROR;
    }
    
    *p_pool = pool;
    return NGX_OK;
}


//-----------------handler--------------------------
static void
ngx_tcp_token_cache_init_connection_handler(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    
    c = rev->data;
    s = c->data;
    
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_token_cache_init_connection_handler");
    
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
    
    size = NGX_TCP_TOKEN_CACHE_HEADER_LEN;
    
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
    
    if(ngx_tcp_token_cache_init_session(s) != NGX_OK){
        ngx_tcp_close_connection(c);
        return;
    }

    c->log->action = "reading client header";
    
    c->write->handler = ngx_tcp_empty_handler;
    rev->handler = ngx_tcp_token_cache_process_header_handler;
    ngx_tcp_token_cache_process_header_handler(rev);
    
}

static ngx_int_t
ngx_tcp_token_cache_init_session(ngx_tcp_session_t* s)
{
    ngx_tcp_core_srv_conf_t  *cscf;
    ngx_pool_t               *pool;
    ngx_connection_t         *c;
    ngx_time_t               *tp;
    ngx_tcp_token_cache_main_conf_t   *tcmcf;
    ngx_tcp_token_cache_session_ctx_t *session_ctx;
    
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    c = s->connection;

    c->requests++;
    
    pool = s->pool;
    if(NULL == pool){
        pool = ngx_create_pool(cscf->session_pool_size, c->log);
        if (NULL == pool) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                         "ngx_token_cache_init_session : ngx_create_pool failed");
            return NGX_ERROR;
        }
            
        s->pool = pool;
    }
    
    session_ctx = ngx_pcalloc(s->pool, sizeof(ngx_tcp_token_cache_session_ctx_t));
    if(NULL == session_ctx){
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                         "ngx_token_cache_init_session : ngx_pcalloc failed");
        
        ngx_destroy_pool(s->pool);
        
        return NGX_ERROR;
    }
    
    tcmcf = ngx_tcp_get_module_main_conf(s, ngx_tcp_token_cache_module);
    
    //set by ngx_pcalloc
    //session_ctx->buffer_in = NULL;
    //session_ctx->buffer_out = NULL;
    //session_ctx->post_handler = NULL;
    session_ctx->token_slab_pool = tcmcf->token_slab_pool;
    
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
ngx_tcp_token_cache_process_header_handler(ngx_event_t *rev)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    ngx_tcp_token_cache_session_ctx_t        *ctx;
    ngx_tcp_core_srv_conf_t   *cscf;
    
    c = rev->data;
    s = c->data;
    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_token_cache_process_header_handler");
    
    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_token_cache_close_session(s);
        return;
    }
    
    b = c->buffer;
    size = b->last - b->pos;
    
    if( size < NGX_TCP_TOKEN_CACHE_HEADER_LEN ) {
        n = c->recv(c, b->last, NGX_TCP_TOKEN_CACHE_HEADER_LEN - size);
        
        if(n == NGX_AGAIN){
            if (!rev->timer_set) {
                ngx_add_timer(rev, cscf->read_timeout);
            }
        
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_token_cache_close_session(s);
                return;
            }
            return;
        }
        
        if (n == NGX_ERROR) {
            ngx_tcp_token_cache_close_session(s);
            return;
        }
        
        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed connection");
            ngx_tcp_token_cache_close_session(s);
            return;
        }
        
        b->last += n;
        
        if(b->last - b->pos < NGX_TCP_TOKEN_CACHE_HEADER_LEN){
            if (!rev->timer_set) {
                ngx_add_timer(rev, cscf->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_token_cache_close_session(s);
                return;
            }
            return;
        }
    }
    
    size = (size_t)ngx_tcp_token_ntoint32(b->pos);
    
    if(size < NGX_TCP_TOKEN_CACHE_MIN_LEN || size > cscf->client_max_body_size){ //8=4head+4cmd
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "body_len %z", size);
        ngx_tcp_token_cache_close_session(s);
        return;
    }
        
        
    ctx = s->ctx;
    ctx->body_len = size - NGX_TCP_TOKEN_CACHE_HEADER_LEN;
        
    b = ngx_create_temp_buf(s->pool, ctx->body_len);
    if(NULL == b){
        ngx_tcp_token_cache_close_session(s);
        return;
    }
        
    ctx->buffer_in = b;
    
    c->log->action = "reading client body";
    
    rev->handler = ngx_tcp_token_cache_process_body_handler;
    ngx_tcp_token_cache_process_body_handler(rev);
}

static void 
ngx_tcp_token_cache_process_body_handler(ngx_event_t *rev)
{
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    ngx_tcp_token_cache_session_ctx_t        *ctx;
    ngx_tcp_core_srv_conf_t          *cscf;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_token_cache_process_body_handler");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_token_cache_close_session(s);
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
                ngx_tcp_token_cache_close_session(s);
                return;
            }
            return;
        }
        
        if (n == NGX_ERROR) {
            ngx_tcp_token_cache_close_session(s);
            return;
        }
        
        if (n == 0) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "client closed connection");
            ngx_tcp_token_cache_close_session(s);
            return;
        }
        
        b->last += n;
        
        if(b->last - b->pos < (signed)ctx->body_len){
            if (!rev->timer_set) {
                cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
                ngx_add_timer(rev, cscf->read_timeout);
            }
            
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                ngx_tcp_token_cache_close_session(s);
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

    ngx_tcp_token_cache_process_session(s);
}



static void
ngx_tcp_token_cache_process_session(ngx_tcp_session_t *s)
{
    ngx_int_t             error_code;
    ngx_connection_t      *c;

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    s->stat_reading = 0;
    (void) ngx_atomic_fetch_add(ngx_stat_writing, 1);
    s->stat_writing = 1;
#endif
    
    c = s->connection;
    error_code = ngx_tcp_token_protocal_handler(s);
    
    if(error_code < NGX_TCP_CACHE_TOKEN_OK){ //-1/-2
        //protocol error
        ngx_log_error(NGX_LOG_WARN, c->log,0,"protocol error,disconnect it");
        
        ngx_tcp_token_cache_close_session(s);

        return;
    }
    
    ngx_tcp_token_cache_send(s,NULL);
}

static void
ngx_tcp_token_cache_close_session(ngx_tcp_session_t *s)
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

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_token_cache_close_session");
    
    ngx_destroy_pool(s->pool);
    ngx_tcp_close_connection(c);
}

static void
ngx_tcp_token_cache_reset_session(ngx_tcp_session_t *s)
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
ngx_tcp_token_cache_finalize_session(ngx_tcp_session_t* s)
{
    ngx_connection_t   *c;
    ngx_event_t        *rev;
    ngx_tcp_core_srv_conf_t   *cscf;

    c = s->connection;
    c->log->action = "finalize session";

    ngx_tcp_token_cache_log_session(s);
    
    rev = c->read;
    cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
    
    ngx_log_error(NGX_LOG_DEBUG, c->log,0,"ngx_tcp_token_cache_finalize_session");

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
    
    ngx_tcp_token_cache_reset_session(s);
    //c->write->handler = ngx_tcp_empty_handler;
    
    c->log->action = "keepalive";
    c->idle = 1;
    ngx_reusable_connection(c, 1);
    rev->handler = ngx_tcp_token_cache_keepalive_handler;
    
    ngx_tcp_test_reading(s);
    
    if(c->error){
        ngx_tcp_token_cache_close_session(s);
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
ngx_tcp_token_cache_keepalive_handler(ngx_event_t *rev)
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
        ngx_tcp_token_cache_close_session(s);
        return;
    }

    if (c->close) {
        ngx_tcp_token_cache_close_session(s);
        return;
    }
    
    size = NGX_TCP_TOKEN_CACHE_HEADER_LEN;
    
    b = c->buffer;

    if (b == NULL) {
        b = ngx_create_temp_buf(c->pool, size);
        if (b == NULL) {
            ngx_tcp_token_cache_close_session(s);
            return;
        }

        c->buffer = b;

    } else if (b->start == NULL) {

        b->start = ngx_palloc(c->pool, size);
        if (b->start == NULL) {
            ngx_tcp_token_cache_close_session(s);
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
            ngx_tcp_token_cache_close_session(s);
            return;
        }
#endif
        
        if (!rev->timer_set) {
            ngx_add_timer(rev, cscf->read_timeout);
        }

        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_tcp_token_cache_close_session(s);
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
        ngx_tcp_token_cache_close_session(s);
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client closed connection");
        ngx_tcp_token_cache_close_session(s);
        return;
    }

    b->last += n;

    c->idle = 0;
    ngx_reusable_connection(c, 0);
    
    if(ngx_tcp_token_cache_init_session(s) != NGX_OK){
        ngx_tcp_token_cache_close_session(s);
        return;
    }

    c->log->action = "reading client header";
    
    c->write->handler = ngx_tcp_empty_handler;
    rev->handler = ngx_tcp_token_cache_process_header_handler;
    ngx_tcp_token_cache_process_header_handler(rev);
}

/*
static void
ngx_tcp_token_cache_read_handler(ngx_event_t *rev)
{

}
*/

static void
ngx_tcp_token_cache_send(ngx_tcp_session_t* s,ngx_tcp_token_cache_post_handler_pt post_handler)
{
    ngx_connection_t          *c;
    ngx_tcp_token_cache_session_ctx_t        *ctx;
    
    c = s->connection;
    ctx = s->ctx;
    
    if(post_handler){
        ctx->post_handler = post_handler;
    }
    else{
        ctx->post_handler = ngx_tcp_token_cache_finalize_session;
    }
    
    c->log->action = "sending respone";
    c->write->handler = ngx_tcp_token_cache_send_handler;
    ngx_tcp_token_cache_send_handler(c->write);
}

static void
ngx_tcp_token_cache_send_handler(ngx_event_t *wev)
{
    ngx_int_t                 n;
    size_t                    size;
    ngx_connection_t          *c;
    ngx_tcp_session_t         *s;
    ngx_tcp_token_cache_session_ctx_t* ctx;
    ngx_buf_t                 *b;
    ngx_tcp_core_srv_conf_t   *cscf;

    c = wev->data;
    s = c->data;
    ctx = s->ctx; //ctx must not NULL
    b = ctx->buffer_out;

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        //c->timedout = 1;//only for ngx_ssl_shutdown
        ngx_tcp_token_cache_close_session(s);
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
                ngx_tcp_token_cache_close_session(s);    
            }
            return;
        }
        
        //send done means session is done.
        ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "ngx_tcp_token_cache_send_handler done");
        goto done;
    }

    if (n == NGX_ERROR) {
        ngx_tcp_token_cache_close_session(s);
        return;
    }
    
    if(n == NGX_AGAIN){
        if (!wev->timer_set) {
            cscf = ngx_tcp_get_module_srv_conf(s,ngx_tcp_core_module);
            ngx_add_timer(wev, cscf->send_timeout);
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            ngx_tcp_token_cache_close_session(s);
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
ngx_tcp_token_cache_log_session(ngx_tcp_session_t* s)
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