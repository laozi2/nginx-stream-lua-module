
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include "ngx_tcp_lua_common.h"
#include "ngx_tcp_lua_session.h"

void 
ngx_tcp_lua_close_session(ngx_tcp_session_t *s)
{
    ngx_connection_t  *c;
    ngx_tcp_cleanup_t *cln;

#if (NGX_STAT_STUB)
    if (s->stat_reading) {
        (void) ngx_atomic_fetch_add(ngx_stat_reading, -1);
    }

    if (s->stat_writing) {
        (void) ngx_atomic_fetch_add(ngx_stat_writing, -1);
    }
#endif


    c = s->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "ngx_tcp_lua_close_session");

    for (cln = s->cleanup; cln; cln = cln->next) {
        if (cln->handler) {
            cln->handler(cln->data);
            cln->handler = NULL;
        }
    }

    ngx_destroy_pool(s->pool);
    ngx_tcp_close_connection(c);

    return;
}

void 
ngx_tcp_lua_log_session(ngx_tcp_session_t* s)
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

ngx_int_t
ngx_tcp_lua_init_light_session(ngx_tcp_session_t* s)
{
    ngx_connection_t         *c;
    ngx_time_t               *tp;
    
    c = s->connection;

    c->requests++;

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

void 
ngx_tcp_lua_finalize_light_session(ngx_tcp_session_t* s)
{
    ngx_connection_t         *c;
    ngx_tcp_lua_ctx_t        *ctx;
    
    c = s->connection;
    ctx = s->ctx;
    //ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0,
    //               "lua req calling wait_next_request() method");
   
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

    ngx_tcp_lua_log_session(s);
    
    ngx_reset_pool(s->pool);

    ctx->buf_in = NULL;
    ctx->buf_out = NULL;
}
