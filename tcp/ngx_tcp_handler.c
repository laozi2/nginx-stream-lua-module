
/*
 * Copyright (C)
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_tcp.h>

#if (NGX_TCP_SSL)
static void ngx_tcp_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c);
static void ngx_tcp_ssl_handshake_handler(ngx_connection_t *c);
#endif

static void ngx_tcp_init_session(ngx_connection_t *c);

void
ngx_tcp_init_connection(ngx_connection_t *c)
{
    ngx_uint_t            i;
    ngx_tcp_port_t        *port;
    struct sockaddr       *sa;
    struct sockaddr_in    *sin;
    ngx_tcp_log_ctx_t     *ctx;
    ngx_tcp_in_addr_t     *addr;
    ngx_tcp_session_t     *s;
    ngx_tcp_addr_conf_t   *addr_conf;
    ngx_tcp_core_srv_conf_t   *cscf;


    /* find the server configuration for the address:port */

    port = c->listening->servers;

    if (port->naddrs > 1) {

        /*
         * There are several addresses on this port and one of them
         * is the "*:port" wildcard so getsockname() is needed to determine
         * the server address.
         *
         * AcceptEx() already gave this address.
         */

        if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
            ngx_tcp_close_connection(c);
            return;
        }

        sa = c->local_sockaddr;

        switch (sa->sa_family) {
        //no care NGX_HAVE_INET6

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;

            addr = port->addrs;

            /* the last address is "*" */

            for (i = 0; i < port->naddrs - 1; i++) {
                if (addr[i].addr == sin->sin_addr.s_addr) {
                    break;
                }
            }

            addr_conf = &addr[i].conf;

            break;
        }

    } else {
        switch (c->local_sockaddr->sa_family) {
        //no care NGX_HAVE_INET6

        default: /* AF_INET */
            addr = port->addrs;
            addr_conf = &addr[0].conf;
            break;
        }
    }

    s = ngx_pcalloc(c->pool, sizeof(ngx_tcp_session_t));
    if (s == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }

    s->main_conf = addr_conf->ctx->main_conf;
    s->srv_conf = addr_conf->ctx->srv_conf;

    s->addr_text = &addr_conf->addr_text;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);
    s->log_handler = cscf->log_handler;

    c->data = s;
    s->connection = c;

    ngx_log_error(NGX_LOG_INFO, c->log, 0, "*%ui client %V connected to %V",
                  c->number, &c->addr_text, s->addr_text);

    ctx = ngx_palloc(c->pool, sizeof(ngx_tcp_log_ctx_t));
    if (ctx == NULL) {
        ngx_tcp_close_connection(c);
        return;
    }

    ctx->client = &c->addr_text;
    ctx->session = s;

    c->log->connection = c->number;
    c->log->handler = ngx_tcp_log_error;
    c->log->data = ctx;
    c->log->action = "ready to read client data";

    c->log_error = NGX_ERROR_INFO;

    /* process the ACL */
    if (ngx_tcp_access_handler(s) == NGX_ERROR) {
        ngx_tcp_close_connection(c);
        return;
    }

#if (NGX_TCP_SSL)

    {
    ngx_tcp_ssl_srv_conf_t  *sscf;

    sscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_ssl_module);
    if (sscf->enable || addr_conf->ssl) {

        if (c->ssl == NULL) {

            c->log->action = "SSL handshaking";

            if (addr_conf->ssl && sscf->ssl.ctx == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "no \"ssl_certificate\" is defined "
                              "in server listening on SSL port");
                ngx_tcp_close_connection(c);
                return;
            }

            ngx_tcp_ssl_init_connection(&sscf->ssl, c);
            return;
        }
    }
    }

#endif


    ngx_tcp_init_session(c);
}


#if (NGX_TCP_SSL)

static void
ngx_tcp_ssl_init_connection(ngx_ssl_t *ssl, ngx_connection_t *c)
{
    if (ngx_ssl_create_connection(ssl, c, NGX_SSL_BUFFER) == NGX_ERROR) {
        ngx_tcp_close_connection(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {

        ngx_add_timer(c->read, c->listening->post_accept_timeout);

        c->ssl->handler = ngx_tcp_ssl_handshake_handler;

        return;
    }

    ngx_tcp_ssl_handshake_handler(c);
}


static void
ngx_tcp_ssl_handshake_handler(ngx_connection_t *c)
{
    if (c->ssl->handshaked) {

        c->read->ready = 0;//?

        ngx_tcp_init_session(c);
        return;
    }

    ngx_tcp_close_connection(c);
}

#endif

static void
ngx_tcp_init_session(ngx_connection_t *c)
{
    ngx_event_t               *rev;
    ngx_tcp_core_srv_conf_t   *cscf;
    ngx_tcp_session_t         *s;

    s = c->data;
    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    rev = c->read;
    rev->handler = cscf->protocol->init_connection;
    c->write->handler = ngx_tcp_empty_handler;
    
    if (rev->ready) {
        /* the deferred accept(), rtsig, aio, iocp */

        if (ngx_use_accept_mutex) {
            ngx_post_event(rev, &ngx_posted_events);
            return;
        }

        rev->handler(rev);
        return;
    }

    ngx_add_timer(rev, c->listening->post_accept_timeout);
    ngx_reusable_connection(c, 1);

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        ngx_tcp_close_connection(c);
        return;
    }
}

void
ngx_tcp_close_connection(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

    ngx_log_debug1(NGX_LOG_DEBUG_TCP, c->log, 0,
                   "close tcp connection: %d", c->fd);

#if (NGX_TCP_SSL)

    if (c->ssl) {
        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_tcp_close_connection;
            return;
        }
    }

#endif

#if (NGX_STAT_STUB)
    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);
#endif

    c->destroyed = 1;

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}

//ngx_log_error can use this
u_char *
ngx_tcp_log_error(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char             *p;
    ngx_tcp_session_t  *s;
    ngx_tcp_log_ctx_t  *ctx;

    if (log->action) {
        p = ngx_snprintf(buf, len, " while %s", log->action);
        len -= p - buf;
        buf = p;
    }

    ctx = log->data;

    p = ngx_snprintf(buf, len, ", client: %V", ctx->client);
    len -= p - buf;
    buf = p;

    s = ctx->session;

    if (s == NULL) {
        return p;
    }

    p = ngx_snprintf(buf, len, ", server: %V",s->addr_text);

    return p;
}


void
ngx_tcp_block_reading(ngx_event_t *rev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, rev->log, 0,
                   "ngx_tcp_block_reading");

    /* aio does not call this handler */

    //assume use edge epoll
    //if ((ngx_event_flags & NGX_USE_LEVEL_EVENT)
    //    && r->connection->read->active)
    //{
    //    if (ngx_del_event(r->connection->read, NGX_READ_EVENT, 0) != NGX_OK) {
    //        ngx_http_close_request(r, 0);
    //    }
    //}
}

void ngx_tcp_empty_handler(ngx_event_t *wev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, wev->log, 0, "ngx_tcp_empty_handler");

    return;
}

ngx_tcp_cleanup_t *
ngx_tcp_cleanup_add(ngx_tcp_session_t *s, size_t size, ngx_pool_t *pool)
{
    ngx_tcp_cleanup_t  *cln;

    if (NULL == pool) {
        pool = s->pool;
    }

    cln = ngx_palloc(pool, sizeof(ngx_tcp_cleanup_t));
    if (cln == NULL) {
        return NULL;
    }

    if (size) {
        cln->data = ngx_palloc(pool, size);
        if (cln->data == NULL) {
            return NULL;
        }

    } else {
        cln->data = NULL;
    }

    cln->handler = NULL;
    cln->next = s->cleanup;

    s->cleanup = cln;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, s->connection->log, 0,
                   "tcp cleanup add: %p", cln);

    return cln;
}

/*
    make sure s->read/write_event_handler is not NULL when this function be called 
*/
void
ngx_tcp_session_handler(ngx_event_t *ev)
{
    ngx_connection_t    *c;
    ngx_tcp_session_t   *s;

    c = ev->data;
    s = c->data;

    if (ev->write) {
        s->write_event_handler(s);

    } else {
        s->read_event_handler(s);
    }
}

void
ngx_tcp_session_empty_handler(ngx_tcp_session_t *s)
{
    ngx_log_debug0(NGX_LOG_DEBUG_TCP, s->connection->log, 0,
                   "tcp session empty handler");

    return;
}

void
ngx_tcp_test_reading(ngx_tcp_session_t *s)
{
    int                n;
    char               buf[1];
    ngx_err_t          err;
    ngx_event_t       *rev;
    ngx_connection_t  *c;

    c = s->connection;
    rev = c->read;

    ngx_log_debug0(NGX_LOG_DEBUG_TCP, c->log, 0, "tcp test reading");

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == 0) {
        rev->eof = 1;
        rev->ready = 0;
        c->error = 1;
        err = 0;

        goto closed;

    } else if (n == -1) {
        err = ngx_socket_errno;
        rev->ready = 0;
        
        if (err == NGX_EAGAIN) {
			/* stale event ; XXX */
			if (ngx_handle_read_event(rev, 0) == NGX_OK) {
				return;
			}
            //return;
        }

        rev->eof = 1;
        c->error = 1;

        goto closed;
    }

    ///* aio does not call this handler */
    //
    //if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && rev->active) {
    //
    //    if (ngx_del_event(rev, NGX_READ_EVENT, 0) != NGX_OK) {
    //        ngx_http_close_request(r, 0);
    //    }
    //}

    rev->ready = 1;

    return;

closed:

    if (err) {
        rev->error = 1;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, err,
                  "client prematurely closed connection");

}

ngx_int_t
ngx_tcp_access_handler(ngx_tcp_session_t *s) 
{
    ngx_uint_t                   i;
    struct sockaddr_in          *sin;
    ngx_tcp_access_rule_t       *rule;
    ngx_tcp_core_srv_conf_t     *cscf;

    cscf = ngx_tcp_get_module_srv_conf(s, ngx_tcp_core_module);

    if (cscf->rules == NULL) {
        return NGX_DECLINED;
    }

    /* AF_INET only */

    if (s->connection->sockaddr->sa_family != AF_INET) {
        return NGX_DECLINED;
    }

    sin = (struct sockaddr_in *) s->connection->sockaddr;

    rule = cscf->rules->elts;
    for (i = 0; i < cscf->rules->nelts; i++) {

        ngx_log_debug3(NGX_LOG_DEBUG, s->connection->log, 0,
                       "access: %08XD %08XD %08XD",
                       sin->sin_addr.s_addr, rule[i].mask, rule[i].addr);

        if ((sin->sin_addr.s_addr & rule[i].mask) == rule[i].addr) {
            if (rule[i].deny) {
                ngx_log_error(NGX_LOG_NOTICE, s->connection->log, 0,
                              "access forbidden by rule");

                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}
