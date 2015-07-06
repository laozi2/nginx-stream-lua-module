#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "../tcp/ngx_tcp_token_cache_module/ngx_tcp_token_cache_module.h"

static char* ngx_http_set_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_get_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_del_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_token_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_token_traverse(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_set_token_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_get_token_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_del_token_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_status_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_token_traverse_handler(ngx_http_request_t *r);

//key must null terminate
static u_char* ngx_http_get_uri_var(ngx_http_request_t *r, char* key, size_t *value_len);

//statistics
static void ngx_http_token_cache_req_statistics(ngx_tcp_token_slab_pool_t* pool);


static ngx_command_t ngx_http_token_cache_commands[] = {

    { ngx_string("set_token"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_set_token,
      0,
      0,
      NULL },

    { ngx_string("get_token"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_get_token,
      0,
      0,
      NULL },

    { ngx_string("del_token"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_del_token,
      0,
      0,
      NULL },

    { ngx_string("token_status"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_token_status,
      0,
      0,
      NULL },

    { ngx_string("token_traverse"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_token_traverse,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_token_cache_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

ngx_module_t ngx_http_token_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_token_cache_module_ctx,
    ngx_http_token_cache_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_set_token_handler(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_buf_t*            b;
    int                   size;
    ngx_chain_t           out;
    u_char*               token_start;
    size_t                token_len;
    u_char*               value_start;
    size_t                value_len;
    int32_t               user_id;
    time_t                expiry_time;
    int                   error_no;
    ngx_tcp_token_info_t* token_info;

    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    //ngx_str_t content_type = ngx_string("text/plain");
    //r->headers_out.content_type = content_type;

    ngx_str_t arg_token = ngx_string("token=");
    ngx_str_t arg_user_id = ngx_string("user_id=");
    ngx_str_t arg_expiry_time = ngx_string("expiry_time=");

    token_start = ngx_http_get_uri_var(r, (char*)arg_token.data, &token_len);
    if ( NULL == token_start || 24 != token_len ) {
        return 406;
    }
    
    value_start = ngx_http_get_uri_var(r, (char*)arg_user_id.data, &value_len);
    if ( NULL == value_start || value_len > NGX_INT32_LEN ) {
        return 406;
    }
    
    user_id = ngx_atoi(value_start, value_len);
    if ( NGX_ERROR == user_id ) {
        return 406;
    }
    
    value_start = ngx_http_get_uri_var(r, (char*)arg_expiry_time.data, &value_len);
    if ( NULL == value_start || value_len > NGX_TIME_T_LEN ) {
        return 406;
    }
    
    expiry_time = ngx_atotm(value_start, value_len);
    if ( NGX_ERROR == expiry_time ) {
        return 406;
    }
    
    token_info = ngx_tcp_token_set_token(ngx_token_slab_pool, r->connection, token_start);
    if ( NULL == token_info ) {
        //ngx_log_error(NGX_LOG_ALERT, s->connection->log,0,"[emergency] no more space");
        error_no = NGX_TCP_CACHE_NO_MORE_SPACE;
    }
    else{
        error_no = NGX_TCP_CACHE_TOKEN_OK;
        memcpy(token_info->token,token_start,NGX_TCP_TOKEN_LEN);
        token_info->user_id = (unsigned)user_id;
        token_info->expiry_time = expiry_time;

        ngx_http_token_cache_req_statistics(ngx_token_slab_pool);
    }

    size = 64;
    b = ngx_create_temp_buf(r->pool, size);
    if ( NULL == b ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->last, "{\"error_no\":\"%d\"}", error_no);
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;
    
    r->headers_out.status = NGX_HTTP_OK;//NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_get_token_handler(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_buf_t*            b;
    int                   size;
    ngx_chain_t           out;
    u_char*               token_start;
    size_t                token_len;
    int                   error_no;
    ngx_tcp_token_info_t* token_info;

    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    //ngx_str_t content_type = ngx_string("text/plain");
    //r->headers_out.content_type = content_type;

    ngx_str_t arg_token = ngx_string("token=");

    token_start = ngx_http_get_uri_var(r, (char*)arg_token.data, &token_len);
    if ( NULL == token_start || 24 != token_len ) {
        return 406;
    }
    
    size = 128;
    b = ngx_create_temp_buf(r->pool, size);
    if ( NULL == b ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    token_info = ngx_tcp_token_get_token(ngx_token_slab_pool, r->connection, token_start);
    if ( NULL == token_info ) {
        error_no = NGX_TCP_CACHE_TOKEN_NOT_FOUND;
        b->last = ngx_sprintf(b->last, "{\"error_no\":\"%d\"}", error_no);
    }
    else{
        error_no = NGX_TCP_CACHE_TOKEN_OK;
        b->last = ngx_sprintf(b->last, "{\"error_no\":\"%d\",\"user_id\":\"%ud\",\"expiry_time\":\"%T\"}",
                                error_no, token_info->user_id, token_info->expiry_time);

        ngx_http_token_cache_req_statistics(ngx_token_slab_pool);
    }
    
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;
    
    r->headers_out.status = NGX_HTTP_OK;//NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_del_token_handler(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_buf_t*            b;
    int                   size;
    ngx_chain_t           out;
    u_char*               token_start;
    size_t                token_len;
    int                   error_no;

    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    //ngx_str_t content_type = ngx_string("text/plain");
    //r->headers_out.content_type = content_type;

    ngx_str_t arg_token = ngx_string("token=");

    token_start = ngx_http_get_uri_var(r, (char*)arg_token.data, &token_len);
    if ( NULL == token_start || 24 != token_len ) {
        return 406;
    }
    
    ngx_tcp_token_delete_token(ngx_token_slab_pool, r->connection, token_start);
    error_no = NGX_TCP_CACHE_TOKEN_OK;
    ngx_http_token_cache_req_statistics(ngx_token_slab_pool);

    size = 64;
    b = ngx_create_temp_buf(r->pool, size);
    if ( NULL == b ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->last, "{\"error_no\":\"%d\"}", error_no);
    
    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;
    
    r->headers_out.status = NGX_HTTP_OK;//NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = b->last - b->pos;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_token_status_handler(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_buf_t*            b;
    int                   size;
    ngx_chain_t           out;
    ngx_tcp_token_status_t    *p_token_status;

    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t content_type = ngx_string("text/plain");
    r->headers_out.content_type = content_type;
    
    p_token_status = &ngx_token_slab_pool->token_status;
    
    size = sizeof("Requests in current second:  \n") + NGX_ATOMIC_T_LEN
           + sizeof("Max requests in one second:  \n") + NGX_INT64_LEN
           + sizeof("Number of tokens in share memory:  \n") + NGX_INT64_LEN
           + 8;
    b = ngx_create_temp_buf(r->pool, size);
    if ( NULL == b ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->last, "Requests in current second: %uA \n", p_token_status->ngx_stat_token_req_cur_sec0);
    b->last = ngx_sprintf(b->last, "Max requests in one second: %ul \n", p_token_status->ngx_stat_token_max_req_sec);
    b->last = ngx_sprintf(b->last, "Number of tokens in share memory: %ul \n", p_token_status->ngx_stat_token_number);
    size = b->last - b->pos;

    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;
    
    r->headers_out.status = NGX_HTTP_OK;//NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = size;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_token_traverse_handler(ngx_http_request_t *r)
{
    ngx_int_t             rc;
    ngx_buf_t*            b;
    ngx_chain_t           out;
    unsigned int          size,i,removed_num = 0;
    unsigned int          hash_times[10] = {0};
    ngx_uint_t            hash_slots_n;

    if(!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t content_type = ngx_string("text/plain");
    r->headers_out.content_type = content_type;

    hash_slots_n = ngx_token_slab_pool->hash_slots_n;
    removed_num = ngx_tcp_token_token_traverse(ngx_token_slab_pool,r->connection, hash_times);

    size = 512;
    b = ngx_create_temp_buf(r->pool, size);
    if ( NULL == b ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    b->last = ngx_sprintf(b->last, "removed tokens : %ud\n", removed_num);
    b->last = ngx_sprintf(b->last, "slots : %ud \n", hash_slots_n);
    for (i = 0; i < 9; i++){
        b->last = ngx_sprintf(b->last, "hash %d times : %ud, %.3f%%\n", i, hash_times[i], (double)hash_times[i]/hash_slots_n);
    }
    b->last = ngx_sprintf(b->last, "hash >%d times : %ud, %.3f%%\n", i, hash_times[i], (double)hash_times[i]/hash_slots_n);

    size = b->last - b->pos;

    out.buf = b;
    out.next = NULL;
    b->memory = 1;
    b->last_buf = 1;
    
    r->headers_out.status = NGX_HTTP_OK;//NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = size;

    rc = ngx_http_send_header(r);
    if(rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


//--------------------------------------------------
static char*
ngx_http_set_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_set_token_handler;

    return NGX_CONF_OK;
}

static char*
ngx_http_get_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_get_token_handler;

    return NGX_CONF_OK;
}

static char*
ngx_http_del_token(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_del_token_handler;

    return NGX_CONF_OK;
}

static char*
ngx_http_token_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_token_status_handler;

    return NGX_CONF_OK;
}

static char*
ngx_http_token_traverse(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_token_traverse_handler;

    return NGX_CONF_OK;
}


static u_char*
ngx_http_get_uri_var(ngx_http_request_t *r, char* key, size_t* value_len)
{
    u_char*  args_start;
    u_char*  args_end;
    u_char*  value_start;
    u_char*  value_end;
    u_char   tmp;
    size_t   args_len;

    args_start = r->args_start;
    args_end = r->uri_end;
    args_len = args_end - args_start;
    
    if( NULL == args_start || args_len <= 0 ){
        return NULL;
    }

    value_start = ngx_strnstr(args_start, key, args_len);
    if( NULL == value_start ){
        return NULL;
    }

    tmp = *(value_start - 1);
    if( tmp != '?' && tmp != '&' ){
        return NULL;
    }

    value_start += ngx_strlen(key);
    value_end = value_start;

    while (value_end <= args_end) {

        if ( *value_end == '&' || *value_end == ' ' ) {
            break;
        }

        value_end++;
    }

    *value_len = value_end - value_start;
    if( *value_len <= 0 ){
        return NULL;
    }
    return value_start;
}

static void
ngx_http_token_cache_req_statistics(ngx_tcp_token_slab_pool_t* pool)
{
    time_t                     now;

    now = ngx_time();
    
    if (pool->token_status.ngx_stat_cur_sec != now){
        *ngx_stat_token_req_cur_sec = 0;
        pool->token_status.ngx_stat_cur_sec = now;
    }
    (void) ngx_atomic_fetch_add(ngx_stat_token_req_cur_sec, 1);
    if(*ngx_stat_token_req_cur_sec > pool->token_status.ngx_stat_token_max_req_sec){
        pool->token_status.ngx_stat_token_max_req_sec = *ngx_stat_token_req_cur_sec;
    }
}
