
/*
 * Copyright (C) 
 */


#ifndef _NGX_TCP_TOKEN_CACHE_MODULE_INCLUDED_
#define _NGX_TCP_TOKEN_CACHE_MODULE_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_tcp.h>

#define NGX_TCP_TOKEN_LEN 24
#define NGX_TCP_TOKEN_FLAG_TOKEN_INUSE 0x01

typedef struct ngx_tcp_token_info_s  ngx_tcp_token_info_t;
typedef struct ngx_tcp_token_status_s  ngx_tcp_token_status_t;

struct ngx_tcp_token_info_s {

    char                  token[NGX_TCP_TOKEN_LEN];
    uint32_t              user_id;
    uint32_t              flag; //use 4byte padding in 64 bit to other purposes
    time_t                expiry_time;
    ngx_tcp_token_info_t* next;

};

extern ngx_atomic_t  *ngx_stat_token_req_cur_sec;

struct ngx_tcp_token_status_s {

    ngx_atomic_t   ngx_stat_token_req_cur_sec0;
    time_t         ngx_stat_cur_sec;
    unsigned long  ngx_stat_token_max_req_sec;
    unsigned long  ngx_stat_token_number;

};

typedef struct{
    ngx_shmtx_sh_t    lock;
    ngx_shmtx_t       mutex;
    
    void* start;
    void* end;
    
    void**              hash_slots;
    ngx_uint_t          hash_slots_n;

    ngx_tcp_token_info_t* tokens;
    ngx_uint_t            tokens_n;
    
    ngx_tcp_token_info_t* free_token;
    ngx_uint_t            free_token_n;

    ngx_tcp_token_status_t token_status;
    
}ngx_tcp_token_slab_pool_t;


typedef void (*ngx_tcp_token_cache_post_handler_pt)(ngx_tcp_session_t *r);


typedef struct {

    size_t                  body_len;
    ngx_buf_t              *buffer_in;//only for buffer client data
    ngx_buf_t              *buffer_out;
    
    ngx_tcp_token_slab_pool_t*            token_slab_pool;
    
    ngx_tcp_token_cache_post_handler_pt   post_handler;
    
}ngx_tcp_token_cache_session_ctx_t;

#define NGX_TCP_CACHE_INTERNAL_ERROR -1
#define NGX_TCP_CACHE_PROTOCOL_ERROR -2
#define NGX_TCP_CACHE_NO_MORE_SPACE   1
#define NGX_TCP_CACHE_TOKEN_NOT_FOUND 2
#define NGX_TCP_CACHE_TOKEN_OK        NGX_OK


ngx_int_t ngx_tcp_token_protocal_handler(ngx_tcp_session_t *s);


//for ngx_http_token_cache_module
extern ngx_tcp_token_slab_pool_t*            ngx_token_slab_pool;

ngx_tcp_token_info_t* ngx_tcp_token_set_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token);
ngx_tcp_token_info_t* ngx_tcp_token_get_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token);
void ngx_tcp_token_delete_token(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c,u_char* token);
unsigned int ngx_tcp_token_token_traverse(ngx_tcp_token_slab_pool_t* pool,ngx_connection_t *c, unsigned int* arr_hash_times);

//4 byte net-endian to 16 
uint16_t ngx_tcp_token_ntoint16(u_char* s);

//4 byte net-endian to 32 
uint32_t ngx_tcp_token_ntoint32(u_char* s);

//8 byte net-endian to 64/time_t
time_t ngx_tcp_token_ntotimet(u_char* s);

//copy short to net-endian binay char
void ngx_tcp_token_memcpy_int16ton(u_char* s,short n);

//copy int to net-endian binay char
void ngx_tcp_token_memcpy_int32ton(u_char* s,int n);

//copy 64/time_t to net-endian binay char
void ngx_tcp_token_memcpy_timetton(u_char* s,time_t n);

#endif /*_NGX_TCP_TOKEN_CACHE_MODULE_INCLUDED_*/