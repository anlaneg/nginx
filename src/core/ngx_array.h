
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
	//数组缓冲区首指针
    void        *elts;
    //当前有多少个元素
    ngx_uint_t   nelts;
    //每个元素的大小
    size_t       size;
    //一共申请了多少个空间
    ngx_uint_t   nalloc;
    //从哪个池里申请
    ngx_pool_t  *pool;
} ngx_array_t;


ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
void ngx_array_destroy(ngx_array_t *a);
//返回下一个可存储的空间
void *ngx_array_push(ngx_array_t *a);
//返回下一个可存储空间（这段空间可存储n个对象）
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);


//array初始化
static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n/*数组大小*/, size_t size/*元素大小*/)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
