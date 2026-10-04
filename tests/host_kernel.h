/* SPDX-License-Identifier: GPL-2.0 */
/* 存储层测试替身：只复用容器/锁/分配语义，不模拟网络栈。 */
#ifndef KDG_HOST_KERNEL_H
#define KDG_HOST_KERNEL_H
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "kdg_base.h"

#define GFP_KERNEL 0
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))

static inline void *kzalloc(size_t n, int flags)
{ (void)flags; return calloc(1, n); }
static inline void *kvcalloc(size_t n, size_t s, int flags)
{ (void)flags; return calloc(n, s); }
static inline void *kmemdup(const void *p, size_t n, int flags)
{ void *out; (void)flags; out = malloc(n); if (out) memcpy(out, p, n); return out; }
#define kfree free
#define kvfree free

typedef pthread_mutex_t spinlock_t;
#define spin_lock_init(l) assert(pthread_mutex_init((l), NULL) == 0)
#define spin_lock(l) assert(pthread_mutex_lock(l) == 0)
#define spin_unlock(l) assert(pthread_mutex_unlock(l) == 0)
typedef atomic_int atomic_t;
#define atomic_read(a) atomic_load(a)
#define atomic_set(a, v) atomic_store((a), (v))
#define atomic_inc(a) ((void)atomic_fetch_add((a), 1))
#define atomic_dec_and_test(a) (atomic_fetch_sub((a), 1) == 1)

struct list_head { struct list_head *next, *prev; };
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l->prev = l; }
static inline int list_empty(const struct list_head *l) { return l->next == l; }
static inline void list_add_tail(struct list_head *n, struct list_head *h)
{ n->prev = h->prev; n->next = h; h->prev->next = n; h->prev = n; }
static inline void list_del_init(struct list_head *n)
{ n->prev->next = n->next; n->next->prev = n->prev; INIT_LIST_HEAD(n); }
#define list_first_entry(h, t, m) container_of((h)->next, t, m)

struct hlist_node { struct hlist_node *next, **pprev; };
struct hlist_head { struct hlist_node *first; };
static inline void INIT_HLIST_NODE(struct hlist_node *n) { n->next = NULL; n->pprev = NULL; }
static inline void hlist_add_head(struct hlist_node *n, struct hlist_head *h)
{ n->next = h->first; if (n->next) n->next->pprev = &n->next; h->first = n; n->pprev = &h->first; }
static inline void hlist_del_init(struct hlist_node *n)
{ if (!n->pprev) return; *n->pprev = n->next; if (n->next) n->next->pprev = n->pprev; INIT_HLIST_NODE(n); }
#define hlist_for_each_entry(p, h, m) \
	for (struct hlist_node *_n = (h)->first; _n && ((p) = container_of(_n, __typeof__(*(p)), m), 1); _n = _n->next)
#define hash_min(h, bits) ((u32)((h) * 0x61c88647u) >> (32 - (bits)))
#endif
