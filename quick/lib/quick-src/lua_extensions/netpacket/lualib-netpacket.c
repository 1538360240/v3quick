#if __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef __GNUC__
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif
#include <lua.h>
#include <lauxlib.h>
#include "stdString.h"

#define DEFAULT_QUEUE_SIZE      2048
#define INCOMPLETE_HASH_SIZE    2024
#define INCOMPLETE_HASH(a)      (a % INCOMPLETE_HASH_SIZE)

#define min(a, b)               ((a) > (b) ? (b) : (a))

#define silly_malloc			malloc
#define silly_free				free

	struct packet {
		int fd;
		int size;
		char *buff;
	};

	struct incomplete {
		int fd;
		int rsize;
		int psize;
		uint8_t *buff;
		struct incomplete *prev;
		struct incomplete *next;
	};

	struct netpacket {
		struct incomplete       *incomplete_hash[INCOMPLETE_HASH_SIZE];
		int                     cap;                            //default DEFAULT_QUEUE_SIZE
		int                     head;
		int                     tail;
		struct packet           queue[DEFAULT_QUEUE_SIZE];      //for more effective gc
	};

	static int
		lcreate(lua_State *L)
	{
			struct netpacket *r = (struct netpacket *)lua_newuserdata(L, sizeof(struct netpacket));
			memset(r, 0, sizeof(*r));

			r->cap = DEFAULT_QUEUE_SIZE;

			luaL_getmetatable(L, "netpacket");
			lua_setmetatable(L, -2);

			return 1;
		}

	static __inline struct netpacket *
		get_netpacket(lua_State *L)
	{
			return (struct netpacket *)luaL_checkudata(L, 1, "netpacket");
		}

	static struct incomplete *
		get_incomplete(struct netpacket *p, int fd)
	{
			struct incomplete *i;
			i = p->incomplete_hash[INCOMPLETE_HASH(fd)];
			while (i) {
				if (i->fd == fd) {
					if (i->prev == NULL)
						p->incomplete_hash[INCOMPLETE_HASH(fd)] = i->next;
					else
						i->prev->next = i->next;
					return i;
				}
				i = i->next;
			}

			return NULL;
		}

	static void
		put_incomplete(struct netpacket *p, struct incomplete *ic)
	{
			struct incomplete *i;
			i = p->incomplete_hash[INCOMPLETE_HASH(ic->fd)];
			ic->next = i;
			ic->prev = NULL;
			p->incomplete_hash[INCOMPLETE_HASH(ic->fd)] = ic;
		}

	static void
		expand_queue(lua_State *L, struct netpacket *p)
	{
			int i, h;
			struct netpacket *new_np = (struct netpacket *)lua_newuserdata(L, sizeof(struct netpacket) + sizeof(struct packet) * p->cap);
			new_np->cap = p->cap + DEFAULT_QUEUE_SIZE;
			new_np->head = p->cap;
			new_np->tail = 0;

			memcpy(new_np->incomplete_hash, p->incomplete_hash, sizeof(new_np->incomplete_hash));
			h = p->tail;
			for (i = 0; i < p->cap; i++) {
				new_np->queue[i] = p->queue[h % p->cap];
				++h;
			}

			luaL_getmetatable(L, "netpacket");
			lua_setmetatable(L, -2);

			p->head = p->tail = 0;

			lua_replace(L, 1);

			return;
		}

	static void
		push_complete(lua_State *L, struct netpacket *p, struct incomplete *ic)
	{
			struct packet *pk;
			int h = p->head;
			p->head = (p->head + 1) % p->cap;

			pk = &p->queue[h];
			pk->fd = ic->fd;
			assert(ic->psize == ic->rsize);
			pk->size = ic->psize;
			pk->buff = (char *)ic->buff;

			assert(p->head < p->cap);
			assert(p->tail < p->cap);
			if (p->head == p->tail) {
				fprintf(stderr, "packet queue full\n");
				expand_queue(L, p);
			}

			return;
		}

	static int
		push_once(lua_State *L, int fd, int size, const uint8_t *buff)
	{
			int eat;
			struct netpacket *p = get_netpacket(L);
			struct incomplete *ic = get_incomplete(p, fd);
			if (ic) {       //continue it
				if (ic->rsize >= 0) {   //have already alloc memory
					assert(ic->buff);
					eat = min(ic->psize - ic->rsize, size);
					memcpy(&ic->buff[ic->rsize], buff, eat);
					ic->rsize += eat;
				}
				else {                //have no enough psize info
					assert(ic->rsize == -1);
					ic->psize |= *buff;
					ic->buff = (uint8_t *)silly_malloc(ic->psize);

					++buff;
					--size;
					++ic->rsize;

					assert(ic->rsize == 0);

					eat = min(ic->psize - ic->rsize, size);
					memcpy(&ic->buff[ic->rsize], buff, eat);
					ic->rsize += eat;
					eat += 1;               //for the length header
				}
			}
			else {        //new incomplete
				ic = (struct incomplete*)silly_malloc(sizeof(*ic));
				ic->fd = fd;
				ic->buff = NULL;
				ic->psize = 0;
				ic->rsize = -2;

				if (size >= 2) {
					ic->psize = (*buff << 8) | *(buff + 1);
					ic->rsize = min(ic->psize, size - 2);
					ic->buff = (uint8_t *)silly_malloc(ic->psize);
					eat = ic->rsize + 2;
					memcpy(ic->buff, buff + 2, ic->rsize);
				}
				else {
					assert(size == 1);
					ic->psize |= *buff << 8;
					ic->rsize = -1;
					eat = 1;
				}
			}

			if (ic->rsize == ic->psize) {
				push_complete(L, p, ic);
				silly_free(ic);
			}
			else {
				assert(ic->rsize < ic->psize);
				put_incomplete(p, ic);
			}
			return eat;
		}

	static void
		push(lua_State *L, int sid, const uint8_t *data, int data_size)
	{
			int n;
			int left;
			const uint8_t *d;

			left = data_size;
			d = data;
			do {
				n = push_once(L, sid, left, d);
				left -= n;
				d += n;
			} while (left);


			return;
		}

	static void
		clear_incomplete(lua_State *L, int sid)
	{
			struct netpacket *p = get_netpacket(L);
			struct incomplete *ic = get_incomplete(p, sid);
			if (ic == NULL)
				return;
			silly_free(ic);
			return;
		}

	static int
		lpop(lua_State *L)
	{
			int t;
			struct packet *pk;
			struct netpacket *p;
			p = (struct netpacket *)luaL_checkudata(L, 1, "netpacket");

			assert(p->head < p->cap);
			assert(p->tail < p->cap);

			if (p->tail == p->head) {       //empty
				lua_pushnil(L);
				lua_pushnil(L);
				lua_pushnil(L);
			}
			else {
				t = p->tail;
				p->tail = (p->tail + 1) % p->cap;
				pk = &p->queue[t];
				lua_pushinteger(L, pk->fd);
				lua_pushlightuserdata(L, pk->buff);
				lua_pushinteger(L, pk->size);
			}

			return 3;
		}

	static int
		lpack(lua_State *L)
	{
			const char *str;
			size_t size;
			char *p;

			str = luaL_checklstring(L, 1, &size);
			assert(size < (unsigned short)-1);

			p = (char *)silly_malloc(size + 2);
			*((unsigned short *)p) = htons(size);
			memcpy(p + 2, str, size);

			lua_pushlightuserdata(L, p);
			lua_pushinteger(L, size + 2);

			return 2;
		}

	static int
		ltostring(lua_State *L)
	{
			char *data = (char *)lua_touserdata(L, 1);
			lua_Integer n = luaL_checkinteger(L, 2);
			lua_pushlstring(L, data, n);
			silly_free(data);
			return 1;
		}

	static int
		lclear(lua_State *L)
	{
			int sid = luaL_checkinteger(L, 2);
			assert(sid >= 0);
			clear_incomplete(L, sid);

			return 0;
		}

	//@input
	//      packet
	//		fd
	//      type
	//      message
	static int
		lmessage(lua_State *L)
	{
			size_t sz;
			const uint8_t *data;
			int fd = luaL_checkinteger(L, 2);
			int type = luaL_checkinteger(L, 3);
			switch (type){
			case 0:
				data = (uint8_t *)luaL_checklstring(L, 4, &sz);
				push(L, fd, data, sz);
				lua_settop(L, 1);
			case 1:
				clear_incomplete(L, fd);
				lua_settop(L, 1);
				return 1;
			default:
				assert(!"never come here");
				return 1;
			}
		}

	int luaopen_netpacket(lua_State *L)
	{
		luaL_Reg tbl[] = {
			{ "create", lcreate },
			{ "pop", lpop },
			{ "pack", lpack },
			{ "tostring", ltostring },
			{ "clear", lclear },
			{ "message", lmessage },
			{ NULL, NULL },
		};

		luaL_newmetatable(L, "netpacket");
		luaL_register(L, "netpack", tbl);

		return 1;
	}
#if __cplusplus
} // extern "C"
#endif
