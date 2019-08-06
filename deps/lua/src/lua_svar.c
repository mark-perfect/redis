// auther: mark 2019-04-12
#include <assert.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#include "lua.h"
#include "lauxlib.h"

typedef struct mk_buf {
	unsigned char *b;
	size_t len, free;
} mk_buf;

void *mk_realloc(lua_State *L, void *target, size_t osize, size_t nsize) {
	void *(*local_realloc) (void *, void *, size_t osize, size_t nsize) = NULL;
	void *ud;
	local_realloc = lua_getallocf(L, &ud);
	return local_realloc(ud, target, osize, nsize);
}

void mk_buf_append(lua_State *L, mk_buf *buf, const unsigned char *s, size_t len) {
	if (buf->free < len) {
		size_t newsize = (buf->len + len) * 2;
		buf->b = (unsigned char*)mk_realloc(L, buf->b, buf->len + buf->free, newsize);
		buf->free = newsize - buf->len;
	}
	memcpy(buf->b + buf->len, s, len);
	buf->len += len;
	buf->free -= len;
}

void mk_buf_free(lua_State *L, mk_buf *buf) {
	mk_realloc(L, buf->b, buf->len + buf->free, 0);
	mk_realloc(L, buf, sizeof(*buf), 0);
}

mk_buf *mk_buf_new(lua_State *L) {
	mk_buf *buf = NULL;

	buf = (mk_buf*)mk_realloc(L, NULL, 0, sizeof(*buf));

	buf->b = NULL;
	buf->len = buf->free = 0;
	return buf;
}

#define MK_CUR_ERROR_NONE   0
#define MK_CUR_ERROR_EOF    1
#define MK_CUR_ERROR_BADFMT 2

typedef struct mk_cur {
	const unsigned char *p;
	size_t left;
	int err;
} mk_cur;

void mk_cur_init(mk_cur *cursor, const unsigned char *s, size_t len) {
	cursor->p = s;
	cursor->left = len;
	cursor->err = MK_CUR_ERROR_NONE;
}

#define mk_cur_consume(_c,_len) do { _c->p += _len; _c->left -= _len; } while(0)

#define mk_cur_need(_c,_len) do { \
    if (_c->left < _len) { \
        _c->err = MK_CUR_ERROR_EOF; \
        return; \
    } \
} while(0)

/* ------------------------------- encoding --------------------------------- */

void mk_encode_lua_type(lua_State *L, mk_buf *buf);

void mk_encode_lua_table(lua_State *L, mk_buf *buf)
{
	lua_pushnil(L);
	while (lua_next(L, -2)) {
		/* Stack: ... key value */
		lua_pushvalue(L, -2); /* Stack: ... key value key */
		mk_encode_lua_type(L, buf); /* encode key */
		mk_encode_lua_type(L, buf); /* encode val */
	}
}

void mk_encode_lua_type(lua_State *L, mk_buf *buf)
{
	int t = lua_type(L, -1);
	switch (t)
	{
	case LUA_TNIL:
	{
		uint8_t b = 0;
		mk_buf_append(L, buf, (const uint8_t*)&b, 1);
		break;
	}
	case LUA_TSTRING:
	{
		size_t len;
		const char *s;
		s = lua_tolstring(L, -1, &len);
		if (len < 63) {
			uint8_t b = 2 | (len << 2);
			mk_buf_append(L, buf, &b, 1);
			mk_buf_append(L, buf, (const uint8_t*)s, len);
			break;
		}
		uint8_t b = 254;
		mk_buf_append(L, buf, (const uint8_t*)&b, 1);
		mk_buf_append(L, buf, (const uint8_t*)s, len + 1);
		break;
	}
	case LUA_TNUMBER:
	{
		lua_Number i = lua_tonumber(L, -1);
		if ((int64_t)i == i && i >= -134217727 && i <= 134217727) {
			uint32_t ni = (uint32_t)fabs(i);
			if (ni <= 0x7ff) {
				uint16_t p = i < 0 ? (21 | (ni << 5)) : (5 | (ni << 5));
				mk_buf_append(L, buf, (const uint8_t*)&p, 2);
				break;
			}
			if (ni <= 0x7ffff) {
				uint8_t b = 0;
				b = i < 0 ? (25 | (ni << 5)) : (9 | (ni << 5));
				mk_buf_append(L, buf, (const uint8_t*)&b, 1);
				uint16_t p = ni >> 3;
				mk_buf_append(L, buf, (const uint8_t*)&p, 2);
				break;
			}
			uint32_t p = i < 0 ? (29 | (ni << 5)) : (13 | (ni << 5));
			mk_buf_append(L, buf, (const uint8_t*)&p, 4);
			break;
		}
		uint8_t b = 1;
		mk_buf_append(L, buf, (const uint8_t*)&b, 1);
		mk_buf_append(L, buf, (const uint8_t*)&i, 8);
		break;
	}
	case LUA_TTABLE:
	{
		size_t len = 0;
		lua_pushnil(L);
		while (lua_next(L, -2)) {
			lua_pop(L, 1);
			len++;
		}

		if (len == 0) {
			uint8_t b = 3;
			mk_buf_append(L, buf, (const uint8_t*)&b, 1);
			break;
		}
		if (len <= 0x1f) {
			uint8_t b = 3 | (len << 3);
			mk_buf_append(L, buf, (const uint8_t*)&b, 1);
		}
		else if (len <= 0x1fff) {
			uint16_t b = 7 | (len << 3);
			mk_buf_append(L, buf, (const uint8_t*)&b, 2);
		}
		else break;
		mk_encode_lua_table(L, buf);
		break;
	}
	}
	lua_pop(L, 1);
}

static int
lencode(lua_State *L)
{
	if (lua_gettop(L) != 1)
		return luaL_argerror(L, 0, "svar pack arguments error.");

	if (lua_istable(L, 1) != 1)
		return luaL_argerror(L, 0, "svar first arguments not table.");

	mk_buf *buf = mk_buf_new(L);

	mk_encode_lua_type(L, buf);

	lua_pushlstring(L, (char*)buf->b, buf->len);

	mk_buf_free(L, buf);
	return 1;
}

/* ------------------------------- decoding --------------------------------- */

void mk_decode_to_lua_type(lua_State *L, mk_cur *c)
{
	mk_cur_need(c, 1);
	uint8_t t = c->p[0] & 3;
	switch (t)
	{
	case 0: /* nil */
	{
		lua_pushnil(L);
		mk_cur_consume(c, 1);
		return;
	}
	case 1: /* number */
	{
		uint32_t ni = (c->p[0] >> 2) & 3;
		if (ni == 0) {
			mk_cur_need(c, 9);
			double d = 0;
			memcpy(&d, c->p + 1, 8);
			lua_pushnumber(L, d);
			/* WRN: if client not support 64, you must convert number to string */
			mk_cur_consume(c, 9);
			return;
		}
		uint32_t ns = (c->p[0] >> 4) & 1;
		if (ni == 1) {
			mk_cur_need(c, 2);
			uint16_t d = 0;
			memcpy(&d, c->p, 2);
			d = d >> 5;
			lua_pushnumber(L, ns == 1 ? -d : d);
			mk_cur_consume(c, 2);
			return;
		}
		if (ni == 2) {
			mk_cur_need(c, 3);
			double d = 0;
			uint16_t e = 0;
			memcpy(&e, c->p + 1, 2);
			d = ((c->p[0] >> 5) & 7) + (e << 3);
			if (ns == 1) d = -d;
			lua_pushnumber(L, d);
			mk_cur_consume(c, 3);
			return;
		}
		mk_cur_need(c, 4);
		uint32_t d = 0;
		memcpy(&d, c->p, 4);
		d = d >> 5;
		lua_pushnumber(L, ns == 1 ? -d : d);
		mk_cur_consume(c, 4);
		return;
	}
	case 2: /* string */
	{
		uint32_t ni = c->p[0] >> 2;
		mk_cur_consume(c, 1);
		if (ni == 63) {
			size_t i = 0;
			for (; i < c->left; i++) {
				if (c->p[i] == 0) {
					i++;
					break;
				}
			}
			if (i > c->left) {
				c->err = MK_CUR_ERROR_EOF;
				return;
			}
			lua_pushlstring(L, (char*)c->p, i - 1);
			mk_cur_consume(c, i);
			return;
		}
		mk_cur_need(c, ni);
		lua_pushlstring(L, (char*)c->p, ni);
		mk_cur_consume(c, ni);
		return;
	}
	case 3: /* table */
	{
		uint32_t ni = (c->p[0] >> 2) & 1;
		if (ni == 0) {
			ni = c->p[0] >> 3;
			mk_cur_consume(c, 1);
		}
		else {
			mk_cur_need(c, 2);
			uint16_t d = 0;
			memcpy(&d, c->p, 2);
			ni = d >> 3;
			mk_cur_consume(c, 2);
		}
		lua_newtable(L);
		uint32_t i = 0;
		for (i = 0; i < ni; i++) {
			mk_decode_to_lua_type(L, c);
			if (c->err) return;
			mk_decode_to_lua_type(L, c);
			if (c->err) return;
			lua_settable(L, -3);
		}
		return;
	}
	case 4: /* NULL */
		c->err = MK_CUR_ERROR_BADFMT;
		return;
	}
}

static int
ldecode(lua_State *L)
{
	size_t len;
	const char *s;
	mk_cur c;
	s = luaL_checklstring(L, 1, &len);
	mk_cur_init(&c, (const uint8_t*)s, len);
	mk_decode_to_lua_type(L, &c);
	if (c.err == MK_CUR_ERROR_EOF)
		return luaL_error(L, "missing bytes in input.");
	if (c.err == MK_CUR_ERROR_BADFMT)
		return luaL_error(L, "Bad data format in input.");
	return 1;
}

LUALIB_API int
luaopen_svar(lua_State *L)
{
	luaL_Reg cmds[] = {
		{ "encode", lencode },
		{ "decode", ldecode },
		{ 0 }
	};
	lua_newtable(L);

	int i = 0;
	for (i = 0; i < (sizeof(cmds) / sizeof(*cmds) - 1); i++) {
		lua_pushcfunction(L, cmds[i].func);
		lua_setfield(L, -2, cmds[i].name);
	}
	lua_pushvalue(L, -1);
	lua_setglobal(L, "svar");
	return 1;
}
