#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ringbuf.h"

#if __has_builtin(__builtin_popcountl)
static inline bool is_pow2(unsigned long x)
{
	return __builtin_popcountl(x) == 1;
}
#else
static inline bool is_pow2(unsigned long x)
{
	return x && !(x & (x - 1));
}
#endif /* __has_builtin(__builtin_popcountl) */

static int ringbuf_alloc(void **buf_ptr, size_t size)
{
	void *buf;

	if (!is_pow2(size))
		return -1;

	buf = malloc(size);
	if (!buf)
		return -1;

	*buf_ptr = buf;
	return 0;
}

static inline void ringbuf_set_size(struct ringbuf *rb, size_t size)
{
	rb->size = size;
	rb->mask = size - 1;
}

int ringbuf_init(struct ringbuf *rb, size_t size)
{
	int ret;

	ret = ringbuf_alloc(&rb->buf, size);
	if (ret < 0)
		return ret;

	ringbuf_set_size(rb, size);
	ringbuf_reset(rb);
	return 0;
}

void ringbuf_release(struct ringbuf *rb)
{
	free(rb->buf);
}

void ringbuf_reset(struct ringbuf *rb)
{
	rb->head = 0;
	rb->tail = 0;
}

struct ringbuf *ringbuf_create(size_t size)
{
	int ret;
	struct ringbuf *rb;

	rb = malloc(sizeof(*rb));
	if (rb) {
		ret = ringbuf_init(rb, size);
		if (ret < 0) {
			free(rb);
			return NULL;
		}
	}

	return rb;
}

void ringbuf_destroy(struct ringbuf *rb)
{
	ringbuf_release(rb);
	free(rb);
}

int ringbuf_resize(struct ringbuf *rb, size_t new_size)
{
	int ret;
	size_t count;
	void *new_buf;

	ret = ringbuf_alloc(&new_buf, new_size);
	if (ret < 0)
		return ret;

	count = ringbuf_read(rb, new_buf, new_size);
	free(rb->buf);
	ringbuf_set_size(rb, new_size);
	rb->buf = new_buf;
	rb->head = count;
	rb->tail = 0;
	return 0;
}

int ringbuf_grow(struct ringbuf *rb)
{
	size_t new_size = rb->size << 1;

	if (new_size < rb->size)
		return -1;

	return ringbuf_resize(rb, new_size);
}

int ringbuf_shrink(struct ringbuf *rb)
{
	size_t new_size = rb->size >> 1;

	if (!new_size)
		return -1;

	return ringbuf_resize(rb, new_size);
}

void *ringbuf_memchr(const struct ringbuf *rb, int c)
{
	void *ret;
	size_t count;

	count = ringbuf_count_to_end(rb);
	ret = memchr(ringbuf_tail(rb), c, count);
	if (!ret) {
		count = ringbuf_count(rb) - count;
		ret = memchr(rb->buf, c, count);
	}

	return ret;
}

size_t ringbuf_memchr_len(const struct ringbuf *rb, int c)
{
	const char *pos, *tail;

	pos = ringbuf_memchr(rb, c);
	if (!pos)
		return 0;

	tail = ringbuf_tail(rb);
	return ((pos >= tail) ? 0 : rb->size) + pos - tail + 1;
}

size_t ringbuf_read(struct ringbuf *rb, void *buf, size_t bufsize)
{
	size_t count;

	bufsize = min(bufsize, ringbuf_count(rb));
	count = min(bufsize, rb->size - (rb->tail & rb->mask));
	memcpy(buf, ringbuf_tail(rb), count);
	memcpy((char *)buf + count, rb->buf, bufsize - count);

	rb->tail += bufsize;
	return bufsize;
}

size_t ringbuf_read_line(struct ringbuf *rb, void *buf, size_t bufsize)
{
	size_t len;

	len = ringbuf_memchr_len(rb, '\n');
	if (len < bufsize)
		bufsize = len;

	return ringbuf_read(rb, buf, bufsize);
}

size_t ringbuf_write(struct ringbuf *rb, const void *buf, size_t bufsize)
{
	size_t space;

	bufsize = min(bufsize, ringbuf_space(rb));
	space = min(bufsize, rb->size - (rb->head & rb->mask));
	memcpy(ringbuf_head(rb), buf, space);
	memcpy(rb->buf, (const char *)buf + space, bufsize - space);

	rb->head += bufsize;
	return bufsize;
}
