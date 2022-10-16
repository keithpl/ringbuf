#if !defined(RINGBUF_H)
#define RINGBUF_H

#include <stdbool.h>
#include <stddef.h>

struct ringbuf {
	void *buf;
	size_t size, mask;
	size_t head, tail;
};

static inline size_t min(size_t x, size_t y)
{
	return (x < y) ? x : y;
}

static inline size_t max(size_t x, size_t y)
{
	return (x > y) ? x : y;
}

static inline void *ringbuf_head(const struct ringbuf *rb)
{
	return (char *)rb->buf + (rb->head & rb->mask);
}

static inline void *ringbuf_tail(const struct ringbuf *rb)
{
	return (char *)rb->buf + (rb->tail & rb->mask);
}

static inline size_t ringbuf_count(const struct ringbuf *rb)
{
	return rb->head - rb->tail;
}

static inline size_t ringbuf_count_to_end(const struct ringbuf *rb)
{
	return min(ringbuf_count(rb), rb->size - (rb->tail & rb->mask));
}

static inline size_t ringbuf_space(const struct ringbuf *rb)
{
	return rb->size - ringbuf_count(rb);
}

static inline size_t ringbuf_space_to_end(const struct ringbuf *rb)
{
	return rb->size - max(ringbuf_count(rb), rb->head & rb->mask);
}

static inline bool ringbuf_is_empty(const struct ringbuf *rb)
{
	return rb->head == rb->tail;
}

static inline bool ringbuf_is_full(const struct ringbuf *rb)
{
	return !ringbuf_space(rb);
}

int ringbuf_init(struct ringbuf *rb, size_t size);
void ringbuf_release(struct ringbuf *rb);
void ringbuf_reset(struct ringbuf *rb);

struct ringbuf *ringbuf_create(size_t size);
void ringbuf_destroy(struct ringbuf *rb);
int ringbuf_resize(struct ringbuf *rb, size_t new_size);
int ringbuf_grow(struct ringbuf *rb);
int ringbuf_shrink(struct ringbuf *rb);

void *ringbuf_memchr(const struct ringbuf *rb, int c);
size_t ringbuf_memchr_len(const struct ringbuf *rb, int c);
size_t ringbuf_read(struct ringbuf *rb, void *buf, size_t bufsize);
size_t ringbuf_read_line(struct ringbuf *rb, void *buf, size_t bufsize);
size_t ringbuf_write(struct ringbuf *rb, const void *buf, size_t bufsize);

#endif /* !defined(RINGBUF_H) */
