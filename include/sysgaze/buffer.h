#ifndef SYSGAZE_BUFFER_H
#define SYSGAZE_BUFFER_H

#include <stdbool.h>
#include <stddef.h>

struct sg_buffer {
    char *data;
    size_t length;
    size_t capacity;
};

void sg_buffer_init(struct sg_buffer *buffer);
void sg_buffer_reset(struct sg_buffer *buffer);
void sg_buffer_destroy(struct sg_buffer *buffer);
bool sg_buffer_reserve(struct sg_buffer *buffer, size_t additional);
bool sg_buffer_append(struct sg_buffer *buffer, const void *data, size_t length);
bool sg_buffer_append_cstr(struct sg_buffer *buffer, const char *text);
bool sg_buffer_append_format(struct sg_buffer *buffer, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

#endif
