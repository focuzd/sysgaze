#include "sysgaze/buffer.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SG_BUFFER_INITIAL_CAPACITY 64U

void sg_buffer_init(struct sg_buffer *buffer)
{
    buffer->data = NULL;
    buffer->length = 0U;
    buffer->capacity = 0U;
}

void sg_buffer_reset(struct sg_buffer *buffer)
{
    buffer->length = 0U;
    if (buffer->data != NULL) {
        buffer->data[0] = '\0';
    }
}

void sg_buffer_destroy(struct sg_buffer *buffer)
{
    free(buffer->data);
    sg_buffer_init(buffer);
}

bool sg_buffer_reserve(struct sg_buffer *buffer, size_t additional)
{
    size_t required;
    size_t capacity;
    char *resized;

    if (buffer->length == SIZE_MAX ||
        additional > SIZE_MAX - buffer->length - 1U) {
        return false;
    }
    required = buffer->length + additional + 1U;
    if (required <= buffer->capacity) {
        return true;
    }

    capacity = buffer->capacity == 0U ? SG_BUFFER_INITIAL_CAPACITY
                                      : buffer->capacity;
    while (capacity < required) {
        if (capacity > SIZE_MAX / 2U) {
            capacity = required;
            break;
        }
        capacity *= 2U;
    }

    resized = realloc(buffer->data, capacity);
    if (resized == NULL) {
        return false;
    }
    buffer->data = resized;
    buffer->capacity = capacity;
    if (buffer->length == 0U) {
        buffer->data[0] = '\0';
    }
    return true;
}

bool sg_buffer_append(struct sg_buffer *buffer, const void *data, size_t length)
{
    if (length != 0U && data == NULL) {
        return false;
    }
    if (!sg_buffer_reserve(buffer, length)) {
        return false;
    }
    if (length != 0U) {
        memcpy(buffer->data + buffer->length, data, length);
    }
    buffer->length += length;
    buffer->data[buffer->length] = '\0';
    return true;
}

bool sg_buffer_append_cstr(struct sg_buffer *buffer, const char *text)
{
    return text != NULL && sg_buffer_append(buffer, text, strlen(text));
}

bool sg_buffer_append_format(struct sg_buffer *buffer, const char *format, ...)
{
    va_list arguments;
    va_list copy;
    int needed;
    size_t amount;

    if (format == NULL) {
        return false;
    }

    va_start(arguments, format);
    va_copy(copy, arguments);
    needed = vsnprintf(NULL, 0U, format, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(arguments);
        return false;
    }
    amount = (size_t)needed;
    if (!sg_buffer_reserve(buffer, amount)) {
        va_end(arguments);
        return false;
    }
    needed = vsnprintf(buffer->data + buffer->length,
                       buffer->capacity - buffer->length, format, arguments);
    va_end(arguments);
    if (needed < 0 || (size_t)needed != amount) {
        return false;
    }
    buffer->length += amount;
    return true;
}
