#ifndef SYSGAZE_DECODER_H
#define SYSGAZE_DECODER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "sysgaze/buffer.h"
#include "sysgaze/event.h"

struct sg_memory_reader {
    void *context;
    bool (*read)(void *context, pid_t tid, uintptr_t address,
                 void *destination, size_t length, size_t *bytes_read);
};

struct sg_decoder {
    size_t string_limit;
    struct sg_memory_reader memory;
};

bool sg_decode_syscall(const struct sg_decoder *decoder,
                       pid_t tid,
                       const struct sg_syscall_event *event,
                       struct sg_buffer *output);
bool sg_decoder_capture_entry(const struct sg_decoder *decoder, pid_t tid,
                              struct sg_syscall_event *event);
void sg_decoder_release_event(struct sg_syscall_event *event);

#endif
