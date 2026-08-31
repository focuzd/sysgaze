#include "sysgaze/filter.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "sysgaze/syscall_catalog.h"

static void set_error(char *error, size_t error_size, const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static void set_number(struct sg_filter *filter, long number, bool enabled)
{
    size_t index;
    unsigned int offset;
    uint64_t mask;

    if (number < 0 || (unsigned long)number >= SG_SYSCALL_LIMIT) {
        return;
    }
    index = (size_t)((unsigned long)number / SG_FILTER_WORD_BITS);
    offset = (unsigned int)((unsigned long)number % SG_FILTER_WORD_BITS);
    mask = UINT64_C(1) << offset;
    if (enabled) {
        filter->words[index] |= mask;
    } else {
        filter->words[index] &= ~mask;
    }
}

void sg_filter_clear(struct sg_filter *filter)
{
    memset(filter->words, 0, sizeof(filter->words));
    filter->active = false;
}

void sg_filter_fill(struct sg_filter *filter)
{
    size_t index;

    for (index = 0U; index < SG_FILTER_WORDS; ++index) {
        filter->words[index] = UINT64_MAX;
    }
    filter->active = true;
}

bool sg_filter_contains(const struct sg_filter *filter, long syscall_number)
{
    size_t index;
    unsigned int offset;

    if (syscall_number < 0 ||
        (unsigned long)syscall_number >= SG_SYSCALL_LIMIT) {
        return false;
    }
    index = (size_t)((unsigned long)syscall_number / SG_FILTER_WORD_BITS);
    offset = (unsigned int)((unsigned long)syscall_number % SG_FILTER_WORD_BITS);
    return (filter->words[index] & (UINT64_C(1) << offset)) != 0U;
}

size_t sg_filter_count(const struct sg_filter *filter)
{
    size_t index;
    size_t count = 0U;

    for (index = 0U; index < SG_FILTER_WORDS; ++index) {
        uint64_t word = filter->words[index];

        while (word != 0U) {
            word &= word - 1U;
            ++count;
        }
    }
    return count;
}

static void apply_class(struct sg_filter *filter, uint32_t class_mask,
                        bool enabled)
{
    const struct sg_syscall_descriptor *catalog;
    size_t count;
    size_t index;

    catalog = sg_syscall_catalog(&count);
    for (index = 0U; index < count; ++index) {
        if ((catalog[index].classes & class_mask) != 0U) {
            set_number(filter, catalog[index].number, enabled);
        }
    }
}

static bool has_positive_term(const char *expression)
{
    const char *cursor = expression;

    while (*cursor != '\0') {
        if (*cursor != '!' && *cursor != ',') {
            return true;
        }
        cursor = strchr(cursor, ',');
        if (cursor == NULL) {
            break;
        }
        ++cursor;
    }
    return false;
}

bool sg_filter_parse(struct sg_filter *filter, const char *spec,
                     char *error, size_t error_size)
{
    struct sg_filter candidate;
    const char prefix[] = "trace=";
    const char *expression;
    const char *cursor;

    if (filter == NULL || spec == NULL) {
        set_error(error, error_size, "filter specification is missing");
        return false;
    }
    if (strncmp(spec, prefix, sizeof(prefix) - 1U) != 0) {
        set_error(error, error_size, "filter must start with 'trace='");
        return false;
    }
    expression = spec + sizeof(prefix) - 1U;
    if (*expression == '\0') {
        set_error(error, error_size, "filter expression is empty");
        return false;
    }

    if (has_positive_term(expression)) {
        sg_filter_clear(&candidate);
        candidate.active = true;
    } else {
        sg_filter_fill(&candidate);
    }

    cursor = expression;
    while (*cursor != '\0') {
        const char *comma = strchr(cursor, ',');
        const char *term_end = comma == NULL ? cursor + strlen(cursor) : comma;
        const char *term = cursor;
        size_t term_length;
        bool enabled = true;
        char name[128];
        uint32_t class_mask;
        const struct sg_syscall_descriptor *descriptor;

        if (*term == '!') {
            enabled = false;
            ++term;
        }
        term_length = (size_t)(term_end - term);
        if (term_length == 0U) {
            set_error(error, error_size, "filter contains an empty term");
            return false;
        }
        if (term_length >= sizeof(name)) {
            set_error(error, error_size, "filter term is too long");
            return false;
        }
        memcpy(name, term, term_length);
        name[term_length] = '\0';

        if (name[0] == '%') {
            if (!sg_syscall_class_by_name(name + 1, &class_mask)) {
                set_error(error, error_size, "unknown syscall class '%s'", name);
                return false;
            }
            apply_class(&candidate, class_mask, enabled);
        } else {
            descriptor = sg_syscall_by_name(name);
            if (descriptor == NULL) {
                set_error(error, error_size, "unknown syscall '%s'", name);
                return false;
            }
            set_number(&candidate, descriptor->number, enabled);
        }

        if (comma == NULL) {
            break;
        }
        cursor = comma + 1;
        if (*cursor == '\0') {
            set_error(error, error_size, "filter contains an empty term");
            return false;
        }
    }
    *filter = candidate;
    return true;
}
