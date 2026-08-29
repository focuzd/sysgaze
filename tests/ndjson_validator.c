#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

struct parser {
    const char *cursor;
    unsigned int depth;
};

static void skip_space(struct parser *parser)
{
    while (*parser->cursor == ' ' || *parser->cursor == '\t' ||
           *parser->cursor == '\r' || *parser->cursor == '\n') {
        ++parser->cursor;
    }
}

static bool parse_value(struct parser *parser);

static bool parse_string(struct parser *parser)
{
    if (*parser->cursor++ != '"') {
        return false;
    }
    while (*parser->cursor != '\0' && *parser->cursor != '"') {
        unsigned char byte = (unsigned char)*parser->cursor++;

        if (byte < 0x20U) {
            return false;
        }
        if (byte == '\\') {
            char escape = *parser->cursor++;
            unsigned int index;

            if (escape == 'u') {
                for (index = 0U; index < 4U; ++index) {
                    if (!isxdigit((unsigned char)*parser->cursor++)) {
                        return false;
                    }
                }
            } else if (strchr("\"\\/bfnrt", escape) == NULL) {
                return false;
            }
        }
    }
    if (*parser->cursor != '"') {
        return false;
    }
    ++parser->cursor;
    return true;
}

static bool parse_number(struct parser *parser)
{
    const char *start = parser->cursor;

    if (*parser->cursor == '-') {
        ++parser->cursor;
    }
    if (*parser->cursor == '0') {
        ++parser->cursor;
    } else {
        if (!isdigit((unsigned char)*parser->cursor)) {
            return false;
        }
        while (isdigit((unsigned char)*parser->cursor)) {
            ++parser->cursor;
        }
    }
    if (*parser->cursor == '.') {
        ++parser->cursor;
        if (!isdigit((unsigned char)*parser->cursor)) {
            return false;
        }
        while (isdigit((unsigned char)*parser->cursor)) {
            ++parser->cursor;
        }
    }
    if (*parser->cursor == 'e' || *parser->cursor == 'E') {
        ++parser->cursor;
        if (*parser->cursor == '+' || *parser->cursor == '-') {
            ++parser->cursor;
        }
        if (!isdigit((unsigned char)*parser->cursor)) {
            return false;
        }
        while (isdigit((unsigned char)*parser->cursor)) {
            ++parser->cursor;
        }
    }
    return parser->cursor != start;
}

static bool parse_array(struct parser *parser)
{
    ++parser->cursor;
    skip_space(parser);
    if (*parser->cursor == ']') {
        ++parser->cursor;
        return true;
    }
    for (;;) {
        if (!parse_value(parser)) {
            return false;
        }
        skip_space(parser);
        if (*parser->cursor == ']') {
            ++parser->cursor;
            return true;
        }
        if (*parser->cursor++ != ',') {
            return false;
        }
        skip_space(parser);
    }
}

static bool parse_object(struct parser *parser)
{
    ++parser->cursor;
    skip_space(parser);
    if (*parser->cursor == '}') {
        ++parser->cursor;
        return true;
    }
    for (;;) {
        if (!parse_string(parser)) {
            return false;
        }
        skip_space(parser);
        if (*parser->cursor++ != ':') {
            return false;
        }
        skip_space(parser);
        if (!parse_value(parser)) {
            return false;
        }
        skip_space(parser);
        if (*parser->cursor == '}') {
            ++parser->cursor;
            return true;
        }
        if (*parser->cursor++ != ',') {
            return false;
        }
        skip_space(parser);
    }
}

static bool parse_value(struct parser *parser)
{
    bool result;

    if (++parser->depth > 64U) {
        return false;
    }
    if (*parser->cursor == '"') {
        result = parse_string(parser);
    } else if (*parser->cursor == '{') {
        result = parse_object(parser);
    } else if (*parser->cursor == '[') {
        result = parse_array(parser);
    } else if (strncmp(parser->cursor, "true", 4U) == 0) {
        parser->cursor += 4;
        result = true;
    } else if (strncmp(parser->cursor, "false", 5U) == 0) {
        parser->cursor += 5;
        result = true;
    } else if (strncmp(parser->cursor, "null", 4U) == 0) {
        parser->cursor += 4;
        result = true;
    } else {
        result = parse_number(parser);
    }
    --parser->depth;
    return result;
}

static bool valid_json_line(const char *line)
{
    struct parser parser = {.cursor = line, .depth = 0U};

    skip_space(&parser);
    if (!parse_value(&parser)) {
        return false;
    }
    skip_space(&parser);
    return *parser.cursor == '\0';
}

int main(int argc, char **argv)
{
    FILE *stream;
    char *line = NULL;
    size_t capacity = 0U;
    ssize_t amount;
    size_t line_number = 0U;
    bool saw_metadata = false;
    bool saw_getpid = false;
    bool saw_exit = false;
    bool syntax_only;
    bool summary;
    bool saw_summary = false;

    if (argc != 2 && argc != 3) {
        return 2;
    }
    syntax_only = argc == 3 && strcmp(argv[2], "syntax-only") == 0;
    summary = argc == 3 && strcmp(argv[2], "summary") == 0;
    if (argc == 3 && !syntax_only && !summary) {
        return 2;
    }
    stream = fopen(argv[1], "r");
    if (stream == NULL) {
        return 2;
    }
    while ((amount = getline(&line, &capacity, stream)) >= 0) {
        ++line_number;
        while (amount > 0 &&
               (line[(size_t)amount - 1U] == '\n' ||
                line[(size_t)amount - 1U] == '\r')) {
            line[--amount] = '\0';
        }
        if (!valid_json_line(line) ||
            strstr(line, summary ? "\"schema\":\"sysgaze.summary/v1\""
                                 : "\"schema\":\"sysgaze.trace/v1\"") ==
                NULL) {
            free(line);
            (void)fclose(stream);
            return 1;
        }
        if (!summary && line_number > 1U &&
            strstr(line, "\"timestamp_ns\":\"") == NULL) {
            free(line);
            (void)fclose(stream);
            return 1;
        }
        if (line_number == 1U &&
            strstr(line, "\"type\":\"metadata\"") != NULL) {
            saw_metadata = true;
        }
        if (line_number == 1U &&
            strstr(line, "\"type\":\"summary\"") != NULL &&
            strstr(line, "\"total_calls\":\"") != NULL &&
            strstr(line, "\"syscalls\":[") != NULL) {
            saw_summary = true;
        }
        if (strstr(line, "\"type\":\"syscall\"") != NULL &&
            strstr(line, "\"number\":\"39\"") != NULL &&
            strstr(line, "\"name\":\"getpid\"") != NULL &&
            strstr(line, "\"text\":\"getpid() = ") != NULL) {
            saw_getpid = true;
        }
        if (strstr(line, "\"type\":\"process-exit\"") != NULL &&
            strstr(line, "\"status\":7") != NULL &&
            strstr(line, "\"signaled\":false") != NULL) {
            saw_exit = true;
        }
    }
    free(line);
    if (ferror(stream) != 0 || fclose(stream) != 0) {
        return 2;
    }
    if (summary) {
        return line_number == 1U && saw_summary ? 0 : 1;
    }
    return saw_metadata && line_number > 1U &&
                   (syntax_only || (saw_getpid && saw_exit))
               ? 0
               : 1;
}
