#define _POSIX_C_SOURCE 200809L
#define JSMN_STATIC
#define JSMN_STRICT

#include "iphm.h"
#include "jsmn.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define IPHM_MAX_JSON_TOKENS 262144U
#define IPHM_MAX_CAIDA_PAGES 4096U
#define IPHM_RIS_RESPONSE_MAX 65536U
#define IPHM_CAIDA_BASE "https://api.spoofer.caida.org"
#define IPHM_ASRANK_BASE "https://api.asrank.caida.org"
#define IPHM_USER_AGENT "iphm-check/1.0 (+https://github.com/OVHGERMANY/SpoofFinder)"

typedef struct {
    const char *text;
    size_t length;
    jsmntok_t *tokens;
    int count;
} JsonDoc;

typedef struct {
    bool session_present;
    uint64_t session;
    bool timestamp_present;
    char timestamp[IPHM_TIMESTAMP_MAX];
    int64_t timestamp_key;
    bool asn4_present;
    uint32_t asn4;
    bool asn6_present;
    uint32_t asn6;
    bool client4_present;
    char client4[IPHM_PREFIX_MAX];
    bool client6_present;
    char client6[IPHM_PREFIX_MAX];
    bool private4_present;
    char private4[IPHM_STATUS_MAX];
    bool routed4_present;
    char routed4[IPHM_STATUS_MAX];
    bool private6_present;
    char private6[IPHM_STATUS_MAX];
    bool routed6_present;
    char routed6[IPHM_STATUS_MAX];
} Session;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
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

static int copy_span(char *destination, size_t capacity, const char *source,
                     size_t length)
{
    if (destination == NULL || source == NULL || capacity == 0U ||
        length >= capacity) {
        return -1;
    }
    (void)memcpy(destination, source, length);
    destination[length] = '\0';
    return 0;
}

static int parse_uint64_text(const char *text, size_t length, uint64_t *value)
{
    uint64_t result = 0U;
    size_t index;

    if (text == NULL || value == NULL || length == 0U) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        unsigned int digit;

        if (text[index] < '0' || text[index] > '9') {
            return -1;
        }
        digit = (unsigned int)(text[index] - '0');
        if (result > (UINT64_MAX - (uint64_t)digit) / 10U) {
            return -1;
        }
        result = result * 10U + (uint64_t)digit;
    }
    *value = result;
    return 0;
}

static int parse_asn_text(const char *text, size_t length, uint32_t *asn)
{
    size_t offset = 0U;
    uint64_t value;

    if (length >= 2U && (text[0] == 'A' || text[0] == 'a') &&
        (text[1] == 'S' || text[1] == 's')) {
        offset = 2U;
    }
    if (parse_uint64_text(text + offset, length - offset, &value) != 0 ||
        value == 0U || value > UINT32_MAX) {
        return -1;
    }
    *asn = (uint32_t)value;
    return 0;
}

int iphm_parse_target(const char *text, IphmTarget *target, char *error,
                      size_t error_size)
{
    const char *slash;
    size_t length;
    size_t address_length;
    char address[IPHM_ADDRESS_MAX];
    unsigned char binary[16];
    int family;

    if (text == NULL || target == NULL) {
        set_error(error, error_size, "target is missing");
        return -1;
    }
    length = strlen(text);
    if (length == 0U || length >= IPHM_INPUT_MAX) {
        set_error(error, error_size, "target is empty or too long");
        return -1;
    }

    (void)memset(target, 0, sizeof(*target));
    if (copy_span(target->original, sizeof(target->original), text, length) !=
        0) {
        set_error(error, error_size, "target is too long");
        return -1;
    }

    if ((length >= 2U && (text[0] == 'A' || text[0] == 'a') &&
         (text[1] == 'S' || text[1] == 's')) ||
        (text[0] >= '0' && text[0] <= '9' && strchr(text, '.') == NULL &&
         strchr(text, ':') == NULL && strchr(text, '/') == NULL)) {
        if (parse_asn_text(text, length, &target->asn) != 0) {
            set_error(error, error_size, "invalid ASN '%s'", text);
            return -1;
        }
        target->kind = IPHM_TARGET_ASN;
        return 0;
    }

    slash = strchr(text, '/');
    if (slash != NULL && strchr(slash + 1, '/') != NULL) {
        set_error(error, error_size, "invalid CIDR '%s'", text);
        return -1;
    }
    address_length = slash == NULL ? length : (size_t)(slash - text);
    if (address_length == 0U || address_length >= sizeof(address) ||
        copy_span(address, sizeof(address), text, address_length) != 0) {
        set_error(error, error_size, "invalid IP address '%s'", text);
        return -1;
    }

    if (inet_pton(AF_INET, address, binary) == 1) {
        family = 4;
        if (inet_ntop(AF_INET, binary, target->address,
                      (socklen_t)sizeof(target->address)) == NULL) {
            set_error(error, error_size, "could not normalize IPv4 address");
            return -1;
        }
    } else if (inet_pton(AF_INET6, address, binary) == 1) {
        family = 6;
        if (inet_ntop(AF_INET6, binary, target->address,
                      (socklen_t)sizeof(target->address)) == NULL) {
            set_error(error, error_size, "could not normalize IPv6 address");
            return -1;
        }
    } else {
        set_error(error, error_size, "invalid ASN, IP address, or CIDR '%s'",
                  text);
        return -1;
    }

    if (slash != NULL) {
        uint64_t prefix_length;
        size_t prefix_text_length = length - address_length - 1U;
        uint64_t maximum = family == 4 ? 32U : 128U;

        if (parse_uint64_text(slash + 1, prefix_text_length, &prefix_length) !=
                0 ||
            prefix_length > maximum) {
            set_error(error, error_size, "invalid CIDR prefix length");
            return -1;
        }
        target->is_cidr = true;
    }
    target->kind = IPHM_TARGET_ADDRESS;
    target->address_family = family;
    return 0;
}

static bool valid_json_number(const char *text, size_t length)
{
    size_t index = 0U;

    if (length == 0U) {
        return false;
    }
    if (text[index] == '-') {
        ++index;
        if (index == length) {
            return false;
        }
    }
    if (text[index] == '0') {
        ++index;
    } else {
        if (text[index] < '1' || text[index] > '9') {
            return false;
        }
        do {
            ++index;
        } while (index < length && text[index] >= '0' && text[index] <= '9');
    }
    if (index < length && text[index] == '.') {
        ++index;
        if (index == length || text[index] < '0' || text[index] > '9') {
            return false;
        }
        do {
            ++index;
        } while (index < length && text[index] >= '0' && text[index] <= '9');
    }
    if (index < length && (text[index] == 'e' || text[index] == 'E')) {
        ++index;
        if (index < length && (text[index] == '+' || text[index] == '-')) {
            ++index;
        }
        if (index == length || text[index] < '0' || text[index] > '9') {
            return false;
        }
        do {
            ++index;
        } while (index < length && text[index] >= '0' && text[index] <= '9');
    }
    return index == length;
}

static bool valid_primitive(const char *text, size_t length)
{
    return (length == 4U && memcmp(text, "true", 4U) == 0) ||
           (length == 5U && memcmp(text, "false", 5U) == 0) ||
           (length == 4U && memcmp(text, "null", 4U) == 0) ||
           valid_json_number(text, length);
}

static int token_after(const JsonDoc *document, int index)
{
    int next = index + 1;
    int end = document->tokens[index].end;

    while (next < document->count &&
           document->tokens[next].start < end) {
        ++next;
    }
    return next;
}

static int validate_object(const JsonDoc *document, int object)
{
    int position = object + 1;
    int pair;

    if (document->tokens[object].type != JSMN_OBJECT) {
        return -1;
    }
    for (pair = 0; pair < document->tokens[object].size; ++pair) {
        int value;

        if (position >= document->count ||
            document->tokens[position].type != JSMN_STRING) {
            return -1;
        }
        value = position + 1;
        if (value >= document->count) {
            return -1;
        }
        position = token_after(document, value);
    }
    return position == token_after(document, object) ? 0 : -1;
}

static int json_parse(const char *text, size_t length, JsonDoc *document,
                      char *error, size_t error_size)
{
    unsigned int capacity = 256U;
    jsmntok_t *tokens = NULL;
    int parsed = JSMN_ERROR_NOMEM;
    size_t index;

    if (text == NULL || document == NULL || length == 0U ||
        length > IPHM_MAX_RESPONSE) {
        set_error(error, error_size, "empty or oversized JSON response");
        return -1;
    }
    while (parsed == JSMN_ERROR_NOMEM && capacity <= IPHM_MAX_JSON_TOKENS) {
        jsmn_parser parser;
        jsmntok_t *replacement =
            realloc(tokens, (size_t)capacity * sizeof(*tokens));

        if (replacement == NULL) {
            free(tokens);
            set_error(error, error_size, "out of memory parsing JSON");
            return -1;
        }
        tokens = replacement;
        jsmn_init(&parser);
        parsed = jsmn_parse(&parser, text, length, tokens, capacity);
        if (parsed == JSMN_ERROR_NOMEM) {
            if (capacity > IPHM_MAX_JSON_TOKENS / 2U) {
                break;
            }
            capacity *= 2U;
        }
    }
    if (parsed < 1) {
        free(tokens);
        set_error(error, error_size, "malformed or overly complex JSON");
        return -1;
    }

    document->text = text;
    document->length = length;
    document->tokens = tokens;
    document->count = parsed;

    for (index = 0U; index < (size_t)tokens[0].start; ++index) {
        if (text[index] != ' ' && text[index] != '\t' &&
            text[index] != '\r' && text[index] != '\n') {
            free(tokens);
            set_error(error, error_size, "invalid data before JSON document");
            return -1;
        }
    }
    for (index = (size_t)tokens[0].end; index < length; ++index) {
        if (text[index] != ' ' && text[index] != '\t' &&
            text[index] != '\r' && text[index] != '\n') {
            free(tokens);
            set_error(error, error_size, "multiple or trailing JSON values");
            return -1;
        }
    }
    if (token_after(document, 0) != parsed) {
        free(tokens);
        set_error(error, error_size, "multiple JSON root values");
        return -1;
    }
    for (index = 0U; index < (size_t)parsed; ++index) {
        const jsmntok_t *token = &tokens[index];

        if (token->start < 0 || token->end < token->start ||
            (size_t)token->end > length) {
            free(tokens);
            set_error(error, error_size, "invalid JSON token bounds");
            return -1;
        }
        if (token->type == JSMN_PRIMITIVE &&
            !valid_primitive(text + token->start,
                             (size_t)(token->end - token->start))) {
            free(tokens);
            set_error(error, error_size, "invalid JSON primitive");
            return -1;
        }
        if (token->type == JSMN_OBJECT &&
            validate_object(document, (int)index) != 0) {
            free(tokens);
            set_error(error, error_size, "invalid JSON object");
            return -1;
        }
    }
    return 0;
}

static void json_free(JsonDoc *document)
{
    free(document->tokens);
    document->tokens = NULL;
    document->count = 0;
}

static bool token_equals(const JsonDoc *document, int token,
                         const char *text)
{
    size_t length = strlen(text);
    const jsmntok_t *item = &document->tokens[token];

    return item->type == JSMN_STRING &&
           (size_t)(item->end - item->start) == length &&
           memcmp(document->text + item->start, text, length) == 0;
}

static int object_field(const JsonDoc *document, int object,
                        const char *name)
{
    int position;
    int pair;
    int found = -1;

    if (validate_object(document, object) != 0) {
        return -2;
    }
    position = object + 1;
    for (pair = 0; pair < document->tokens[object].size; ++pair) {
        int value = position + 1;

        if (token_equals(document, position, name)) {
            if (found >= 0) {
                return -2;
            }
            found = value;
        }
        position = token_after(document, value);
    }
    return found;
}

static bool token_is_null(const JsonDoc *document, int token)
{
    const jsmntok_t *item = &document->tokens[token];

    return item->type == JSMN_PRIMITIVE &&
           item->end - item->start == 4 &&
           memcmp(document->text + item->start, "null", 4U) == 0;
}

static int hex_value(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int append_utf8(char *output, size_t capacity, size_t *used,
                       uint32_t codepoint)
{
    unsigned char encoded[4];
    size_t count;
    size_t index;

    if (codepoint == 0U || codepoint > 0x10ffffU ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
        return -1;
    }
    if (codepoint <= 0x7fU) {
        encoded[0] = (unsigned char)codepoint;
        count = 1U;
    } else if (codepoint <= 0x7ffU) {
        encoded[0] = (unsigned char)(0xc0U | (codepoint >> 6U));
        encoded[1] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 2U;
    } else if (codepoint <= 0xffffU) {
        encoded[0] = (unsigned char)(0xe0U | (codepoint >> 12U));
        encoded[1] =
            (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 3U;
    } else {
        encoded[0] = (unsigned char)(0xf0U | (codepoint >> 18U));
        encoded[1] =
            (unsigned char)(0x80U | ((codepoint >> 12U) & 0x3fU));
        encoded[2] =
            (unsigned char)(0x80U | ((codepoint >> 6U) & 0x3fU));
        encoded[3] = (unsigned char)(0x80U | (codepoint & 0x3fU));
        count = 4U;
    }
    if (*used > capacity || count >= capacity - *used) {
        return -1;
    }
    for (index = 0U; index < count; ++index) {
        output[*used + index] = (char)encoded[index];
    }
    *used += count;
    return 0;
}

static int decode_json_string(const JsonDoc *document, int token, char *output,
                              size_t capacity)
{
    const jsmntok_t *item = &document->tokens[token];
    size_t input;
    size_t end;
    size_t used = 0U;

    if (item->type != JSMN_STRING || capacity == 0U) {
        return -1;
    }
    input = (size_t)item->start;
    end = (size_t)item->end;
    while (input < end) {
        unsigned char character = (unsigned char)document->text[input++];

        if (character != (unsigned char)'\\') {
            if (character < 0x20U || used + 1U >= capacity) {
                return -1;
            }
            output[used++] = (char)character;
            continue;
        }
        if (input >= end) {
            return -1;
        }
        character = (unsigned char)document->text[input++];
        if (character == (unsigned char)'"' ||
            character == (unsigned char)'\\' ||
            character == (unsigned char)'/') {
            if (used + 1U >= capacity) {
                return -1;
            }
            output[used++] = (char)character;
        } else if (character == (unsigned char)'b' ||
                   character == (unsigned char)'f' ||
                   character == (unsigned char)'n' ||
                   character == (unsigned char)'r' ||
                   character == (unsigned char)'t') {
            static const char escaped[] = {'\b', '\f', '\n', '\r', '\t'};
            const char names[] = {'b', 'f', 'n', 'r', 't'};
            size_t escape_index;

            for (escape_index = 0U; escape_index < sizeof(names);
                 ++escape_index) {
                if ((char)character == names[escape_index]) {
                    if (used + 1U >= capacity) {
                        return -1;
                    }
                    output[used++] = escaped[escape_index];
                    break;
                }
            }
        } else if (character == (unsigned char)'u') {
            uint32_t codepoint = 0U;
            size_t digit;

            if (end - input < 4U) {
                return -1;
            }
            for (digit = 0U; digit < 4U; ++digit) {
                int value = hex_value(document->text[input++]);

                if (value < 0) {
                    return -1;
                }
                codepoint = codepoint * 16U + (uint32_t)value;
            }
            if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                uint32_t low = 0U;

                if (end - input < 6U || document->text[input] != '\\' ||
                    document->text[input + 1U] != 'u') {
                    return -1;
                }
                input += 2U;
                for (digit = 0U; digit < 4U; ++digit) {
                    int value = hex_value(document->text[input++]);

                    if (value < 0) {
                        return -1;
                    }
                    low = low * 16U + (uint32_t)value;
                }
                if (low < 0xdc00U || low > 0xdfffU) {
                    return -1;
                }
                codepoint =
                    0x10000U + ((codepoint - 0xd800U) << 10U) +
                    (low - 0xdc00U);
            }
            if (append_utf8(output, capacity, &used, codepoint) != 0) {
                return -1;
            }
        } else {
            return -1;
        }
    }
    output[used] = '\0';
    return 0;
}

static int token_uint64(const JsonDoc *document, int token, bool allow_string,
                        uint64_t *value)
{
    const jsmntok_t *item = &document->tokens[token];

    if (item->type != JSMN_PRIMITIVE &&
        !(allow_string && item->type == JSMN_STRING)) {
        return -1;
    }
    return parse_uint64_text(document->text + item->start,
                             (size_t)(item->end - item->start), value);
}

static int optional_string(const JsonDoc *document, int object,
                           const char *name, char *output, size_t capacity,
                           bool *present, char *error, size_t error_size)
{
    int token = object_field(document, object, name);

    *present = false;
    if (token == -1) {
        return 0;
    }
    if (token < 0) {
        set_error(error, error_size, "duplicate or malformed '%s'", name);
        return -1;
    }
    if (token_is_null(document, token)) {
        return 0;
    }
    if (decode_json_string(document, token, output, capacity) != 0) {
        set_error(error, error_size, "'%s' is not a bounded JSON string", name);
        return -1;
    }
    *present = true;
    return 0;
}

static int optional_uint(const JsonDoc *document, int object, const char *name,
                         bool allow_string, uint64_t *value, bool *present,
                         char *error, size_t error_size)
{
    int token = object_field(document, object, name);

    *present = false;
    if (token == -1) {
        return 0;
    }
    if (token < 0) {
        set_error(error, error_size, "duplicate or malformed '%s'", name);
        return -1;
    }
    if (token_is_null(document, token)) {
        return 0;
    }
    if (token_uint64(document, token, allow_string, value) != 0) {
        set_error(error, error_size, "'%s' is not an unsigned integer", name);
        return -1;
    }
    *present = true;
    return 0;
}

static int optional_bool(const JsonDoc *document, int object, const char *name,
                         bool *value, bool *present, char *error,
                         size_t error_size)
{
    int token = object_field(document, object, name);
    const jsmntok_t *item;
    size_t length;

    *present = false;
    if (token == -1) {
        return 0;
    }
    if (token < 0) {
        set_error(error, error_size, "duplicate or malformed '%s'", name);
        return -1;
    }
    if (token_is_null(document, token)) {
        return 0;
    }
    item = &document->tokens[token];
    length = (size_t)(item->end - item->start);
    if (item->type != JSMN_PRIMITIVE) {
        set_error(error, error_size, "'%s' is not a boolean", name);
        return -1;
    }
    if (length == 4U &&
        memcmp(document->text + item->start, "true", 4U) == 0) {
        *value = true;
    } else if (length == 5U &&
               memcmp(document->text + item->start, "false", 5U) == 0) {
        *value = false;
    } else {
        set_error(error, error_size, "'%s' is not a boolean", name);
        return -1;
    }
    *present = true;
    return 0;
}

static int optional_object(const JsonDoc *document, int object,
                           const char *name, int *value, bool *present,
                           char *error, size_t error_size)
{
    int token = object_field(document, object, name);

    *present = false;
    if (token == -1 || (token >= 0 && token_is_null(document, token))) {
        return 0;
    }
    if (token < 0 || document->tokens[token].type != JSMN_OBJECT ||
        validate_object(document, token) != 0) {
        set_error(error, error_size, "'%s' is not an object", name);
        return -1;
    }
    *value = token;
    *present = true;
    return 0;
}

static int fixed_digits(const char *text, size_t offset, size_t count,
                        int64_t *value)
{
    size_t index;
    int64_t result = 0;

    for (index = 0U; index < count; ++index) {
        char character = text[offset + index];

        if (character < '0' || character > '9') {
            return -1;
        }
        result = result * 10 + (int64_t)(character - '0');
    }
    *value = result;
    return 0;
}

static int64_t days_from_civil(int64_t year, int64_t month, int64_t day)
{
    int64_t era;
    int64_t year_of_era;
    int64_t day_of_year;
    int64_t day_of_era;

    year -= month <= 2 ? 1 : 0;
    era = (year >= 0 ? year : year - 399) / 400;
    year_of_era = year - era * 400;
    day_of_year =
        (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 +
        day_of_year;
    return era * 146097 + day_of_era - 719468;
}

static bool leap_year(int64_t year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

int iphm_parse_timestamp_key(const char *text, int64_t *key)
{
    size_t length = strlen(text);
    size_t position = 19U;
    int64_t year;
    int64_t month;
    int64_t day;
    int64_t hour;
    int64_t minute;
    int64_t second;
    int64_t offset_hour = 0;
    int64_t offset_minute = 0;
    int64_t offset_sign = 0;
    static const int month_lengths[] = {
        0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    };
    int maximum_day;

    if (length < 20U || text[4] != '-' || text[7] != '-' ||
        (text[10] != 'T' && text[10] != 't') || text[13] != ':' ||
        text[16] != ':' ||
        fixed_digits(text, 0U, 4U, &year) != 0 ||
        fixed_digits(text, 5U, 2U, &month) != 0 ||
        fixed_digits(text, 8U, 2U, &day) != 0 ||
        fixed_digits(text, 11U, 2U, &hour) != 0 ||
        fixed_digits(text, 14U, 2U, &minute) != 0 ||
        fixed_digits(text, 17U, 2U, &second) != 0) {
        return -1;
    }
    if (month < 1 || month > 12 || hour > 23 || minute > 59 ||
        second > 60) {
        return -1;
    }
    maximum_day = month_lengths[(size_t)month];
    if (month == 2 && leap_year(year)) {
        ++maximum_day;
    }
    if (day < 1 || day > maximum_day) {
        return -1;
    }
    if (position < length && text[position] == '.') {
        size_t first_fraction;

        ++position;
        first_fraction = position;
        while (position < length && text[position] >= '0' &&
               text[position] <= '9') {
            ++position;
        }
        if (position == first_fraction) {
            return -1;
        }
    }
    if (position < length &&
        (text[position] == 'Z' || text[position] == 'z')) {
        ++position;
    } else if (position + 6U == length &&
               (text[position] == '+' || text[position] == '-') &&
               text[position + 3U] == ':' &&
               fixed_digits(text, position + 1U, 2U, &offset_hour) == 0 &&
               fixed_digits(text, position + 4U, 2U, &offset_minute) == 0) {
        offset_sign = text[position] == '+' ? 1 : -1;
        position += 6U;
        if (offset_hour > 23 || offset_minute > 59) {
            return -1;
        }
    } else {
        return -1;
    }
    if (position != length) {
        return -1;
    }
    *key = days_from_civil(year, month, day) * 86400 +
           hour * 3600 + minute * 60 + second -
           offset_sign * (offset_hour * 3600 + offset_minute * 60);
    return 0;
}

static int optional_asn(const JsonDoc *document, int object, const char *name,
                        uint32_t *asn, bool *present, char *error,
                        size_t error_size)
{
    uint64_t value = 0U;

    if (optional_uint(document, object, name, true, &value, present, error,
                      error_size) != 0) {
        return -1;
    }
    if (*present && (value == 0U || value > UINT32_MAX)) {
        set_error(error, error_size, "'%s' is outside the ASN range", name);
        return -1;
    }
    *asn = (uint32_t)value;
    return 0;
}

static int parse_session(const JsonDoc *document, int object, Session *session,
                         char *error, size_t error_size)
{
    if (document->tokens[object].type != JSMN_OBJECT) {
        set_error(error, error_size, "CAIDA member is not an object");
        return -1;
    }
    (void)memset(session, 0, sizeof(*session));
    if (optional_uint(document, object, "session", false, &session->session,
                      &session->session_present, error, error_size) != 0 ||
        optional_string(document, object, "timestamp", session->timestamp,
                        sizeof(session->timestamp),
                        &session->timestamp_present, error, error_size) != 0 ||
        optional_asn(document, object, "asn4", &session->asn4,
                     &session->asn4_present, error, error_size) != 0 ||
        optional_asn(document, object, "asn6", &session->asn6,
                     &session->asn6_present, error, error_size) != 0 ||
        optional_string(document, object, "client4", session->client4,
                        sizeof(session->client4), &session->client4_present,
                        error, error_size) != 0 ||
        optional_string(document, object, "client6", session->client6,
                        sizeof(session->client6), &session->client6_present,
                        error, error_size) != 0 ||
        optional_string(document, object, "privatespoof", session->private4,
                        sizeof(session->private4), &session->private4_present,
                        error, error_size) != 0 ||
        optional_string(document, object, "routedspoof", session->routed4,
                        sizeof(session->routed4), &session->routed4_present,
                        error, error_size) != 0 ||
        optional_string(document, object, "privatespoof6", session->private6,
                        sizeof(session->private6), &session->private6_present,
                        error, error_size) != 0 ||
        optional_string(document, object, "routedspoof6", session->routed6,
                        sizeof(session->routed6), &session->routed6_present,
                        error, error_size) != 0) {
        return -1;
    }
    if (session->timestamp_present &&
        iphm_parse_timestamp_key(session->timestamp,
                                 &session->timestamp_key) != 0) {
        set_error(error, error_size, "CAIDA timestamp is not RFC 3339");
        return -1;
    }
    return 0;
}

IphmVerdict iphm_derive_verdict(const char *private_source,
                                bool private_present,
                                const char *routable_source,
                                bool routable_present)
{
    bool private_received =
        private_present && strcmp(private_source, "received") == 0;
    bool routable_received =
        routable_present && strcmp(routable_source, "received") == 0;
    bool private_known =
        private_present && (strcmp(private_source, "blocked") == 0 ||
                            strcmp(private_source, "rewritten") == 0);
    bool routable_known =
        routable_present && (strcmp(routable_source, "blocked") == 0 ||
                             strcmp(routable_source, "rewritten") == 0);

    if (private_received || routable_received) {
        return IPHM_VERDICT_SPOOFABLE;
    }
    if (!private_known || !routable_known) {
        return IPHM_VERDICT_INCONCLUSIVE;
    }
    if (strcmp(private_source, "rewritten") == 0 ||
        strcmp(routable_source, "rewritten") == 0) {
        return IPHM_VERDICT_REWRITTEN;
    }
    return IPHM_VERDICT_BLOCKED;
}

static int update_measurement(IphmMeasurement *measurement,
                              const Session *session, bool ipv6)
{
    const char *client = ipv6 ? session->client6 : session->client4;
    const char *private_source =
        ipv6 ? session->private6 : session->private4;
    const char *routable_source =
        ipv6 ? session->routed6 : session->routed4;
    bool client_present =
        ipv6 ? session->client6_present : session->client4_present;
    bool private_present =
        ipv6 ? session->private6_present : session->private4_present;
    bool routable_present =
        ipv6 ? session->routed6_present : session->routed4_present;

    if (measurement->present &&
        (measurement->timestamp_key > session->timestamp_key ||
         (measurement->timestamp_key == session->timestamp_key &&
          measurement->session_id >= session->session))) {
        return 0;
    }
    (void)memset(measurement, 0, sizeof(*measurement));
    measurement->present = true;
    measurement->session_id = session->session;
    measurement->timestamp_key = session->timestamp_key;
    (void)memcpy(measurement->timestamp, session->timestamp,
                 strlen(session->timestamp) + 1U);
    measurement->client_prefix_present = client_present;
    if (client_present) {
        (void)memcpy(measurement->client_prefix, client,
                     strlen(client) + 1U);
    }
    measurement->private_source_present = private_present;
    if (private_present) {
        (void)memcpy(measurement->private_source, private_source,
                     strlen(private_source) + 1U);
    }
    measurement->routable_source_present = routable_present;
    if (routable_present) {
        (void)memcpy(measurement->routable_source, routable_source,
                     strlen(routable_source) + 1U);
    }
    measurement->verdict =
        iphm_derive_verdict(private_source, private_present, routable_source,
                            routable_present);
    return 0;
}

int iphm_parse_caida_page(const char *json, size_t length, uint32_t asn,
                          IphmReport *report, char *next, size_t next_size,
                          char *error, size_t error_size)
{
    JsonDoc document;
    int members;
    int position;
    int member;
    int view;
    bool view_present;

    if (report == NULL || next == NULL || next_size == 0U) {
        set_error(error, error_size, "invalid CAIDA parser arguments");
        return -1;
    }
    next[0] = '\0';
    if (json_parse(json, length, &document, error, error_size) != 0) {
        return -1;
    }
    if (document.tokens[0].type != JSMN_OBJECT) {
        set_error(error, error_size, "CAIDA response root is not an object");
        json_free(&document);
        return -1;
    }
    members = object_field(&document, 0, "hydra:member");
    if (members < 0 || document.tokens[members].type != JSMN_ARRAY) {
        set_error(error, error_size,
                  "CAIDA response has no valid hydra:member array");
        json_free(&document);
        return -1;
    }
    position = members + 1;
    for (member = 0; member < document.tokens[members].size; ++member) {
        Session session;

        if (position >= document.count ||
            parse_session(&document, position, &session, error, error_size) !=
                0) {
            json_free(&document);
            return -1;
        }
        if ((session.asn4_present && session.asn4 == asn) ||
            (session.asn6_present && session.asn6 == asn)) {
            if (!session.session_present || !session.timestamp_present) {
                set_error(error, error_size,
                          "matching CAIDA session lacks identity or timestamp");
                json_free(&document);
                return -1;
            }
        }
        if (session.asn4_present && session.asn4 == asn) {
            (void)update_measurement(&report->ipv4, &session, false);
        }
        if (session.asn6_present && session.asn6 == asn) {
            (void)update_measurement(&report->ipv6, &session, true);
        }
        position = token_after(&document, position);
    }
    if (position != token_after(&document, members)) {
        set_error(error, error_size, "malformed CAIDA member array");
        json_free(&document);
        return -1;
    }

    if (optional_object(&document, 0, "hydra:view", &view, &view_present,
                        error, error_size) != 0) {
        json_free(&document);
        return -1;
    }
    if (view_present) {
        bool next_present;

        if (optional_string(&document, view, "hydra:next", next, next_size,
                            &next_present, error, error_size) != 0) {
            json_free(&document);
            return -1;
        }
        if (!next_present) {
            next[0] = '\0';
        }
    }
    json_free(&document);
    return 0;
}

int iphm_parse_caida_session(const char *json, size_t length,
                             uint64_t expected_session, uint32_t expected_asn,
                             int family, IphmMeasurement *measurement,
                             char *error, size_t error_size)
{
    JsonDoc document;
    Session session;
    bool matching_asn;
    bool client_present;
    bool private_present;
    bool routable_present;

    if (measurement == NULL || (family != 4 && family != 6)) {
        set_error(error, error_size, "invalid CAIDA session arguments");
        return -1;
    }
    if (json_parse(json, length, &document, error, error_size) != 0) {
        return -1;
    }
    if (document.tokens[0].type != JSMN_OBJECT ||
        token_after(&document, 0) != document.count ||
        parse_session(&document, 0, &session, error, error_size) != 0) {
        if (document.tokens[0].type != JSMN_OBJECT) {
            set_error(error, error_size,
                      "CAIDA session response root is not an object");
        }
        json_free(&document);
        return -1;
    }
    matching_asn = family == 4
                       ? session.asn4_present && session.asn4 == expected_asn
                       : session.asn6_present && session.asn6 == expected_asn;
    client_present =
        family == 4 ? session.client4_present : session.client6_present;
    private_present =
        family == 4 ? session.private4_present : session.private6_present;
    routable_present =
        family == 4 ? session.routed4_present : session.routed6_present;
    if (!session.session_present || session.session != expected_session ||
        !session.timestamp_present || !matching_asn || !client_present ||
        !private_present || !routable_present) {
        set_error(error, error_size,
                  "CAIDA session identity, ASN, or result fields do not match");
        json_free(&document);
        return -1;
    }
    (void)memset(measurement, 0, sizeof(*measurement));
    (void)update_measurement(measurement, &session, family == 6);
    json_free(&document);
    return 0;
}

int iphm_validate_caida_next(const char *next, uint32_t asn,
                             uint32_t expected_page, char *error,
                             size_t error_size)
{
    char expected[IPHM_NEXT_MAX];
    int written = snprintf(expected, sizeof(expected),
                           "/sessions?asn=%" PRIu32 "&page=%" PRIu32, asn,
                           expected_page);

    if (written < 0 || (size_t)written >= sizeof(expected) ||
        next == NULL || strcmp(next, expected) != 0) {
        set_error(error, error_size,
                  "pagination target is noncanonical or leaves the query");
        return -1;
    }
    return 0;
}

static int http_get_status(const char *url, unsigned int timeout_seconds,
                           bool allow_not_found, long *status_out, char **body,
                           size_t *body_length, char *error,
                           size_t error_size)
{
    CURL *curl = curl_easy_init();
    CURLcode code;
    long status = 0L;
    char *buffer;
    FILE *stream;
    long stream_position;
    size_t response_length = 0U;
    bool stream_failed = false;
    bool overflow = false;
    struct curl_slist *headers = NULL;

    *body = NULL;
    *body_length = 0U;
    if (status_out != NULL) {
        *status_out = 0L;
    }
    if (curl == NULL) {
        set_error(error, error_size, "could not create HTTP client");
        return -1;
    }
    buffer = malloc(IPHM_MAX_RESPONSE + 1U);
    if (buffer == NULL) {
        curl_easy_cleanup(curl);
        set_error(error, error_size, "out of memory buffering HTTP response");
        return -1;
    }
    stream = fmemopen(buffer, IPHM_MAX_RESPONSE + 1U, "w");
    if (stream == NULL || setvbuf(stream, NULL, _IONBF, 0U) != 0) {
        if (stream != NULL) {
            (void)fclose(stream);
        }
        free(buffer);
        curl_easy_cleanup(curl);
        set_error(error, error_size, "could not create HTTP response stream");
        return -1;
    }
    headers = curl_slist_append(headers, "Accept: application/ld+json, application/json");
    if (headers == NULL) {
        (void)fclose(stream);
        free(buffer);
        curl_easy_cleanup(curl);
        set_error(error, error_size, "out of memory creating HTTP headers");
        return -1;
    }

    code = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_USERAGENT, IPHM_USER_AGENT);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    }
#if LIBCURL_VERSION_NUM >= 0x075500
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    }
#else
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS,
                                CURLPROTO_HTTPS);
    }
#endif
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
                                (long)timeout_seconds);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_TIMEOUT,
                                (long)timeout_seconds);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_FAILONERROR,
                                allow_not_found ? 0L : 1L);
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    }
    if (code == CURLE_OK) {
        code = curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE,
                                (curl_off_t)IPHM_MAX_RESPONSE);
    }
    if (code == CURLE_OK) {
        code = curl_easy_perform(curl);
    }
    if (code == CURLE_OK) {
        code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    }
    if (fflush(stream) != 0) {
        stream_failed = true;
    }
    stream_position = ftell(stream);
    if (stream_position < 0L || ferror(stream) != 0) {
        stream_failed = true;
    } else {
        response_length = (size_t)stream_position;
        overflow = response_length > IPHM_MAX_RESPONSE ||
                   (code == CURLE_WRITE_ERROR &&
                    response_length == IPHM_MAX_RESPONSE);
    }
    if (fclose(stream) != 0) {
        stream_failed = true;
    }
    if (!overflow && !stream_failed) {
        buffer[response_length] = '\0';
    }

    if (code != CURLE_OK || stream_failed || overflow ||
        ((status < 200L || status >= 300L) &&
         !(allow_not_found && status == 404L)) ||
        (status != 404L && response_length == 0U)) {
        if (overflow) {
            set_error(error, error_size, "response exceeded %u bytes",
                      IPHM_MAX_RESPONSE);
        } else if (code != CURLE_OK) {
            set_error(error, error_size, "%s", curl_easy_strerror(code));
        } else if (stream_failed) {
            set_error(error, error_size, "HTTP response buffering failed");
        } else {
            set_error(error, error_size, "HTTP status %ld or empty response",
                      status);
        }
        free(buffer);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    *body = buffer;
    *body_length = response_length;
    if (status_out != NULL) {
        *status_out = status;
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return 0;
}

static int http_get(const char *url, unsigned int timeout_seconds, char **body,
                    size_t *body_length, char *error, size_t error_size)
{
    long status;

    return http_get_status(url, timeout_seconds, false, &status, body,
                           body_length, error, error_size);
}

int iphm_query_caida_session(uint64_t session_id, uint32_t asn, int family,
                             unsigned int timeout_seconds, bool *found,
                             IphmMeasurement *measurement, char *error,
                             size_t error_size)
{
    char url[256];
    char *body = NULL;
    size_t body_length = 0U;
    long status = 0L;
    int written;
    int result;

    if (found == NULL || measurement == NULL ||
        (family != 4 && family != 6)) {
        set_error(error, error_size, "invalid CAIDA session query arguments");
        return -1;
    }
    *found = false;
    (void)memset(measurement, 0, sizeof(*measurement));
    written = snprintf(url, sizeof(url), IPHM_CAIDA_BASE "/sessions/%" PRIu64,
                       session_id);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        set_error(error, error_size, "CAIDA session URL is too long");
        return -1;
    }
    if (http_get_status(url, timeout_seconds, true, &status, &body,
                        &body_length, error, error_size) != 0) {
        return -1;
    }
    if (status == 404L) {
        free(body);
        return 0;
    }
    result = iphm_parse_caida_session(body, body_length, session_id, asn,
                                      family, measurement, error, error_size);
    free(body);
    if (result == 0) {
        *found = true;
    }
    return result;
}

int iphm_query_caida(uint32_t asn, unsigned int timeout_seconds,
                     IphmReport *report, char *error, size_t error_size)
{
    char url[IPHM_NEXT_MAX + 64U];
    uint32_t page = 1U;

    (void)memset(&report->ipv4, 0, sizeof(report->ipv4));
    (void)memset(&report->ipv6, 0, sizeof(report->ipv6));
    if (snprintf(url, sizeof(url), IPHM_CAIDA_BASE "/sessions?asn=%" PRIu32,
                 asn) < 0) {
        set_error(error, error_size, "could not construct CAIDA URL");
        return -1;
    }

    while (page <= IPHM_MAX_CAIDA_PAGES) {
        char *body = NULL;
        size_t body_length = 0U;
        char next[IPHM_NEXT_MAX];

        if (http_get(url, timeout_seconds, &body, &body_length, error,
                     error_size) != 0) {
            return -1;
        }
        if (iphm_parse_caida_page(body, body_length, asn, report, next,
                                  sizeof(next), error, error_size) != 0) {
            free(body);
            return -1;
        }
        free(body);
        if (next[0] == '\0') {
            return 0;
        }
        if (page == UINT32_MAX ||
            iphm_validate_caida_next(next, asn, page + 1U, error,
                                     error_size) != 0) {
            return -1;
        }
        if (snprintf(url, sizeof(url), IPHM_CAIDA_BASE "%s", next) < 0 ||
            strlen(url) >= sizeof(url)) {
            set_error(error, error_size, "CAIDA pagination URL is too long");
            return -1;
        }
        ++page;
    }
    set_error(error, error_size, "pagination exceeded %u pages",
              IPHM_MAX_CAIDA_PAGES);
    return -1;
}

int iphm_parse_asrank(const char *json, size_t length, uint32_t expected_asn,
                      IphmAsrank *asrank, char *error, size_t error_size)
{
    JsonDoc document;
    int data;
    int asn_object;
    bool present;
    uint64_t response_asn = 0U;
    int nested;
    bool nested_present;

    (void)memset(asrank, 0, sizeof(*asrank));
    if (json_parse(json, length, &document, error, error_size) != 0) {
        return -1;
    }
    if (document.tokens[0].type != JSMN_OBJECT) {
        set_error(error, error_size, "ASRank response root is not an object");
        json_free(&document);
        return -1;
    }
    data = object_field(&document, 0, "data");
    if (data < 0 || document.tokens[data].type != JSMN_OBJECT) {
        set_error(error, error_size, "ASRank response has no data object");
        json_free(&document);
        return -1;
    }
    asn_object = object_field(&document, data, "asn");
    if (asn_object < 0 || document.tokens[asn_object].type != JSMN_OBJECT) {
        set_error(error, error_size, "ASRank response has no ASN object");
        json_free(&document);
        return -1;
    }
    if (optional_uint(&document, asn_object, "asn", true, &response_asn,
                      &present, error, error_size) != 0 ||
        !present || response_asn != expected_asn ||
        optional_string(&document, asn_object, "asnName", asrank->name,
                        sizeof(asrank->name), &asrank->name_present, error,
                        error_size) != 0 ||
        optional_uint(&document, asn_object, "rank", false, &asrank->rank,
                      &asrank->rank_present, error, error_size) != 0 ||
        optional_bool(&document, asn_object, "seen", &asrank->seen,
                      &asrank->seen_present, error, error_size) != 0) {
        if (present && response_asn != expected_asn) {
            set_error(error, error_size, "ASRank returned a different ASN");
        }
        json_free(&document);
        return -1;
    }

    if (optional_object(&document, asn_object, "country", &nested,
                        &nested_present, error, error_size) != 0) {
        json_free(&document);
        return -1;
    }
    if (nested_present &&
        optional_string(&document, nested, "iso", asrank->country,
                        sizeof(asrank->country), &asrank->country_present,
                        error, error_size) != 0) {
        json_free(&document);
        return -1;
    }
    if (optional_object(&document, asn_object, "cone", &nested,
                        &nested_present, error, error_size) != 0) {
        json_free(&document);
        return -1;
    }
    if (nested_present &&
        (optional_uint(&document, nested, "numberAsns", false,
                       &asrank->cone_asns, &asrank->cone_asns_present, error,
                       error_size) != 0 ||
         optional_uint(&document, nested, "numberPrefixes", false,
                       &asrank->cone_prefixes,
                       &asrank->cone_prefixes_present, error,
                       error_size) != 0 ||
         optional_uint(&document, nested, "numberAddresses", false,
                       &asrank->cone_addresses,
                       &asrank->cone_addresses_present, error,
                       error_size) != 0)) {
        json_free(&document);
        return -1;
    }
    if (optional_object(&document, asn_object, "asnDegree", &nested,
                        &nested_present, error, error_size) != 0) {
        json_free(&document);
        return -1;
    }
    if (nested_present &&
        (optional_uint(&document, nested, "total", false,
                       &asrank->degree_total,
                       &asrank->degree_total_present, error,
                       error_size) != 0 ||
         optional_uint(&document, nested, "customer", false,
                       &asrank->degree_customer,
                       &asrank->degree_customer_present, error,
                       error_size) != 0 ||
         optional_uint(&document, nested, "peer", false,
                       &asrank->degree_peer, &asrank->degree_peer_present,
                       error, error_size) != 0 ||
         optional_uint(&document, nested, "provider", false,
                       &asrank->degree_provider,
                       &asrank->degree_provider_present, error,
                       error_size) != 0)) {
        json_free(&document);
        return -1;
    }
    asrank->available = true;
    json_free(&document);
    return 0;
}

int iphm_query_asrank(uint32_t asn, unsigned int timeout_seconds,
                      IphmAsrank *asrank, char *error, size_t error_size)
{
    char url[160];
    char *body = NULL;
    size_t body_length = 0U;
    int result;

    if (snprintf(url, sizeof(url),
                 IPHM_ASRANK_BASE "/v2/restful/asns/%" PRIu32, asn) < 0 ||
        strlen(url) >= sizeof(url)) {
        set_error(error, error_size, "could not construct ASRank URL");
        return -1;
    }
    if (http_get(url, timeout_seconds, &body, &body_length, error,
                 error_size) != 0) {
        return -1;
    }
    result = iphm_parse_asrank(body, body_length, asn, asrank, error,
                               error_size);
    free(body);
    return result;
}

static int64_t monotonic_milliseconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)now.tv_nsec / 1000000;
}

static int wait_socket(int socket_fd, short events, int64_t deadline)
{
    struct pollfd descriptor;
    int64_t now = monotonic_milliseconds();
    int64_t remaining;
    int timeout;
    int result;

    if (now < 0) {
        return -1;
    }
    remaining = deadline - now;
    if (remaining <= 0) {
        return 0;
    }
    timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
    descriptor.fd = socket_fd;
    descriptor.events = events;
    descriptor.revents = 0;
    do {
        result = poll(&descriptor, 1U, timeout);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) {
        return result;
    }
    return (descriptor.revents & (events | POLLERR | POLLHUP | POLLNVAL)) != 0
               ? 1
               : -1;
}

static int connect_ris(unsigned int timeout_seconds, int64_t deadline,
                       char *error, size_t error_size)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    int socket_fd = -1;
    int status;

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    status = getaddrinfo("riswhois.ripe.net", "43", &hints, &addresses);
    if (status != 0) {
        set_error(error, error_size, "DNS failure: %s", gai_strerror(status));
        return -1;
    }
    for (address = addresses; address != NULL; address = address->ai_next) {
        int flags;
        int connected;

        if (monotonic_milliseconds() >= deadline) {
            break;
        }
        socket_fd =
            socket(address->ai_family, address->ai_socktype,
                   address->ai_protocol);
        if (socket_fd < 0) {
            continue;
        }
        flags = fcntl(socket_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
            fcntl(socket_fd, F_SETFD, FD_CLOEXEC) < 0) {
            (void)close(socket_fd);
            socket_fd = -1;
            continue;
        }
        connected = connect(socket_fd, address->ai_addr,
                            address->ai_addrlen);
        if (connected == 0) {
            break;
        }
        if (errno == EINPROGRESS &&
            wait_socket(socket_fd, POLLOUT, deadline) == 1) {
            int socket_error = 0;
            socklen_t socket_error_size = (socklen_t)sizeof(socket_error);

            if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error,
                           &socket_error_size) == 0 &&
                socket_error == 0) {
                break;
            }
        }
        (void)close(socket_fd);
        socket_fd = -1;
    }
    freeaddrinfo(addresses);
    if (socket_fd < 0) {
        set_error(error, error_size, "connection timed out after %u seconds",
                  timeout_seconds);
    }
    return socket_fd;
}

int iphm_query_ris_text(const char *query, unsigned int timeout_seconds,
                        size_t maximum, char **response,
                        size_t *response_length, char *error,
                        size_t error_size)
{
    int64_t start = monotonic_milliseconds();
    int64_t deadline;
    int socket_fd;
    size_t query_length;
    size_t sent = 0U;
    char *data;
    size_t used = 0U;

    if (query == NULL || response == NULL || response_length == NULL ||
        start < 0 || maximum == 0U || maximum > 4U * IPHM_MAX_RESPONSE) {
        set_error(error, error_size, "invalid RISwhois query arguments");
        return -1;
    }
    query_length = strlen(query);
    if (query_length == 0U || query_length > 512U ||
        query[query_length - 1U] != '\n') {
        set_error(error, error_size, "invalid RISwhois query text");
        return -1;
    }
    *response = NULL;
    *response_length = 0U;
    deadline = start + (int64_t)timeout_seconds * 1000;
    socket_fd = connect_ris(timeout_seconds, deadline, error, error_size);
    if (socket_fd < 0) {
        return -1;
    }
    while (sent < query_length) {
        ssize_t count;

        if (wait_socket(socket_fd, POLLOUT, deadline) != 1) {
            set_error(error, error_size, "send timed out");
            (void)close(socket_fd);
            return -1;
        }
        count = send(socket_fd, query + sent, query_length - sent,
                     MSG_NOSIGNAL);
        if (count > 0) {
            sent += (size_t)count;
        } else if (count < 0 && errno != EINTR && errno != EAGAIN &&
                   errno != EWOULDBLOCK) {
            set_error(error, error_size, "send failed: %s", strerror(errno));
            (void)close(socket_fd);
            return -1;
        }
    }
    data = malloc(maximum + 1U);
    if (data == NULL) {
        set_error(error, error_size, "out of memory receiving RISwhois data");
        (void)close(socket_fd);
        return -1;
    }
    for (;;) {
        ssize_t count;

        if (wait_socket(socket_fd, POLLIN, deadline) != 1) {
            set_error(error, error_size, "receive timed out");
            free(data);
            (void)close(socket_fd);
            return -1;
        }
        count = recv(socket_fd, data + used, maximum - used, 0);
        if (count > 0) {
            used += (size_t)count;
            if (used == maximum) {
                set_error(error, error_size,
                          "RISwhois response exceeded %zu bytes", maximum);
                free(data);
                (void)close(socket_fd);
                return -1;
            }
        } else if (count == 0) {
            break;
        } else if (errno != EINTR && errno != EAGAIN &&
                   errno != EWOULDBLOCK) {
            set_error(error, error_size, "receive failed: %s",
                      strerror(errno));
            free(data);
            (void)close(socket_fd);
            return -1;
        }
    }
    (void)close(socket_fd);
    data[used] = '\0';
    *response = data;
    *response_length = used;
    return 0;
}

static int parse_prefix_bits(const char *prefix, unsigned int *bits)
{
    const char *slash = strrchr(prefix, '/');
    uint64_t value;

    if (slash == NULL ||
        parse_uint64_text(slash + 1, strlen(slash + 1), &value) != 0 ||
        value > 128U) {
        return -1;
    }
    *bits = (unsigned int)value;
    return 0;
}

static bool prefix_contains(const char *prefix, const char *address,
                            int family, unsigned int bits)
{
    unsigned char network[16];
    unsigned char candidate[16];
    unsigned int full_bytes = bits / 8U;
    unsigned int remaining_bits = bits % 8U;
    int socket_family = family == 4 ? AF_INET : AF_INET6;

    if (inet_pton(socket_family, prefix, network) != 1 ||
        inet_pton(socket_family, address, candidate) != 1 ||
        memcmp(network, candidate, full_bytes) != 0) {
        return false;
    }
    if (remaining_bits != 0U) {
        unsigned int mask = 0xffU << (8U - remaining_bits);

        return ((unsigned int)network[full_bytes] & mask) ==
               ((unsigned int)candidate[full_bytes] & mask);
    }
    return true;
}

bool iphm_prefix_contains_address(const char *prefix, const char *address)
{
    IphmTarget prefix_target;
    IphmTarget address_target;
    unsigned int bits;
    char error[64];

    if (prefix == NULL || address == NULL ||
        iphm_parse_target(prefix, &prefix_target, error, sizeof(error)) != 0 ||
        prefix_target.kind != IPHM_TARGET_ADDRESS ||
        !prefix_target.is_cidr ||
        iphm_parse_target(address, &address_target, error,
                          sizeof(error)) != 0 ||
        address_target.kind != IPHM_TARGET_ADDRESS ||
        address_target.is_cidr ||
        prefix_target.address_family != address_target.address_family ||
        parse_prefix_bits(prefix, &bits) != 0) {
        return false;
    }
    return prefix_contains(prefix_target.address, address_target.address,
                           prefix_target.address_family, bits);
}

static bool span_starts_with(const char *text, size_t length,
                             const char *prefix, size_t prefix_length)
{
    return length > prefix_length &&
           memcmp(text, prefix, prefix_length) == 0;
}

int iphm_parse_ris_response(const char *text, size_t length,
                            const char *address, uint32_t *asn, char *prefix,
                            size_t prefix_size, char *error,
                            size_t error_size)
{
    size_t position = 0U;
    char pending_prefix[IPHM_PREFIX_MAX] = "";
    unsigned int pending_bits = 0U;
    bool pending = false;
    bool found = false;
    uint32_t found_asn = 0U;
    unsigned int found_bits = 0U;
    char found_prefix[IPHM_PREFIX_MAX] = "";
    IphmTarget query_target;

    if (text == NULL || address == NULL || asn == NULL || prefix == NULL ||
        length == 0U || length > IPHM_RIS_RESPONSE_MAX) {
        set_error(error, error_size, "empty or oversized RISwhois response");
        return -1;
    }
    if (iphm_parse_target(address, &query_target, error, error_size) != 0 ||
        query_target.kind != IPHM_TARGET_ADDRESS ||
        query_target.is_cidr) {
        set_error(error, error_size, "invalid RISwhois query address");
        return -1;
    }
    while (position < length) {
        size_t line_start = position;
        size_t line_end;
        size_t value_start;
        size_t value_end;

        while (position < length && text[position] != '\n') {
            ++position;
        }
        line_end = position;
        if (position < length) {
            ++position;
        }
        if (line_end > line_start && text[line_end - 1U] == '\r') {
            --line_end;
        }
        value_start = line_start;
        while (value_start < line_end &&
               (text[value_start] == ' ' || text[value_start] == '\t')) {
            ++value_start;
        }
        value_end = line_end;
        while (value_end > value_start &&
               (text[value_end - 1U] == ' ' ||
                text[value_end - 1U] == '\t')) {
            --value_end;
        }

        if (span_starts_with(text + value_start, value_end - value_start,
                             "route:", 6U) ||
            span_starts_with(text + value_start, value_end - value_start,
                             "route6:", 7U)) {
            size_t colon = value_start;
            IphmTarget route_target;

            while (colon < value_end && text[colon] != ':') {
                ++colon;
            }
            ++colon;
            while (colon < value_end &&
                   (text[colon] == ' ' || text[colon] == '\t')) {
                ++colon;
            }
            if (copy_span(pending_prefix, sizeof(pending_prefix),
                          text + colon, value_end - colon) != 0 ||
                iphm_parse_target(pending_prefix, &route_target, error,
                                  error_size) != 0 ||
                route_target.kind != IPHM_TARGET_ADDRESS ||
                !route_target.is_cidr ||
                route_target.address_family != query_target.address_family ||
                parse_prefix_bits(pending_prefix, &pending_bits) != 0 ||
                !prefix_contains(route_target.address, query_target.address,
                                 route_target.address_family, pending_bits)) {
                set_error(error, error_size,
                          "RISwhois returned a nonmatching route prefix");
                return -1;
            }
            pending = true;
        } else if (span_starts_with(text + value_start,
                                    value_end - value_start, "origin:", 7U)) {
            size_t origin = value_start + 7U;
            uint32_t candidate;

            while (origin < value_end &&
                   (text[origin] == ' ' || text[origin] == '\t')) {
                ++origin;
            }
            if (!pending ||
                parse_asn_text(text + origin, value_end - origin,
                               &candidate) != 0) {
                set_error(error, error_size,
                          "RISwhois returned an invalid origin");
                return -1;
            }
            if (!found || pending_bits > found_bits) {
                found = true;
                found_asn = candidate;
                found_bits = pending_bits;
                (void)memcpy(found_prefix, pending_prefix,
                             strlen(pending_prefix) + 1U);
            } else if (pending_bits == found_bits &&
                       candidate != found_asn) {
                set_error(error, error_size,
                          "RISwhois returned conflicting most-specific origins");
                return -1;
            }
            pending = false;
        }
    }
    if (!found || copy_span(prefix, prefix_size, found_prefix,
                            strlen(found_prefix)) != 0) {
        set_error(error, error_size, "no routed origin was found");
        return -1;
    }
    *asn = found_asn;
    return 0;
}

int iphm_resolve_ris(const IphmTarget *target, unsigned int timeout_seconds,
                     uint32_t *asn, char *prefix, size_t prefix_size,
                     char *error, size_t error_size)
{
    char query[IPHM_ADDRESS_MAX + 8U];
    int query_length;
    int64_t start = monotonic_milliseconds();
    int64_t deadline;
    int socket_fd;
    size_t sent = 0U;
    char *response;
    size_t response_length = 0U;
    int result;

    if (target == NULL || target->kind != IPHM_TARGET_ADDRESS || start < 0) {
        set_error(error, error_size, "invalid resolver arguments");
        return -1;
    }
    deadline = start + (int64_t)timeout_seconds * 1000;
    query_length = snprintf(query, sizeof(query), "-1 %s\r\n",
                            target->address);
    if (query_length < 0 || (size_t)query_length >= sizeof(query)) {
        set_error(error, error_size, "RISwhois query is too long");
        return -1;
    }
    socket_fd = connect_ris(timeout_seconds, deadline, error, error_size);
    if (socket_fd < 0) {
        return -1;
    }
    while (sent < (size_t)query_length) {
        ssize_t count;

        if (wait_socket(socket_fd, POLLOUT, deadline) != 1) {
            set_error(error, error_size, "send timed out");
            (void)close(socket_fd);
            return -1;
        }
        count = send(socket_fd, query + sent,
                     (size_t)query_length - sent, MSG_NOSIGNAL);
        if (count > 0) {
            sent += (size_t)count;
        } else if (count < 0 && errno != EINTR && errno != EAGAIN &&
                   errno != EWOULDBLOCK) {
            set_error(error, error_size, "send failed: %s", strerror(errno));
            (void)close(socket_fd);
            return -1;
        }
    }

    response = malloc(IPHM_RIS_RESPONSE_MAX + 1U);
    if (response == NULL) {
        set_error(error, error_size, "out of memory receiving RISwhois data");
        (void)close(socket_fd);
        return -1;
    }
    for (;;) {
        ssize_t count;

        if (wait_socket(socket_fd, POLLIN, deadline) != 1) {
            set_error(error, error_size, "receive timed out");
            free(response);
            (void)close(socket_fd);
            return -1;
        }
        count = recv(socket_fd, response + response_length,
                     IPHM_RIS_RESPONSE_MAX - response_length, 0);
        if (count > 0) {
            response_length += (size_t)count;
            if (response_length == IPHM_RIS_RESPONSE_MAX) {
                set_error(error, error_size,
                          "RISwhois response exceeded %u bytes",
                          IPHM_RIS_RESPONSE_MAX);
                free(response);
                (void)close(socket_fd);
                return -1;
            }
        } else if (count == 0) {
            break;
        } else if (errno != EINTR && errno != EAGAIN &&
                   errno != EWOULDBLOCK) {
            set_error(error, error_size, "receive failed: %s",
                      strerror(errno));
            free(response);
            (void)close(socket_fd);
            return -1;
        }
    }
    (void)close(socket_fd);
    response[response_length] = '\0';
    result = iphm_parse_ris_response(response, response_length,
                                     target->address, asn, prefix,
                                     prefix_size, error, error_size);
    free(response);
    return result;
}

void iphm_finalize_report(IphmReport *report)
{
    bool have_ipv4 = report->ipv4.present;
    bool have_ipv6 = report->ipv6.present;

    if (!have_ipv4 && !have_ipv6) {
        report->overall_verdict = IPHM_VERDICT_NO_DATA;
    } else if ((have_ipv4 &&
                report->ipv4.verdict == IPHM_VERDICT_SPOOFABLE) ||
               (have_ipv6 &&
                report->ipv6.verdict == IPHM_VERDICT_SPOOFABLE)) {
        report->overall_verdict = IPHM_VERDICT_SPOOFABLE;
    } else if ((have_ipv4 &&
                report->ipv4.verdict == IPHM_VERDICT_INCONCLUSIVE) ||
               (have_ipv6 &&
                report->ipv6.verdict == IPHM_VERDICT_INCONCLUSIVE)) {
        report->overall_verdict = IPHM_VERDICT_INCONCLUSIVE;
    } else if ((have_ipv4 &&
                report->ipv4.verdict == IPHM_VERDICT_REWRITTEN) ||
               (have_ipv6 &&
                report->ipv6.verdict == IPHM_VERDICT_REWRITTEN)) {
        report->overall_verdict = IPHM_VERDICT_REWRITTEN;
    } else {
        report->overall_verdict = IPHM_VERDICT_BLOCKED;
    }
}

const char *iphm_verdict_name(IphmVerdict verdict)
{
    switch ((int)verdict) {
    case IPHM_VERDICT_NO_DATA:
        return "no_data";
    case IPHM_VERDICT_SPOOFABLE:
        return "spoofable";
    case IPHM_VERDICT_REWRITTEN:
        return "rewritten";
    case IPHM_VERDICT_BLOCKED:
        return "blocked";
    case IPHM_VERDICT_INCONCLUSIVE:
    default:
        return "inconclusive";
    }
}

int iphm_json_write_string(FILE *stream, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    if (fputc('"', stream) == EOF) {
        return -1;
    }
    while (*cursor != 0U) {
        unsigned char character = *cursor++;

        if (character == (unsigned char)'"' ||
            character == (unsigned char)'\\') {
            if (fputc('\\', stream) == EOF ||
                fputc((int)character, stream) == EOF) {
                return -1;
            }
        } else if (character == (unsigned char)'\b') {
            if (fputs("\\b", stream) == EOF) {
                return -1;
            }
        } else if (character == (unsigned char)'\f') {
            if (fputs("\\f", stream) == EOF) {
                return -1;
            }
        } else if (character == (unsigned char)'\n') {
            if (fputs("\\n", stream) == EOF) {
                return -1;
            }
        } else if (character == (unsigned char)'\r') {
            if (fputs("\\r", stream) == EOF) {
                return -1;
            }
        } else if (character == (unsigned char)'\t') {
            if (fputs("\\t", stream) == EOF) {
                return -1;
            }
        } else if (character < 0x20U) {
            if (fprintf(stream, "\\u%04x", (unsigned int)character) < 0) {
                return -1;
            }
        } else if (fputc((int)character, stream) == EOF) {
            return -1;
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int emit_optional_string(FILE *stream, const char *name,
                                const char *value, bool present,
                                bool leading_comma)
{
    if (fprintf(stream, "%s\"%s\":", leading_comma ? "," : "", name) < 0) {
        return -1;
    }
    return present ? iphm_json_write_string(stream, value)
                   : (fputs("null", stream) == EOF ? -1 : 0);
}

static int emit_optional_uint(FILE *stream, const char *name, uint64_t value,
                              bool present, bool leading_comma)
{
    if (fprintf(stream, "%s\"%s\":", leading_comma ? "," : "", name) < 0) {
        return -1;
    }
    if (present) {
        return fprintf(stream, "%" PRIu64, value) < 0 ? -1 : 0;
    }
    return fputs("null", stream) == EOF ? -1 : 0;
}

static int emit_measurement(FILE *stream, const IphmMeasurement *measurement)
{
    if (!measurement->present) {
        return fputs("null", stream) == EOF ? -1 : 0;
    }
    if (fprintf(stream, "{\"session_id\":%" PRIu64 ",\"timestamp\":",
                measurement->session_id) < 0 ||
        iphm_json_write_string(stream, measurement->timestamp) != 0 ||
        emit_optional_string(stream, "client_prefix",
                             measurement->client_prefix,
                             measurement->client_prefix_present, true) != 0 ||
        emit_optional_string(stream, "private_source",
                             measurement->private_source,
                             measurement->private_source_present, true) != 0 ||
        emit_optional_string(stream, "routable_source",
                             measurement->routable_source,
                             measurement->routable_source_present, true) != 0 ||
        fputs(",\"verdict\":", stream) == EOF ||
        iphm_json_write_string(stream,
                               iphm_verdict_name(measurement->verdict)) != 0 ||
        fputc('}', stream) == EOF) {
        return -1;
    }
    return 0;
}

static int emit_asrank(FILE *stream, const IphmAsrank *asrank)
{
    if (!asrank->available) {
        return fputs("null", stream) == EOF ? -1 : 0;
    }
    if (fputc('{', stream) == EOF ||
        emit_optional_string(stream, "name", asrank->name,
                             asrank->name_present, false) != 0 ||
        emit_optional_uint(stream, "rank", asrank->rank,
                           asrank->rank_present, true) != 0 ||
        emit_optional_string(stream, "country", asrank->country,
                             asrank->country_present, true) != 0 ||
        fputs(",\"seen\":", stream) == EOF) {
        return -1;
    }
    if (asrank->seen_present) {
        if (fputs(asrank->seen ? "true" : "false", stream) == EOF) {
            return -1;
        }
    } else if (fputs("null", stream) == EOF) {
        return -1;
    }
    if (fputs(",\"customer_cone\":{", stream) == EOF ||
        emit_optional_uint(stream, "asns", asrank->cone_asns,
                           asrank->cone_asns_present, false) != 0 ||
        emit_optional_uint(stream, "prefixes", asrank->cone_prefixes,
                           asrank->cone_prefixes_present, true) != 0 ||
        emit_optional_uint(stream, "addresses", asrank->cone_addresses,
                           asrank->cone_addresses_present, true) != 0 ||
        fputs("},\"degree\":{", stream) == EOF ||
        emit_optional_uint(stream, "total", asrank->degree_total,
                           asrank->degree_total_present, false) != 0 ||
        emit_optional_uint(stream, "customer", asrank->degree_customer,
                           asrank->degree_customer_present, true) != 0 ||
        emit_optional_uint(stream, "peer", asrank->degree_peer,
                           asrank->degree_peer_present, true) != 0 ||
        emit_optional_uint(stream, "provider", asrank->degree_provider,
                           asrank->degree_provider_present, true) != 0 ||
        fputs("}}", stream) == EOF) {
        return -1;
    }
    return 0;
}

int iphm_emit_json(FILE *stream, const IphmReport *report)
{
    if (fputs("{\"input\":", stream) == EOF ||
        iphm_json_write_string(stream, report->input) != 0 ||
        fprintf(stream, ",\"asn\":%" PRIu32 ",\"matched_prefix\":",
                report->asn) < 0) {
        return -1;
    }
    if (report->matched_prefix_present) {
        if (iphm_json_write_string(stream, report->matched_prefix) != 0) {
            return -1;
        }
    } else if (fputs("null", stream) == EOF) {
        return -1;
    }
    if (fputs(",\"asrank\":", stream) == EOF ||
        emit_asrank(stream, &report->asrank) != 0 ||
        fputs(",\"ipv4\":", stream) == EOF ||
        emit_measurement(stream, &report->ipv4) != 0 ||
        fputs(",\"ipv6\":", stream) == EOF ||
        emit_measurement(stream, &report->ipv6) != 0 ||
        fputs(",\"overall_verdict\":", stream) == EOF ||
        iphm_json_write_string(
            stream, iphm_verdict_name(report->overall_verdict)) != 0 ||
        fputs("}\n", stream) == EOF) {
        return -1;
    }
    return ferror(stream) == 0 ? 0 : -1;
}

static int emit_plain_measurement(FILE *stream, const char *family,
                                  const IphmMeasurement *measurement)
{
    if (!measurement->present) {
        return fprintf(stream, "%s: no data\n", family) < 0 ? -1 : 0;
    }
    if (fprintf(stream,
                "%s: %s\n"
                "  session: %" PRIu64 "\n"
                "  timestamp: %s\n"
                "  client prefix: %s\n"
                "  private source: %s\n"
                "  routable source: %s\n",
                family, iphm_verdict_name(measurement->verdict),
                measurement->session_id, measurement->timestamp,
                measurement->client_prefix_present
                    ? measurement->client_prefix
                    : "unknown",
                measurement->private_source_present
                    ? measurement->private_source
                    : "unknown",
                measurement->routable_source_present
                    ? measurement->routable_source
                    : "unknown") < 0) {
        return -1;
    }
    return 0;
}

int iphm_emit_plain(FILE *stream, const IphmReport *report)
{
    if (fprintf(stream, "IPHM Check\nInput: %s\nASN: AS%" PRIu32 "\n",
                report->input, report->asn) < 0) {
        return -1;
    }
    if (report->matched_prefix_present &&
        fprintf(stream, "Matched BGP prefix: %s\n",
                report->matched_prefix) < 0) {
        return -1;
    }
    if (report->asrank.available) {
        if (fprintf(stream, "ASRank: %s | rank ",
                    report->asrank.name_present ? report->asrank.name
                                                : "unknown") < 0) {
            return -1;
        }
        if (report->asrank.rank_present) {
            if (fprintf(stream, "%" PRIu64, report->asrank.rank) < 0) {
                return -1;
            }
        } else if (fputs("unknown", stream) == EOF) {
            return -1;
        }
        if (fprintf(stream, " | country %s | seen %s\n",
                    report->asrank.country_present ? report->asrank.country
                                                   : "unknown",
                    report->asrank.seen_present
                        ? (report->asrank.seen ? "yes" : "no")
                        : "unknown") < 0) {
            return -1;
        }
    } else if (fputs("ASRank: unavailable\n", stream) == EOF) {
        return -1;
    }
    if (emit_plain_measurement(stream, "IPv4", &report->ipv4) != 0 ||
        emit_plain_measurement(stream, "IPv6", &report->ipv6) != 0 ||
        fprintf(stream, "Overall: %s\n",
                iphm_verdict_name(report->overall_verdict)) < 0 ||
        fputs("Historical CAIDA data; not a current-policy guarantee.\n",
              stream) == EOF) {
        return -1;
    }
    return ferror(stream) == 0 ? 0 : -1;
}

int iphm_json_is_valid(const char *json, size_t length)
{
    JsonDoc document;
    char error[64];

    if (json_parse(json, length, &document, error, sizeof(error)) != 0) {
        return 0;
    }
    json_free(&document);
    return 1;
}
