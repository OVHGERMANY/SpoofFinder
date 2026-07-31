#define _POSIX_C_SOURCE 200809L
#define JSMN_STATIC
#define JSMN_STRICT

#include "iphm.h"
#include "jsmn.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define INVENTORY_RESPONSE_MAX (4U * IPHM_MAX_RESPONSE)
#define CONFIG_RESPONSE_MAX IPHM_MAX_RESPONSE
#define LEDGER_RESPONSE_MAX (8U * IPHM_MAX_RESPONSE)
#define LEDGER_LINE_MAX 4096U
#define JSON_TOKEN_MAX 8192U
#define SECONDS_PER_DAY 86400LL
#define SOURCE_MAX_AGE 86400LL
#define RECONCILE_GRACE 86400LL

typedef struct {
    const char *text;
    size_t length;
    jsmntok_t *tokens;
    int count;
} JsonView;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
static void coverage_error(char *error, size_t error_size,
                           const char *format, ...)
{
    va_list arguments;

    if (error == NULL || error_size == 0U) {
        return;
    }
    va_start(arguments, format);
    (void)vsnprintf(error, error_size, format, arguments);
    va_end(arguments);
}

static int copy_text(char *destination, size_t capacity, const char *source,
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

static int parse_u64(const char *text, size_t length, uint64_t *value)
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

static int json_open(const char *text, size_t length, JsonView *view,
                     char *error, size_t error_size)
{
    jsmn_parser parser;
    int count;

    if (text == NULL || view == NULL || length == 0U) {
        coverage_error(error, error_size, "empty JSON document");
        return -1;
    }
    (void)memset(view, 0, sizeof(*view));
    view->tokens = calloc(JSON_TOKEN_MAX, sizeof(*view->tokens));
    if (view->tokens == NULL) {
        coverage_error(error, error_size, "out of memory parsing JSON");
        return -1;
    }
    jsmn_init(&parser);
    count = jsmn_parse(&parser, text, length, view->tokens, JSON_TOKEN_MAX);
    if (count <= 0) {
        coverage_error(error, error_size, "malformed or oversized JSON");
        free(view->tokens);
        (void)memset(view, 0, sizeof(*view));
        return -1;
    }
    view->text = text;
    view->length = length;
    view->count = count;
    return 0;
}

static void json_close(JsonView *view)
{
    free(view->tokens);
    (void)memset(view, 0, sizeof(*view));
}

static int token_after(const JsonView *view, int token)
{
    int next = token + 1;
    int end;

    if (token < 0 || token >= view->count) {
        return view->count;
    }
    end = view->tokens[token].end;
    while (next < view->count && view->tokens[next].start < end) {
        ++next;
    }
    return next;
}

static bool token_equals(const JsonView *view, int token, const char *text)
{
    size_t length = strlen(text);
    const jsmntok_t *item;

    if (token < 0 || token >= view->count) {
        return false;
    }
    item = &view->tokens[token];
    return item->type == JSMN_STRING && item->start >= 0 &&
           item->end >= item->start &&
           (size_t)(item->end - item->start) == length &&
           memcmp(view->text + item->start, text, length) == 0;
}

static int object_field(const JsonView *view, int object, const char *name)
{
    int position;
    int end;

    if (object < 0 || object >= view->count ||
        view->tokens[object].type != JSMN_OBJECT) {
        return -1;
    }
    position = object + 1;
    end = token_after(view, object);
    while (position < end) {
        int value = position + 1;

        if (value >= end || view->tokens[position].type != JSMN_STRING) {
            return -1;
        }
        if (token_equals(view, position, name)) {
            return value;
        }
        position = token_after(view, value);
    }
    return -1;
}

static int token_ascii(const JsonView *view, int token, char *output,
                       size_t capacity)
{
    const jsmntok_t *item;
    size_t length;
    size_t index;

    if (token < 0 || token >= view->count ||
        view->tokens[token].type != JSMN_STRING) {
        return -1;
    }
    item = &view->tokens[token];
    length = (size_t)(item->end - item->start);
    if (length >= capacity) {
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char character =
            (unsigned char)view->text[(size_t)item->start + index];

        if (character < 0x20U || character > 0x7eU || character == '\\' ||
            character == '"') {
            return -1;
        }
    }
    return copy_text(output, capacity, view->text + item->start, length);
}

static int token_uint64(const JsonView *view, int token, uint64_t *value)
{
    const jsmntok_t *item;

    if (token < 0 || token >= view->count ||
        view->tokens[token].type != JSMN_PRIMITIVE) {
        return -1;
    }
    item = &view->tokens[token];
    return parse_u64(view->text + item->start,
                     (size_t)(item->end - item->start), value);
}

static int token_boolean(const JsonView *view, int token, bool *value)
{
    const jsmntok_t *item;
    size_t length;

    if (token < 0 || token >= view->count ||
        view->tokens[token].type != JSMN_PRIMITIVE) {
        return -1;
    }
    item = &view->tokens[token];
    length = (size_t)(item->end - item->start);
    if (length == 4U &&
        memcmp(view->text + item->start, "true", 4U) == 0) {
        *value = true;
        return 0;
    }
    if (length == 5U &&
        memcmp(view->text + item->start, "false", 5U) == 0) {
        *value = false;
        return 0;
    }
    return -1;
}

static bool valid_segment_id(const char *text)
{
    size_t index;
    size_t length = strlen(text);

    if (length == 0U || length >= IPHM_SEGMENT_ID_MAX) {
        return false;
    }
    for (index = 0U; index < length; ++index) {
        char character = text[index];

        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') || character == '-' ||
              character == '_' || character == '.')) {
            return false;
        }
    }
    return true;
}

static int prefix_parts(const char *prefix, char *normalized,
                        size_t normalized_size, int *family,
                        unsigned int *bits)
{
    const char *slash = strrchr(prefix, '/');
    char address[IPHM_ADDRESS_MAX];
    unsigned char binary[16];
    char rendered[IPHM_ADDRESS_MAX];
    uint64_t parsed_bits;
    size_t address_length;
    unsigned int maximum;
    unsigned int byte;
    int socket_family;
    int written;

    if (slash == NULL || slash == prefix) {
        return -1;
    }
    address_length = (size_t)(slash - prefix);
    if (copy_text(address, sizeof(address), prefix, address_length) != 0 ||
        parse_u64(slash + 1, strlen(slash + 1), &parsed_bits) != 0) {
        return -1;
    }
    if (inet_pton(AF_INET, address, binary) == 1) {
        *family = 4;
        maximum = 32U;
        socket_family = AF_INET;
    } else if (inet_pton(AF_INET6, address, binary) == 1) {
        *family = 6;
        maximum = 128U;
        socket_family = AF_INET6;
    } else {
        return -1;
    }
    if (parsed_bits > maximum) {
        return -1;
    }
    *bits = (unsigned int)parsed_bits;
    for (byte = *bits / 8U + ((*bits % 8U) != 0U ? 1U : 0U);
         byte < maximum / 8U; ++byte) {
        binary[byte] = 0U;
    }
    if ((*bits % 8U) != 0U) {
        unsigned int index = *bits / 8U;
        unsigned int mask = 0xffU << (8U - (*bits % 8U));

        binary[index] = (unsigned char)((unsigned int)binary[index] & mask);
    }
    if (inet_ntop(socket_family, binary, rendered,
                  (socklen_t)sizeof(rendered)) == NULL) {
        return -1;
    }
    written = snprintf(normalized, normalized_size, "%s/%u", rendered,
                       *bits);
    return written < 0 || (size_t)written >= normalized_size ? -1 : 0;
}

static int route_compare(const void *left, const void *right)
{
    const IphmRoute *a = left;
    const IphmRoute *b = right;

    if (a->family != b->family) {
        return a->family < b->family ? -1 : 1;
    }
    return strcmp(a->prefix, b->prefix);
}

static int add_route(IphmInventory *inventory, const char *prefix, int family,
                     unsigned int bits, const uint32_t *origins,
                     size_t origin_count, char *error, size_t error_size)
{
    size_t route_index;
    IphmRoute *route = NULL;

    for (route_index = 0U; route_index < inventory->route_count;
         ++route_index) {
        if (strcmp(inventory->routes[route_index].prefix, prefix) == 0) {
            route = &inventory->routes[route_index];
            break;
        }
    }
    if (route == NULL) {
        if (inventory->route_count >= IPHM_MAX_ROUTES) {
            coverage_error(error, error_size,
                           "RISwhois returned more than %u routes",
                           IPHM_MAX_ROUTES);
            return -1;
        }
        if (inventory->route_count == inventory->route_capacity) {
            IphmRoute *replacement;
            size_t capacity = inventory->route_capacity == 0U
                                  ? 64U
                                  : inventory->route_capacity * 2U;

            if (capacity > IPHM_MAX_ROUTES) {
                capacity = IPHM_MAX_ROUTES;
            }
            replacement =
                realloc(inventory->routes, capacity * sizeof(*replacement));
            if (replacement == NULL) {
                coverage_error(error, error_size,
                               "out of memory storing RIS routes");
                return -1;
            }
            inventory->routes = replacement;
            inventory->route_capacity = capacity;
        }
        route = &inventory->routes[inventory->route_count++];
        (void)memset(route, 0, sizeof(*route));
        (void)memcpy(route->prefix, prefix, strlen(prefix) + 1U);
        route->family = family;
        route->prefix_bits = bits;
    }
    for (route_index = 0U; route_index < origin_count; ++route_index) {
        size_t existing;
        bool duplicate = false;

        for (existing = 0U; existing < route->origin_count; ++existing) {
            if (route->origins[existing] == origins[route_index]) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            if (route->origin_count >= IPHM_MAX_ORIGINS) {
                coverage_error(error, error_size,
                               "route has too many origin ASNs");
                return -1;
            }
            route->origins[route->origin_count++] = origins[route_index];
        }
    }
    route->moas = route->origin_count > 1U;
    return 0;
}

static int parse_origins(const char *text, size_t length, uint32_t *origins,
                         size_t *origin_count)
{
    size_t position = 0U;

    *origin_count = 0U;
    while (position < length) {
        size_t start;
        uint64_t value;

        while (position < length &&
               !((text[position] == 'A' || text[position] == 'a') &&
                 position + 2U < length &&
                 (text[position + 1U] == 'S' ||
                  text[position + 1U] == 's') &&
                 text[position + 2U] >= '0' &&
                 text[position + 2U] <= '9')) {
            ++position;
        }
        if (position == length) {
            break;
        }
        position += 2U;
        start = position;
        while (position < length && text[position] >= '0' &&
               text[position] <= '9') {
            ++position;
        }
        if (*origin_count >= IPHM_MAX_ORIGINS ||
            parse_u64(text + start, position - start, &value) != 0 ||
            value == 0U || value > UINT32_MAX) {
            return -1;
        }
        origins[(*origin_count)++] = (uint32_t)value;
    }
    return *origin_count == 0U ? -1 : 0;
}

static bool span_starts_with(const char *text, size_t length,
                             const char *prefix, size_t prefix_length)
{
    return length > prefix_length &&
           memcmp(text, prefix, prefix_length) == 0;
}

int iphm_parse_ris_inventory(const char *text, size_t length,
                             uint32_t filter_asn, IphmInventory *inventory,
                             char *error, size_t error_size)
{
    size_t position = 0U;
    char pending_prefix[IPHM_PREFIX_MAX] = "";
    int pending_family = 0;
    unsigned int pending_bits = 0U;
    bool pending = false;

    if (text == NULL || inventory == NULL || length == 0U ||
        length > INVENTORY_RESPONSE_MAX) {
        coverage_error(error, error_size,
                       "empty or oversized RIS inventory response");
        return -1;
    }
    while (position < length) {
        size_t start = position;
        size_t end;
        size_t value;

        while (position < length && text[position] != '\n') {
            ++position;
        }
        end = position;
        if (position < length) {
            ++position;
        }
        if (end > start && text[end - 1U] == '\r') {
            --end;
        }
        while (start < end &&
               (text[start] == ' ' || text[start] == '\t')) {
            ++start;
        }
        if (span_starts_with(text + start, end - start, "route:", 6U) ||
            span_starts_with(text + start, end - start, "route6:", 7U)) {
            value = start;
            while (value < end && text[value] != ':') {
                ++value;
            }
            ++value;
            while (value < end &&
                   (text[value] == ' ' || text[value] == '\t')) {
                ++value;
            }
            while (end > value &&
                   (text[end - 1U] == ' ' || text[end - 1U] == '\t')) {
                --end;
            }
            if (copy_text(pending_prefix, sizeof(pending_prefix),
                          text + value, end - value) != 0 ||
                prefix_parts(pending_prefix, pending_prefix,
                             sizeof(pending_prefix), &pending_family,
                             &pending_bits) != 0) {
                coverage_error(error, error_size,
                               "RIS inventory contains an invalid route");
                return -1;
            }
            pending = true;
        } else if (span_starts_with(text + start, end - start, "origin:",
                                    7U)) {
            uint32_t origins[IPHM_MAX_ORIGINS];
            size_t origin_count;
            bool include = filter_asn == 0U;
            size_t origin_index;

            value = start + 7U;
            while (value < end &&
                   (text[value] == ' ' || text[value] == '\t')) {
                ++value;
            }
            if (!pending ||
                parse_origins(text + value, end - value, origins,
                              &origin_count) != 0) {
                coverage_error(error, error_size,
                               "RIS inventory contains an invalid origin");
                return -1;
            }
            for (origin_index = 0U; origin_index < origin_count;
                 ++origin_index) {
                if (origins[origin_index] == filter_asn) {
                    include = true;
                }
            }
            if (include &&
                add_route(inventory, pending_prefix, pending_family,
                          pending_bits, origins, origin_count, error,
                          error_size) != 0) {
                return -1;
            }
            pending = false;
        }
    }
    qsort(inventory->routes, inventory->route_count,
          sizeof(*inventory->routes), route_compare);
    return 0;
}

int iphm_parse_ris_source_times(const char *text, size_t length, int64_t now,
                                IphmInventory *inventory, char *error,
                                size_t error_size)
{
    size_t position;
    bool found = false;
    int64_t newest = 0;

    if (text == NULL || inventory == NULL || length == 0U ||
        length > INVENTORY_RESPONSE_MAX) {
        coverage_error(error, error_size,
                       "empty or oversized RIS source response");
        return -1;
    }
    for (position = 0U; position + 16U < length; ++position) {
        char timestamp[32];
        size_t second_offset;
        int64_t key;

        if (!(text[position] >= '0' && text[position] <= '9') ||
            position + 15U >= length || text[position + 4U] != '-' ||
            text[position + 7U] != '-' ||
            (text[position + 10U] != ' ' &&
             text[position + 10U] != 'T') ||
            text[position + 13U] != ':') {
            continue;
        }
        second_offset =
            position + 18U < length && text[position + 16U] == ':'
                ? 19U
                : 16U;
        if (second_offset == 19U) {
            if (snprintf(timestamp, sizeof(timestamp),
                         "%.10sT%.8sZ", text + position,
                         text + position + 11U) < 0) {
                continue;
            }
        } else if (snprintf(timestamp, sizeof(timestamp),
                            "%.10sT%.5s:00Z", text + position,
                            text + position + 11U) < 0) {
            continue;
        }
        if (iphm_parse_timestamp_key(timestamp, &key) == 0 &&
            (!found || key > newest)) {
            found = true;
            newest = key;
        }
    }
    inventory->source_time_present = found;
    inventory->newest_source_time = newest;
    inventory->source_fresh =
        found && newest <= now + 300LL && now - newest <= SOURCE_MAX_AGE;
    return 0;
}

void iphm_inventory_free(IphmInventory *inventory)
{
    if (inventory != NULL) {
        free(inventory->routes);
        (void)memset(inventory, 0, sizeof(*inventory));
    }
}

int iphm_query_inventory(uint32_t asn, unsigned int timeout_seconds,
                         IphmInventory *inventory, char *error,
                         size_t error_size)
{
    char query[64];
    char *response = NULL;
    size_t response_length = 0U;
    int written;
    time_t now;

    if (inventory == NULL || asn == 0U) {
        coverage_error(error, error_size, "invalid inventory arguments");
        return -1;
    }
    (void)memset(inventory, 0, sizeof(*inventory));
    written = snprintf(query, sizeof(query), "-i AS%" PRIu32 "\r\n", asn);
    if (written < 0 || (size_t)written >= sizeof(query) ||
        iphm_query_ris_text(query, timeout_seconds, INVENTORY_RESPONSE_MAX,
                            &response, &response_length, error,
                            error_size) != 0) {
        return -1;
    }
    if (iphm_parse_ris_inventory(response, response_length, asn, inventory,
                                 error, error_size) != 0) {
        free(response);
        iphm_inventory_free(inventory);
        return -1;
    }
    free(response);
    response = NULL;
    if (iphm_query_ris_text("-q sources\r\n", timeout_seconds,
                            INVENTORY_RESPONSE_MAX, &response,
                            &response_length, error, error_size) != 0) {
        iphm_inventory_free(inventory);
        return -1;
    }
    now = time(NULL);
    if (now == (time_t)-1 ||
        iphm_parse_ris_source_times(response, response_length, (int64_t)now,
                                    inventory, error, error_size) != 0) {
        free(response);
        iphm_inventory_free(inventory);
        return -1;
    }
    free(response);
    inventory->queried_at = (int64_t)now;
    return 0;
}

int iphm_inventory_longest_route(const IphmInventory *inventory,
                                 const char *address, size_t *route_index)
{
    size_t index;
    bool found = false;
    unsigned int longest = 0U;

    if (inventory == NULL || address == NULL || route_index == NULL) {
        return -1;
    }
    for (index = 0U; index < inventory->route_count; ++index) {
        if (iphm_prefix_contains_address(inventory->routes[index].prefix,
                                         address) &&
            (!found || inventory->routes[index].prefix_bits > longest)) {
            found = true;
            longest = inventory->routes[index].prefix_bits;
            *route_index = index;
        }
    }
    return found ? 0 : -1;
}

int iphm_parse_segments_config(const char *json, size_t length,
                               IphmConfig *config, char *error,
                               size_t error_size)
{
    JsonView view;
    int token;
    uint64_t value;
    int segments;
    int position;
    int end;

    if (config == NULL || length > CONFIG_RESPONSE_MAX ||
        json_open(json, length, &view, error, error_size) != 0) {
        return -1;
    }
    (void)memset(config, 0, sizeof(*config));
    if (view.tokens[0].type != JSMN_OBJECT ||
        token_after(&view, 0) != view.count) {
        coverage_error(error, error_size,
                       "configuration root must be one JSON object");
        json_close(&view);
        return -1;
    }
    token = object_field(&view, 0, "schema_version");
    if (token_uint64(&view, token, &value) != 0 || value != 1U) {
        coverage_error(error, error_size,
                       "schema_version must be exactly 1");
        json_close(&view);
        return -1;
    }
    config->schema_version = 1U;
    token = object_field(&view, 0, "asn");
    if (token_uint64(&view, token, &value) != 0 || value == 0U ||
        value > UINT32_MAX) {
        coverage_error(error, error_size, "configuration ASN is invalid");
        json_close(&view);
        return -1;
    }
    config->asn = (uint32_t)value;
    token = object_field(&view, 0, "minimum_interval_days");
    if (token_uint64(&view, token, &value) != 0 || value < 1U ||
        value > 365U) {
        coverage_error(error, error_size,
                       "minimum_interval_days must be 1 through 365");
        json_close(&view);
        return -1;
    }
    config->minimum_interval_days = (unsigned int)value;
    segments = object_field(&view, 0, "segments");
    if (segments < 0 || view.tokens[segments].type != JSMN_ARRAY ||
        view.tokens[segments].size <= 0 ||
        (size_t)view.tokens[segments].size > IPHM_MAX_SEGMENTS) {
        coverage_error(error, error_size,
                       "segments must be a nonempty bounded array");
        json_close(&view);
        return -1;
    }
    position = segments + 1;
    end = token_after(&view, segments);
    while (position < end) {
        IphmSegment *segment;
        int families;
        int prefixes;
        int array_position;
        int array_end;
        size_t prior;

        if (view.tokens[position].type != JSMN_OBJECT ||
            config->segment_count >= IPHM_MAX_SEGMENTS) {
            coverage_error(error, error_size, "invalid segment object");
            json_close(&view);
            return -1;
        }
        segment = &config->segments[config->segment_count];
        (void)memset(segment, 0, sizeof(*segment));
        token = object_field(&view, position, "id");
        if (token_ascii(&view, token, segment->id, sizeof(segment->id)) != 0 ||
            !valid_segment_id(segment->id)) {
            coverage_error(error, error_size, "segment id is invalid");
            json_close(&view);
            return -1;
        }
        for (prior = 0U; prior < config->segment_count; ++prior) {
            if (strcmp(config->segments[prior].id, segment->id) == 0) {
                coverage_error(error, error_size, "duplicate segment id");
                json_close(&view);
                return -1;
            }
        }
        families = object_field(&view, position, "families");
        if (families < 0 || view.tokens[families].type != JSMN_ARRAY ||
            view.tokens[families].size <= 0) {
            coverage_error(error, error_size,
                           "segment families must be nonempty");
            json_close(&view);
            return -1;
        }
        array_position = families + 1;
        array_end = token_after(&view, families);
        while (array_position < array_end) {
            if (token_equals(&view, array_position, "ipv4")) {
                if (segment->ipv4) {
                    coverage_error(error, error_size,
                                   "duplicate ipv4 segment family");
                    json_close(&view);
                    return -1;
                }
                segment->ipv4 = true;
            } else if (token_equals(&view, array_position, "ipv6")) {
                if (segment->ipv6) {
                    coverage_error(error, error_size,
                                   "duplicate ipv6 segment family");
                    json_close(&view);
                    return -1;
                }
                segment->ipv6 = true;
            } else {
                coverage_error(error, error_size,
                               "segment family must be ipv4 or ipv6");
                json_close(&view);
                return -1;
            }
            array_position = token_after(&view, array_position);
        }
        prefixes = object_field(&view, position, "expected_prefixes");
        if (prefixes < 0 || view.tokens[prefixes].type != JSMN_ARRAY ||
            view.tokens[prefixes].size <= 0 ||
            (size_t)view.tokens[prefixes].size >
                IPHM_MAX_EXPECTED_PREFIXES) {
            coverage_error(error, error_size,
                           "expected_prefixes must be nonempty and bounded");
            json_close(&view);
            return -1;
        }
        array_position = prefixes + 1;
        array_end = token_after(&view, prefixes);
        while (array_position < array_end) {
            char raw[IPHM_PREFIX_MAX];
            int family;
            unsigned int bits;

            if (segment->expected_prefix_count >=
                    IPHM_MAX_EXPECTED_PREFIXES ||
                token_ascii(&view, array_position, raw, sizeof(raw)) != 0 ||
                prefix_parts(
                    raw,
                    segment->expected_prefixes[segment->expected_prefix_count],
                    IPHM_PREFIX_MAX, &family, &bits) != 0 ||
                (family == 4 && !segment->ipv4) ||
                (family == 6 && !segment->ipv6)) {
                coverage_error(error, error_size,
                               "segment expected prefix is invalid");
                json_close(&view);
                return -1;
            }
            (void)bits;
            segment->expected_families[segment->expected_prefix_count] =
                family;
            ++segment->expected_prefix_count;
            array_position = token_after(&view, array_position);
        }
        if ((segment->ipv4 &&
             !memchr(segment->expected_families, 4,
                     segment->expected_prefix_count *
                         sizeof(segment->expected_families[0]))) ||
            (segment->ipv6 &&
             !memchr(segment->expected_families, 6,
                     segment->expected_prefix_count *
                         sizeof(segment->expected_families[0])))) {
            size_t check;
            bool have4 = false;
            bool have6 = false;

            for (check = 0U; check < segment->expected_prefix_count; ++check) {
                have4 = have4 || segment->expected_families[check] == 4;
                have6 = have6 || segment->expected_families[check] == 6;
            }
            if ((segment->ipv4 && !have4) || (segment->ipv6 && !have6)) {
                coverage_error(error, error_size,
                               "each family needs an expected prefix");
                json_close(&view);
                return -1;
            }
        }
        ++config->segment_count;
        position = token_after(&view, position);
    }
    json_close(&view);
    return 0;
}

static int read_secure_file(const char *path, size_t maximum,
                            bool allow_missing, bool *present, char **text,
                            size_t *length, char *error, size_t error_size)
{
    int descriptor;
    struct stat status;
    char *buffer;
    size_t used = 0U;

    *present = false;
    *text = NULL;
    *length = 0U;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (allow_missing && errno == ENOENT) {
            return 0;
        }
        coverage_error(error, error_size, "cannot open %s: %s", path,
                       strerror(errno));
        return -1;
    }
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_uid != (uid_t)0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        coverage_error(error, error_size,
                       "%s must be a root-owned, non-writable regular file",
                       path);
        (void)close(descriptor);
        return -1;
    }
    buffer = malloc(maximum + 1U);
    if (buffer == NULL) {
        coverage_error(error, error_size, "out of memory reading %s", path);
        (void)close(descriptor);
        return -1;
    }
    while (used <= maximum) {
        ssize_t count = read(descriptor, buffer + used, maximum + 1U - used);

        if (count > 0) {
            used += (size_t)count;
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            coverage_error(error, error_size, "cannot read %s: %s", path,
                           strerror(errno));
            free(buffer);
            (void)close(descriptor);
            return -1;
        }
    }
    (void)close(descriptor);
    if (used > maximum) {
        coverage_error(error, error_size, "%s exceeds %zu bytes", path,
                       maximum);
        free(buffer);
        return -1;
    }
    buffer[used] = '\0';
    *present = true;
    *text = buffer;
    *length = used;
    return 0;
}

int iphm_load_config_default(IphmConfig *config, bool *present, char *error,
                             size_t error_size)
{
    char *text;
    size_t length;
    int result;

    if (read_secure_file(IPHM_CONFIG_PATH, CONFIG_RESPONSE_MAX, true, present,
                         &text, &length, error, error_size) != 0) {
        return -1;
    }
    if (!*present) {
        (void)memset(config, 0, sizeof(*config));
        return 0;
    }
    result =
        iphm_parse_segments_config(text, length, config, error, error_size);
    free(text);
    return result;
}

static int ledger_add(IphmLedger *ledger, const IphmActiveMeasurement *item,
                      char *error, size_t error_size)
{
    if (ledger->count == ledger->capacity) {
        IphmActiveMeasurement *replacement;
        size_t capacity =
            ledger->capacity == 0U ? 32U : ledger->capacity * 2U;

        if (capacity > 65536U) {
            coverage_error(error, error_size,
                           "measurement ledger has too many records");
            return -1;
        }
        replacement =
            realloc(ledger->items, capacity * sizeof(*replacement));
        if (replacement == NULL) {
            coverage_error(error, error_size,
                           "out of memory loading measurement ledger");
            return -1;
        }
        ledger->items = replacement;
        ledger->capacity = capacity;
    }
    ledger->items[ledger->count++] = *item;
    return 0;
}

static IphmActiveMeasurement *ledger_find(IphmLedger *ledger,
                                          uint64_t session_id, int family)
{
    size_t index;

    for (index = 0U; index < ledger->count; ++index) {
        if (ledger->items[index].session_id == session_id &&
            ledger->items[index].family == family) {
            return &ledger->items[index];
        }
    }
    return NULL;
}

static int required_ascii_field(const JsonView *view, int object,
                                const char *name, char *output,
                                size_t capacity)
{
    return token_ascii(view, object_field(view, object, name), output,
                       capacity);
}

static int optional_ascii_field(const JsonView *view, int object,
                                const char *name, char *output,
                                size_t capacity)
{
    int token = object_field(view, object, name);

    if (token < 0) {
        output[0] = '\0';
        return 0;
    }
    return token_ascii(view, token, output, capacity);
}

static int parse_measurement_event(const JsonView *view, IphmLedger *ledger,
                                   char *error, size_t error_size)
{
    IphmActiveMeasurement item;
    uint64_t value;
    int token;
    IphmTarget address;
    char parse_error[128];

    (void)memset(&item, 0, sizeof(item));
    token = object_field(view, 0, "session_id");
    if (token_uint64(view, token, &item.session_id) != 0 ||
        item.session_id == 0U ||
        token_uint64(view, object_field(view, 0, "asn"), &value) != 0 ||
        value == 0U || value > UINT32_MAX ||
        required_ascii_field(view, 0, "segment", item.segment,
                             sizeof(item.segment)) != 0 ||
        !valid_segment_id(item.segment) ||
        token_uint64(view, object_field(view, 0, "family"), &value) != 0 ||
        (value != 4U && value != 6U)) {
        coverage_error(error, error_size,
                       "ledger measurement identity is invalid");
        return -1;
    }
    token = object_field(view, 0, "asn");
    if (token_uint64(view, token, &value) != 0) {
        return -1;
    }
    item.asn = (uint32_t)value;
    if (token_uint64(view, object_field(view, 0, "family"), &value) != 0) {
        return -1;
    }
    item.family = (int)value;
    if (token_uint64(view, object_field(view, 0, "started_at"), &value) != 0 ||
        value > INT64_MAX) {
        coverage_error(error, error_size, "ledger started_at is invalid");
        return -1;
    }
    item.started_at = (int64_t)value;
    if (token_uint64(view, object_field(view, 0, "ended_at"), &value) != 0 ||
        value > INT64_MAX) {
        coverage_error(error, error_size, "ledger ended_at is invalid");
        return -1;
    }
    item.ended_at = (int64_t)value;
    if (required_ascii_field(view, 0, "client_ip", item.client_ip,
                             sizeof(item.client_ip)) != 0 ||
        iphm_parse_target(item.client_ip, &address, parse_error,
                          sizeof(parse_error)) != 0 ||
        address.kind != IPHM_TARGET_ADDRESS || address.is_cidr ||
        address.address_family != item.family ||
        required_ascii_field(view, 0, "route_at_run", item.route_at_run,
                             sizeof(item.route_at_run)) != 0 ||
        required_ascii_field(view, 0, "prober_version",
                             item.prober_version,
                             sizeof(item.prober_version)) != 0 ||
        required_ascii_field(view, 0, "private_source",
                             item.private_source,
                             sizeof(item.private_source)) != 0 ||
        required_ascii_field(view, 0, "routable_source",
                             item.routable_source,
                             sizeof(item.routable_source)) != 0 ||
        token_boolean(view, object_field(view, 0, "reconciled"),
                      &item.reconciled) != 0 ||
        token_boolean(view, object_field(view, 0, "conflict"),
                      &item.conflict) != 0 ||
        optional_ascii_field(view, 0, "caida_prefix", item.caida_prefix,
                             sizeof(item.caida_prefix)) != 0 ||
        optional_ascii_field(view, 0, "caida_timestamp",
                             item.caida_timestamp,
                             sizeof(item.caida_timestamp)) != 0) {
        coverage_error(error, error_size,
                       "ledger measurement fields are invalid");
        return -1;
    }
    if (item.caida_timestamp[0] != '\0' &&
        iphm_parse_timestamp_key(item.caida_timestamp,
                                 &item.caida_timestamp_key) != 0) {
        coverage_error(error, error_size,
                       "ledger CAIDA timestamp is invalid");
        return -1;
    }
    item.verdict =
        iphm_derive_verdict(item.private_source, true,
                            item.routable_source, true);
    item.present = true;
    if (ledger_find(ledger, item.session_id, item.family) != NULL) {
        coverage_error(error, error_size,
                       "duplicate measurement event in ledger");
        return -1;
    }
    return ledger_add(ledger, &item, error, error_size);
}

static int parse_reconciliation_event(const JsonView *view,
                                      IphmLedger *ledger, char *error,
                                      size_t error_size)
{
    uint64_t session_id;
    uint64_t family;
    bool reconciled;
    bool conflict;
    IphmActiveMeasurement *item;

    if (token_uint64(view, object_field(view, 0, "session_id"),
                     &session_id) != 0 ||
        token_uint64(view, object_field(view, 0, "family"), &family) != 0 ||
        (family != 4U && family != 6U) ||
        token_boolean(view, object_field(view, 0, "reconciled"),
                      &reconciled) != 0 ||
        token_boolean(view, object_field(view, 0, "conflict"),
                      &conflict) != 0) {
        coverage_error(error, error_size,
                       "ledger reconciliation identity is invalid");
        return -1;
    }
    item = ledger_find(ledger, session_id, (int)family);
    if (item == NULL) {
        coverage_error(error, error_size,
                       "reconciliation precedes its measurement");
        return -1;
    }
    if (optional_ascii_field(view, 0, "caida_prefix", item->caida_prefix,
                             sizeof(item->caida_prefix)) != 0 ||
        optional_ascii_field(view, 0, "caida_timestamp",
                             item->caida_timestamp,
                             sizeof(item->caida_timestamp)) != 0) {
        coverage_error(error, error_size,
                       "ledger reconciliation fields are invalid");
        return -1;
    }
    item->reconciled = reconciled;
    item->conflict = conflict;
    if (item->caida_timestamp[0] != '\0' &&
        iphm_parse_timestamp_key(item->caida_timestamp,
                                 &item->caida_timestamp_key) != 0) {
        coverage_error(error, error_size,
                       "reconciliation timestamp is invalid");
        return -1;
    }
    return 0;
}

static int parse_ledger(const char *text, size_t length, IphmLedger *ledger,
                        char *error, size_t error_size)
{
    size_t position = 0U;

    while (position < length) {
        size_t start = position;
        size_t end;
        JsonView view;
        char event[32];
        int result;

        while (position < length && text[position] != '\n') {
            ++position;
        }
        end = position;
        if (position < length) {
            ++position;
        }
        if (end == start) {
            continue;
        }
        if (end - start > LEDGER_LINE_MAX ||
            json_open(text + start, end - start, &view, error,
                      error_size) != 0) {
            coverage_error(error, error_size,
                           "measurement ledger contains a malformed line");
            return -1;
        }
        if (view.tokens[0].type != JSMN_OBJECT ||
            token_after(&view, 0) != view.count ||
            required_ascii_field(&view, 0, "event", event,
                                 sizeof(event)) != 0) {
            json_close(&view);
            coverage_error(error, error_size,
                           "measurement ledger event is invalid");
            return -1;
        }
        if (strcmp(event, "measurement") == 0) {
            result = parse_measurement_event(&view, ledger, error,
                                             error_size);
        } else if (strcmp(event, "reconciliation") == 0) {
            result = parse_reconciliation_event(&view, ledger, error,
                                                error_size);
        } else {
            coverage_error(error, error_size,
                           "measurement ledger event type is unsupported");
            result = -1;
        }
        json_close(&view);
        if (result != 0) {
            return -1;
        }
    }
    return 0;
}

int iphm_load_ledger_default(IphmLedger *ledger, char *error,
                             size_t error_size)
{
    bool present;
    char *text;
    size_t length;
    int result;

    (void)memset(ledger, 0, sizeof(*ledger));
    if (read_secure_file(IPHM_LEDGER_PATH, LEDGER_RESPONSE_MAX, true,
                         &present, &text, &length, error,
                         error_size) != 0) {
        return -1;
    }
    if (!present) {
        return 0;
    }
    result = parse_ledger(text, length, ledger, error, error_size);
    free(text);
    if (result != 0) {
        iphm_ledger_free(ledger);
    }
    return result;
}

void iphm_ledger_free(IphmLedger *ledger)
{
    if (ledger != NULL) {
        free(ledger->items);
        (void)memset(ledger, 0, sizeof(*ledger));
    }
}

static int ensure_state_directory(char *error, size_t error_size)
{
    struct stat status;

    if (lstat(IPHM_STATE_DIR, &status) != 0) {
        if (errno != ENOENT || mkdir(IPHM_STATE_DIR, 0750) != 0 ||
            lstat(IPHM_STATE_DIR, &status) != 0) {
            coverage_error(error, error_size,
                           "cannot create secure state directory: %s",
                           strerror(errno));
            return -1;
        }
    }
    if (!S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode) ||
        status.st_uid != (uid_t)0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        coverage_error(error, error_size,
                       "%s must be a root-owned, non-writable directory",
                       IPHM_STATE_DIR);
        return -1;
    }
    return 0;
}

static int append_ledger_line(const char *line, size_t length, char *error,
                              size_t error_size)
{
    int descriptor;
    struct stat status;
    size_t written = 0U;

    if (geteuid() != (uid_t)0 ||
        ensure_state_directory(error, error_size) != 0) {
        if (geteuid() != (uid_t)0) {
            coverage_error(error, error_size,
                           "root is required to update measurement state");
        }
        return -1;
    }
    descriptor = open(IPHM_LEDGER_PATH,
                      O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
                      0600);
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISREG(status.st_mode) || status.st_uid != (uid_t)0 ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        coverage_error(error, error_size,
                       "measurement ledger is not a secure root-owned file");
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    if (flock(descriptor, LOCK_EX) != 0) {
        coverage_error(error, error_size, "cannot lock measurement ledger");
        (void)close(descriptor);
        return -1;
    }
    while (written < length) {
        ssize_t count = write(descriptor, line + written, length - written);

        if (count > 0) {
            written += (size_t)count;
        } else if (count < 0 && errno != EINTR) {
            coverage_error(error, error_size,
                           "cannot append measurement ledger: %s",
                           strerror(errno));
            (void)flock(descriptor, LOCK_UN);
            (void)close(descriptor);
            return -1;
        }
    }
    if (fsync(descriptor) != 0) {
        coverage_error(error, error_size,
                       "cannot synchronize measurement ledger");
        (void)flock(descriptor, LOCK_UN);
        (void)close(descriptor);
        return -1;
    }
    (void)flock(descriptor, LOCK_UN);
    return close(descriptor) == 0 ? 0 : -1;
}

static bool safe_ledger_text(const char *text)
{
    const unsigned char *position = (const unsigned char *)text;

    while (*position != 0U) {
        if (*position < 0x20U || *position > 0x7eU || *position == '"' ||
            *position == '\\') {
            return false;
        }
        ++position;
    }
    return true;
}

int iphm_append_measurement(const IphmActiveMeasurement *measurement,
                            char *error, size_t error_size)
{
    char line[LEDGER_LINE_MAX + 1U];
    int length;

    if (measurement == NULL || !safe_ledger_text(measurement->segment) ||
        !safe_ledger_text(measurement->client_ip) ||
        !safe_ledger_text(measurement->route_at_run) ||
        !safe_ledger_text(measurement->caida_prefix) ||
        !safe_ledger_text(measurement->caida_timestamp) ||
        !safe_ledger_text(measurement->prober_version) ||
        !safe_ledger_text(measurement->private_source) ||
        !safe_ledger_text(measurement->routable_source)) {
        coverage_error(error, error_size,
                       "measurement contains unsafe ledger text");
        return -1;
    }
    length = snprintf(
        line, sizeof(line),
        "{\"event\":\"measurement\",\"session_id\":%" PRIu64
        ",\"asn\":%" PRIu32 ",\"segment\":\"%s\",\"family\":%d,"
        "\"started_at\":%" PRId64 ",\"ended_at\":%" PRId64
        ",\"client_ip\":\"%s\",\"route_at_run\":\"%s\","
        "\"prober_version\":\"%s\",\"private_source\":\"%s\","
        "\"routable_source\":\"%s\",\"verdict\":\"%s\","
        "\"reconciled\":%s,\"conflict\":%s,"
        "\"caida_prefix\":\"%s\",\"caida_timestamp\":\"%s\"}\n",
        measurement->session_id, measurement->asn, measurement->segment,
        measurement->family, measurement->started_at, measurement->ended_at,
        measurement->client_ip, measurement->route_at_run,
        measurement->prober_version, measurement->private_source,
        measurement->routable_source,
        iphm_verdict_name(measurement->verdict),
        measurement->reconciled ? "true" : "false",
        measurement->conflict ? "true" : "false",
        measurement->caida_prefix, measurement->caida_timestamp);
    if (length < 0 || (size_t)length >= sizeof(line)) {
        coverage_error(error, error_size, "measurement ledger line is too long");
        return -1;
    }
    return append_ledger_line(line, (size_t)length, error, error_size);
}

static int append_reconciliation(const IphmActiveMeasurement *measurement,
                                 char *error, size_t error_size)
{
    char line[1024];
    int length = snprintf(
        line, sizeof(line),
        "{\"event\":\"reconciliation\",\"session_id\":%" PRIu64
        ",\"family\":%d,\"reconciled\":%s,\"conflict\":%s,"
        "\"caida_prefix\":\"%s\",\"caida_timestamp\":\"%s\"}\n",
        measurement->session_id, measurement->family,
        measurement->reconciled ? "true" : "false",
        measurement->conflict ? "true" : "false",
        measurement->caida_prefix, measurement->caida_timestamp);

    if (length < 0 || (size_t)length >= sizeof(line)) {
        coverage_error(error, error_size,
                       "reconciliation ledger line is too long");
        return -1;
    }
    return append_ledger_line(line, (size_t)length, error, error_size);
}

int iphm_reconcile_active(IphmActiveMeasurement *measurement,
                          unsigned int timeout_seconds, bool persist,
                          char *error, size_t error_size)
{
    IphmMeasurement api;
    bool found;
    time_t now = time(NULL);
    bool matches;

    if (measurement == NULL || measurement->reconciled ||
        measurement->conflict) {
        return 0;
    }
    if (iphm_query_caida_session(measurement->session_id, measurement->asn,
                                 measurement->family, timeout_seconds,
                                 &found, &api, error, error_size) != 0) {
        return -1;
    }
    if (!found) {
        if (now != (time_t)-1 &&
            (int64_t)now - measurement->ended_at > RECONCILE_GRACE) {
            measurement->conflict = true;
            if (persist &&
                append_reconciliation(measurement, error, error_size) != 0) {
                return -2;
            }
        }
        return 0;
    }
    matches =
        api.client_prefix_present &&
        iphm_prefix_contains_address(api.client_prefix,
                                     measurement->client_ip) &&
        api.private_source_present && api.routable_source_present &&
        strcmp(api.private_source, measurement->private_source) == 0 &&
        strcmp(api.routable_source, measurement->routable_source) == 0;
    measurement->conflict = !matches;
    measurement->reconciled = matches;
    if (api.client_prefix_present) {
        (void)memcpy(measurement->caida_prefix, api.client_prefix,
                     strlen(api.client_prefix) + 1U);
    }
    (void)memcpy(measurement->caida_timestamp, api.timestamp,
                 strlen(api.timestamp) + 1U);
    measurement->caida_timestamp_key = api.timestamp_key;
    if (persist &&
        append_reconciliation(measurement, error, error_size) != 0) {
        return -2;
    }
    return 0;
}

IphmVerdict iphm_conservative_verdict(bool coverage_complete,
                                      const IphmVerdict *fresh_verdicts,
                                      size_t fresh_count,
                                      bool historical_present)
{
    size_t index;
    bool rewritten = false;
    bool all_blocked = fresh_count > 0U;

    for (index = 0U; index < fresh_count; ++index) {
        if (fresh_verdicts[index] == IPHM_VERDICT_SPOOFABLE) {
            return IPHM_VERDICT_SPOOFABLE;
        }
        rewritten =
            rewritten || fresh_verdicts[index] == IPHM_VERDICT_REWRITTEN;
        all_blocked =
            all_blocked && fresh_verdicts[index] == IPHM_VERDICT_BLOCKED;
    }
    if (rewritten) {
        return IPHM_VERDICT_REWRITTEN;
    }
    if (coverage_complete && all_blocked) {
        return IPHM_VERDICT_BLOCKED;
    }
    if (fresh_count == 0U && !historical_present) {
        return IPHM_VERDICT_NO_DATA;
    }
    return IPHM_VERDICT_INCONCLUSIVE;
}

const char *iphm_coverage_state_name(IphmCoverageState state)
{
    switch (state) {
    case IPHM_COVERAGE_UNMEASURED:
        return "unmeasured";
    case IPHM_COVERAGE_STALE:
        return "stale";
    case IPHM_COVERAGE_FRESH:
        return "fresh";
    case IPHM_COVERAGE_ROUTE_CHANGED:
        return "route_changed";
    case IPHM_COVERAGE_AMBIGUOUS:
        return "ambiguous";
    default:
        return "ambiguous";
    }
}

static void format_epoch(int64_t epoch, char *output, size_t output_size)
{
    time_t value = (time_t)epoch;
    struct tm broken_down;

    if (gmtime_r(&value, &broken_down) == NULL ||
        strftime(output, output_size, "%Y-%m-%dT%H:%M:%SZ",
                 &broken_down) == 0U) {
        (void)snprintf(output, output_size, "unknown");
    }
}

static int emit_inventory_json(const IphmInventory *inventory, uint32_t asn)
{
    size_t index;
    char queried[IPHM_TIMESTAMP_MAX];
    char newest[IPHM_TIMESTAMP_MAX];

    format_epoch(inventory->queried_at, queried, sizeof(queried));
    if (inventory->source_time_present) {
        format_epoch(inventory->newest_source_time, newest, sizeof(newest));
    }
    if (fprintf(stdout,
                "{\"mode\":\"inventory\",\"asn\":%" PRIu32
                ",\"routing_snapshot\":{\"queried_at\":",
                asn) < 0 ||
        iphm_json_write_string(stdout, queried) != 0 ||
        fputs(",\"newest_source_at\":", stdout) == EOF) {
        return -1;
    }
    if (inventory->source_time_present) {
        if (iphm_json_write_string(stdout, newest) != 0) {
            return -1;
        }
    } else if (fputs("null", stdout) == EOF) {
        return -1;
    }
    if (fprintf(stdout, ",\"status\":\"%s\"},\"routes\":[",
                inventory->source_fresh ? "fresh" : "stale") < 0) {
        return -1;
    }
    for (index = 0U; index < inventory->route_count; ++index) {
        size_t origin;

        if ((index != 0U && fputc(',', stdout) == EOF) ||
            fputs("{\"prefix\":", stdout) == EOF ||
            iphm_json_write_string(stdout,
                                   inventory->routes[index].prefix) != 0 ||
            fprintf(stdout, ",\"family\":\"ipv%d\",\"origins\":[",
                    inventory->routes[index].family) < 0) {
            return -1;
        }
        for (origin = 0U;
             origin < inventory->routes[index].origin_count; ++origin) {
            if ((origin != 0U && fputc(',', stdout) == EOF) ||
                fprintf(stdout, "%" PRIu32,
                        inventory->routes[index].origins[origin]) < 0) {
                return -1;
            }
        }
        if (fprintf(stdout, "],\"moas\":%s}",
                    inventory->routes[index].moas ? "true" : "false") < 0) {
            return -1;
        }
    }
    return fputs("]}\n", stdout) == EOF ? -1 : 0;
}

int iphm_command_inventory(uint32_t asn, unsigned int timeout_seconds,
                           bool json, char *error, size_t error_size)
{
    IphmInventory inventory;

    if (iphm_query_inventory(asn, timeout_seconds, &inventory, error,
                             error_size) != 0) {
        return IPHM_EXIT_RESOLUTION;
    }
    if (json) {
        if (emit_inventory_json(&inventory, asn) != 0) {
            coverage_error(error, error_size, "inventory output failed");
            iphm_inventory_free(&inventory);
            return IPHM_EXIT_CAIDA;
        }
    } else {
        size_t index;

        (void)printf("AS%" PRIu32 " current RIS route inventory\n", asn);
        (void)printf("Routing snapshot: %s\n",
                     inventory.source_fresh ? "fresh" : "stale or unknown");
        for (index = 0U; index < inventory.route_count; ++index) {
            (void)printf("  %s%s\n", inventory.routes[index].prefix,
                         inventory.routes[index].moas ? " (MOAS)" : "");
        }
        (void)printf("Routes: %zu\n", inventory.route_count);
    }
    iphm_inventory_free(&inventory);
    return 0;
}

static int coverage_rank(IphmCoverageState state)
{
    switch (state) {
    case IPHM_COVERAGE_UNMEASURED:
        return 0;
    case IPHM_COVERAGE_STALE:
        return 1;
    case IPHM_COVERAGE_ROUTE_CHANGED:
        return 2;
    case IPHM_COVERAGE_FRESH:
        return 3;
    case IPHM_COVERAGE_AMBIGUOUS:
        return 4;
    default:
        return 4;
    }
}

static void promote_state(IphmCoverageState *state,
                          IphmCoverageState candidate)
{
    if (coverage_rank(candidate) > coverage_rank(*state)) {
        *state = candidate;
    }
}

static const IphmSegment *find_segment(const IphmConfig *config,
                                       const char *id)
{
    size_t index;

    for (index = 0U; index < config->segment_count; ++index) {
        if (strcmp(config->segments[index].id, id) == 0) {
            return &config->segments[index];
        }
    }
    return NULL;
}

static bool measurement_is_fresh(const IphmActiveMeasurement *measurement,
                                 int64_t now, unsigned int max_age_days)
{
    int64_t age;

    if (!measurement->reconciled || measurement->conflict ||
        measurement->caida_timestamp_key == 0) {
        return false;
    }
    age = now - measurement->caida_timestamp_key;
    return age >= -300LL &&
           age <= (int64_t)max_age_days * SECONDS_PER_DAY;
}

static int emit_historical_json(const IphmMeasurement *measurement,
                                int64_t now, unsigned int max_age_days)
{
    bool fresh;

    if (!measurement->present) {
        return fputs("null", stdout) == EOF ? -1 : 0;
    }
    fresh = now - measurement->timestamp_key >= -300LL &&
            now - measurement->timestamp_key <=
                (int64_t)max_age_days * SECONDS_PER_DAY;
    if (fprintf(stdout, "{\"session_id\":%" PRIu64 ",\"timestamp\":",
                measurement->session_id) < 0 ||
        iphm_json_write_string(stdout, measurement->timestamp) != 0 ||
        fputs(",\"client_prefix\":", stdout) == EOF) {
        return -1;
    }
    if (measurement->client_prefix_present) {
        if (iphm_json_write_string(stdout, measurement->client_prefix) != 0) {
            return -1;
        }
    } else if (fputs("null", stdout) == EOF) {
        return -1;
    }
    return fprintf(stdout, ",\"verdict\":\"%s\",\"fresh\":%s}",
                   iphm_verdict_name(measurement->verdict),
                   fresh ? "true" : "false") < 0
               ? -1
               : 0;
}

static int emit_audit_json(
    uint32_t asn, unsigned int max_age_days, const IphmInventory *inventory,
    const IphmConfig *config, bool managed, const IphmLedger *ledger,
    const IphmCoverageState *route_states,
    IphmCoverageState segment_states[IPHM_MAX_SEGMENTS][2],
    size_t routes_fresh, size_t segment_requirements, size_t segments_fresh,
    bool complete, bool inconclusive_coverage, IphmVerdict overall,
    const IphmReport *historical, int64_t now)
{
    size_t index;
    bool first;
    char queried[IPHM_TIMESTAMP_MAX];
    char newest[IPHM_TIMESTAMP_MAX];
    const char *coverage_name =
        inconclusive_coverage ? "inconclusive"
                              : (complete ? "complete" : "partial");

    format_epoch(inventory->queried_at, queried, sizeof(queried));
    if (inventory->source_time_present) {
        format_epoch(inventory->newest_source_time, newest, sizeof(newest));
    }
    if (fprintf(stdout,
                "{\"mode\":\"audit\",\"asn\":%" PRIu32
                ",\"freshness_days\":%u,\"routing_snapshot\":"
                "{\"queried_at\":",
                asn, max_age_days) < 0 ||
        iphm_json_write_string(stdout, queried) != 0 ||
        fputs(",\"newest_source_at\":", stdout) == EOF) {
        return -1;
    }
    if (inventory->source_time_present) {
        if (iphm_json_write_string(stdout, newest) != 0) {
            return -1;
        }
    } else if (fputs("null", stdout) == EOF) {
        return -1;
    }
    if (fprintf(stdout,
                ",\"status\":\"%s\"},\"coverage\":"
                "{\"status\":\"%s\",\"managed\":%s,"
                "\"routes_total\":%zu,\"routes_fresh\":%zu,"
                "\"segment_requirements\":%zu,\"segments_fresh\":%zu},"
                "\"routes\":[",
                inventory->source_fresh ? "fresh" : "stale", coverage_name,
                managed ? "true" : "false", inventory->route_count,
                routes_fresh, segment_requirements, segments_fresh) < 0) {
        return -1;
    }
    for (index = 0U; index < inventory->route_count; ++index) {
        if ((index != 0U && fputc(',', stdout) == EOF) ||
            fputs("{\"prefix\":", stdout) == EOF ||
            iphm_json_write_string(stdout, inventory->routes[index].prefix) !=
                0 ||
            fprintf(stdout,
                    ",\"family\":\"ipv%d\",\"moas\":%s,\"status\":\"%s\"}",
                    inventory->routes[index].family,
                    inventory->routes[index].moas ? "true" : "false",
                    iphm_coverage_state_name(route_states[index])) < 0) {
            return -1;
        }
    }
    if (fputs("],\"segments\":[", stdout) == EOF) {
        return -1;
    }
    first = true;
    if (managed) {
        for (index = 0U; index < config->segment_count; ++index) {
            int family_index;

            for (family_index = 0; family_index < 2; ++family_index) {
                int family = family_index == 0 ? 4 : 6;
                bool enabled = family == 4 ? config->segments[index].ipv4
                                           : config->segments[index].ipv6;

                if (!enabled) {
                    continue;
                }
                if ((!first && fputc(',', stdout) == EOF) ||
                    fputs("{\"id\":", stdout) == EOF ||
                    iphm_json_write_string(stdout,
                                           config->segments[index].id) != 0 ||
                    fprintf(stdout,
                            ",\"family\":\"ipv%d\",\"status\":\"%s\"}",
                            family,
                            iphm_coverage_state_name(
                                segment_states[index][family_index])) < 0) {
                    return -1;
                }
                first = false;
            }
        }
    }
    if (fputs("],\"fresh_measurements\":[", stdout) == EOF) {
        return -1;
    }
    first = true;
    for (index = 0U; index < ledger->count; ++index) {
        const IphmActiveMeasurement *measurement = &ledger->items[index];
        size_t route_index;
        const IphmSegment *segment;

        if (measurement->asn != asn ||
            !measurement_is_fresh(measurement, now, max_age_days) ||
            iphm_inventory_longest_route(inventory, measurement->client_ip,
                                         &route_index) != 0 ||
            strcmp(inventory->routes[route_index].prefix,
                   measurement->route_at_run) != 0 ||
            inventory->routes[route_index].moas) {
            continue;
        }
        segment = managed ? find_segment(config, measurement->segment) : NULL;
        if (segment == NULL) {
            continue;
        }
        if ((!first && fputc(',', stdout) == EOF) ||
            fprintf(stdout, "{\"session_id\":%" PRIu64 ",\"segment\":",
                    measurement->session_id) < 0 ||
            iphm_json_write_string(stdout, measurement->segment) != 0 ||
            fprintf(stdout, ",\"family\":\"ipv%d\",\"timestamp\":",
                    measurement->family) < 0 ||
            iphm_json_write_string(stdout,
                                   measurement->caida_timestamp) != 0 ||
            fputs(",\"matched_prefix\":", stdout) == EOF ||
            iphm_json_write_string(stdout,
                                   measurement->route_at_run) != 0 ||
            fputs(",\"client_prefix\":", stdout) == EOF ||
            iphm_json_write_string(stdout,
                                   measurement->caida_prefix) != 0 ||
            fprintf(stdout, ",\"verdict\":\"%s\"}",
                    iphm_verdict_name(measurement->verdict)) < 0) {
            return -1;
        }
        first = false;
    }
    if (fputs("],\"historical_measurements\":{\"ipv4\":", stdout) == EOF ||
        emit_historical_json(&historical->ipv4, now, max_age_days) != 0 ||
        fputs(",\"ipv6\":", stdout) == EOF ||
        emit_historical_json(&historical->ipv6, now, max_age_days) != 0 ||
        fprintf(stdout, "},\"overall_verdict\":\"%s\"}\n",
                iphm_verdict_name(overall)) < 0) {
        return -1;
    }
    return 0;
}

int iphm_command_audit(uint32_t asn, unsigned int timeout_seconds,
                       unsigned int max_age_days, bool require_complete,
                       bool json, char *error, size_t error_size)
{
    IphmInventory inventory;
    IphmConfig config;
    bool config_present;
    bool managed;
    IphmLedger ledger;
    IphmReport historical;
    IphmCoverageState *route_states;
    IphmCoverageState segment_states[IPHM_MAX_SEGMENTS][2];
    IphmVerdict *fresh_verdicts;
    size_t fresh_count = 0U;
    size_t routes_fresh = 0U;
    size_t segment_requirements = 0U;
    size_t segments_fresh = 0U;
    size_t index;
    int64_t now;
    bool conflict = false;
    bool moas = false;
    bool complete;
    bool inconclusive_coverage;
    bool historical_present;
    IphmVerdict overall;
    time_t current_time = time(NULL);

    if (current_time == (time_t)-1) {
        coverage_error(error, error_size, "system time is unavailable");
        return IPHM_EXIT_CAIDA;
    }
    now = (int64_t)current_time;
    if (iphm_load_config_default(&config, &config_present, error,
                                 error_size) != 0) {
        return IPHM_EXIT_AUTH;
    }
    managed = config_present && config.asn == asn;
    if (iphm_query_inventory(asn, timeout_seconds, &inventory, error,
                             error_size) != 0) {
        return IPHM_EXIT_RESOLUTION;
    }
    if (iphm_load_ledger_default(&ledger, error, error_size) != 0) {
        iphm_inventory_free(&inventory);
        return IPHM_EXIT_STATE;
    }
    for (index = 0U; index < ledger.count; ++index) {
        int result;

        if (ledger.items[index].asn != asn ||
            ledger.items[index].reconciled ||
            ledger.items[index].conflict) {
            continue;
        }
        result = iphm_reconcile_active(&ledger.items[index], timeout_seconds,
                                       geteuid() == (uid_t)0, error,
                                       error_size);
        if (result == -2) {
            iphm_ledger_free(&ledger);
            iphm_inventory_free(&inventory);
            return IPHM_EXIT_STATE;
        }
        if (result != 0) {
            iphm_ledger_free(&ledger);
            iphm_inventory_free(&inventory);
            return IPHM_EXIT_CAIDA;
        }
    }
    (void)memset(&historical, 0, sizeof(historical));
    historical.asn = asn;
    (void)snprintf(historical.input, sizeof(historical.input), "AS%" PRIu32,
                   asn);
    if (iphm_query_caida(asn, timeout_seconds, &historical, error,
                         error_size) != 0) {
        iphm_ledger_free(&ledger);
        iphm_inventory_free(&inventory);
        return IPHM_EXIT_CAIDA;
    }
    iphm_finalize_report(&historical);
    route_states =
        calloc(inventory.route_count == 0U ? 1U : inventory.route_count,
               sizeof(*route_states));
    fresh_verdicts =
        calloc(ledger.count == 0U ? 1U : ledger.count,
               sizeof(*fresh_verdicts));
    if (route_states == NULL || fresh_verdicts == NULL) {
        coverage_error(error, error_size, "out of memory evaluating audit");
        free(route_states);
        free(fresh_verdicts);
        iphm_ledger_free(&ledger);
        iphm_inventory_free(&inventory);
        return IPHM_EXIT_CAIDA;
    }
    (void)memset(segment_states, 0, sizeof(segment_states));
    for (index = 0U; index < inventory.route_count; ++index) {
        if (inventory.routes[index].moas) {
            route_states[index] = IPHM_COVERAGE_AMBIGUOUS;
            moas = true;
        }
    }
    for (index = 0U; index < ledger.count; ++index) {
        const IphmActiveMeasurement *measurement = &ledger.items[index];
        size_t route_index;
        const IphmSegment *segment;
        IphmCoverageState candidate;
        size_t segment_index;
        int family_index;

        if (measurement->asn != asn) {
            continue;
        }
        conflict = conflict || measurement->conflict;
        if (measurement->conflict) {
            candidate = IPHM_COVERAGE_AMBIGUOUS;
        } else if (iphm_inventory_longest_route(
                       &inventory, measurement->client_ip,
                       &route_index) != 0 ||
                   strcmp(inventory.routes[route_index].prefix,
                          measurement->route_at_run) != 0) {
            candidate = IPHM_COVERAGE_ROUTE_CHANGED;
        } else if (measurement_is_fresh(measurement, now, max_age_days)) {
            candidate = IPHM_COVERAGE_FRESH;
        } else if (measurement->reconciled) {
            candidate = IPHM_COVERAGE_STALE;
        } else {
            candidate = IPHM_COVERAGE_UNMEASURED;
        }
        if (iphm_inventory_longest_route(&inventory, measurement->client_ip,
                                         &route_index) == 0) {
            promote_state(&route_states[route_index], candidate);
        }
        segment = managed ? find_segment(&config, measurement->segment) : NULL;
        if (segment == NULL) {
            continue;
        }
        segment_index = (size_t)(segment - config.segments);
        family_index = measurement->family == 4 ? 0 : 1;
        promote_state(&segment_states[segment_index][family_index],
                      candidate);
        if (candidate == IPHM_COVERAGE_FRESH &&
            iphm_inventory_longest_route(&inventory,
                                         measurement->client_ip,
                                         &route_index) == 0 &&
            !inventory.routes[route_index].moas) {
            fresh_verdicts[fresh_count++] = measurement->verdict;
        }
    }
    for (index = 0U; index < inventory.route_count; ++index) {
        if (route_states[index] == IPHM_COVERAGE_FRESH) {
            ++routes_fresh;
        }
    }
    if (managed) {
        for (index = 0U; index < config.segment_count; ++index) {
            if (config.segments[index].ipv4) {
                ++segment_requirements;
                if (segment_states[index][0] == IPHM_COVERAGE_FRESH) {
                    ++segments_fresh;
                }
            }
            if (config.segments[index].ipv6) {
                ++segment_requirements;
                if (segment_states[index][1] == IPHM_COVERAGE_FRESH) {
                    ++segments_fresh;
                }
            }
        }
    }
    complete = managed && inventory.source_fresh &&
               inventory.route_count > 0U &&
               routes_fresh == inventory.route_count &&
               segment_requirements > 0U &&
               segments_fresh == segment_requirements && !conflict && !moas;
    inconclusive_coverage =
        !inventory.source_fresh || conflict || moas;
    historical_present = historical.ipv4.present || historical.ipv6.present;
    overall = iphm_conservative_verdict(complete, fresh_verdicts,
                                        fresh_count, historical_present);
    if (json) {
        if (emit_audit_json(
                asn, max_age_days, &inventory, &config, managed, &ledger,
                route_states, segment_states, routes_fresh,
                segment_requirements, segments_fresh, complete,
                inconclusive_coverage, overall, &historical, now) != 0) {
            coverage_error(error, error_size, "audit output failed");
            free(route_states);
            free(fresh_verdicts);
            iphm_ledger_free(&ledger);
            iphm_inventory_free(&inventory);
            return IPHM_EXIT_CAIDA;
        }
    } else {
        const char *coverage_name =
            inconclusive_coverage ? "inconclusive"
                                  : (complete ? "complete" : "partial");

        (void)printf("AS%" PRIu32 " IPHM audit\n", asn);
        (void)printf("Evidence window: %u days\n", max_age_days);
        (void)printf("Coverage: %s, routes %zu/%zu, segments %zu/%zu\n",
                     coverage_name, routes_fresh, inventory.route_count,
                     segments_fresh, segment_requirements);
        for (index = 0U; index < inventory.route_count; ++index) {
            if (route_states[index] != IPHM_COVERAGE_FRESH) {
                (void)printf("  Route %s: %s\n",
                             inventory.routes[index].prefix,
                             iphm_coverage_state_name(route_states[index]));
            }
        }
        if (managed) {
            for (index = 0U; index < config.segment_count; ++index) {
                if (config.segments[index].ipv4 &&
                    segment_states[index][0] != IPHM_COVERAGE_FRESH) {
                    (void)printf("  Segment %s/IPv4: %s\n",
                                 config.segments[index].id,
                                 iphm_coverage_state_name(
                                     segment_states[index][0]));
                }
                if (config.segments[index].ipv6 &&
                    segment_states[index][1] != IPHM_COVERAGE_FRESH) {
                    (void)printf("  Segment %s/IPv6: %s\n",
                                 config.segments[index].id,
                                 iphm_coverage_state_name(
                                     segment_states[index][1]));
                }
            }
        } else {
            (void)puts("  No matching managed segment configuration.");
        }
        (void)printf("Verdict: %s, observed on measured paths only\n",
                     iphm_verdict_name(overall));
        if (historical.ipv4.present) {
            (void)printf("Historical IPv4: %s at %s\n",
                         iphm_verdict_name(historical.ipv4.verdict),
                         historical.ipv4.timestamp);
        }
        if (historical.ipv6.present) {
            (void)printf("Historical IPv6: %s at %s\n",
                         iphm_verdict_name(historical.ipv6.verdict),
                         historical.ipv6.timestamp);
        }
    }
    free(route_states);
    free(fresh_verdicts);
    iphm_ledger_free(&ledger);
    iphm_inventory_free(&inventory);
    return require_complete && !complete ? IPHM_EXIT_INCOMPLETE : 0;
}
