#define _POSIX_C_SOURCE 200809L

#include "iphm.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROBER_OUTPUT_MAX (4U * IPHM_MAX_RESPONSE)
#define PROBER_PATH_COUNT 2U
#define SECONDS_PER_DAY 86400LL

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
    bool overflow;
} Capture;

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 3, 4)))
#endif
static void measure_error(char *error, size_t error_size,
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

static int copy_value(char *destination, size_t capacity, const char *source,
                      size_t length)
{
    if (length >= capacity) {
        return -1;
    }
    (void)memcpy(destination, source, length);
    destination[length] = '\0';
    return 0;
}

static int parse_u64_value(const char *text, uint64_t *value)
{
    uint64_t result = 0U;
    size_t index;
    size_t length = strlen(text);

    if (length == 0U) {
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

static char *trim(char *text)
{
    char *end;

    while (*text == ' ' || *text == '\t' || *text == '\r') {
        ++text;
    }
    end = text + strlen(text);
    while (end > text &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
        --end;
    }
    *end = '\0';
    return text;
}

static bool valid_status(const char *status)
{
    return strcmp(status, "blocked") == 0 ||
           strcmp(status, "rewritten") == 0 ||
           strcmp(status, "received") == 0 ||
           strcmp(status, "unknown") == 0;
}

static IphmProberFamily *prober_family(IphmProberOutput *output, int family)
{
    return family == 4 ? &output->ipv4 : &output->ipv6;
}

int iphm_parse_prober_output(const char *text, size_t length,
                             IphmProberOutput *output, char *error,
                             size_t error_size)
{
    char *copy;
    char *line;
    char *save = NULL;
    int context_family = 0;
    bool summary_context = false;
    unsigned int summary4 = 0U;
    unsigned int summary6 = 0U;

    if (text == NULL || output == NULL || length == 0U ||
        length > PROBER_OUTPUT_MAX) {
        measure_error(error, error_size, "empty or oversized prober output");
        return -1;
    }
    copy = malloc(length + 1U);
    if (copy == NULL) {
        measure_error(error, error_size, "out of memory parsing prober output");
        return -1;
    }
    (void)memcpy(copy, text, length);
    copy[length] = '\0';
    (void)memset(output, 0, sizeof(*output));
    line = strtok_r(copy, "\n", &save);
    while (line != NULL) {
        char *value;
        uint64_t number;
        IphmProberFamily *family_result;

        line = trim(line);
        if (strstr(line, "ServerMessage (IPv4):") != NULL) {
            context_family = 4;
            summary_context = false;
        } else if (strstr(line, "ServerMessage (IPv6):") != NULL) {
            context_family = 6;
            summary_context = false;
        } else if (strstr(line, "IPv4 Result Summary:") != NULL) {
            context_family = 4;
            summary_context = true;
            ++summary4;
            output->ipv4.present = true;
            output->ipv4.family = 4;
        } else if (strstr(line, "IPv6 Result Summary:") != NULL) {
            context_family = 6;
            summary_context = true;
            ++summary6;
            output->ipv6.present = true;
            output->ipv6.family = 6;
        } else if (context_family != 0 &&
                   (value = strstr(line, "sessionid:")) != NULL) {
            family_result = prober_family(output, context_family);
            value = trim(value + strlen("sessionid:"));
            if (parse_u64_value(value, &number) != 0 || number == 0U ||
                (family_result->session_id != 0U &&
                 family_result->session_id != number)) {
                measure_error(error, error_size,
                              "prober session id is invalid or conflicting");
                free(copy);
                return -1;
            }
            family_result->session_id = number;
        } else if (context_family != 0 &&
                   (value = strstr(line, "clientip:")) != NULL) {
            IphmTarget target;
            char target_error[128];

            family_result = prober_family(output, context_family);
            value = trim(value + strlen("clientip:"));
            if (iphm_parse_target(value, &target, target_error,
                                  sizeof(target_error)) != 0 ||
                target.kind != IPHM_TARGET_ADDRESS || target.is_cidr ||
                target.address_family != context_family ||
                copy_value(family_result->client_ip,
                           sizeof(family_result->client_ip), target.address,
                           strlen(target.address)) != 0) {
                measure_error(error, error_size,
                              "prober client address is invalid");
                free(copy);
                return -1;
            }
        } else if (summary_context && context_family != 0 &&
                   (value = strstr(line, "ASN:")) != NULL) {
            family_result = prober_family(output, context_family);
            value = trim(value + strlen("ASN:"));
            if (parse_u64_value(value, &number) != 0 || number == 0U ||
                number > UINT32_MAX) {
                measure_error(error, error_size, "prober ASN is invalid");
                free(copy);
                return -1;
            }
            family_result->asn = (uint32_t)number;
        } else if (summary_context && context_family != 0 &&
                   strstr(line, "Spoofed private addresses, outbound:") !=
                       NULL) {
            family_result = prober_family(output, context_family);
            value = strrchr(line, ':');
            value = value == NULL ? line : trim(value + 1);
            if (!valid_status(value) ||
                copy_value(family_result->private_source,
                           sizeof(family_result->private_source), value,
                           strlen(value)) != 0) {
                measure_error(error, error_size,
                              "prober private-source status is invalid");
                free(copy);
                return -1;
            }
        } else if (summary_context && context_family != 0 &&
                   strstr(line, "Spoofed routable addresses, outbound:") !=
                       NULL) {
            family_result = prober_family(output, context_family);
            value = strrchr(line, ':');
            value = value == NULL ? line : trim(value + 1);
            if (!valid_status(value) ||
                copy_value(family_result->routable_source,
                           sizeof(family_result->routable_source), value,
                           strlen(value)) != 0) {
                measure_error(error, error_size,
                              "prober routable-source status is invalid");
                free(copy);
                return -1;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(copy);
    if (summary4 > 1U || summary6 > 1U) {
        measure_error(error, error_size, "duplicate prober result summary");
        return -1;
    }
    if (!output->ipv4.present && !output->ipv6.present) {
        measure_error(error, error_size, "prober produced no result summary");
        return -1;
    }
    if ((output->ipv4.present &&
         (output->ipv4.session_id == 0U || output->ipv4.asn == 0U ||
          output->ipv4.client_ip[0] == '\0' ||
          output->ipv4.private_source[0] == '\0' ||
          output->ipv4.routable_source[0] == '\0')) ||
        (output->ipv6.present &&
         (output->ipv6.session_id == 0U || output->ipv6.asn == 0U ||
          output->ipv6.client_ip[0] == '\0' ||
          output->ipv6.private_source[0] == '\0' ||
          output->ipv6.routable_source[0] == '\0'))) {
        measure_error(error, error_size,
                      "prober result is missing required fields");
        return -1;
    }
    if (output->ipv4.present) {
        output->ipv4.verdict =
            iphm_derive_verdict(output->ipv4.private_source, true,
                                output->ipv4.routable_source, true);
    }
    if (output->ipv6.present) {
        output->ipv6.verdict =
            iphm_derive_verdict(output->ipv6.private_source, true,
                                output->ipv6.routable_source, true);
    }
    return 0;
}

static int64_t monotonic_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000LL +
           (int64_t)now.tv_nsec / 1000000LL;
}

static int capture_append(Capture *capture, const char *data, size_t length)
{
    size_t needed;

    if (length > PROBER_OUTPUT_MAX - capture->length) {
        capture->overflow = true;
        return -1;
    }
    needed = capture->length + length + 1U;
    if (needed > capture->capacity) {
        size_t capacity =
            capture->capacity == 0U ? 4096U : capture->capacity;
        char *replacement;

        while (capacity < needed) {
            capacity *= 2U;
        }
        replacement = realloc(capture->data, capacity);
        if (replacement == NULL) {
            return -1;
        }
        capture->data = replacement;
        capture->capacity = capacity;
    }
    (void)memcpy(capture->data + capture->length, data, length);
    capture->length += length;
    capture->data[capture->length] = '\0';
    return 0;
}

static void terminate_child(pid_t child)
{
    struct timespec pause_time;

    (void)kill(-child, SIGTERM);
    (void)kill(child, SIGTERM);
    pause_time.tv_sec = 0;
    pause_time.tv_nsec = 200000000L;
    while (nanosleep(&pause_time, &pause_time) != 0 && errno == EINTR) {
    }
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
}

static int run_program(const char *path, char *const arguments[],
                       unsigned int timeout_seconds, Capture *capture,
                       int *exit_status, char *error, size_t error_size)
{
    int pipe_fds[2];
    pid_t child;
    int flags;
    int64_t deadline;
    bool open_pipe = true;
    bool timed_out = false;
    int child_status = 0;

    (void)memset(capture, 0, sizeof(*capture));
    if (pipe(pipe_fds) != 0) {
        measure_error(error, error_size, "cannot create prober output pipe");
        return -1;
    }
    if (fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC) != 0) {
        measure_error(error, error_size, "cannot secure prober output pipe");
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        return -1;
    }
    child = fork();
    if (child < 0) {
        measure_error(error, error_size, "cannot create prober process");
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        return -1;
    }
    if (child == 0) {
        (void)setpgid(0, 0);
        (void)close(pipe_fds[0]);
        if (dup2(pipe_fds[1], STDOUT_FILENO) < 0 ||
            dup2(pipe_fds[1], STDERR_FILENO) < 0) {
            _exit(126);
        }
        (void)close(pipe_fds[1]);
        execv(path, arguments);
        _exit(127);
    }
    (void)setpgid(child, child);
    (void)close(pipe_fds[1]);
    flags = fcntl(pipe_fds[0], F_GETFL, 0);
    if (flags < 0 ||
        fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        terminate_child(child);
        (void)waitpid(child, &child_status, 0);
        (void)close(pipe_fds[0]);
        measure_error(error, error_size, "cannot configure prober pipe");
        return -1;
    }
    deadline = monotonic_ms() + (int64_t)timeout_seconds * 1000LL;
    while (open_pipe) {
        struct pollfd descriptor;
        int64_t now = monotonic_ms();
        int poll_timeout;
        int polled;

        if (now < 0 || now >= deadline) {
            timed_out = true;
            break;
        }
        poll_timeout = deadline - now > 100LL ? 100 : (int)(deadline - now);
        descriptor.fd = pipe_fds[0];
        descriptor.events = POLLIN | POLLHUP;
        descriptor.revents = 0;
        do {
            polled = poll(&descriptor, 1U, poll_timeout);
        } while (polled < 0 && errno == EINTR);
        if (polled < 0) {
            break;
        }
        if (polled > 0 &&
            (descriptor.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            for (;;) {
                char buffer[4096];
                ssize_t count = read(pipe_fds[0], buffer, sizeof(buffer));

                if (count > 0) {
                    if (capture_append(capture, buffer, (size_t)count) != 0) {
                        open_pipe = false;
                        break;
                    }
                } else if (count == 0) {
                    open_pipe = false;
                    break;
                } else if (errno != EINTR && errno != EAGAIN &&
                           errno != EWOULDBLOCK) {
                    open_pipe = false;
                    break;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
            }
        }
    }
    (void)close(pipe_fds[0]);
    if (timed_out || capture->overflow) {
        terminate_child(child);
    }
    do {
        if (waitpid(child, &child_status, 0) >= 0) {
            break;
        }
    } while (errno == EINTR);
    if (timed_out) {
        measure_error(error, error_size, "prober timed out after %u seconds",
                      timeout_seconds);
        return -1;
    }
    if (capture->overflow) {
        measure_error(error, error_size,
                      "prober output exceeded %u bytes", PROBER_OUTPUT_MAX);
        return -1;
    }
    if (!WIFEXITED(child_status)) {
        measure_error(error, error_size, "prober terminated abnormally");
        return -1;
    }
    *exit_status = WEXITSTATUS(child_status);
    return 0;
}

static int find_trusted_prober(char *path, size_t path_size, char *error,
                               size_t error_size)
{
    static const char *const paths[PROBER_PATH_COUNT] = {
        "/usr/bin/spoofer-prober",
        "/usr/local/bin/spoofer-prober"
    };
    size_t index;

    for (index = 0U; index < PROBER_PATH_COUNT; ++index) {
        struct stat status;

        if (lstat(paths[index], &status) == 0 &&
            S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode) &&
            status.st_uid == (uid_t)0 &&
            (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
            access(paths[index], X_OK) == 0 &&
            copy_value(path, path_size, paths[index],
                       strlen(paths[index])) == 0) {
            return 0;
        }
    }
    measure_error(error, error_size,
                  "no trusted root-owned spoofer-prober was found");
    return -1;
}

static int parse_version(const char *text, char *version, size_t version_size)
{
    size_t position;
    size_t length = strlen(text);

    for (position = 0U; position < length; ++position) {
        unsigned int major;
        unsigned int minor;
        unsigned int patch;
        int consumed = 0;

        if (text[position] < '0' || text[position] > '9') {
            continue;
        }
        if (sscanf(text + position, "%u.%u.%u%n", &major, &minor, &patch,
                   &consumed) == 3 &&
            consumed > 0 && major == 1U && minor >= 5U) {
            return copy_value(version, version_size, text + position,
                              (size_t)consumed);
        }
    }
    return -1;
}

static const IphmSegment *select_segment(const IphmConfig *config,
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

static int requested_mask(const IphmSegment *segment, const char *family)
{
    int configured = (segment->ipv4 ? 1 : 0) | (segment->ipv6 ? 2 : 0);

    if (family == NULL) {
        return configured;
    }
    if (strcmp(family, "4") == 0) {
        return (configured & 1) != 0 ? 1 : 0;
    }
    if (strcmp(family, "6") == 0) {
        return (configured & 2) != 0 ? 2 : 0;
    }
    if (strcmp(family, "both") == 0) {
        return configured == 3 ? 3 : 0;
    }
    return 0;
}

static bool expected_client(const IphmSegment *segment, int family,
                            const char *client_ip)
{
    size_t index;

    for (index = 0U; index < segment->expected_prefix_count; ++index) {
        if (segment->expected_families[index] == family &&
            iphm_prefix_contains_address(segment->expected_prefixes[index],
                                         client_ip)) {
            return true;
        }
    }
    return false;
}

static bool rate_limited(const IphmLedger *ledger, const char *segment,
                         int family, int64_t now, unsigned int days)
{
    size_t index;
    int64_t interval = (int64_t)days * SECONDS_PER_DAY;

    for (index = 0U; index < ledger->count; ++index) {
        if (ledger->items[index].session_id != 0U &&
            ledger->items[index].family == family &&
            strcmp(ledger->items[index].segment, segment) == 0 &&
            now - ledger->items[index].ended_at >= 0 &&
            now - ledger->items[index].ended_at < interval) {
            return true;
        }
    }
    return false;
}

static int emit_measure_json(const IphmActiveMeasurement *items,
                             size_t count)
{
    size_t index;

    if (fputs("{\"mode\":\"measure\",\"results\":[", stdout) == EOF) {
        return -1;
    }
    for (index = 0U; index < count; ++index) {
        if ((index != 0U && fputc(',', stdout) == EOF) ||
            fprintf(stdout,
                    "{\"asn\":%" PRIu32 ",\"segment\":",
                    items[index].asn) < 0 ||
            iphm_json_write_string(stdout, items[index].segment) != 0 ||
            fprintf(stdout,
                    ",\"family\":\"ipv%d\",\"session_id\":%" PRIu64
                    ",\"matched_prefix\":",
                    items[index].family, items[index].session_id) < 0 ||
            iphm_json_write_string(stdout, items[index].route_at_run) != 0 ||
            fputs(",\"client_prefix\":", stdout) == EOF) {
            return -1;
        }
        if (items[index].caida_prefix[0] != '\0') {
            if (iphm_json_write_string(stdout,
                                       items[index].caida_prefix) != 0) {
                return -1;
            }
        } else if (fputs("null", stdout) == EOF) {
            return -1;
        }
        if (fprintf(stdout,
                    ",\"reconciliation\":\"%s\",\"verdict\":\"%s\"}",
                    items[index].conflict
                        ? "conflict"
                        : (items[index].reconciled ? "verified" : "pending"),
                    iphm_verdict_name(items[index].verdict)) < 0) {
            return -1;
        }
    }
    return fputs("]}\n", stdout) == EOF ? -1 : 0;
}

int iphm_command_measure(const char *segment_id, const char *family,
                         unsigned int network_timeout,
                         unsigned int prober_timeout, bool json, char *error,
                         size_t error_size)
{
    IphmConfig config;
    bool config_present;
    const IphmSegment *segment;
    IphmLedger ledger;
    IphmInventory inventory;
    char path[128];
    Capture version_output;
    Capture run_output;
    char version_option[] = "--version";
    char *version_arguments[3];
    char version[IPHM_PROBER_VERSION_MAX];
    char share_public[] = "-s1";
    char share_remedy[] = "-r0";
    char ipv4_option[] = "-4";
    char ipv6_option[] = "-6";
    char *arguments[8];
    size_t argument_count = 0U;
    int process_status;
    int mask;
    int64_t started;
    int64_t ended;
    time_t now;
    IphmProberOutput parsed;
    IphmActiveMeasurement stored[2];
    size_t stored_count = 0U;
    int missing = 0;
    int family_index;

    if (geteuid() != (uid_t)0) {
        measure_error(error, error_size,
                      "measure requires root for the official raw-socket client");
        return IPHM_EXIT_AUTH;
    }
    if (iphm_load_config_default(&config, &config_present, error,
                                 error_size) != 0 ||
        !config_present) {
        if (!config_present) {
            measure_error(error, error_size,
                          "managed segment configuration is missing");
        }
        return IPHM_EXIT_AUTH;
    }
    segment = select_segment(&config, segment_id);
    if (segment == NULL) {
        measure_error(error, error_size, "segment is not authorized");
        return IPHM_EXIT_AUTH;
    }
    mask = requested_mask(segment, family);
    if (mask == 0) {
        measure_error(error, error_size,
                      "requested family is not authorized for this segment");
        return IPHM_EXIT_AUTH;
    }
    if (iphm_load_ledger_default(&ledger, error, error_size) != 0) {
        return IPHM_EXIT_STATE;
    }
    now = time(NULL);
    if (now == (time_t)-1 ||
        ((mask & 1) != 0 &&
         rate_limited(&ledger, segment_id, 4, (int64_t)now,
                      config.minimum_interval_days)) ||
        ((mask & 2) != 0 &&
         rate_limited(&ledger, segment_id, 6, (int64_t)now,
                      config.minimum_interval_days))) {
        measure_error(error, error_size,
                      "segment/family is inside the configured minimum interval");
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_AUTH;
    }
    if (iphm_query_inventory(config.asn, network_timeout, &inventory, error,
                             error_size) != 0) {
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_RESOLUTION;
    }
    if (!inventory.source_fresh) {
        measure_error(error, error_size,
                      "RIS routing sources are stale or unavailable");
        iphm_inventory_free(&inventory);
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_RESOLUTION;
    }
    if (find_trusted_prober(path, sizeof(path), error, error_size) != 0) {
        iphm_inventory_free(&inventory);
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_AUTH;
    }
    version_arguments[0] = path;
    version_arguments[1] = version_option;
    version_arguments[2] = NULL;
    if (run_program(path, version_arguments, 10U, &version_output,
                    &process_status, error, error_size) != 0 ||
        process_status != 0 ||
        parse_version(version_output.data == NULL ? "" : version_output.data,
                      version, sizeof(version)) != 0) {
        free(version_output.data);
        measure_error(error, error_size,
                      "spoofer-prober 1.5.x or newer compatible 1.x is required");
        iphm_inventory_free(&inventory);
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_PROBER;
    }
    free(version_output.data);
    arguments[argument_count++] = path;
    arguments[argument_count++] = share_public;
    arguments[argument_count++] = share_remedy;
    if ((mask & 1) != 0) {
        arguments[argument_count++] = ipv4_option;
    }
    if ((mask & 2) != 0) {
        arguments[argument_count++] = ipv6_option;
    }
    arguments[argument_count] = NULL;
    now = time(NULL);
    started = now == (time_t)-1 ? 0 : (int64_t)now;
    if (run_program(path, arguments, prober_timeout, &run_output,
                    &process_status, error, error_size) != 0) {
        free(run_output.data);
        iphm_inventory_free(&inventory);
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_PROBER;
    }
    now = time(NULL);
    ended = now == (time_t)-1 ? started : (int64_t)now;
    if (process_status != 0 ||
        iphm_parse_prober_output(run_output.data == NULL ? ""
                                                         : run_output.data,
                                 run_output.length, &parsed, error,
                                 error_size) != 0) {
        free(run_output.data);
        iphm_inventory_free(&inventory);
        iphm_ledger_free(&ledger);
        return IPHM_EXIT_PROBER;
    }
    free(run_output.data);
    for (family_index = 0; family_index < 2; ++family_index) {
        int current_family = family_index == 0 ? 4 : 6;
        int family_bit = family_index == 0 ? 1 : 2;
        const IphmProberFamily *result =
            current_family == 4 ? &parsed.ipv4 : &parsed.ipv6;
        IphmActiveMeasurement *measurement;
        size_t route_index;

        if ((mask & family_bit) == 0) {
            if (result->present) {
                missing = 1;
            }
            continue;
        }
        if (!result->present) {
            missing = 1;
            continue;
        }
        if (result->asn != config.asn ||
            !expected_client(segment, current_family, result->client_ip) ||
            iphm_inventory_longest_route(&inventory, result->client_ip,
                                         &route_index) != 0) {
            missing = 1;
            continue;
        }
        measurement = &stored[stored_count++];
        (void)memset(measurement, 0, sizeof(*measurement));
        measurement->present = true;
        measurement->session_id = result->session_id;
        measurement->asn = config.asn;
        measurement->family = current_family;
        (void)memcpy(measurement->segment, segment_id,
                     strlen(segment_id) + 1U);
        measurement->started_at = started;
        measurement->ended_at = ended;
        (void)memcpy(measurement->client_ip, result->client_ip,
                     strlen(result->client_ip) + 1U);
        (void)memcpy(measurement->route_at_run,
                     inventory.routes[route_index].prefix,
                     strlen(inventory.routes[route_index].prefix) + 1U);
        (void)memcpy(measurement->prober_version, version,
                     strlen(version) + 1U);
        (void)memcpy(measurement->private_source, result->private_source,
                     strlen(result->private_source) + 1U);
        (void)memcpy(measurement->routable_source, result->routable_source,
                     strlen(result->routable_source) + 1U);
        measurement->verdict = result->verdict;
        measurement->conflict = inventory.routes[route_index].moas;
        if (!measurement->conflict) {
            int reconcile_result =
                iphm_reconcile_active(measurement, network_timeout, false,
                                      error, error_size);

            if (reconcile_result != 0) {
                (void)fprintf(stderr,
                              "iphm-check: warning: CAIDA reconciliation "
                              "pending: %s\n",
                              error);
                measurement->reconciled = false;
                measurement->conflict = false;
                error[0] = '\0';
            }
        }
        if (iphm_append_measurement(measurement, error, error_size) != 0) {
            iphm_inventory_free(&inventory);
            iphm_ledger_free(&ledger);
            return IPHM_EXIT_STATE;
        }
    }
    if (json) {
        if (emit_measure_json(stored, stored_count) != 0) {
            measure_error(error, error_size, "measurement output failed");
            iphm_inventory_free(&inventory);
            iphm_ledger_free(&ledger);
            return IPHM_EXIT_PROBER;
        }
    } else {
        size_t index;

        for (index = 0U; index < stored_count; ++index) {
            (void)printf(
                "AS%" PRIu32 " segment %s IPv%d session %" PRIu64
                ": %s on %s (%s)\n",
                stored[index].asn, stored[index].segment,
                stored[index].family, stored[index].session_id,
                iphm_verdict_name(stored[index].verdict),
                stored[index].route_at_run,
                stored[index].conflict
                    ? "conflict"
                    : (stored[index].reconciled ? "verified" : "pending"));
        }
    }
    iphm_inventory_free(&inventory);
    iphm_ledger_free(&ledger);
    if (missing != 0 || stored_count == 0U) {
        measure_error(error, error_size,
                      "one or more requested family results were invalid");
        return IPHM_EXIT_PROBER;
    }
    return 0;
}
