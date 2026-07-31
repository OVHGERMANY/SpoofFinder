#ifndef IPHM_H
#define IPHM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define IPHM_INPUT_MAX 256U
#define IPHM_ADDRESS_MAX 46U
#define IPHM_PREFIX_MAX 80U
#define IPHM_TIMESTAMP_MAX 64U
#define IPHM_STATUS_MAX 64U
#define IPHM_NAME_MAX 256U
#define IPHM_COUNTRY_MAX 8U
#define IPHM_NEXT_MAX 512U
#define IPHM_MAX_RESPONSE (1024U * 1024U)
#define IPHM_SEGMENT_ID_MAX 64U
#define IPHM_PROBER_VERSION_MAX 32U
#define IPHM_MAX_SEGMENTS 64U
#define IPHM_MAX_EXPECTED_PREFIXES 32U
#define IPHM_MAX_ORIGINS 16U
#define IPHM_MAX_ROUTES 8192U
#define IPHM_CONFIG_PATH "/etc/iphm-check/segments.json"
#define IPHM_STATE_DIR "/var/lib/iphm-check"
#define IPHM_LEDGER_PATH "/var/lib/iphm-check/measurements.jsonl"

#define IPHM_EXIT_CLI 2
#define IPHM_EXIT_RESOLUTION 3
#define IPHM_EXIT_CAIDA 4
#define IPHM_EXIT_AUTH 5
#define IPHM_EXIT_PROBER 6
#define IPHM_EXIT_STATE 7
#define IPHM_EXIT_INCOMPLETE 8

typedef enum {
    IPHM_TARGET_ASN = 0,
    IPHM_TARGET_ADDRESS = 1
} IphmTargetKind;

typedef enum {
    IPHM_VERDICT_NO_DATA = 0,
    IPHM_VERDICT_SPOOFABLE,
    IPHM_VERDICT_REWRITTEN,
    IPHM_VERDICT_BLOCKED,
    IPHM_VERDICT_INCONCLUSIVE
} IphmVerdict;

typedef struct {
    IphmTargetKind kind;
    char original[IPHM_INPUT_MAX];
    uint32_t asn;
    char address[IPHM_ADDRESS_MAX];
    int address_family;
    bool is_cidr;
} IphmTarget;

typedef struct {
    bool present;
    uint64_t session_id;
    int64_t timestamp_key;
    char timestamp[IPHM_TIMESTAMP_MAX];
    bool client_prefix_present;
    char client_prefix[IPHM_PREFIX_MAX];
    bool private_source_present;
    char private_source[IPHM_STATUS_MAX];
    bool routable_source_present;
    char routable_source[IPHM_STATUS_MAX];
    IphmVerdict verdict;
} IphmMeasurement;

typedef struct {
    bool available;
    bool name_present;
    char name[IPHM_NAME_MAX];
    bool rank_present;
    uint64_t rank;
    bool country_present;
    char country[IPHM_COUNTRY_MAX];
    bool seen_present;
    bool seen;
    bool cone_asns_present;
    uint64_t cone_asns;
    bool cone_prefixes_present;
    uint64_t cone_prefixes;
    bool cone_addresses_present;
    uint64_t cone_addresses;
    bool degree_total_present;
    uint64_t degree_total;
    bool degree_customer_present;
    uint64_t degree_customer;
    bool degree_peer_present;
    uint64_t degree_peer;
    bool degree_provider_present;
    uint64_t degree_provider;
} IphmAsrank;

typedef struct {
    char input[IPHM_INPUT_MAX];
    uint32_t asn;
    bool matched_prefix_present;
    char matched_prefix[IPHM_PREFIX_MAX];
    IphmAsrank asrank;
    IphmMeasurement ipv4;
    IphmMeasurement ipv6;
    IphmVerdict overall_verdict;
} IphmReport;

typedef enum {
    IPHM_COVERAGE_UNMEASURED = 0,
    IPHM_COVERAGE_STALE,
    IPHM_COVERAGE_FRESH,
    IPHM_COVERAGE_ROUTE_CHANGED,
    IPHM_COVERAGE_AMBIGUOUS
} IphmCoverageState;

typedef struct {
    char prefix[IPHM_PREFIX_MAX];
    int family;
    unsigned int prefix_bits;
    uint32_t origins[IPHM_MAX_ORIGINS];
    size_t origin_count;
    bool moas;
} IphmRoute;

typedef struct {
    IphmRoute *routes;
    size_t route_count;
    size_t route_capacity;
    int64_t queried_at;
    bool source_time_present;
    int64_t newest_source_time;
    bool source_fresh;
} IphmInventory;

typedef struct {
    char id[IPHM_SEGMENT_ID_MAX];
    bool ipv4;
    bool ipv6;
    char expected_prefixes[IPHM_MAX_EXPECTED_PREFIXES][IPHM_PREFIX_MAX];
    int expected_families[IPHM_MAX_EXPECTED_PREFIXES];
    size_t expected_prefix_count;
} IphmSegment;

typedef struct {
    uint32_t schema_version;
    uint32_t asn;
    unsigned int minimum_interval_days;
    IphmSegment segments[IPHM_MAX_SEGMENTS];
    size_t segment_count;
} IphmConfig;

typedef struct {
    bool present;
    uint64_t session_id;
    uint32_t asn;
    int family;
    char segment[IPHM_SEGMENT_ID_MAX];
    int64_t started_at;
    int64_t ended_at;
    char client_ip[IPHM_ADDRESS_MAX];
    char route_at_run[IPHM_PREFIX_MAX];
    char caida_prefix[IPHM_PREFIX_MAX];
    char caida_timestamp[IPHM_TIMESTAMP_MAX];
    int64_t caida_timestamp_key;
    char prober_version[IPHM_PROBER_VERSION_MAX];
    char private_source[IPHM_STATUS_MAX];
    char routable_source[IPHM_STATUS_MAX];
    IphmVerdict verdict;
    bool reconciled;
    bool conflict;
} IphmActiveMeasurement;

typedef struct {
    IphmActiveMeasurement *items;
    size_t count;
    size_t capacity;
} IphmLedger;

typedef struct {
    bool present;
    int family;
    uint64_t session_id;
    uint32_t asn;
    char client_ip[IPHM_ADDRESS_MAX];
    char private_source[IPHM_STATUS_MAX];
    char routable_source[IPHM_STATUS_MAX];
    IphmVerdict verdict;
} IphmProberFamily;

typedef struct {
    IphmProberFamily ipv4;
    IphmProberFamily ipv6;
} IphmProberOutput;

int iphm_parse_target(const char *text, IphmTarget *target, char *error,
                      size_t error_size);
int iphm_parse_ris_response(const char *text, size_t length,
                            const char *address, uint32_t *asn, char *prefix,
                            size_t prefix_size, char *error,
                            size_t error_size);
int iphm_resolve_ris(const IphmTarget *target, unsigned int timeout_seconds,
                     uint32_t *asn, char *prefix, size_t prefix_size,
                     char *error, size_t error_size);
int iphm_parse_caida_page(const char *json, size_t length, uint32_t asn,
                          IphmReport *report, char *next, size_t next_size,
                          char *error, size_t error_size);
int iphm_validate_caida_next(const char *next, uint32_t asn,
                             uint32_t expected_page, char *error,
                             size_t error_size);
int iphm_query_caida(uint32_t asn, unsigned int timeout_seconds,
                     IphmReport *report, char *error, size_t error_size);
int iphm_parse_caida_session(const char *json, size_t length,
                             uint64_t expected_session, uint32_t expected_asn,
                             int family, IphmMeasurement *measurement,
                             char *error, size_t error_size);
int iphm_query_caida_session(uint64_t session_id, uint32_t asn, int family,
                             unsigned int timeout_seconds, bool *found,
                             IphmMeasurement *measurement, char *error,
                             size_t error_size);
int iphm_parse_asrank(const char *json, size_t length, uint32_t expected_asn,
                      IphmAsrank *asrank, char *error, size_t error_size);
int iphm_query_asrank(uint32_t asn, unsigned int timeout_seconds,
                      IphmAsrank *asrank, char *error, size_t error_size);
int iphm_parse_timestamp_key(const char *text, int64_t *key);
bool iphm_prefix_contains_address(const char *prefix, const char *address);
int iphm_query_ris_text(const char *query, unsigned int timeout_seconds,
                        size_t maximum, char **response,
                        size_t *response_length, char *error,
                        size_t error_size);
IphmVerdict iphm_derive_verdict(const char *private_source,
                                bool private_present,
                                const char *routable_source,
                                bool routable_present);
void iphm_finalize_report(IphmReport *report);
const char *iphm_verdict_name(IphmVerdict verdict);
int iphm_emit_plain(FILE *stream, const IphmReport *report);
int iphm_emit_json(FILE *stream, const IphmReport *report);
int iphm_json_write_string(FILE *stream, const char *text);
int iphm_json_is_valid(const char *json, size_t length);

int iphm_parse_ris_inventory(const char *text, size_t length,
                             uint32_t filter_asn, IphmInventory *inventory,
                             char *error, size_t error_size);
int iphm_parse_ris_source_times(const char *text, size_t length, int64_t now,
                                IphmInventory *inventory, char *error,
                                size_t error_size);
int iphm_query_inventory(uint32_t asn, unsigned int timeout_seconds,
                         IphmInventory *inventory, char *error,
                         size_t error_size);
void iphm_inventory_free(IphmInventory *inventory);
int iphm_inventory_longest_route(const IphmInventory *inventory,
                                 const char *address, size_t *route_index);
int iphm_parse_segments_config(const char *json, size_t length,
                               IphmConfig *config, char *error,
                               size_t error_size);
int iphm_load_config_default(IphmConfig *config, bool *present, char *error,
                             size_t error_size);
int iphm_load_ledger_default(IphmLedger *ledger, char *error,
                             size_t error_size);
void iphm_ledger_free(IphmLedger *ledger);
int iphm_append_measurement(const IphmActiveMeasurement *measurement,
                            char *error, size_t error_size);
int iphm_reconcile_active(IphmActiveMeasurement *measurement,
                          unsigned int timeout_seconds, bool persist,
                          char *error, size_t error_size);
IphmVerdict iphm_conservative_verdict(bool coverage_complete,
                                      const IphmVerdict *fresh_verdicts,
                                      size_t fresh_count,
                                      bool historical_present);
const char *iphm_coverage_state_name(IphmCoverageState state);
int iphm_parse_prober_output(const char *text, size_t length,
                             IphmProberOutput *output, char *error,
                             size_t error_size);
int iphm_command_inventory(uint32_t asn, unsigned int timeout_seconds,
                           bool json, char *error, size_t error_size);
int iphm_command_audit(uint32_t asn, unsigned int timeout_seconds,
                       unsigned int max_age_days, bool require_complete,
                       bool json, char *error, size_t error_size);
int iphm_command_measure(const char *segment_id, const char *family,
                         unsigned int network_timeout,
                         unsigned int prober_timeout, bool json, char *error,
                         size_t error_size);

#endif
