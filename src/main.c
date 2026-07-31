#define _POSIX_C_SOURCE 200809L

#include "iphm.h"

#include <curl/curl.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *stream)
{
    (void)fprintf(
        stream,
        "Usage: iphm-check TARGET [--json] [--timeout SECONDS]\n"
        "       iphm-check -t TARGET [--json] [--timeout SECONDS]\n"
        "       iphm-check inventory ASN [--json] [--timeout SECONDS]\n"
        "       iphm-check audit ASN [--max-age DAYS] [--require-complete]\n"
        "                          [--json] [--timeout SECONDS]\n"
        "       sudo iphm-check measure --segment ID --authorized\n"
        "                          [--family 4|6|both]\n"
        "                          [--prober-timeout SECONDS] [--json]\n"
        "\n"
        "Passive output is historical. Active measurements are limited to\n"
        "root-configured, explicitly authorized network segments.\n");
}

static int parse_range(const char *text, unsigned long minimum,
                       unsigned long maximum, unsigned int *output)
{
    char *end = NULL;
    unsigned long value;

    if (text == NULL || *text == '\0') {
        return -1;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < minimum ||
        value > maximum) {
        return -1;
    }
    *output = (unsigned int)value;
    return 0;
}

static int parse_asn_target(const char *text, uint32_t *asn)
{
    IphmTarget target;
    char error[128];

    if (iphm_parse_target(text, &target, error, sizeof(error)) != 0 ||
        target.kind != IPHM_TARGET_ASN) {
        return -1;
    }
    *asn = target.asn;
    return 0;
}

static int passive_command(int argc, char **argv)
{
    static const struct option options[] = {
        {"target", required_argument, NULL, 't'},
        {"json", no_argument, NULL, 'j'},
        {"timeout", required_argument, NULL, 'T'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char *option_target = NULL;
    const char *target_text;
    unsigned int timeout = 10U;
    bool json = false;
    IphmTarget target;
    IphmReport report;
    char error[256];
    int option;
    int result;

    optind = 1;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "t:jT:h", options, NULL)) != -1) {
        switch (option) {
        case 't':
            if (option_target != NULL) {
                (void)fprintf(stderr, "iphm-check: target specified twice\n");
                usage(stderr);
                return IPHM_EXIT_CLI;
            }
            option_target = optarg;
            break;
        case 'j':
            json = true;
            break;
        case 'T':
            if (parse_range(optarg, 1UL, 300UL, &timeout) != 0) {
                (void)fprintf(stderr,
                              "iphm-check: timeout must be 1 through 300\n");
                usage(stderr);
                return IPHM_EXIT_CLI;
            }
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            (void)fprintf(stderr, "iphm-check: invalid option\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
    }
    if (option_target != NULL) {
        if (optind != argc) {
            (void)fprintf(stderr,
                          "iphm-check: use either -t or a positional target\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
        target_text = option_target;
    } else {
        if (optind + 1 != argc) {
            (void)fprintf(stderr,
                          "iphm-check: exactly one target is required\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
        target_text = argv[optind];
    }
    if (iphm_parse_target(target_text, &target, error, sizeof(error)) != 0) {
        (void)fprintf(stderr, "iphm-check: %s\n", error);
        return IPHM_EXIT_CLI;
    }
    (void)memset(&report, 0, sizeof(report));
    (void)memcpy(report.input, target.original,
                 strlen(target.original) + 1U);
    if (target.kind == IPHM_TARGET_ASN) {
        report.asn = target.asn;
    } else {
        result = iphm_resolve_ris(&target, timeout, &report.asn,
                                  report.matched_prefix,
                                  sizeof(report.matched_prefix), error,
                                  sizeof(error));
        if (result != 0) {
            (void)fprintf(stderr, "iphm-check: RISwhois: %s\n", error);
            return IPHM_EXIT_RESOLUTION;
        }
        report.matched_prefix_present = true;
    }
    if (iphm_query_caida(report.asn, timeout, &report, error,
                         sizeof(error)) != 0) {
        (void)fprintf(stderr, "iphm-check: CAIDA: %s\n", error);
        return IPHM_EXIT_CAIDA;
    }
    if (iphm_query_asrank(report.asn, timeout, &report.asrank, error,
                          sizeof(error)) != 0) {
        (void)fprintf(stderr, "iphm-check: warning: ASRank: %s\n", error);
    }
    iphm_finalize_report(&report);
    result =
        json ? iphm_emit_json(stdout, &report) : iphm_emit_plain(stdout, &report);
    if (result != 0) {
        (void)fprintf(stderr, "iphm-check: output failed\n");
        return IPHM_EXIT_CAIDA;
    }
    return 0;
}

static int inventory_command(int argc, char **argv)
{
    static const struct option options[] = {
        {"json", no_argument, NULL, 'j'},
        {"timeout", required_argument, NULL, 'T'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    bool json = false;
    unsigned int timeout = 10U;
    uint32_t asn;
    char error[256] = "";
    int option;
    int result;

    optind = 1;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "jT:h", options, NULL)) != -1) {
        if (option == 'j') {
            json = true;
        } else if (option == 'T' &&
                   parse_range(optarg, 1UL, 300UL, &timeout) == 0) {
        } else if (option == 'h') {
            usage(stdout);
            return 0;
        } else {
            (void)fprintf(stderr, "iphm-check: invalid inventory option\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
    }
    if (optind + 1 != argc || parse_asn_target(argv[optind], &asn) != 0) {
        (void)fprintf(stderr, "iphm-check: inventory requires one ASN\n");
        usage(stderr);
        return IPHM_EXIT_CLI;
    }
    result = iphm_command_inventory(asn, timeout, json, error, sizeof(error));
    if (result != 0) {
        (void)fprintf(stderr, "iphm-check: inventory: %s\n", error);
    }
    return result;
}

static int audit_command(int argc, char **argv)
{
    static const struct option options[] = {
        {"json", no_argument, NULL, 'j'},
        {"timeout", required_argument, NULL, 'T'},
        {"max-age", required_argument, NULL, 'a'},
        {"require-complete", no_argument, NULL, 'r'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    bool json = false;
    bool require_complete = false;
    unsigned int timeout = 10U;
    unsigned int max_age = 30U;
    uint32_t asn;
    char error[256] = "";
    int option;
    int result;

    optind = 1;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "jT:a:rh", options, NULL)) != -1) {
        if (option == 'j') {
            json = true;
        } else if (option == 'r') {
            require_complete = true;
        } else if (option == 'T' &&
                   parse_range(optarg, 1UL, 300UL, &timeout) == 0) {
        } else if (option == 'a' &&
                   parse_range(optarg, 1UL, 365UL, &max_age) == 0) {
        } else if (option == 'h') {
            usage(stdout);
            return 0;
        } else {
            (void)fprintf(stderr, "iphm-check: invalid audit option\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
    }
    if (optind + 1 != argc || parse_asn_target(argv[optind], &asn) != 0) {
        (void)fprintf(stderr, "iphm-check: audit requires one ASN\n");
        usage(stderr);
        return IPHM_EXIT_CLI;
    }
    result = iphm_command_audit(asn, timeout, max_age, require_complete, json,
                                error, sizeof(error));
    if (result != 0 && result != IPHM_EXIT_INCOMPLETE) {
        (void)fprintf(stderr, "iphm-check: audit: %s\n", error);
    }
    return result;
}

static int measure_command(int argc, char **argv)
{
    static const struct option options[] = {
        {"segment", required_argument, NULL, 's'},
        {"authorized", no_argument, NULL, 'A'},
        {"family", required_argument, NULL, 'f'},
        {"prober-timeout", required_argument, NULL, 'P'},
        {"json", no_argument, NULL, 'j'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char *segment = NULL;
    const char *family = NULL;
    bool authorized = false;
    bool json = false;
    unsigned int prober_timeout = 900U;
    char error[256] = "";
    int option;
    int result;

    optind = 1;
    opterr = 0;
    while ((option = getopt_long(argc, argv, "s:Af:P:jh", options, NULL)) !=
           -1) {
        if (option == 's' && segment == NULL) {
            segment = optarg;
        } else if (option == 'A') {
            authorized = true;
        } else if (option == 'f' && family == NULL &&
                   (strcmp(optarg, "4") == 0 ||
                    strcmp(optarg, "6") == 0 ||
                    strcmp(optarg, "both") == 0)) {
            family = optarg;
        } else if (option == 'P' &&
                   parse_range(optarg, 60UL, 3600UL,
                               &prober_timeout) == 0) {
        } else if (option == 'j') {
            json = true;
        } else if (option == 'h') {
            usage(stdout);
            return 0;
        } else {
            (void)fprintf(stderr, "iphm-check: invalid measure option\n");
            usage(stderr);
            return IPHM_EXIT_CLI;
        }
    }
    if (optind != argc || segment == NULL || !authorized) {
        (void)fprintf(stderr,
                      "iphm-check: measure requires --segment and --authorized\n");
        usage(stderr);
        return IPHM_EXIT_CLI;
    }
    result = iphm_command_measure(segment, family, 10U, prober_timeout, json,
                                  error, sizeof(error));
    if (result != 0) {
        (void)fprintf(stderr, "iphm-check: measure: %s\n", error);
    }
    return result;
}

int main(int argc, char **argv)
{
    int result;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        (void)fprintf(stderr, "iphm-check: libcurl initialization failed\n");
        return IPHM_EXIT_CAIDA;
    }
    if (argc > 1 && strcmp(argv[1], "inventory") == 0) {
        result = inventory_command(argc - 1, argv + 1);
    } else if (argc > 1 && strcmp(argv[1], "audit") == 0) {
        result = audit_command(argc - 1, argv + 1);
    } else if (argc > 1 && strcmp(argv[1], "measure") == 0) {
        result = measure_command(argc - 1, argv + 1);
    } else {
        result = passive_command(argc, argv);
    }
    curl_global_cleanup();
    return result;
}
