# IPHM Check

`iphm-check` reports historical CAIDA Spoofer measurements and can manage
fresh, authorized measurements from explicitly configured network segments.
It does not treat one old result as proof of an ASN's current policy, and it
does not assume that every prefix or exit behaves identically.

The active mode delegates all measurement traffic to CAIDA's official
`spoofer-prober`. This project does not implement or vendor spoofed-packet
generation.

## Build

Ubuntu and Debian:

```bash
sudo apt update
sudo apt install -y build-essential libcurl4-openssl-dev
make
```

Strict checks:

```bash
make clean && make CC=gcc
make clean && make CC=clang
make clang-strict
make debug
make analyze
```

Install:

```bash
sudo make install
```

## Commands

```text
iphm-check TARGET [--json] [--timeout SECONDS]
iphm-check -t TARGET [--json] [--timeout SECONDS]
iphm-check inventory ASN [--json] [--timeout SECONDS]
iphm-check audit ASN [--max-age DAYS] [--require-complete] [--json]
sudo iphm-check measure --segment ID --authorized \
    [--family 4|6|both] [--prober-timeout SECONDS] [--json]
```

The original target command remains a passive historical query. It accepts an
ASN, IPv4 or IPv6 address, or CIDR. IP input is resolved through RISwhois and
reports the matched BGP route.

`inventory` performs a RISwhois inverse-origin query and preserves IPv4,
IPv6, overlapping routes, and multiple-origin routes.

`audit` combines:

- The current RIS route inventory and source-RIB freshness.
- Locally initiated, exact-session-reconciled active measurements.
- Explicit segment/family requirements.
- Historical public CAIDA results as context only.

The default evidence window is 30 days. `--max-age` accepts 1 through 365.
`--require-complete` returns exit status `8` unless every current route and
every configured segment/family has fresh, unambiguous evidence.

## Authorized active measurements

Install CAIDA's official `spoofer-prober` 1.5.0 or a compatible later 1.x
release from the official package or source:

- [CAIDA Spoofer project](https://www.caida.org/projects/spoofer/)
- [CAIDA Spoofer FAQ](https://www.caida.org/projects/spoofer/faq/)

The executable must be a root-owned, non-writable regular file at
`/usr/bin/spoofer-prober` or `/usr/local/bin/spoofer-prober`.

Disable any independent Spoofer scheduler before using managed measurements.
This avoids duplicate sessions outside `iphm-check`'s local interval control.

Create `/etc/iphm-check/segments.json` as a root-owned file that is not
group- or world-writable:

```json
{
  "schema_version": 1,
  "asn": 34927,
  "minimum_interval_days": 7,
  "segments": [
    {
      "id": "edge-ch-1",
      "families": ["ipv4"],
      "expected_prefixes": ["185.44.82.0/24"]
    }
  ]
}
```

```bash
sudo chown root:root /etc/iphm-check/segments.json
sudo chmod 0644 /etc/iphm-check/segments.json
sudo iphm-check measure --segment edge-ch-1 --authorized
```

Active mode:

- Requires root and an explicit `--authorized` acknowledgment.
- Derives the ASN and permitted families only from the secure configuration.
- Refuses arbitrary active ASN targets.
- Runs the official client directly with anonymized public sharing enabled and
  unanonymized remediation sharing disabled, equivalent to `-s1 -r0`.
- Never disables TLS verification or selects development/custom servers.
- Enforces the configured interval after CAIDA issues a session ID.
- Captures bounded output and never stores or prints CAIDA's session key.

Only run active mode from a network you own or for which you have explicit
authorization. CAIDA states that meaningful source-address-validation testing
requires a vantage inside or immediately upstream of the tested network.

## Evidence and privacy

The append-only ledger is
`/var/lib/iphm-check/measurements.jsonl`. It is created root-owned with mode
`0600`; symlinks and group/world-writable state are rejected.

The ledger retains the exact server-observed egress address so later audits can
detect BGP route changes. Normal plain and JSON output never includes that
address. It exposes only the matched BGP route and CAIDA's public anonymized
client prefix.

Each active result is reconciled through CAIDA's exact `/sessions/{id}` API
resource. ASN, family, timestamp, anonymized prefix, and raw statuses must
agree. A newly completed session may remain `pending` while publication
propagates. An unreconciled session older than 24 hours becomes a conflict and
cannot satisfy coverage.

CAIDA publicly masks IPv4 results to `/24` and IPv6 results to `/40`. The local
server-observed address is therefore necessary to distinguish finer routes
without disclosing it in normal output.

## Verdicts

- `spoofable`: at least one fresh validated path reports `received`.
- `rewritten`: no fresh result is `received`, and at least one reports
  `rewritten`.
- `blocked`: all required routes and segments have complete fresh coverage and
  every required result is `blocked`.
- `inconclusive`: evidence is partial, stale, changed, conflicting,
  unsupported, or affected by MOAS/routing-source ambiguity.
- `no_data`: no usable active or historical measurement exists.

“Fresh” means within the selected evidence window. “Complete” means the
current RIS routes and operator-declared segments were sampled. Neither term
proves every address, customer interface, internal path, or moment in time has
the same policy.

## Exit statuses

- `0`: command completed, regardless of whether spoofing was observed.
- `2`: invalid command line or target.
- `3`: RIS resolution or route-inventory failure.
- `4`: CAIDA transport, pagination, parsing, reconciliation, or output failure.
- `5`: authorization, secure configuration, or trusted-prober failure.
- `6`: prober version, execution, timeout, or output failure.
- `7`: secure ledger loading or persistence failure.
- `8`: `--require-complete` requested and coverage is incomplete.

## Data sources and terms

- [CAIDA Spoofer Data API](https://www.caida.org/projects/spoofer/data-api/)
- [CAIDA Master Acceptable Use Agreement](https://www.caida.org/about/legal/aua/)
- [CAIDA ASRank](https://asrank.caida.org/)
- [RIPE RISwhois](https://ris.ripe.net/docs/ris-whois/)

## License

This repository remains under its existing MIT license. The external CAIDA
Spoofer client is distributed separately under its own license and is not
vendored or linked into `iphm-check`. Vendored component notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
