# DNS enrichment

DNS enrichment captures infrastructure evidence for a domain. It collects A
(IPv4), AAAA (IPv6), NS (nameserver), and MX (mail exchanger with preference)
records concurrently. No candidate website is fetched, and no SMTP connection
is made. DNS observations do not currently change the ML model's score.

## Use the API

Start the existing backend stack, then request an observation:

```sh
curl -X POST http://localhost:8080/v1/domains/example.com/dns
curl http://localhost:8080/v1/domains/example.com/dns
curl 'http://localhost:8080/v1/domains/example.com/dns/history?limit=20'
```

For a previously saved analysis, use:

```text
POST /v1/analyses/{analysis-id}/dns
```

This extracts the candidate URL's hostname and enriches it. It does not rescore
the analysis. Requests are explicit and synchronous; creating a normal analysis
does not trigger external DNS queries.

POST accepts no payload and returns HTTP 200 with `{"snapshot": ..., "cached": ...}`.
Concurrent callers may share a newly created snapshot. A cache hit keeps the
original snapshot ID and observation timestamps. GET returns the most recently
stored snapshot, including expired evidence, and returns 404 if none exists.
History returns `{"observations": [...]}` newest first; limit defaults to 20
and must be 1–100. It returns an empty list for an unobserved domain.

Domains are normalized to lowercase ASCII IDNA spelling, with the final dot
removed. Unicode hostnames are accepted. URLs, ports, wildcards, IP literals,
empty labels, and single-label names are rejected with 422. Queries use fully
qualified names, avoiding local DNS search-suffix expansion.

## Observation format

Each snapshot contains:

- `id`: database-generated UUID.
- `domain`: normalized queried hostname.
- `resolver`: configured DNS server address, or `system`.
- `observed_at`: UTC completion time for this batch of lookups.
- `expires_at`: application cache expiry, not DNS record expiry.
- `queries`: four entries with record type, status, UTC observation time, and records.
- `relationships`: successful records projected into graph-ready evidence.

A query's records contain `value` and, for MX, `preference`. Records are
deduplicated and sorted, with MX ordered by preference then hostname. The
query timestamp is when the resolver result was received; it does not establish
when a DNS record was first created.

Query statuses are `ok`, `no_records`, `not_found`, `timeout`, `canceled`,
and `error`. Failed queries have an empty record list while successful sibling
queries retain their evidence. A DNS failure is a stored observation, so POST
still returns 200. A database failure returns 500; an exhausted request deadline
returns 504. When all 16 in-process enrichment slots are occupied, new unique
domains return 503 with Retry-After.

Go's resolver does not distinguish NXDOMAIN from all forms of missing record
answers through `DNSError.IsNotFound`. Do not interpret a single `not_found`
entry as proof that the entire domain does not exist.

## Cache and timeouts

| Setting | Default | Meaning |
| --- | --- | --- |
| DNS_SERVER | system resolver | Optional IP:port; IPv6 uses [address]:port |
| DNS_LOOKUP_TIMEOUT | 2s | Shared deadline for all four concurrent lookups; maximum 10s |
| DNS_CACHE_TTL | 5m | Application lifetime for an entirely successful observation |
| DNS_NEGATIVE_CACHE_TTL | 30s | Shorter lifetime when any query has no records/not-found |

Cache lifetimes must satisfy `0 < negative <= positive <= 24h`.
Observations containing timeout, cancellation, or other transient errors are
stored with zero cache lifetime and retried on the next request.

The cache is persisted in PostgreSQL and survives API restarts. The service
checks resolver provenance before reuse. Same-domain requests are coalesced
within one API process; multiple API replicas can still create duplicate
observations concurrently. The cache does not impose a global QPS limit.
Changing lifetime settings affects newly collected snapshots; existing ones
retain their saved expiry.

The standard Go resolver does not return authoritative record TTLs. These are
explicit application cache policies, not protocol-correct DNS TTL caching.
The configured recursive resolver may itself cache answers. System resolution
can also consult local host configuration. See the
[Go resolver documentation](https://pkg.go.dev/net#Resolver).

A canceled HTTP caller stops waiting, while an already shared enrichment can
finish for other callers. Work remains bounded by the lookup timeout and two
2-second database-operation deadlines. The HTTP enrichment deadline is 14s.
No background queue or Redis service is required for this increment.

## Storage and future graph

The `dns_observations` table stores immutable JSON snapshots with domain,
observation time, and expiry columns. An index supports recent observations per
domain. Cache hits do not insert another row. Snapshots are retained after expiry
for investigations; a retention/archive policy is future work.

The migration runner applies ordered embedded SQL files once, records them in
`schema_migrations`, and takes a PostgreSQL transaction advisory lock to serialize
API startup migrations. Existing installations without a migration ledger are
supported by the idempotent first migration. The runner currently supports plain
semicolon-separated SQL statements, not procedural SQL bodies.

Relationships use these types:

| DNS record | Relationship | Target |
| --- | --- | --- |
| A / AAAA | RESOLVES_TO | IP address |
| NS | USES_NAMESERVER | Nameserver domain |
| MX | MAIL_HANDLED_BY | Mail server domain |

Each edge carries its record type and observation timestamp, plus MX preference
where applicable. The enclosing snapshot ID supplies provenance. A null MX
(`0 .`) is preserved as evidence that the domain does not accept mail and
produces no mail-server edge. Relationship timestamps represent observations,
not continuous ownership or campaign membership. Shared hosting, DNS providers,
and mail providers routinely connect unrelated domains.

These relationships are stored in PostgreSQL JSON for later graph ingestion.
Neo4j ingestion and campaign detection are future steps.

## Verification

Go unit tests cover normalization, partial failures, timeouts, deduplication,
MX preferences, graph evidence, cache expiry, negative cache lifetimes,
resolver changes, concurrent requests, and API error responses.

```sh
(cd backend && go test -race ./...)
```

The real-service suite starts an isolated UDP DNS fixture, PostgreSQL cluster,
Python model service, and compiled Go API. The DNS fixture never forwards
questions to the internet. It verifies record values, cache hits across API
restarts, expiry/history, partial timeouts, NXDOMAIN, null MX, analysis-based
enrichment, and upgrading a legacy database without losing analyses.

```sh
THREATGRAPH_RUN_STACK_TESTS=1 \
ml/.venv/bin/python -m pytest tests/functional -v
```

Set PG_BINDIR and GO_BIN as described in the backend README if the tools are
not discoverable. PostgreSQL must be allowed to use shared memory and local
sockets. This suite validates controlled DNS behavior; it does not benchmark
public resolver availability or exercise every possible DNS response.
