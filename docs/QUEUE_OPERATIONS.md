# Incident queue capacity and operator archival

Each protected instance has a private SQLite transport queue with a limit of
2,048 total records. Queued, held, pending and completed records all count.
An identical event is deduplicated even when capacity is full; a conflicting
record with the same ID is rejected. A new event at capacity is rejected rather
than silently evicting evidence. Suspicious requests remain blocked when the
incident sink cannot accept their metadata. An unrecorded event is an explicit
coverage gap, not evidence that a response agent processed it.

The queue is not an approval authority. Mothership owns approvals and action
receipts. Pending approvals retain their original identifiers; held records
require operator reconciliation and must not be changed to queued to obtain a
fresh action key. Archival never resumes, approves or repeats work.

## Export completed records

Run `counter-swarm archive-completed --destination /absolute/private/archives/new-file.jsonl`
with the instance's `COUNTER_SWARM_RUNTIME_CONFIG` set. Create the owner-only
archive directory first, for example with `mkdir -m 700 /absolute/private/archives`.
This command calls `IncidentQueue.archive_completed(destination)`, an operator-only API. It is
never called automatically by the proxy, worker, model or supervisor. Stop or
coordinate operator maintenance before using it when predictable intake
availability matters. The operation holds a SQLite write transaction while
exporting; concurrent intake can receive a queue-unavailable response.

The destination must be an absolute path for a new file in an **existing,
owner-only directory**. The method does not create the directory, overwrite an
archive, follow a final directory/file symlink, or accept a shared directory.
The archive is created exclusively with mode `0600`. At most 2,048 completed
records are exported as JSONL, with their incident metadata and completion
state. Queued, held and pending rows are never selected or removed.

Before removing anything, the method flushes and fsyncs the archive contents,
then fsyncs its parent directory. It deletes only the exact exported completed
rows in one SQLite transaction. The returned receipt contains the archive path,
number of archived rows and SHA-256 digest. Check that receipt and retain the
archive with the instance's private evidence/backup material. The archive does
not contain a recoverable live queue, Mothership state, credentials or DeadBolt
state; it does not replace their backups.

An error before the transaction commits preserves the queue rows. A failed
write can leave a partial file, and an unsuccessful or interrupted database
commit can leave a durable duplicate archive alongside the retained rows. Keep
the original file for reconciliation and use a **different new destination**
only after inspecting the outcome. Do not delete queue rows manually to make
an incomplete archive look successful. A crash after a successful commit may
lose the caller's returned receipt even though the archive is durable and rows
were removed; inspect the archive and queue before acting again.

With zero completed rows the method creates a durable empty archive and removes
nothing. Archival frees queue slots and reusable SQLite pages; it does not
promise to shrink the database file or perform a secure erase. Filesystem and
device durability still depend on the underlying storage honoring fsync.

## Public listener resource bounds

The colocated supervisor starts only its private services first. It waits for a
fresh admission from the target's DeadBolt gate and a successful Mothership
store-health check before opening the public proxy listener. If startup fails,
it stops its children without opening that listener. A required service exiting
later causes the supervisor to stop the edge and remaining children.

The public Uvicorn process explicitly uses one worker, h11, no WebSocket
protocol and no trusted forwarded-header middleware. It defaults to:

| Resource | Default | Trusted environment setting | Accepted range |
| --- | ---: | --- | --- |
| Concurrent connections/tasks | 32 | `COUNTER_SWARM_EDGE_CONCURRENCY` | 1–128 |
| Listening socket backlog | 128 | `COUNTER_SWARM_EDGE_BACKLOG` | 16–512 |
| Idle keep-alive timeout | 5 seconds | `COUNTER_SWARM_EDGE_KEEP_ALIVE_SECONDS` | 1–15 |
| h11 incomplete-event buffer | 16,384 bytes | `COUNTER_SWARM_EDGE_HEADER_BYTES` | 1,024–16,384 |

Overrides must be plain positive ASCII integers in range. Requests and model
advice cannot set these values. One worker is explicit so an inherited
`WEB_CONCURRENCY` value cannot multiply the configured limit.

These are focused resource controls, not a complete denial-of-service defense
or a total process-memory bound. The h11 option bounds an **incomplete HTTP
event**, not every possible fully received header block. The deterministic
detector separately rejects request headers exceeding 16 KiB or 64 fields after
ASGI parsing. The keep-alive setting is an idle timeout between requests, not a
universal slow-header deadline. Connection floods, TLS termination, total header
limits before parsing and upstream reachability need an appropriately configured
external ingress/firewall. The operating system may further clamp socket backlog.
