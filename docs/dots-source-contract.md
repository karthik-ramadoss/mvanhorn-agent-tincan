# Dots backend ownership and native events

Private operations continue through Dots → ephemeral codex-dots-backend-v2 →
Tincan. The existing public gateway provides an event-only connection for the
same mailbox. No additional daemon, proxy or credential broker is introduced.

This is a source candidate. Deployment remains held pending restricted backend
enrollment, dedicated tag ownership and execution access. A service-role tag
authorizes an environment; it cannot prove that a task originated in Dots.

## Source baseline

The independently verified owner fork is
`https://github.com/karthik-ramadoss/mvanhorn-agent-tincan.git`, whose `main` was
`e2345981bc244033cc9036e50718694664bab8b2` at source acquisition. That commit is
an ancestor of audited upstream `270e1c15106be7ceb940e102a98109f7c6114c01`.
The candidate starts from the audited commit and preserves the maintained
enrollment patch SHA-256
`a2081d4a0cf7b79fde39371dfe4de27f20c351e0b194453db71014219f1369f0` and incremental
rebind patch SHA-256
`79b6b20d34f9064e90129b537e76f8ef1da9a9ca8231515cdd612b2404a452d2`.
The retained workspaces were read only. The owner fork's main was not changed.

## Explicit migration controls

All three controls default off:

| Proposed flag | Effect |
|---|---|
| `--service-role tag:dedicated-dots-backend=openai-dots` | Authorizes verified WhoIs tag holders as the existing logical mailbox without changing its persisted binding. |
| `--require-claim-ownership openai-dots` | Requires task/attempt receipts for receiver mutations, including the first claim. |
| `--gateway-events-only openai-dots` | Enables native events and limits every OAuth grant for the mailbox to event operations. Requires the existing gateway. |

The tag shown above is an example, not an instruction to create or assign it.
The shared `tag:codex-forgejo` is rejected as a service-role mapping. Machine
names, message fields and headers never establish a role. A header may only
narrow the authenticated grant. Matching conflicting roles fails closed.
The actual WhoIs StableID remains the claim actor and audit actor; the logical
agent is recorded separately. No agent is enrolled or rebound during role
authentication. Existing agents retain their legacy contract until migration.
Once a request has an ownership receipt, legacy mutations cannot bypass it.

## FM incoming wire contract

Use the existing tailnet HTTP authentication and optional `X-Tincan-Agent`
header. The relay derives `actor_id`; caller-supplied actor fields are ignored.
Identifiers must match `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}`.

| Operation | Request | Success |
|---|---|---|
| `GET /v1/peek` | No body; always a non-taking read. | Pending request IDs and counts; 204 when empty. |
| `GET /v1/requests/{id}/inspect` | No body. | Existing Result shape: request, status, reply, progress and exchanges; no delivery/reply acknowledgement. |
| `POST /v1/requests/{id}/claim` | `{"task_id":"fm-task-123","attempt_id":"attempt-1"}` | Request with server-issued `ownership`. |
| `POST /v1/requests/{id}/progress` | `{"note":"working","ownership":{...}}` | `{"ok":true}`; renews the current lease. |
| `POST /v1/requests/{id}/reply` | `{"body":"result","status":"answered","ownership":{...}}` | Existing Reply shape including reply `generation`. |
| `POST /v1/requests/{id}/release` | `{"ownership":{...}}` | `{"ok":true}`; returns the request to queued. |

The existing `/v1/poll?peek=1&replies=keep&hold=0` also remains non-taking.
`/v1/peek` lists pending IDs only. Use `/inspect` to read a selected body.

Example claim receipt:

```json
{
  "id": "request-123",
  "to": "openai-dots",
  "body": "the original request",
  "status": "claimed",
  "ownership": {
    "task_id": "fm-task-123",
    "attempt_id": "attempt-1",
    "actor_id": "authenticated-node-stable-id",
    "lease_generation": 1,
    "lease_until": "2026-10-12T18:30:00Z"
  }
}
```

Submit only `task_id`, `attempt_id` and `lease_generation` under `ownership`
for progress, clarification, terminal reply and release. Clarification uses the
same reply route with `status:"needs_input"`; final statuses are `answered`,
`failed` or `declined`. The original sender answers through the existing
`POST /v1/requests/{id}/answer` with `{"body":"input"}`. A resumed receiver
claims with a fresh attempt ID. The reply's `generation` is distinct from the
ownership `lease_generation` and remains the existing acknowledgement fence.

A live claim retried by the same actor/task/attempt returns its original
generation and deadline. An identical committed reply retry returns the same
reply and generation; changed payloads fail. Release retries are idempotent
until another generation is acquired. Lease expiry, replacement, competing
tasks/nodes, missing ownership and stale generations return HTTP 409:

```json
{"error":"claim_conflict"}
```

After a lease is lost, retry reads and recover task state before deciding to
start a fresh attempt. Retired actor/task/attempt tuples remain recorded, so an
old attempt cannot reacquire the request after later workers have run. Only a
new attempt may acquire a new generation. SQLite commits ownership, lease,
generation and the claim audit together. Terminal reply/clarification state,
reply generation, event journal and audit also commit together.

## Native MCP Events

The gateway adds `events` to MCP 2 `server/discover` for the event principal and
implements `events/list`, `events/subscribe` and `events/unsubscribe` on the
same authenticated `/mcp` endpoint, using the existing SDK 1.8 discovery path.
It exposes no operational tools for that principal; dispatch rejects tool
calls and other operational methods centrally. Existing full grants, including
legacy database rows, cannot bypass an events-only mailbox policy at login,
code exchange, refresh or dispatch. Event login checks the existing mailbox
and never calls `BindVirtual`.

The OAuth `resource` must be the exact advertised HTTPS `/mcp` identifier at
authorization, token exchange and refresh. Access validation checks the stored
audience and current policy. A connection has an independent persistent grant
ID that survives transactional refresh rotation. The plugin holds and rotates
the refresh token; backend adapters never receive it. Revocation disables the
grant independently of other connections to the same mailbox. The advertised
`POST /revoke` endpoint accepts the connection's token and registered
`client_id`; repeated revocation is idempotent and leaves backend bindings
intact. Mailbox removal
and policy removal also stop delivery.

Available event names are `tincan.request.queued` and `tincan.reply.created`.
Both filter arguments to `{"mailbox":"openai-dots"}`, with mailbox ownership
derived from the grant. Event payloads contain only
`data:{request_id,status,generation}`, plus `eventId`, `name`, occurrence
`timestamp` and `cursor:null`. They contain no message, clarification or reply
bodies. Native subscription identity includes grant, callback URL, event name
and canonical arguments. Lifetimes default to 24 hours, capped at seven days;
an explicit null lifetime receives a finite seven days. No replay cursor is
advertised.

The existing SQLite database stores subscriptions, event outbox and leased
deliveries. Triggers journal queued requests and replies in their existing
state transaction. Queued/Replied hooks only wake the worker. Startup reads
raw outstanding queue/reply state without `check_inbox`, delivery or sender
Get acknowledgement. Stable event IDs and subscription/event primary keys
deduplicate persistence; ambiguous callback receipts retry the same event ID.
The receiver must deduplicate that ID because delivery is at least once.

Callbacks require a `whsec_` base64 key decoding to 24–64 bytes, verified with a
fresh signed ten-second challenge. HTTPS destination addresses are checked
at every connection and dialed by validated IP with hostname TLS verification.
Private, local and other non-public destinations, redirects and proxies are
blocked. Standard Webhooks signs the exact serialized bytes, event ID and
fresh signing timestamp. Deliveries are capped at 256 KiB. Transient failures
back off with at most eight attempts and a 24-hour event horizon. HTTP 410
unsubscribes; 413 and permanent client errors stop retries. Expiration,
unsubscribe and revoked access cancel outstanding delivery. Signing-key
rotation keeps a five-minute dual-signature overlap.

Protocol references: [MCP Events](https://developers.openai.com/plugins/build/mcp-events)
and [Authentication](https://developers.openai.com/plugins/build/auth).

## Validation boundary

Tests use SQLite files, fake WhoIs, local HTTP/TLS fixtures and mocked callbacks.
They cover multiple tasks/nodes, stale/retired receipts, ambiguous retries,
binding-preserving login, forbidden operational calls, audience mismatch,
refresh rollback, state/delivery crashes, callback validation and independent
revocation. These checks do not claim live ChatGPT/Dots acceptance or restricted
tag/enrollment readiness. No live canary, deployment, credential or settings
mutation is included. Unix filesystem checks and race tests require a suitable
Linux/CGO environment before promotion.
