# Threat model

## Assets and actors

| Asset | Why it matters |
|---|---|
| `Tier0-Admins`, `carol.admin` | Control of the tenant |
| Payroll document | Confidential data, Finance only |
| `HelpdeskCopilot` client secret | The app's identity, usable from anywhere |

| Actor | Starts with |
|---|---|
| Mallory, contractor | An ordinary account, mail, KB edit rights |
| Bob, employee | An ordinary account, chat with the copilot |
| Tool maintainer | The ability to ship an updated tool definition |

## Trust boundaries

1. Ticket, document, web page, tool description into the prompt. Text becomes instructions.
2. Model decision into tool call. The guards live here.
3. Agent into Graph. Token type decides whose rights apply.
4. Agent out to the network, including rendered images.
5. Secret store into the agent process.

## Assumptions

The model can be hijacked. Hardened mode must hold when it is, so spotlighting is never counted. fake-graph, the sidecar and the guard code are trusted. The approver is simulated and rejects during attacks.

## What hardened mode does not stop

- **Abuse of the victim's own rights inside the tenant.** If Dave from Finance asks a question that retrieves a poisoned page, a hijacked agent can mail payroll rows to Mallory. Dave may read them, the recipient is internal and no approval applies. This works today and is kept as [a test](../tests/test_guards.py) (`test_known_gap_...`). No rule detects it either. Options: tag sessions that read labelled data and require approval before sending it on (information flow control), or limit the agent to replying to the requester.
- **Approval fatigue.** A person who approves everything removes the control. The approval text is built by code, so at least the facts are right.
- **Control of the agent host.** Whoever runs code in the agent can use the sidecar, and can replay on-behalf-of tokens until they expire.
- **Static tier 0 list.** The Cedar inventory is a file. A new privileged group is not covered until someone adds it. Graph's own check still applies.
- **Allowlisted destinations.** Data can leave through a host that is on the list.
- **Requester identity theft.** On-behalf-of faithfully acts for whoever signed in.

## Fidelity

Where the lab differs from Microsoft Entra ID and Graph. Checked against Microsoft Learn on 2026-11-24.

| Topic | Real service | Lab |
|---|---|---|
| Role-assignable groups | Need `RoleManagement.ReadWrite.Directory` as well. `Group.ReadWrite.All` is not enough ([source](https://learn.microsoft.com/graph/api/group-post-members)) | Enforced. `Tier0-Admins` is not role-assignable. It stands for a normal group that carries tier 0 power elsewhere, such as Azure RBAC Owner, which is a common real finding |
| Group gives a directory role | Only role-assignable groups can | Simplified: membership of `Tier0-Admins` confers the role directly |
| App-only password reset | Permission and a directory role for the app ([source](https://learn.microsoft.com/graph/api/user-update)) | Enforced. The seed gives the app Privileged Authentication Administrator, as an admin in a hurry might |
| Mailbox scoping | Exchange RBAC for Applications. An unscoped Entra grant would override it, since grants add up ([source](https://learn.microsoft.com/exchange/permissions-exo/application-rbac)) | `mailbox_scope` on the app |
| On-behalf-of | User tokens only, assertion audience must be the calling app ([source](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow)) | Enforced |
| On-behalf-of from a ticket | Not possible from e-mail. Needs a portal or chat where the user signs in | The lab attaches a user assertion to tickets filed by a signed-in user. Spoofed mail gets none |
| Token signing | RS256, JWKS | HS256 and an introspection endpoint |
| User sign-in | Interactive, MFA | Password grant |
| Privileged flag in logs | Absent, use a watchlist | `targetPrivileged` enrichment |
| Extra permission | - | `Mail.Read` is granted because the agent must read its queue |

Rule KQL comments are untested references.
