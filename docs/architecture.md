# Architecture

```mermaid
flowchart TB
  subgraph corp [network: corp, internal]
    graph[fake-graph .5]
    av[agent-vulnerable .10]
    ah[agent-hardened .11]
    at[attacker .66<br/>listener and launch point]
  end
  subgraph idp [network: idp, internal]
    sc[token sidecar .12]
  end
  subgraph side [network: sidecar, internal]
    link[agent-hardened and sidecar only]
  end
  av --> graph
  ah --> graph
  at --> graph
  ah --- link --- sc
  sc --> graph
  av & ah --> at
```

No port is published and every network is `internal`, so containers have no route to the internet. `LLM=anthropic` or `LLM=ollama` adds [one network](../docker-compose.llm.yml) for the two agents only.

## Components

| Part | Job |
|---|---|
| [fake_graph](../fake_graph) | Tokens, authorization, mail, documents, audit log. Delegated access is the app's scopes intersected with the user's rights, and app-only access is whatever was consented |
| [agent/core.py](../agent/core.py) | Agent loop. `Session.graph()` is the one line that decides whose rights are used |
| [agent/guards](../agent/guards) | Policy (Cedar), approval, egress, spotlighting. Run in code, between the model's decision and the call |
| [agent/tools](../agent/tools) | `prepare` resolves names and parses destinations, guards run, then `run` uses the same resolved values |
| [agent/llm](../agent/llm) | `anthropic`, `ollama`, `scripted` |
| [scenarios/lab_env.py](../scenarios/lab_env.py) | The same lab in one process (tests) or in Compose. Both present the same source addresses |
| [detections](../detections) | Sigma rules and a small evaluator that raises on anything it cannot read |

## Order of checks for a tool call

1. Resolve and parse: user and group to directory objects, URL and recipients to hosts. Unparseable input is an error.
2. Policy engine, with the canonical name and the authenticated requester. Default deny.
3. Group changes to the queue, if the permission is not held.
4. Human approval.
5. Egress allowlist.
6. Graph makes its own decision from the token. This is the check that does not depend on the agent being correct.

Markdown images are checked when the answer is rendered, since they need no tool call.

## The scripted model

It runs attack steps only when the payload text is in its context, so a test fails if delivery breaks. Values it exfiltrates are taken from real tool results. By default, scenario runs assume it is fully hijacked and ignores spotlighting. `--honour-marking` switches that off.

## The referee key

`run.py` runs in the attacker container so that requests come from the attacker's address. The same process resets the lab and reads ground truth with `LAB_ADMIN_KEY`. Attack steps never use that key.
