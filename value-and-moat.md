# WorkFort: Value Proposition & Moat

## Value Proposition

When running WorkFort from a hosted Nexus instance, agents have access to
MCP tools that manage the full application deployment lifecycle — DNS, SSL,
Ingress — through environment promotion: dev → PR (private) → staging
(semi-public) → production. Users invoke agent teams from Sharkfin
(Slack-clone) for full ChatOps.

## Moat: Proprietary Deployment Control Plane

The open source stack (Nexus, Sharkfin, pkg/btrfs) drives adoption. The moat
is that the **deployment MCP tools only work against WorkFort Cloud's control
plane**. A self-hosted Nexus can write code and chat, but cannot
`deploy create-pr-env` or `deploy promote staging` — those MCP tools call a
proprietary API that only exists in the hosted offering.

Same pattern as Terraform CLI (open source) vs Terraform Cloud (proprietary).

## Open Source vs Proprietary Split

| Component | License | Why |
|---|---|---|
| Nexus (agent orchestrator) | Open source | Adoption, community, trust |
| Sharkfin (chat) | Open source | Same |
| pkg/btrfs, guest tools | Open source | Same |
| WorkFort Cloud MCP server | **Proprietary** | **The moat** |
| WorkFort Cloud API | **Proprietary** | Deployment logic |
| K8s operators/controllers | **Proprietary** | Deployment logic |
| Billing, multi-tenancy, quotas | **Proprietary** | Business logic |

## Architecture: VM Config at Creation Time

The open source Nexus has **zero knowledge** of WorkFort Cloud. There is no
cloud connector, no discovery protocol, no provider interface. The seam is
pure configuration: WorkFort Cloud configures the agent's MCP servers when
it creates the VM.

```
Self-hosted:
  Nexus creates VM → injects local MCP server config
  Agent sees: file, git, shell, sharkfin

WorkFort Cloud:
  Nexus creates VM → injects local MCP + cloud MCP server configs
  Agent sees: file, git, shell, sharkfin, deploy, dns, ssl, envs
```

The cloud MCP server is just another `mcpServers` entry in the agent's
Claude config, pointing at a WorkFort Cloud endpoint with a per-agent token.
No special interfaces in Nexus, no provider abstractions, no discovery.

### Why This Is Better

- **No API surface leaked.** Nexus doesn't import, reference, or know about
  any cloud types. A competitor reading the open source code learns nothing
  about the deployment API.
- **No extension points to reverse-engineer.** There's no `CloudProvider`
  interface to implement. The proprietary MCP server is a completely separate
  service.
- **Simpler Nexus.** Nexus just creates VMs and injects MCP config. It
  doesn't need to be "cloud-aware" at all.
- **Standard MCP.** The agent connects to the cloud MCP server using the
  standard MCP protocol. No custom transport, no proprietary client SDK.

### How It Works

```
┌─────────────────────────────────────────────────┐
│              WorkFort Cloud (proprietary)         │
│                                                  │
│  ┌────────────┐    ┌──────────────────────────┐  │
│  │ Orchestrator│    │ Cloud MCP Server          │  │
│  │            │    │                          │  │
│  │ Creates VM │    │ deploy.create-pr-env     │  │
│  │ via Nexus  │    │ deploy.promote           │  │
│  │ API, adds  │    │ dns.set-record           │  │
│  │ cloud MCP  │    │ ssl.provision            │  │
│  │ to config  │    │ env.list / env.delete    │  │
│  └──────┬─────┘    └──────────▲───────────────┘  │
│         │                     │                  │
│         │          ┌──────────┼───────────────┐  │
│         │          │  K8s Control Plane       │  │
│         │          │  cert-manager, ingress,  │  │
│         │          │  namespaces, operators   │  │
│         │          └──────────────────────────┘  │
└─────────┼─────────────────────┼──────────────────┘
          │                     │
          ▼                     │
┌─────────────────┐             │
│  Nexus (OSS)     │             │
│  containerd      │             │
│  ┌─────────────┐ │             │
│  │  Agent VM    │ │             │
│  │             │ │             │
│  │  Claude CLI──┼─┼── MCP ─────┘  (standard HTTP+token)
│  │    │        │ │
│  │    ├── local MCP (file, git, shell)
│  │    └── sharkfin MCP
│  └─────────────┘ │
└─────────────────┘
```

The WorkFort Cloud orchestrator calls the open source Nexus API to create
VMs. The only thing it adds is an extra MCP server entry in the agent's
config. That entry points back to the Cloud MCP Server with a scoped token.

Nexus never sees or proxies MCP traffic. The agent talks directly to the
cloud MCP server over HTTP. Nexus is a pure VM lifecycle manager.

## Invocation Flow

```
User
  → Sharkfin message: "deploy the PR to staging"
  → Sharkfin webhook → WorkFort Cloud orchestrator
  → orchestrator calls Nexus: task.Exec(claude -p "deploy to staging")
  → Claude in VM calls MCP tool: deploy.promote("staging")
  → Cloud MCP server → k8s API → deployment created
  → Claude responds in Sharkfin: "Deployed to staging.app.acme.workfort.dev"
```

## Environment Lifecycle

| Environment | DNS Pattern | Access | Lifecycle |
|---|---|---|---|
| Dev | `dev.app.customer.workfort.dev` | Private (agent only) | Persistent |
| PR | `pr-123.app.customer.workfort.dev` | Private (team link) | Ephemeral, auto-deleted on merge |
| Staging | `staging.app.customer.workfort.dev` | Semi-public (customer decides) | Persistent, promoted from PR |
| Production | `app.customer.workfort.dev` or custom domain | Public | Promoted from staging |

## Pricing Tiers

| Tier | Infrastructure | Deployment Target |
|---|---|---|
| Self-hosted (free) | Customer runs Nexus | No deployment tools |
| WorkFort Cloud | WorkFort-managed | WorkFort k8s cluster |
| Enterprise ("Contact Us") | WorkFort-managed | Customer's own k8s cluster |
