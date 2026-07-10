# patch-tuesday-mcp skills

Portable [agent skills](https://agentskills.io/) for the Patch Tuesday
triage workflow. These are **plain Markdown + YAML front matter** — they carry
no code and can be deployed **independently of the MCP server**.

A skill teaches an AI agent *how* to drive the `msrc_search` tool (which
searches to run, in what order, how to prioritize). It does **not** replace the
tool: the agent still needs a running `patch-tuesday-mcp` server (or another
host exposing `msrc_search`) to execute the searches.

## Contents

| Skill | Purpose |
|-------|---------|
| [`patch-tuesday-triage/SKILL.md`](patch-tuesday-triage/SKILL.md) | Monthly identity/security triage: product watchlists, ordered `msrc_search` steps, briefing output, trends. |

## Deploying a skill (separate from the server)

The skill file is host-agnostic. Copy `patch-tuesday-triage/` into wherever your
agent loads skills from. Common locations:

- **GitHub Copilot CLI / repo-local:** `.copilot/skills/<name>/SKILL.md`
- **Personal (all repos):** `~/.copilot/skills/<name>/SKILL.md`

For example:

```bash
# repo-local install
mkdir -p .copilot/skills
cp -r skills/patch-tuesday-triage .copilot/skills/

# or personal install
mkdir -p ~/.copilot/skills
cp -r skills/patch-tuesday-triage ~/.copilot/skills/
```

The skill and the MCP server are decoupled: you can ship the skill to an agent
that talks to a remote `msrc_search` deployment, or run the server with no skill
at all.

## Installing into an agent

`skills/` here is the canonical, distributable copy. To use the skill, copy the
`patch-tuesday-triage/` directory into wherever your agent loads skills from
(see the paths above). The skill and the MCP server stay decoupled — updating
one has no effect on the other.

## Notes

- Keep organization-specific profile names and product lists **local** — the
  skill deliberately references generic, built-in profile names only.
- The skill assumes the single-tool design: every workflow is a `msrc_search`
  call. See the server [README](../README.md) for the full parameter surface.
