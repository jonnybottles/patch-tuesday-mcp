# LinkedIn post — hosted endpoint migration (v0.9.1)

> Post once the 0.9.1 release is live. Same house style as the monthly template: **no outbound link in
> the post body** (LinkedIn suppresses those) — repo + endpoint URL go in the **first comment**.
> Suggested visual: a screenshot of the two-line config change, or the `/health` response showing
> `"version": "0.9.1"`.

---

The hosted patch-tuesday-mcp endpoint just moved — and got a lot more room to breathe. 🚀

Quick context: patch-tuesday-mcp is an open-source MCP server that lets an AI assistant answer
"what do I patch first this month?" It queries Microsoft's MSRC Security Update Guide and enriches
every CVE with FIRST.org EPSS exploit-probability scores and the CISA KEV catalog. No API keys.

I've been running a free hosted instance so people could try it without installing anything. That
instance was living on a subscription I was paying for out of pocket. It has now moved — and while
I was at it, I gave it the resources it should have had from the start:

⚡ 2x the CPU and memory per replica
⚡ A minimum of 2 always-on replicas — no cold starts, no scale-to-zero
⚡ Autoscaling to 6 replicas on sustained concurrency, so a spike doesn't mean a timeout

And because "it scales" is a claim, not a fact, I wrote tests that prove it: assertions that pin the
replica floor, the ceiling, and the CPU/memory spec, plus a load test that opens dozens of
concurrent MCP sessions in ramped waves and asserts the platform actually scales out and never
drops below its floor.

That test suite immediately earned its keep — it caught a real misconfiguration where the autoscale
trigger sat *above* the server's own connection limit, meaning the container would have started
refusing requests before the platform ever decided to add a replica. Exactly the kind of bug you
only find by actually driving load through the thing.

📅 The important bit if you're using the hosted endpoint: the old URL keeps working until
**August 11, 2026** (next Patch Tuesday), then it retires. It'll tell you it's deprecated — the
responses now carry standard HTTP deprecation headers (RFC 9745 / 8594) and a machine-readable
notice pointing at the new address. Nothing breaks today; just update the URL in your MCP client
config before then.

Nothing changes for local installs — `uvx patch-tuesday-mcp` is unaffected.

New URL in the comments. Happy patching. 🛠️

#PatchTuesday #CyberSecurity #MCP #VulnerabilityManagement #SysAdmin #AI

**First comment:**
🔗 Repo: https://github.com/jonnybottles/patch-tuesday-mcp
🔗 New hosted endpoint: https://patch-tuesday-mcp.agreeabledesert-d0b8e491.eastus2.azurecontainerapps.io/mcp
Old endpoint (retires Aug 11, 2026): https://patch-tuesday-mcp.happyrock-b60185ec.eastus.azurecontainerapps.io/mcp
Local install is one command and needs no endpoint at all: `uvx patch-tuesday-mcp`
