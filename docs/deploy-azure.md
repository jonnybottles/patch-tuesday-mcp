# Deploying to Azure Container Apps

This guide deploys patch-tuesday-mcp as an always-warm remote MCP server on
Azure Container Apps (ACA), with rate limiting, cost protections, and optional
Application Insights usage telemetry.

**Expected cost:** roughly **$5/month** at 0.25 vCPU / 0.5 GiB with one
always-on replica (after ACA's monthly free grants). Telemetry is free at this
scale (first 5 GB/month of App Insights ingestion included).

## 1. Build and push the image (ghcr.io — free for public images)

Using GitHub Container Registry avoids paying ~$5/month for Azure Container
Registry Basic.

```bash
docker build -t ghcr.io/jonnybottles/patch-tuesday-mcp:latest .
echo $GITHUB_TOKEN | docker login ghcr.io -u jonnybottles --password-stdin
docker push ghcr.io/jonnybottles/patch-tuesday-mcp:latest
```

Make the package public in GitHub → Packages → patch-tuesday-mcp → Settings,
so ACA can pull it without credentials.

## 2. Create the Container Apps environment

```bash
az group create --name patch-tuesday-rg --location eastus

az containerapp env create \
  --name patch-tuesday-env \
  --resource-group patch-tuesday-rg \
  --location eastus
```

## 3. (Optional) Create Application Insights for usage telemetry

```bash
az monitor app-insights component create \
  --app patch-tuesday-insights \
  --resource-group patch-tuesday-rg \
  --location eastus

# Capture the connection string for step 4
az monitor app-insights component show \
  --app patch-tuesday-insights \
  --resource-group patch-tuesday-rg \
  --query connectionString -o tsv
```

## 4. Deploy the container app

Always-warm (no cold starts), capped at 2 replicas so abuse cannot run up the
bill — worst case cost is bounded by the replica cap.

```bash
az containerapp create \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --environment patch-tuesday-env \
  --image ghcr.io/jonnybottles/patch-tuesday-mcp:latest \
  --target-port 8000 \
  --ingress external \
  --cpu 0.25 --memory 0.5Gi \
  --min-replicas 1 \
  --max-replicas 2 \
  --scale-rule-name http-concurrency \
  --scale-rule-type http \
  --scale-rule-http-concurrency 100 \
  --env-vars \
    MCP_TRANSPORT=http \
    RATE_LIMIT_RPM=60 \
    APPLICATIONINSIGHTS_CONNECTION_STRING="<connection string from step 3, or omit>"
```

The MCP endpoint will be:

```
https://<app-fqdn>/mcp
```

Get the FQDN:

```bash
az containerapp show \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --query properties.configuration.ingress.fqdn -o tsv
```

Connect from Claude Code:

```bash
claude mcp add --transport http patch-tuesday https://<app-fqdn>/mcp
```

## 5. Abuse protections in place

| Layer | Protection |
|-------|-----------|
| `--max-replicas 2` | Hard cost ceiling — a flood of requests cannot scale your bill |
| `RATE_LIMIT_RPM=60` | Per-client-IP token bucket, returns 429 with Retry-After |
| In-process caching | Even hammered, the server hits the MSRC API at most ~hourly per month document |
| Read-only public data | Nothing sensitive to leak; worst case is compute cost, which is capped |

## 6. Budget alert (recommended)

Get emailed if monthly spend exceeds $15:

```bash
az consumption budget create \
  --budget-name patch-tuesday-budget \
  --amount 15 \
  --time-grain Monthly \
  --resource-group patch-tuesday-rg \
  --category Cost
```

(Or set it up in Portal → Cost Management → Budgets, which also supports
action groups for email notifications.)

## 7. Useful App Insights KQL queries

Daily unique users (hashed IPs — raw addresses are never stored):

```kusto
traces
| where customDimensions.event_name == "http_request"
| extend user = tostring(customDimensions.custom_user_hash)
| summarize uniques = dcount(user) by bin(timestamp, 1d)
| order by timestamp desc
```

Requests per day:

```kusto
traces
| where customDimensions.event_name == "http_request"
| summarize requests = count() by bin(timestamp, 1d)
| order by timestamp desc
```

Which tool parameters people actually use:

```kusto
traces
| where customDimensions.event_name == "tool_call"
| extend params = tostring(customDimensions.custom_params_used)
| summarize calls = count() by params
| order by calls desc
```

Tool latency:

```kusto
traces
| where customDimensions.event_name == "tool_call"
| extend ms = todouble(customDimensions.custom_duration_ms)
| summarize p50 = percentile(ms, 50), p95 = percentile(ms, 95) by bin(timestamp, 1d)
```

## 8. Updating the deployment

```bash
docker build -t ghcr.io/jonnybottles/patch-tuesday-mcp:latest .
docker push ghcr.io/jonnybottles/patch-tuesday-mcp:latest

az containerapp update \
  --name patch-tuesday-mcp \
  --resource-group patch-tuesday-rg \
  --image ghcr.io/jonnybottles/patch-tuesday-mcp:latest
```
