# Subnet Calculator MCP

Subnet Calculator MCP is a Cloudflare Workers-hosted Model Context Protocol server that calculates IPv4 subnet information from an IP address and CIDR prefix or dotted decimal subnet mask.

## Public endpoint

```text
https://subnet-calculator.zekedoesai.com/mcp
```

Transport: **Streamable HTTP**

Authentication: **none currently required**

## Tools

### `calculate_subnet`

Calculates IPv4 subnet details.

Accepted input forms:

```json
{ "address": "192.168.1.10/24" }
```

```json
{ "address": "192.168.1.10", "prefixLength": 24 }
```

```json
{ "address": "192.168.1.10", "subnetMask": "255.255.255.0" }
```

Returns:

- network address
- broadcast address
- subnet mask
- wildcard mask
- first usable host
- last usable host
- total address count
- usable host count
- CIDR prefix
- IP class
- scope: private, public, loopback, link-local, multicast, or reserved
- notes for `/31` and `/32` networks

## Connect from an MCP client

```json
{
  "mcpServers": {
    "subnet-calculator": {
      "url": "https://subnet-calculator.zekedoesai.com/mcp"
    }
  }
}
```

Some clients may require explicitly setting the transport type to `streamable-http`.

## Local development

Install dependencies:

```bash
npm install
```

Run type checking:

```bash
npm run typecheck
```

Start a local Cloudflare Workers development server:

```bash
npm run dev
```

The MCP endpoint is available at `/mcp` on the local Wrangler dev URL.

## Deploy

Authenticate with Cloudflare Wrangler if needed:

```bash
wrangler login
```

Deploy to Cloudflare Workers:

```bash
npm run deploy
```

## MCP Registry

This repository includes `server.json` for MCP Registry publication. The registry entry describes the hosted remote server and its Streamable HTTP endpoint.
