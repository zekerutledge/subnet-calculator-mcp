import { Hono } from "hono";
import { cors } from "hono/cors";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";

type LogLevel = "info" | "warn" | "error";

type RequestLogContext = {
  requestId: string;
  method: string;
  path: string;
  userAgent: string | null;
  referer: string | null;
  cfRay: string | null;
  colo: string | null;
  country: string | null;
};

type HonoVariables = {
  requestLogContext: RequestLogContext;
};

type SubnetInput = {
  address: string;
  prefixLength?: number;
  subnetMask?: string;
};

type SubnetInfo = {
  input: {
    address: string;
    ipAddress: string;
    cidr: string;
    subnetMask: string;
  };
  networkAddress: string;
  broadcastAddress: string;
  firstUsableHost: string;
  lastUsableHost: string;
  totalAddresses: number;
  usableHostCount: number;
  prefixLength: number;
  subnetMask: string;
  wildcardMask: string;
  ipVersion: "IPv4";
  ipClass: "A" | "B" | "C" | "D" | "E";
  scope: "private" | "public" | "loopback" | "link-local" | "multicast" | "reserved";
  notes: string[];
};

function getRequestLogContext(request: Request): RequestLogContext {
  const url = new URL(request.url);
  const cf = request.cf as Record<string, unknown> | undefined;
  const cfRay = request.headers.get("cf-ray");

  return {
    requestId: cfRay ?? crypto.randomUUID(),
    method: request.method,
    path: url.pathname,
    userAgent: request.headers.get("user-agent"),
    referer: request.headers.get("referer"),
    cfRay,
    colo: typeof cf?.colo === "string" ? cf.colo : null,
    country: typeof cf?.country === "string" ? cf.country : null,
  };
}

function getTrafficKind(path: string): "mcp" | "crawler_or_probe" | "health_check" | "other" {
  if (path === "/mcp") return "mcp";
  if (path === "/health") return "health_check";
  if (path === "/") return "crawler_or_probe";
  return "other";
}

function logEvent(level: LogLevel, event: string, data: Record<string, unknown>) {
  console[level](
    JSON.stringify({
      level,
      event,
      timestamp: new Date().toISOString(),
      service: "subnet-calculator-mcp",
      ...data,
    }),
  );
}

function parseIPv4(ip: string): number {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }

  const octets = parts.map((part) => {
    if (!/^\d+$/.test(part)) {
      throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      throw new Error(`Invalid IPv4 address: ${ip}`);
    }
    return octet;
  });

  return (((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0);
}

function ipv4ToString(value: number): string {
  return [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ].join(".");
}

function prefixToMask(prefixLength: number): number {
  if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 32) {
    throw new Error("CIDR prefix length must be an integer from 0 through 32.");
  }
  return prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;
}

function maskToPrefix(maskString: string): number {
  const mask = parseIPv4(maskString);
  let prefixLength = 0;
  let seenZero = false;

  for (let bit = 31; bit >= 0; bit -= 1) {
    const isOne = ((mask >>> bit) & 1) === 1;
    if (isOne && seenZero) {
      throw new Error(`Subnet mask must be contiguous: ${maskString}`);
    }
    if (isOne) {
      prefixLength += 1;
    } else {
      seenZero = true;
    }
  }

  return prefixLength;
}

function parseAddressAndPrefix(input: SubnetInput): { ip: string; prefixLength: number } {
  const address = input.address.trim();
  const slashParts = address.split("/");

  if (slashParts.length > 2) {
    throw new Error("Address must contain at most one CIDR slash.");
  }

  const ip = slashParts[0]?.trim();
  if (!ip) {
    throw new Error("Address is required.");
  }

  const prefixSources = [
    slashParts[1]?.trim(),
    input.prefixLength === undefined ? undefined : String(input.prefixLength),
    input.subnetMask?.trim(),
  ].filter((value): value is string => Boolean(value));

  if (prefixSources.length === 0) {
    throw new Error("Provide a CIDR prefix in address, prefixLength, or subnetMask.");
  }

  const parsedPrefixes = prefixSources.map((source) => {
    const normalized = source.startsWith("/") ? source.slice(1) : source;
    if (/^\d+$/.test(normalized)) {
      const prefixLength = Number(normalized);
      prefixToMask(prefixLength);
      return prefixLength;
    }
    return maskToPrefix(normalized);
  });

  const [firstPrefix, ...otherPrefixes] = parsedPrefixes;
  if (otherPrefixes.some((prefix) => prefix !== firstPrefix)) {
    throw new Error("Conflicting CIDR prefix/subnet mask values were provided.");
  }

  return { ip, prefixLength: firstPrefix };
}

function getIpClass(ipNumber: number): SubnetInfo["ipClass"] {
  const firstOctet = (ipNumber >>> 24) & 255;
  if (firstOctet <= 127) return "A";
  if (firstOctet <= 191) return "B";
  if (firstOctet <= 223) return "C";
  if (firstOctet <= 239) return "D";
  return "E";
}

function getScope(ipNumber: number): SubnetInfo["scope"] {
  const first = (ipNumber >>> 24) & 255;
  const second = (ipNumber >>> 16) & 255;

  if (first === 10) return "private";
  if (first === 172 && second >= 16 && second <= 31) return "private";
  if (first === 192 && second === 168) return "private";
  if (first === 127) return "loopback";
  if (first === 169 && second === 254) return "link-local";
  if (first >= 224 && first <= 239) return "multicast";
  if (first === 0 || first >= 240) return "reserved";
  return "public";
}

function calculateSubnet(input: SubnetInput): SubnetInfo {
  const { ip, prefixLength } = parseAddressAndPrefix(input);
  const ipNumber = parseIPv4(ip);
  const mask = prefixToMask(prefixLength);
  const wildcard = (~mask) >>> 0;
  const network = (ipNumber & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;
  const totalAddresses = 2 ** (32 - prefixLength);

  let firstUsableHost = network;
  let lastUsableHost = broadcast;
  let usableHostCount = totalAddresses;
  const notes: string[] = [];

  if (prefixLength <= 30) {
    firstUsableHost = (network + 1) >>> 0;
    lastUsableHost = (broadcast - 1) >>> 0;
    usableHostCount = Math.max(totalAddresses - 2, 0);
  } else if (prefixLength === 31) {
    notes.push("/31 networks are treated as point-to-point links with both addresses usable per RFC 3021.");
  } else {
    notes.push("/32 identifies a single host address.");
  }

  const subnetMask = ipv4ToString(mask);

  return {
    input: {
      address: input.address,
      ipAddress: ip,
      cidr: `${ip}/${prefixLength}`,
      subnetMask,
    },
    networkAddress: ipv4ToString(network),
    broadcastAddress: ipv4ToString(broadcast),
    firstUsableHost: ipv4ToString(firstUsableHost),
    lastUsableHost: ipv4ToString(lastUsableHost),
    totalAddresses,
    usableHostCount,
    prefixLength,
    subnetMask,
    wildcardMask: ipv4ToString(wildcard),
    ipVersion: "IPv4",
    ipClass: getIpClass(ipNumber),
    scope: getScope(ipNumber),
    notes,
  };
}

function formatSubnetInfo(info: SubnetInfo): string {
  return [
    `Subnet information for ${info.input.cidr}`,
    "",
    `Network address: ${info.networkAddress}`,
    `Broadcast address: ${info.broadcastAddress}`,
    `Subnet mask: ${info.subnetMask}`,
    `Wildcard mask: ${info.wildcardMask}`,
    `First usable host: ${info.firstUsableHost}`,
    `Last usable host: ${info.lastUsableHost}`,
    `Total addresses: ${info.totalAddresses}`,
    `Usable host count: ${info.usableHostCount}`,
    `CIDR prefix: /${info.prefixLength}`,
    `IP class: ${info.ipClass}`,
    `Scope: ${info.scope}`,
    ...(info.notes.length > 0 ? ["", "Notes:", ...info.notes.map((note) => `- ${note}`)] : []),
    "",
    "JSON:",
    JSON.stringify(info, null, 2),
  ].join("\n");
}

function makeServer(requestLogContext: RequestLogContext) {
  const server = new McpServer({
    name: "subnet-calculator-mcp",
    version: "1.0.0",
  });

  server.registerTool(
    "calculate_subnet",
    {
      title: "Calculate Subnet",
      description:
        "Calculate IPv4 subnet information from an address with CIDR notation, a prefix length, or a dotted decimal subnet mask.",
      inputSchema: {
        address: z
          .string()
          .describe("IPv4 address, optionally including CIDR notation, for example 192.168.1.10/24."),
        prefixLength: z
          .number()
          .int()
          .min(0)
          .max(32)
          .optional()
          .describe("Optional CIDR prefix length from 0 to 32, for example 24."),
        subnetMask: z
          .string()
          .optional()
          .describe("Optional dotted decimal subnet mask, for example 255.255.255.0."),
      },
    },
    async ({ address, prefixLength, subnetMask }) => {
      const startedAt = Date.now();

      try {
        const info = calculateSubnet({ address, prefixLength, subnetMask });

        logEvent("info", "mcp_tool_invocation", {
          ...requestLogContext,
          tool: "calculate_subnet",
          success: true,
          durationMs: Date.now() - startedAt,
          prefixLength: info.prefixLength,
          scope: info.scope,
        });

        return {
          content: [
            {
              type: "text" as const,
              text: formatSubnetInfo(info),
            },
          ],
          structuredContent: info,
        };
      } catch (error) {
        logEvent("warn", "mcp_tool_invocation", {
          ...requestLogContext,
          tool: "calculate_subnet",
          success: false,
          durationMs: Date.now() - startedAt,
          error: error instanceof Error ? error.message : String(error),
        });

        return {
          isError: true,
          content: [
            {
              type: "text" as const,
              text: error instanceof Error ? error.message : String(error),
            },
          ],
        };
      }
    },
  );

  return server;
}

const app = new Hono<{ Variables: HonoVariables }>();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "mcp-session-id", "Last-Event-ID", "mcp-protocol-version"],
    exposeHeaders: ["mcp-session-id", "mcp-protocol-version"],
  }),
);

app.use("*", async (c, next) => {
  const requestLogContext = getRequestLogContext(c.req.raw);
  const startedAt = Date.now();
  c.set("requestLogContext", requestLogContext);

  try {
    await next();

    logEvent("info", "http_request", {
      ...requestLogContext,
      trafficKind: getTrafficKind(requestLogContext.path),
      status: c.res.status,
      success: c.res.status < 500,
      durationMs: Date.now() - startedAt,
    });
  } catch (error) {
    logEvent("error", "http_request", {
      ...requestLogContext,
      trafficKind: getTrafficKind(requestLogContext.path),
      success: false,
      durationMs: Date.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
    });

    throw error;
  }
});

app.get("/", (c) =>
  c.json({
    name: "subnet-calculator-mcp",
    description: "An MCP server that calculates IPv4 subnet information.",
    mcpEndpoint: "/mcp",
    tools: ["calculate_subnet"],
    examples: [
      { address: "192.168.1.10/24" },
      { address: "192.168.1.10", prefixLength: 24 },
      { address: "192.168.1.10", subnetMask: "255.255.255.0" },
    ],
  }),
);

app.get("/health", (c) => c.json({ status: "ok" }));

app.all("/mcp", async (c) => {
  const transport = new WebStandardStreamableHTTPServerTransport();
  const server = makeServer(c.get("requestLogContext"));

  await server.connect(transport);
  return transport.handleRequest(c.req.raw);
});

export default app;
