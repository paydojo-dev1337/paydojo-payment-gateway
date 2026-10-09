
/**
 * PayDojo Payment Gateway
 * Internal Payment Processing Service
 *
 * Service: paydojo-gateway
 * Version: 1.2.0
 * Environment: Internal / Development
 *
 * Copyright (c) 2026 PayDojo Engineering
 */

const http = require("http");
const crypto = require("crypto");

// ==========================================
// Application Configuration
// ==========================================

const config = {
  service: "paydojo-payment-gateway",
  version: "1.2.0",
  environment: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT) || 3000,

  jwt: {
    secret: process.env.JWT_SECRET,
    algorithm: "HS256",
    issuer: process.env.JWT_ISSUER || "paydojo-gateway",
    audience: "paydojo-internal"
  },

  payment: {
    currency: "VND",
    maxAmount: 100000000,
    timeout: 30000,
    retryLimit: 3
  }
};

// ==========================================
// Mock Database
// ==========================================

const merchants = [
  {
    id: "MER-1001",
    name: "PayDojo Digital",
    email: "merchant@paydojo.example",
    status: "active",
    settlementCycle: "T+1"
  },
  {
    id: "MER-1002",
    name: "PayDojo Retail",
    email: "retail@paydojo.example",
    status: "active",
    settlementCycle: "T+2"
  },
  {
    id: "MER-1003",
    name: "PayDojo Sandbox",
    email: "sandbox@paydojo.example",
    status: "testing",
    settlementCycle: "Manual"
  }
];

const transactions = [
  {
    id: "TXN-2026-00001",
    merchantId: "MER-1001",
    amount: 1500000,
    currency: "VND",
    method: "bank_transfer",
    status: "success",
    createdAt: "2026-10-01T09:30:00Z"
  },
  {
    id: "TXN-2026-00002",
    merchantId: "MER-1002",
    amount: 2750000,
    currency: "VND",
    method: "card",
    status: "pending",
    createdAt: "2026-10-02T10:15:00Z"
  },
  {
    id: "TXN-2026-00003",
    merchantId: "MER-1001",
    amount: 890000,
    currency: "VND",
    method: "qr_payment",
    status: "failed",
    createdAt: "2026-10-03T11:20:00Z"
  }
];

// ==========================================
// Response Utilities
// ==========================================

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "X-Service": config.service,
    "Cache-Control": "no-store"
  });

  res.end(JSON.stringify(data, null, 2));
}

function success(res, data, message = "Success") {
  sendJSON(res, 200, {
    success: true,
    message,
    data,
    timestamp: new Date().toISOString()
  });
}

function error(res, status, message) {
  sendJSON(res, status, {
    success: false,
    error: {
      code: status,
      message
    },
    timestamp: new Date().toISOString()
  });
}

// ==========================================
// Request Body Parser
// ==========================================

async function parseBody(req) {
  let body = "";

  for await (const chunk of req) {
    body += chunk;

    if (body.length > 1024 * 1024) {
      throw new Error("Payload too large");
    }
  }

  if (!body.trim()) {
    return {};
  }

  return JSON.parse(body);
}

// ==========================================
// JWT Authentication Service
// ==========================================

function verifyJWT(token) {
  try {
    if (!config.jwt.secret) return null;

    const parts = token.split(".");

    if (parts.length !== 3) return null;

    const [header, payload, signature] = parts;

    const decodedHeader = JSON.parse(
      Buffer.from(header, "base64url").toString()
    );

    if (decodedHeader.alg !== "HS256") {
      return null;
    }

    const expectedSignature = crypto
      .createHmac("sha256", config.jwt.secret)
      .update(`${header}.${payload}`)
      .digest();

    const providedSignature = Buffer.from(
      signature,
      "base64url"
    );

    if (
      expectedSignature.length !== providedSignature.length ||
      !crypto.timingSafeEqual(
        expectedSignature,
        providedSignature
      )
    ) {
      return null;
    }

    const claims = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    const now = Math.floor(Date.now() / 1000);

    if (
      typeof claims.exp !== "number" ||
      claims.exp <= now ||
      claims.iss !== config.jwt.issuer ||
      claims.aud !== config.jwt.audience
    ) {
      return null;
    }

    return claims;

  } catch {
    return null;
  }
}

function requireAdmin(req, res) {
  if (!config.jwt.secret) {
    error(res, 503, "Authentication service unavailable");
    return false;
  }

  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    error(res, 401, "Authentication token required");
    return false;
  }

  const token = authorization.slice(7);

  const user = verifyJWT(token);

  if (!user) {
    error(res, 401, "Invalid or expired token");
    return false;
  }

  if (user.role !== "admin") {
    error(res, 403, "Insufficient permissions");
    return false;
  }

  return user;
}

// ==========================================
// Merchant Service
// ==========================================

function getMerchants(req, res) {
  success(res, merchants);
}

function getMerchantById(req, res, id) {
  const merchant = merchants.find(m => m.id === id);

  if (!merchant) {
    return error(res, 404, "Merchant not found");
  }

  success(res, merchant);
}

// ==========================================
// Transaction Service
// ==========================================

function getTransactions(req, res, url) {
  const status = url.searchParams.get("status");
  const merchantId = url.searchParams.get("merchantId");

  let result = [...transactions];

  if (status) {
    result = result.filter(t => t.status === status);
  }

  if (merchantId) {
    result = result.filter(t => t.merchantId === merchantId);
  }

  success(res, {
    total: result.length,
    transactions: result
  });
}

function getTransactionById(req, res, id) {
  const transaction = transactions.find(
    t => t.id === id
  );

  if (!transaction) {
    return error(res, 404, "Transaction not found");
  }

  success(res, transaction);
}

// ==========================================
// Payment Processing Service
// ==========================================

async function createPayment(req, res) {
  let body;

  try {
    body = await parseBody(req);
  } catch {
    return error(res, 400, "Invalid request body");
  }

  const {
    merchantId,
    amount,
    method
  } = body;

  if (
    !merchantId ||
    !Number.isSafeInteger(amount) ||
    amount <= 0 ||
    !method
  ) {
    return error(res, 400, "Invalid payment information");
  }

  if (amount > config.payment.maxAmount) {
    return error(res, 400, "Payment limit exceeded");
  }

  const merchant = merchants.find(
    m => m.id === merchantId
  );

  if (!merchant) {
    return error(res, 404, "Merchant not found");
  }

  if (merchant.status !== "active") {
    return error(res, 403, "Merchant is not active");
  }

  const allowedMethods = [
    "card",
    "bank_transfer",
    "qr_payment"
  ];

  if (!allowedMethods.includes(method)) {
    return error(res, 400, "Unsupported payment method");
  }

  const transaction = {
    id: `TXN-${crypto.randomUUID()}`,
    merchantId,
    amount,
    currency: config.payment.currency,
    method,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  transactions.push(transaction);

  sendJSON(res, 201, {
    success: true,
    message: "Payment initialized",
    data: transaction
  });
}

// ==========================================
// Settlement & Reporting Service
// ==========================================

function getSettlementSummary(req, res) {
  const successful = transactions.filter(
    t => t.status === "success"
  );

  const totalVolume = successful.reduce(
    (sum, t) => sum + t.amount,
    0
  );

  success(res, {
    currency: "VND",
    totalTransactions: transactions.length,
    successfulTransactions: successful.length,
    pendingTransactions: transactions.filter(
      t => t.status === "pending"
    ).length,
    failedTransactions: transactions.filter(
      t => t.status === "failed"
    ).length,
    totalSettledAmount: totalVolume,
    generatedAt: new Date().toISOString()
  });
}

// ==========================================
// Internal Administration
// ==========================================

function getInternalConfiguration(req, res) {
  success(res, {
    service: config.service,
    environment: config.environment,
    paymentSettings: config.payment,
    authentication: {
      algorithm: config.jwt.algorithm,
      issuer: config.jwt.issuer,
      audience: config.jwt.audience
    },
    features: {
      cardPayments: true,
      bankTransfer: true,
      qrPayments: true,
      settlementEngine: true,
      auditLogging: true
    }
  });
}

// ==========================================
// Health Monitoring
// ==========================================

function healthCheck(req, res) {
  success(res, {
    service: config.service,
    version: config.version,
    status: "healthy",
    uptime: Math.floor(process.uptime()),
    environment: config.environment
  });
}

// ==========================================
// Main API Router
// ==========================================

async function router(req, res) {
  const url = new URL(
    req.url,
    `http://${req.headers.host || "localhost"}`
  );

  const path = url.pathname;
  const method = req.method;

  console.log(
    `[${new Date().toISOString()}] ${method} ${path}`
  );

  // Public endpoints

  if (method === "GET" && path === "/health") {
    return healthCheck(req, res);
  }

  if (method === "GET" && path === "/api/v1") {
    return success(res, {
      service: config.service,
      version: config.version,
      documentation: "/api/v1/docs"
    });
  }

  if (method === "GET" && path === "/api/v1/docs") {
    return success(res, {
      endpoints: [
        "GET /health",
        "GET /api/v1/merchants",
        "GET /api/v1/merchants/:id",
        "GET /api/v1/transactions",
        "GET /api/v1/transactions/:id",
        "POST /api/v1/payments",
        "GET /api/v1/internal/config",
        "GET /api/v1/internal/settlements"
      ]
    });
  }

  if (method === "GET" && path === "/api/v1/merchants") {
    return getMerchants(req, res);
  }

  if (
    method === "GET" &&
    path.startsWith("/api/v1/merchants/")
  ) {
    const id = path.split("/").pop();
    return getMerchantById(req, res, id);
  }

  if (method === "GET" && path === "/api/v1/transactions") {
    return getTransactions(req, res, url);
  }

  if (
    method === "GET" &&
    path.startsWith("/api/v1/transactions/")
  ) {
    const id = path.split("/").pop();
    return getTransactionById(req, res, id);
  }

  if (method === "POST" && path === "/api/v1/payments") {
    return createPayment(req, res);
  }

  // Internal admin endpoints

  if (path.startsWith("/api/v1/internal/")) {
    const user = requireAdmin(req, res);

    if (!user) return;

    if (
      method === "GET" &&
      path === "/api/v1/internal/config"
    ) {
      return getInternalConfiguration(req, res);
    }

    if (
      method === "GET" &&
      path === "/api/v1/internal/settlements"
    ) {
      return getSettlementSummary(req, res);
    }
  }

  return error(res, 404, "Endpoint not found");
}

// ==========================================
// HTTP Server
// ==========================================

const server = http.createServer(async (req, res) => {
  try {
    await router(req, res);
  } catch (err) {
    console.error("[Gateway Error]", err.message);

    error(res, 500, "Internal server error");
  }
});

// ==========================================
// Startup
// ==========================================

server.listen(config.port, () => {
  console.log("=======================================");
  console.log("       PAYDOJO PAYMENT GATEWAY        ");
  console.log("=======================================");
  console.log(`Service : ${config.service}`);
  console.log(`Version : ${config.version}`);
  console.log(`Mode    : ${config.environment}`);
  console.log(`Port    : ${config.port}`);
  console.log("---------------------------------------");
  console.log("Gateway initialized successfully");
  console.log("=======================================");
});
