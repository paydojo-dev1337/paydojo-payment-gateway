const http = require("http");

const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");

  if (req.url === "/health") {
    res.end(JSON.stringify({
      service: "paydojo-gateway",
      status: "healthy",
      version: "1.2.0"
    }));
    return;
  }

  res.statusCode = 404;
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(3000, () => {
  console.log("PayDojo Gateway running on port 3000");
});