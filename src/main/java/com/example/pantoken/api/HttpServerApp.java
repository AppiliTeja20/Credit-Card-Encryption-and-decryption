package com.example.pantoken.api;

import com.example.pantoken.exception.InvalidPanException;
import com.example.pantoken.exception.TokenNotFoundException;
import com.example.pantoken.exception.UnauthorizedDetokenizationException;
import com.example.pantoken.model.TokenRecord;
import com.example.pantoken.service.PanValidator;
import com.example.pantoken.service.TokenVaultService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Minimal, dependency-free REST layer (java.net.httpserver) fronting the
 * {@link TokenVaultService}. No framework needed for a demo of this size,
 * and it keeps the crypto/service code fully framework-agnostic.
 *
 * Endpoints:
 *   POST   /api/pan/tokenize        {"pan": "4111111111111111"}
 *   GET    /api/pan/{token}/mask    optional ?showFirst6=true
 *   POST   /api/pan/{token}/detokenize   requires header: X-Authorization-Level: PCI_AUTHORIZED
 *   DELETE /api/pan/{token}
 *   GET    /api/pan/validate?pan=...     Luhn/format check only, never touches the vault
 *   GET    /health
 */
public final class HttpServerApp {

    private static final Logger LOG = Logger.getLogger(HttpServerApp.class.getName());
    private static final String REQUIRED_AUTH_HEADER = "X-Authorization-Level";
    private static final String REQUIRED_AUTH_VALUE = "PCI_AUTHORIZED";

    private final TokenVaultService vaultService;
    private final int port;

    public HttpServerApp(TokenVaultService vaultService, int port) {
        this.vaultService = vaultService;
        this.port = port;
    }

    public HttpServer start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/health", ex -> respond(ex, 200, Map.of("status", "UP")));
        server.createContext("/api/pan/tokenize", this::handleTokenize);
        server.createContext("/api/pan/validate", this::handleValidate);
        server.createContext("/api/pan/", this::handleTokenScopedRoutes);
        server.setExecutor(null);
        server.start();
        LOG.info(() -> "PAN token service listening on http://localhost:" + port);
        return server;
    }

    // ---- handlers -----------------------------------------------------

    private void handleTokenize(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            respondMethodNotAllowed(ex);
            return;
        }
        try {
            Map<String, Object> body = JsonUtil.readJsonObject(ex.getRequestBody());
            Object rawPan = body.get("pan");
            TokenRecord record = vaultService.tokenize(rawPan == null ? null : rawPan.toString());

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("token", record.getToken());
            response.put("brand", record.getBrand());
            response.put("last4", record.getLast4());
            response.put("first6", record.getFirst6());
            response.put("maskedPan", vaultService.maskedPan(record.getToken(), true));
            response.put("createdAt", record.getCreatedAt().toString());
            respond(ex, 201, response);
        } catch (InvalidPanException e) {
            respondError(ex, 400, e.getMessage());
        }
    }

    private void handleValidate(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            respondMethodNotAllowed(ex);
            return;
        }
        Map<String, String> query = parseQuery(ex.getRequestURI().getRawQuery());
        String pan = query.get("pan");
        try {
            String normalized = PanValidator.normalizeAndValidate(pan);
            respond(ex, 200, Map.of(
                    "valid", true,
                    "brand", PanValidator.detectBrand(normalized)
            ));
        } catch (InvalidPanException e) {
            respond(ex, 200, Map.of("valid", false, "reason", e.getMessage()));
        }
    }

    /** Dispatches /api/pan/{token}, /api/pan/{token}/mask, /api/pan/{token}/detokenize */
    private void handleTokenScopedRoutes(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath(); // e.g. /api/pan/tok_xxx/mask
        String[] parts = path.split("/");
        // parts: ["", "api", "pan", "{token}", optionally "mask"|"detokenize"]
        if (parts.length < 4) {
            respondError(ex, 404, "Unknown route");
            return;
        }
        String token = parts[3];
        String subresource = parts.length >= 5 ? parts[4] : null;

        try {
            if (subresource == null && "DELETE".equalsIgnoreCase(ex.getRequestMethod())) {
                boolean removed = vaultService.revoke(token);
                respond(ex, removed ? 204 : 404, removed ? null : Map.of("error", "token not found"));
                return;
            }
            if ("mask".equals(subresource) && "GET".equalsIgnoreCase(ex.getRequestMethod())) {
                Map<String, String> query = parseQuery(ex.getRequestURI().getRawQuery());
                boolean showFirst6 = Boolean.parseBoolean(query.getOrDefault("showFirst6", "false"));
                respond(ex, 200, Map.of("token", token, "maskedPan", vaultService.maskedPan(token, showFirst6)));
                return;
            }
            if ("detokenize".equals(subresource) && "POST".equalsIgnoreCase(ex.getRequestMethod())) {
                String authHeader = ex.getRequestHeaders().getFirst(REQUIRED_AUTH_HEADER);
                boolean authorized = REQUIRED_AUTH_VALUE.equals(authHeader);
                String pan = vaultService.detokenize(token, authorized);
                respond(ex, 200, Map.of("token", token, "pan", pan));
                return;
            }
            respondError(ex, 404, "Unknown route");
        } catch (TokenNotFoundException e) {
            respondError(ex, 404, e.getMessage());
        } catch (UnauthorizedDetokenizationException e) {
            respondError(ex, 403, e.getMessage());
        }
    }

    // ---- helpers --------------------------------------------------------

    private void respond(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes = body == null ? new byte[0] : JsonUtil.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        } else {
            ex.close();
        }
    }

    private void respondError(HttpExchange ex, int status, String message) throws IOException {
        respond(ex, status, Map.of("error", message));
    }

    private void respondMethodNotAllowed(HttpExchange ex) throws IOException {
        respondError(ex, 405, "Method not allowed");
    }

    private Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> result = new LinkedHashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return result;
        }
        for (String pair : rawQuery.split("&")) {
            int idx = pair.indexOf('=');
            if (idx < 0) {
                continue;
            }
            String key = java.net.URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8);
            String value = java.net.URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8);
            result.put(key, value);
        }
        return result;
    }
}
