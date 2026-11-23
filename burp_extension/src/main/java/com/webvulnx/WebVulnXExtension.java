package com.webvulnx;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class WebVulnXExtension implements BurpExtension, ContextMenuItemsProvider {

    private static final String API_URL = "http://127.0.0.1:5000/api/v1/traffic";
    private static final String API_KEY = "wv_local_burp_token_9f8a7b6c5d4e3f2a1b";

    private MontoyaApi api;
    private HttpClient httpClient;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        api.extension().setName("WebVulnX Connector");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("[WebVulnX] Extension loaded successfully. Target API: " + API_URL);
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        List<HttpRequestResponse> selected = new ArrayList<>();

        event.messageEditorRequestResponse().ifPresent(editor -> selected.add(editor.requestResponse()));
        selected.addAll(event.selectedRequestResponses());

        if (selected.isEmpty()) {
            return menuItems;
        }

        JMenuItem sendItem = new JMenuItem("Send to WebVulnX (" + selected.size() + " item" + (selected.size() > 1 ? "s" : "") + ")");
        sendItem.addActionListener(e -> {
            for (HttpRequestResponse item : selected) {
                CompletableFuture.runAsync(() -> sendTransaction(item));
            }
        });

        menuItems.add(sendItem);
        return menuItems;
    }

    private void sendTransaction(HttpRequestResponse item) {
        try {
            HttpRequest req = item.request();
            HttpResponse res = item.response();

            if (req == null) {
                return;
            }

            String jsonPayload = buildJsonPayload(req, res);

            java.net.http.HttpRequest httpRequest = java.net.http.HttpRequest.newBuilder()
                    .uri(URI.create(API_URL))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("X-WebVulnX-Key", API_KEY)
                    .POST(BodyPublishers.ofString(jsonPayload))
                    .build();

            java.net.http.HttpResponse<String> response = httpClient.send(httpRequest, BodyHandlers.ofString());

            if (response.statusCode() == 201) {
                api.logging().logToOutput("[WebVulnX] Sent: " + req.method() + " " + req.url() + " -> OK (201)");
            } else {
                api.logging().logToError("[WebVulnX] Rejected (" + response.statusCode() + ") for " + req.url() + ": " + response.body());
            }
        } catch (Exception ex) {
            api.logging().logToError("[WebVulnX] Connection error: " + ex.getMessage());
        }
    }

    private String buildJsonPayload(HttpRequest req, HttpResponse res) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"source\":\"Burp Community Extension\",");
        sb.append("\"method\":\"").append(escapeJson(req.method())).append("\",");
        sb.append("\"url\":\"").append(escapeJson(req.url())).append("\",");
        sb.append("\"request_headers\":").append(headersToJson(req.headers())).append(",");
        sb.append("\"request_body\":\"").append(escapeJson(req.bodyToString())).append("\"");

        if (res != null) {
            sb.append(",\"status_code\":").append(res.statusCode());
            sb.append(",\"response_headers\":").append(headersToJson(res.headers()));
            sb.append(",\"response_body\":\"").append(escapeJson(res.bodyToString())).append("\"");
        }

        sb.append("}");
        return sb.toString();
    }

    private String headersToJson(List<HttpHeader> headers) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < headers.size(); i++) {
            HttpHeader h = headers.get(i);
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(h.name())).append("\":\"")
              .append(escapeJson(h.value())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private String escapeJson(String text) {
        if (text == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
