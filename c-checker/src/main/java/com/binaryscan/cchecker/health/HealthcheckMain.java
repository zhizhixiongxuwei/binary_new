package com.binaryscan.cchecker.health;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class HealthcheckMain {
    private HealthcheckMain() {
    }

    public static void main(String[] args) {
        try {
            String port = System.getenv().getOrDefault("C_CHECKER_HEALTH_PORT", "8080");
            if (!port.matches("[0-9]{1,5}")) {
                System.exit(1);
            }
            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(2))
                    .build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://127.0.0.1:" + port + "/actuator/health/readiness"))
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            int status = client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
            System.exit(status >= 200 && status < 300 ? 0 : 1);
        } catch (Exception ignored) {
            System.exit(1);
        }
    }
}
