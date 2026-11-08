/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.distribution;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * {@code radiusward probe <url>}: exit 0 if the URL answers HTTP 200 within 2 s, 1 otherwise. Used as the
 * container health check, since the JRE base image has no curl.
 */
final class Probe {

    private Probe() {}

    static int run(String[] args) {
        if (args.length != 1) {
            System.err.println("usage: radiusward probe <url>");
            return 64;
        }
        try {
            HttpResponse<String> response = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(2))
                    .build()
                    .send(
                            HttpRequest.newBuilder(URI.create(args[0]))
                                    .timeout(Duration.ofSeconds(2))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString());
            System.out.println(response.statusCode() + " " + response.body());
            return response.statusCode() == 200 ? 0 : 1;
        } catch (Exception e) {
            System.out.println("probe failed: " + e.getMessage());
            return 1;
        }
    }
}
