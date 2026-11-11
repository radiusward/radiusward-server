/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing.images;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.testcontainers.images.builder.ImageFromDockerfile;

/**
 * The prebuilt test images (docs/testing/strategy.md#test-images): eapol_test, radsecproxy, Samba AD and the bases of
 * the Linux images, published to {@code ghcr.io/radiusward/radiusward-test-images} as {@code <image>-<hash>}, the
 * hash covering the image's inputs as listed in {@code testing/test-images/images.txt}. A test takes the published
 * image when it exists, so no test run depends on package mirrors; otherwise it builds the image from its Dockerfile
 * as before. {@code -Dradiusward.test.images=build} always builds, {@code =pull} requires the published image.
 * {@code scripts/test-images.sh} computes the same hash.
 */
public final class TestImages {

    public static final String REPOSITORY = "ghcr.io/radiusward/radiusward-test-images";
    private static final System.Logger LOG = System.getLogger(TestImages.class.getName());

    /** One line of images.txt. */
    record Definition(String name, String context, String dockerfile, List<String> inputs) {}

    private TestImages() {}

    /** The image for a {@code GenericContainer}: the published one, or a local build of the same inputs. */
    public static Future<String> image(String name) {
        Path root = root();
        Definition d = definition(root, name);
        String tag = name + "-" + hash(root, d);
        String mode = System.getProperty("radiusward.test.images", "auto");
        if (!"build".equals(mode)) {
            if (published(tag)) {
                LOG.log(System.Logger.Level.INFO, "test image " + name + ": " + REPOSITORY + ":" + tag);
                return CompletableFuture.completedFuture(REPOSITORY + ":" + tag);
            }
            if ("pull".equals(mode)) {
                throw new IllegalStateException(
                        REPOSITORY + ":" + tag + " is not published (radiusward.test.images=pull)");
            }
        }
        LOG.log(System.Logger.Level.INFO, "test image " + name + ": building " + tag + " locally");
        Path context = root.resolve(d.context());
        ImageFromDockerfile build = new ImageFromDockerfile("radiusward-test-images:" + tag, false);
        try (Stream<Path> files = Files.walk(context)) {
            for (Path f : files.filter(Files::isRegularFile).toList()) {
                build.withFileFromPath(context.relativize(f).toString(), f);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        // a path inside the context: withDockerfile(Path) needs a base directory and fails silently without one
        return build.withDockerfilePath(
                context.relativize(root.resolve(d.dockerfile())).toString().replace('\\', '/'));
    }

    /** Whether the registry has the tag; anonymous, through the registry API (the package is public). */
    static boolean published(String tag) {
        try {
            HttpClient http = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(5))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();
            String repository = REPOSITORY.substring(REPOSITORY.indexOf('/') + 1);
            String body = http.send(
                            HttpRequest.newBuilder(URI.create(
                                            "https://ghcr.io/token?scope=repository:" + repository + ":pull"))
                                    .timeout(Duration.ofSeconds(10))
                                    .build(),
                            HttpResponse.BodyHandlers.ofString())
                    .body();
            Matcher m = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"").matcher(body);
            if (!m.find()) {
                return false;
            }
            int status = http.send(
                            HttpRequest.newBuilder(URI.create("https://ghcr.io/v2/" + repository + "/manifests/" + tag))
                                    .method("HEAD", HttpRequest.BodyPublishers.noBody())
                                    .header("Authorization", "Bearer " + m.group(1))
                                    .header(
                                            "Accept",
                                            "application/vnd.oci.image.index.v1+json,"
                                                    + "application/vnd.docker.distribution.manifest.list.v2+json,"
                                                    + "application/vnd.oci.image.manifest.v1+json")
                                    .timeout(Duration.ofSeconds(10))
                                    .build(),
                            HttpResponse.BodyHandlers.discarding())
                    .statusCode();
            return status == 200;
        } catch (IOException e) {
            return false; // offline: build it here
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    /** The repository root: the nearest directory upwards holding {@code mvnw}. */
    static Path root() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.exists(p.resolve("mvnw"))) {
            p = p.getParent();
        }
        if (p == null) {
            throw new IllegalStateException(
                    "no repository root (mvnw) above " + Path.of("").toAbsolutePath());
        }
        return p;
    }

    static Definition definition(Path root, String name) {
        try {
            for (String line : Files.readAllLines(root.resolve("testing/test-images/images.txt"))) {
                String[] f = line.trim().split("\\s+");
                if (line.isBlank() || line.startsWith("#") || !f[0].equals(name)) {
                    continue;
                }
                // platforms=… only says where the image is published
                List<String> inputs =
                        Stream.of(f).skip(3).filter(i -> !i.contains("=")).toList();
                return new Definition(f[0], f[1], f[2], inputs);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        throw new IllegalArgumentException("unknown test image " + name + " (testing/test-images/images.txt)");
    }

    /**
     * The first 12 hex digits of sha256 over every input file in path order: its repository-relative path, a NUL
     * byte, its content, a NUL byte. Directories count recursively without {@code *.md}, as in scripts/test-images.sh.
     */
    static String hash(Path root, Definition d) {
        TreeSet<String> files = new TreeSet<>();
        for (String input : d.inputs()) {
            Path p = root.resolve(input);
            if (Files.isDirectory(p)) {
                try (Stream<Path> walk = Files.walk(p)) {
                    walk.filter(Files::isRegularFile)
                            .filter(f -> !f.getFileName().toString().endsWith(".md"))
                            .forEach(
                                    f -> files.add(root.relativize(f).toString().replace('\\', '/')));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            } else {
                files.add(input);
            }
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (String f : files) {
                sha.update(f.getBytes(StandardCharsets.UTF_8));
                sha.update((byte) 0);
                sha.update(Files.readAllBytes(root.resolve(f)));
                sha.update((byte) 0);
            }
            return HexFormat.of().formatHex(sha.digest()).substring(0, 12);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The names in images.txt. */
    static List<String> names(Path root) throws IOException {
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(root.resolve("testing/test-images/images.txt"))) {
            if (!line.isBlank() && !line.startsWith("#")) {
                out.add(line.trim().split("\\s+")[0]);
            }
        }
        return out;
    }
}
