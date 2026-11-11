/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.testing.images;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The image tags: the same hash as scripts/test-images.sh, so tests pull what the workflow published. */
class TestImagesTest {

    @TempDir
    Path root;

    @Test
    void hashEqualsTheScripts() throws Exception {
        // the same tree as the check in docs/testing/strategy.md: `scripts/test-images.sh tag demo` with
        // TEST_IMAGES_ROOT pointing at it prints demo-d90bcf49de82
        Files.createDirectories(root.resolve("testing/x/sub"));
        Files.createDirectories(root.resolve("testing/test-images"));
        Files.writeString(root.resolve("testing/x/Dockerfile"), "FROM scratch\n");
        Files.writeString(root.resolve("testing/x/sub/b.txt"), "b\n");
        Files.writeString(root.resolve("testing/x/README.md"), "readme"); // not an input
        Files.writeString(
                root.resolve("testing/test-images/images.txt"),
                "# comment\ndemo testing/x testing/x/Dockerfile testing/x platforms=linux/amd64\n");
        TestImages.Definition d = TestImages.definition(root, "demo");
        assertThat(d.context()).isEqualTo("testing/x");
        assertThat(d.inputs()).containsExactly("testing/x");
        assertThat(TestImages.hash(root, d)).isEqualTo("d90bcf49de82");

        Files.writeString(root.resolve("testing/x/README.md"), "changed");
        assertThat(TestImages.hash(root, d))
                .as("documentation does not change the image")
                .isEqualTo("d90bcf49de82");
        Files.writeString(root.resolve("testing/x/sub/b.txt"), "c\n");
        assertThat(TestImages.hash(root, d)).isNotEqualTo("d90bcf49de82");
        assertThatThrownBy(() -> TestImages.definition(root, "nothing")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void everyImageOfTheRepositoryHasItsInputs() throws Exception {
        Path repo = TestImages.root();
        assertThat(TestImages.names(repo))
                .containsExactly(
                        "eapol-test", "radsec-client", "samba-ad", "linux-test-base", "systemd-base", "interop-debs");
        for (String name : TestImages.names(repo)) {
            TestImages.Definition d = TestImages.definition(repo, name);
            assertThat(repo.resolve(d.dockerfile())).as(name + " Dockerfile").isRegularFile();
            assertThat(TestImages.hash(repo, d)).hasSize(12);
        }
    }
}
