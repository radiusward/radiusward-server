/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codegen;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CodeGeneratorTest {

    private static Dictionary dictionary;

    @BeforeAll
    static void load() {
        dictionary = DictionaryLoader.loadBundled();
    }

    private static HotAttributeSpec spec(String... lines) {
        return HotAttributeSpec.parse(List.of(lines), dictionary);
    }

    @Nested
    class Spec {

        @Test
        void parsesFieldsAndVendors() {
            HotAttributeSpec spec = spec(
                    "# comment",
                    "",
                    "constants Juniper",
                    "ietf Acct-Status-Type statusType",
                    "Cisco AVPair ciscoAvPair repeat=8   # trailing comment");
            assertThat(spec.fields()).hasSize(2);
            assertThat(spec.fields().get(1).attribute().vendorId()).isEqualTo(9);
            assertThat(spec.fields().get(1).repeat()).isEqualTo(8);
            assertThat(spec.constantVendors()).extracting(v -> v.name()).containsExactly("Juniper", "Cisco");
        }

        @Test
        void errorsNameTheLine() {
            assertThatThrownBy(() -> spec("ietf Acct-Status-Type statusType", "ietf No-Such-Attribute x"))
                    .hasMessage("hot-attributes line 2: unknown attribute ietf No-Such-Attribute");
            assertThatThrownBy(() -> spec("Nobody Foo foo")).hasMessageContaining("unknown vendor Nobody");
            assertThatThrownBy(() -> spec("constants Nobody")).hasMessageContaining("unknown vendor Nobody");
            assertThatThrownBy(() -> spec("Cisco No-Such ciscoX"))
                    .hasMessageContaining("unknown attribute Cisco No-Such");
        }

        @Test
        void validation() {
            assertThatThrownBy(() -> spec("ietf Frag-Status fragStatus")).hasMessageContaining("not a top-level");
            assertThatThrownBy(() -> spec("ietf User-Name UserName")).hasMessageContaining("lowerCamelCase");
            assertThatThrownBy(() -> spec("ietf User-Name a", "ietf NAS-Port a"))
                    .hasMessageContaining("duplicate field");
            assertThatThrownBy(() -> spec("ietf User-Name a", "ietf User-Name b"))
                    .hasMessageContaining("listed twice");
            assertThatThrownBy(() -> spec("ietf Class c repeat=1")).hasMessageContaining("between 2 and 64");
            assertThatThrownBy(() -> spec("ietf Class c repeat=x")).hasMessageContaining("invalid repeat");
            assertThatThrownBy(() -> spec("ietf Class c every=2")).hasMessageContaining("unknown option");
            assertThatThrownBy(() -> spec("ietf Class")).hasMessageContaining("expected");
        }

        @Test
        void atMost64Fields() {
            String[] lines = new String[65];
            int n = 0;
            for (var attribute : dictionary.root().children()) {
                if (n < 65 && attribute.number() > 0 && attribute.number() < 200 && !attribute.internal()) {
                    lines[n] = "ietf " + attribute.name() + " f" + n;
                    n++;
                }
            }
            assertThatThrownBy(() -> spec(lines)).hasMessageContaining("at most 64");
        }
    }

    @Nested
    class Names {

        @Test
        void constants() {
            assertThat(JavaNames.constant("Acct-Status-Type")).isEqualTo("ACCT_STATUS_TYPE");
            assertThat(JavaNames.constant("3GPP-IMSI")).isEqualTo("_3GPP_IMSI");
            assertThat(JavaNames.constant("--")).isEqualTo("UNNAMED");
            assertThat(JavaNames.constant("Class")).isEqualTo("_CLASS");
            assertThat(JavaNames.fieldConstant("nasIpv6Address")).isEqualTo("NAS_IPV6_ADDRESS");
        }

        @Test
        void types() {
            assertThat(JavaNames.type("Mikrotik")).isEqualTo("Mikrotik");
            assertThat(JavaNames.type("ADSL-Forum")).isEqualTo("AdslForum");
            assertThat(JavaNames.type("3GPP")).isEqualTo("V3gpp");
        }

        @Test
        void unique() {
            JavaNames.Unique unique = new JavaNames.Unique();
            assertThat(unique.next("A")).isEqualTo("A");
            assertThat(unique.next("A")).isEqualTo("A_2");
            assertThat(unique.next("A")).isEqualTo("A_3");
        }
    }

    @Nested
    class Generation {

        private final CodeGenerator generator = new CodeGenerator(
                dictionary,
                spec(
                        "constants Mikrotik",
                        "ietf Acct-Status-Type statusType",
                        "ietf Acct-Session-Id sessionId",
                        "ietf Class classValue repeat=4",
                        "Cisco AVPair ciscoAvPair repeat=8"),
                "test.generated",
                "test dictionaries");

        @Test
        void isDeterministic() {
            assertThat(generator.generate()).isEqualTo(generator.generate());
        }

        @Test
        void producesExpectedFiles() {
            Map<String, String> files = generator.generate();
            assertThat(files)
                    .containsOnlyKeys(
                            "Ietf.java",
                            "Mikrotik.java",
                            "Cisco.java",
                            "AccountingFields.java",
                            "AccountingAttributeExtractor.java");
            assertThat(files.get("Ietf.java"))
                    .contains("public static final int ACCT_STATUS_TYPE = 40;")
                    .contains("public static final long ACCT_STATUS_TYPE_INTERIM_UPDATE = 3L;")
                    .contains("Derived from test dictionaries.");
            assertThat(files.get("Cisco.java")).contains("public static final int VENDOR_ID = 9;");
            assertThat(files.get("AccountingFields.java"))
                    .contains("public static final int STATUS_TYPE = 0;")
                    .contains("final int[] ciscoAvPairOffsets = new int[8];");
            assertThat(files.get("AccountingAttributeExtractor.java"))
                    .contains("case 9 -> vendor9(out);")
                    .contains("case 40 ->");
        }

        @Test
        void canonicalValueNameComesFirst() {
            String ietf = generator.generate().get("Ietf.java");
            assertThat(ietf.indexOf("ACCT_STATUS_TYPE_INTERIM_UPDATE = 3L"))
                    .isLessThan(ietf.indexOf("ACCT_STATUS_TYPE_ALIVE = 3L"));
        }

        @Test
        void constantsClassesCompile() {
            Map<String, String> files = generator.generate();
            JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
            List<JavaFileObject> units = files.entrySet().stream()
                    .filter(f -> !f.getKey().startsWith("Accounting"))
                    .map(f -> source(f.getKey(), f.getValue()))
                    .toList();
            Boolean ok = compiler.getTask(null, null, null, List.of("-d", tempClasses()), null, units)
                    .call();
            assertThat(ok).isTrue();
        }

        @Test
        void writesOnlyChangedFiles(@TempDir Path out) throws IOException {
            assertThat(generator.writeTo(out)).isEqualTo(5);
            assertThat(generator.writeTo(out)).isZero();
            Path ietf = out.resolve("test/generated/Ietf.java");
            Files.writeString(ietf, "stale");
            assertThat(generator.writeTo(out)).isEqualTo(1);
        }

        private static JavaFileObject source(String name, String content) {
            return new SimpleJavaFileObject(URI.create("string:///" + name), JavaFileObject.Kind.SOURCE) {
                @Override
                public CharSequence getCharContent(boolean ignoreEncodingErrors) {
                    return content;
                }
            };
        }

        private static String tempClasses() {
            try {
                return Files.createTempDirectory("codegen-classes").toString();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    @Test
    void mainEndToEnd(@TempDir Path dir) throws IOException {
        Path spec = Files.writeString(dir.resolve("spec.txt"), "ietf Acct-Status-Type statusType\n");
        Path extra = Files.createDirectories(dir.resolve("dictionary.d"));
        Files.writeString(extra.resolve("dictionary.local"), "ATTRIBUTE Local-Thing 3000 string\n");
        CodeGenerator.main(new String[] {
            "--spec", spec.toString(),
            "--output", dir.resolve("out").toString(),
            "--package", "x.y",
            "--dictionary-dir", extra.toString()
        });
        assertThat(dir.resolve("out/x/y/AccountingFields.java")).exists();
        assertThat(Files.readString(dir.resolve("out/x/y/Ietf.java"))).contains("commit ");
        assertThatThrownBy(() -> CodeGenerator.main(new String[] {"--spec"})).hasMessageContaining("needs a value");
        assertThatThrownBy(() -> CodeGenerator.main(new String[] {"--bogus", "x"}))
                .hasMessageContaining("unknown argument");
        assertThatThrownBy(() -> CodeGenerator.main(new String[0])).hasMessageContaining("usage");
    }
}
