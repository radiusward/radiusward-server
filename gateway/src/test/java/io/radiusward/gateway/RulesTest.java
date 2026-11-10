/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.radiusward.auth.AttributeItem;
import io.radiusward.radius.dictionary.Dictionary;
import io.radiusward.radius.dictionary.DictionaryLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RulesTest {

    static final Dictionary DICTIONARY = DictionaryLoader.loadBundled();

    static Rules parse(String text) {
        return Rules.parse(text, name -> DICTIONARY.find(name) != null);
    }

    static Rules.Request request(Map<String, String> values, Set<String> groups) {
        return new Rules.Request() {
            @Override
            public String value(String attribute) {
                return values.get(attribute);
            }

            @Override
            public boolean inGroup(String group) {
                return groups.contains(group);
            }
        };
    }

    static List<AttributeItem> reply(AttributeItem... items) {
        return new ArrayList<>(List.of(items));
    }

    static final String RULES = """
            # guests on Wi-Fi
            if NAS-Port-Type == Wireless-802.11 && Group == guests {
                reply Session-Timeout := 3600
                reply Filter-Id = "guest-%{Called-Station-Id}"   # only if not set
                reply Reply-Message += "welcome"
                remove Framed-IP-Address
                stop
            }
            if User-Name =~ "^test-" && NAS-Identifier absent {
                reject
            }
            if NAS-Port >= 100 && Group != staff {
                reply Class := "high-port"
            }
            if Calling-Station-Id present && Calling-Station-Id !~ "^aa" && User-Name != bob {
                reply Idle-Timeout := 60
            }
            """;

    @Test
    void conditionsAndActions() {
        Rules rules = parse(RULES);
        assertThat(rules.rules()).hasSize(4);

        List<AttributeItem> guest = reply(
                new AttributeItem("Session-Timeout", "=", "86400"),
                new AttributeItem("Framed-IP-Address", "=", "10.0.0.1"));
        assertThat(rules.apply(
                        request(
                                Map.of(
                                        "NAS-Port-Type", "Wireless-802.11",
                                        "Called-Station-Id", "ap1",
                                        "NAS-Port", "200"),
                                Set.of("guests")),
                        guest))
                .isTrue();
        assertThat(guest)
                .containsExactly(
                        new AttributeItem("Session-Timeout", "=", "3600"),
                        new AttributeItem("Filter-Id", "=", "guest-ap1"),
                        new AttributeItem("Reply-Message", "+=", "welcome"));

        List<AttributeItem> tester = reply();
        assertThat(rules.apply(request(Map.of("User-Name", "test-1"), Set.of()), tester))
                .isFalse();
        assertThat(rules.apply(request(Map.of("User-Name", "test-1", "NAS-Identifier", "x"), Set.of()), tester))
                .isTrue();
        assertThat(tester).isEmpty();

        List<AttributeItem> high = reply(new AttributeItem("Filter-Id", "=", "own"));
        rules.apply(
                request(Map.of("NAS-Port", "150", "Calling-Station-Id", "bb-cc", "User-Name", "carol"), Set.of()),
                high);
        assertThat(high)
                .containsExactly(
                        new AttributeItem("Filter-Id", "=", "own"),
                        new AttributeItem("Class", "=", "high-port"),
                        new AttributeItem("Idle-Timeout", "=", "60"));
        List<AttributeItem> staff = reply();
        rules.apply(request(Map.of("NAS-Port", "150", "Calling-Station-Id", "aa-1"), Set.of("staff")), staff);
        assertThat(staff).isEmpty();
        List<AttributeItem> notANumber = reply();
        rules.apply(request(Map.of("NAS-Port", "x"), Set.of()), notANumber);
        assertThat(notANumber).isEmpty();
    }

    @Test
    void parseErrorsNameTheLine() {
        for (String[] bad : new String[][] {
            {"reply Class := x", "line 1: expected: if"},
            {"if User-Name == a {\n}", "line 2: a rule without actions"},
            {"if User-Name == a {\n reject", "line 1: the rule is not closed"},
            {"if Bogus-Attribute == a {\n reject\n}", "unknown attribute Bogus-Attribute"},
            {"if User-Name ~= a {\n reject\n}", "expected: <attribute> <operator> <value>"},
            {"if User-Name == a || User-Name == b {\n reject\n}", "joined with &&"},
            {"if User-Name =~ \"(\" {\n reject\n}", "invalid pattern"},
            {"if Group =~ x {\n reject\n}", "Group takes == or !="},
            {"if User-Name == a {\n reject now\n}", "reject takes nothing"},
            {"if User-Name == a {\n remove\n}", "expected: remove <attribute>"},
            {"if User-Name == a {\n reply Class -= x\n}", "expected: reply"},
            {"if User-Name == a {\n drop\n}", "unknown action drop"},
            {"if User-Name == \"a {\n reject\n}", "unterminated string"},
            {"if User-Name {\n reject\n}", "expected: <attribute>"}
        }) {
            assertThatThrownBy(() -> parse(bad[0])).as(bad[0]).hasMessageContaining(bad[1]);
        }
        assertThat(parse("# nothing\n\n").rules()).isEmpty();
        assertThat(parse("if User-Name == \"a \\\"b\\\"\" {\n stop\n}")
                        .rules()
                        .get(0)
                        .conditions()
                        .get(0)
                        .value())
                .isEqualTo("a \"b\"");
    }

    @Test
    void theFileIsReloadedWhenItChanges(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("rules");
        Files.writeString(file, "if User-Name == a {\n reject\n}\n");
        long[] now = {0};
        RulesFile rules =
                new RulesFile(file, Duration.ofSeconds(5), name -> DICTIONARY.find(name) != null, () -> now[0]);
        assertThat(rules.current().rules()).hasSize(1);

        Files.writeString(file, "if User-Name == a {\n reject\n}\nif User-Name == b {\n reject\n}\n");
        Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 10_000));
        assertThat(rules.current().rules()).as("not yet checked").hasSize(1);
        now[0] = 5_000;
        assertThat(rules.current().rules()).hasSize(2);

        Files.writeString(file, "if broken");
        Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() + 20_000));
        now[0] = 10_000;
        assertThat(rules.current().rules()).as("the previous rules stay").hasSize(2);

        Files.writeString(file, "nonsense");
        assertThatThrownBy(() -> new RulesFile(file, Duration.ZERO, n -> true, () -> 0))
                .isInstanceOf(io.radiusward.common.config.ConfigException.class)
                .hasMessageContaining("line 1");
        assertThat(RulesFile.from(io.radiusward.common.config.Config.of(Map.of()), n -> true))
                .isNull();
    }
}
