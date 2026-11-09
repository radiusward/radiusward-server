/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import javax.naming.NamingException;
import org.junit.jupiter.api.Test;

class DomainControllersTest {

    private final long[] now = {1_000};
    private final List<String> asked = new ArrayList<>();
    private List<DomainControllers.Srv> answer = List.of();
    private boolean failing;

    private DomainControllers dns() {
        return new DomainControllers(
                List.of(),
                "corp.example",
                name -> {
                    asked.add(name);
                    if (failing) {
                        throw new NamingException("SERVFAIL");
                    }
                    return answer;
                },
                600_000,
                () -> now[0]);
    }

    @Test
    void srvRecordsOrderedByPriorityThenWeight() {
        answer = List.of(
                new DomainControllers.Srv(10, 50, 389, "dc3.corp.example."),
                new DomainControllers.Srv(0, 10, 389, "dc2.corp.example."),
                new DomainControllers.Srv(0, 100, 389, "dc1.corp.example."),
                new DomainControllers.Srv(0, 100, 389, "dc1.corp.example."),
                new DomainControllers.Srv(0, 0, 0, "."));
        DomainControllers dcs = dns();
        assertThat(dcs.current()).containsExactly("dc1.corp.example", "dc2.corp.example", "dc3.corp.example");
        assertThat(asked).containsExactly("_ldap._tcp.dc._msdcs.corp.example");
    }

    @Test
    void refreshedAfterTheIntervalOrAfterAllFailedAndKeptWhenDnsFails() {
        answer = List.of(new DomainControllers.Srv(0, 0, 389, "dc1.corp.example."));
        DomainControllers dcs = dns();
        dcs.current();
        dcs.current();
        assertThat(asked).hasSize(1);
        now[0] += 600_000;
        failing = true;
        assertThat(dcs.current()).as("a failed lookup keeps the last good list").containsExactly("dc1.corp.example");
        assertThat(asked).hasSize(2);
        failing = false;
        answer = List.of(new DomainControllers.Srv(0, 0, 389, "dc9.corp.example."));
        dcs.failed();
        assertThat(dcs.current()).as("every server failed: asked again").containsExactly("dc9.corp.example");
        answer = List.of();
        dcs.failed();
        assertThat(dcs.current()).as("an empty answer keeps the list").containsExactly("dc9.corp.example");
    }

    @Test
    void aConfiguredListNeedsNoDns() {
        DomainControllers fixed = new DomainControllers(
                List.of("dc1", "dc2"),
                "",
                name -> {
                    throw new AssertionError("no DNS");
                },
                1,
                () -> 0);
        assertThat(fixed.current()).containsExactly("dc1", "dc2");
    }
}
