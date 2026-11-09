/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.verifier.netlogon;

import io.radiusward.auth.StoreContext;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Settings of a Netlogon verifier ({@code auth.verifier.<name>.*}).
 *
 * @param servers domain controllers, tried in order ({@code server}, comma or space separated)
 * @param domain the NetBIOS domain name ({@code domain}), for users given without one
 * @param machineAccount the workstation trust account ({@code machine.account}, e.g. {@code RADIUSWARD$})
 * @param machinePassword its password ({@code machine.password}, e.g. {@code ${env:NETLOGON_MACHINE_PASSWORD}})
 * @param serverName the name the client gives the domain controller in calls ({@code server.name})
 * @param netlogonPort a fixed Netlogon TCP port instead of asking the endpoint mapper ({@code netlogon.port}); 0 = ask
 * @param stripRealm treat {@code user@realm} as {@code user} in {@code domain} ({@code strip.realm})
 */
record NetlogonSettings(
        String name,
        List<String> servers,
        String domain,
        String machineAccount,
        String machinePassword,
        String serverName,
        int endpointMapperPort,
        int netlogonPort,
        boolean stripRealm,
        Duration timeout,
        int connections) {

    String machineName() {
        return machineAccount.endsWith("$") ? machineAccount.substring(0, machineAccount.length() - 1) : machineAccount;
    }

    static NetlogonSettings from(StoreContext context) {
        String prefix = "auth.verifier." + context.name() + ".";
        List<String> servers = Arrays.stream(context.required("server").split("[,\\s]+"))
                .filter(s -> !s.isEmpty())
                .toList();
        String account = context.required("machine.account").trim();
        if (!account.endsWith("$")) {
            throw new IllegalArgumentException(prefix + "machine.account: a computer account ends with $, e.g. "
                    + account.toUpperCase(Locale.ROOT) + "$");
        }
        String domain = context.required("domain").trim().toUpperCase(Locale.ROOT);
        if (domain.contains(".") || domain.length() > 15) {
            throw new IllegalArgumentException(prefix + "domain: the NetBIOS name (e.g. CORP), not the DNS name");
        }
        int connections = Integer.parseInt(context.setting("connections", Integer.toString(context.workers())));
        if (connections < 1) {
            throw new IllegalArgumentException(prefix + "connections: at least 1");
        }
        return new NetlogonSettings(
                context.name(),
                servers,
                domain,
                account,
                context.required("machine.password"),
                context.setting("server.name", servers.get(0)),
                Integer.parseInt(context.setting("endpoint.mapper.port", "135")),
                Integer.parseInt(context.setting("netlogon.port", "0")),
                Boolean.parseBoolean(context.setting("strip.realm", "true")),
                context.duration("timeout", "2s"),
                connections);
    }
}
