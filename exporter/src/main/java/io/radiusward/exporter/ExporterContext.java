/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.exporter;

import io.radiusward.cluster.service.AccountingStateMachine;
import java.io.File;
import java.nio.file.Path;

/**
 * Where the exporter of one member finds what it needs.
 *
 * @param ingressEndpoints the cluster's client endpoints, for checkpoints and leases
 * @param egressHost an address of this member the cluster can answer to
 * @param archiveControlChannel the member archive's local control channel
 * @param serviceSettings the state machine settings of the cluster (the replica must decide identically)
 * @param pluginsDir directory with sink plug-in jars, or {@code null}
 * @param dictionaryDir operator dictionaries loaded after the bundled set, or {@code null}
 */
public record ExporterContext(
        int memberId,
        String aeronDir,
        File clusterDir,
        String ingressEndpoints,
        String egressHost,
        String archiveControlChannel,
        AccountingStateMachine.Settings serviceSettings,
        Path pluginsDir,
        Path dictionaryDir) {}
