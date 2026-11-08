/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The bundled FreeRADIUS set must load in strict mode and contain what the accounting path relies on. */
class BundledDictionaryTest {

    private static Dictionary dictionary;

    @BeforeAll
    static void load() {
        dictionary = DictionaryLoader.loadBundled();
    }

    @Test
    void loadsWithoutWarnings() {
        assertThat(dictionary.warnings()).isEmpty();
        assertThat(dictionary.attributeCount()).isGreaterThan(5000);
        assertThat(dictionary.vendors()).hasSizeGreaterThan(150);
    }

    @Test
    void sourceIsPinnedAndCcBy() throws IOException {
        Properties source = new Properties();
        try (InputStream in = getClass()
                .getClassLoader()
                .getResourceAsStream("io/radiusward/radius/dictionary/freeradius/SOURCE.properties")) {
            assertThat(in).isNotNull();
            source.load(in);
        }
        assertThat(source.getProperty("commit")).matches("[0-9a-f]{40}");
        assertThat(source.getProperty("license")).isEqualTo("CC-BY-4.0");
    }

    @ParameterizedTest
    @CsvSource({
        "Acct-Status-Type, 40, UINT32",
        "Acct-Delay-Time, 41, UINT32",
        "Acct-Input-Octets, 42, UINT32",
        "Acct-Output-Octets, 43, UINT32",
        "Acct-Session-Id, 44, STRING",
        "Acct-Session-Time, 46, UINT32",
        "Acct-Input-Gigawords, 52, UINT32",
        "Acct-Output-Gigawords, 53, UINT32",
        "Event-Timestamp, 55, DATE",
        "NAS-IP-Address, 4, IPV4_ADDR",
        "NAS-Identifier, 32, STRING",
        "Framed-IP-Address, 8, IPV4_ADDR",
        "Acct-Multi-Session-Id, 50, STRING",
        "Message-Authenticator, 80, OCTETS",
    })
    void accountingAttributes(String name, int number, DataType type) {
        AttributeDef def = dictionary.attribute(number);
        assertThat(def).isNotNull();
        assertThat(def.name()).isEqualTo(name);
        assertThat(def.type()).isEqualTo(type);
        assertThat(def.isTopLevel()).isTrue();
        assertThat(dictionary.find(name)).isSameAs(def);
    }

    @ParameterizedTest
    @CsvSource({
        "Cisco, 9, Cisco.AVPair, 1",
        "Juniper, 2636, Juniper.Local-User-Name, 1",
        "Unisphere, 4874, Unisphere.Virtual-Router-Name, 1",
        "Mikrotik, 14988, Mikrotik.Rate-Limit, 8",
        "Huawei, 2011, Huawei.Input-Peak-Rate, 3",
        "Meraki, 29671, Meraki.Device-Name, 1",
        "Ruckus, 25053, Ruckus.SSID, 3",
    })
    void targetVendors(String vendorName, int vendorId, String attribute, int type) {
        VendorDef vendor = dictionary.vendor(vendorName);
        assertThat(vendor).isNotNull();
        assertThat(vendor.id()).isEqualTo(vendorId);
        assertThat(vendor.isStandardFormat()).isTrue();

        AttributeDef def = dictionary.find(attribute);
        assertThat(def).isNotNull();
        assertThat(def.vendorId()).isEqualTo(vendorId);
        assertThat(def.number()).isEqualTo(type);
        assertThat(dictionary.vendorAttribute(vendorId, type)).isSameAs(def);
        assertThat(dictionary.find("Vendor-Specific." + attribute)).isSameAs(def);
    }

    @Test
    void statusTypeValues() {
        AttributeDef status = dictionary.attribute(40);
        assertThat(status.value("Start")).isEqualTo(1L);
        assertThat(status.value("Stop")).isEqualTo(2L);
        assertThat(status.value("Interim-Update")).isEqualTo(3L);
        assertThat(status.value("Accounting-On")).isEqualTo(7L);
        assertThat(status.value("Accounting-Off")).isEqualTo(8L);
        assertThat(status.valueName(3)).isEqualTo("Interim-Update");
    }

    @Test
    void aliasesResolve() {
        assertThat(dictionary.find("Caller-ID")).isSameAs(dictionary.attribute(31));
        assertThat(dictionary.find("cisco.avpair")).isSameAs(dictionary.vendorAttribute(9, 1));
    }

    @Test
    void extendedAttributesAreNested() {
        AttributeDef fragStatus = dictionary.find("Frag-Status");
        assertThat(fragStatus).isNotNull();
        assertThat(fragStatus.oid()).isEqualTo("241.1");
        assertThat(dictionary.attribute(241).type()).isEqualTo(DataType.TLV);
        assertThat(dictionary.attribute(241).child(26).type()).isEqualTo(DataType.VSA);
    }

    @Test
    void numberLookupsDoNotAllocate() {
        // warm up
        for (int i = 0; i < 100_000; i++) {
            dictionary.vendorAttribute(9, 1);
            dictionary.attribute(40);
            dictionary.vendor(14988);
        }
        long before = AllocationMeter.allocatedBytes();
        for (int i = 0; i < 100_000; i++) {
            dictionary.vendorAttribute(9, 1);
            dictionary.attribute(40);
            dictionary.vendor(14988);
        }
        assertThat(AllocationMeter.allocatedBytes() - before).isLessThan(1024);
    }
}
