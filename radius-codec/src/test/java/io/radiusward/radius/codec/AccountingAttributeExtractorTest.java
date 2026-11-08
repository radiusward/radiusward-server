/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static io.radiusward.radius.codec.Packets.wrap;
import static org.assertj.core.api.Assertions.assertThat;

import io.radiusward.radius.codec.attributes.AccountingAttributeExtractor;
import io.radiusward.radius.codec.attributes.AccountingFields;
import io.radiusward.radius.codec.attributes.Cisco;
import io.radiusward.radius.codec.attributes.Ietf;
import java.util.Arrays;
import org.agrona.concurrent.UnsafeBuffer;
import org.junit.jupiter.api.Test;

class AccountingAttributeExtractorTest {

    private final AccountingAttributeExtractor extractor = new AccountingAttributeExtractor(VendorFormats.ALL_STANDARD);
    private final AccountingFields fields = new AccountingFields();
    private final UnsafeBuffer buffer = new UnsafeBuffer(new byte[RadiusPacket.MAX_LENGTH]);
    private final RadiusPacketEncoder encoder = new RadiusPacketEncoder();

    private RadiusPacket finish() {
        int length = encoder.finish();
        return wrap(Arrays.copyOf(buffer.byteArray(), length));
    }

    @Test
    void extractsScalarsBytesAndVendorAttributes() {
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, 1)
                .uint32(Ietf.ACCT_STATUS_TYPE, Ietf.ACCT_STATUS_TYPE_INTERIM_UPDATE)
                .attribute(Ietf.ACCT_SESSION_ID, "s-1")
                .uint32(Ietf.ACCT_INPUT_OCTETS, 10)
                .uint32(Ietf.ACCT_INPUT_GIGAWORDS, 2)
                .ipv4(Ietf.NAS_IP_ADDRESS, 0x0A000001L)
                .vendorAttribute(Cisco.VENDOR_ID, Cisco.AVPAIR, "a=1")
                .vendorAttribute(Cisco.VENDOR_ID, Cisco.AVPAIR, "b=2");
        AccountingFields out = extractor.extract(finish(), fields);

        assertThat(out).isSameAs(fields);
        assertThat(out.has(AccountingFields.STATUS_TYPE)).isTrue();
        assertThat(out.statusType()).isEqualTo(Ietf.ACCT_STATUS_TYPE_INTERIM_UPDATE);
        assertThat(AttributeValues.string(out.buffer(), out.sessionIdOffset(), out.sessionIdLength()))
                .isEqualTo("s-1");
        assertThat(AttributeValues.octets64(out.inputOctets(), out.inputGigawords()))
                .isEqualTo((2L << 32) + 10);
        assertThat(AttributeValues.ipv4String(out.nasIpAddress())).isEqualTo("10.0.0.1");
        assertThat(out.ciscoAvPairCount()).isEqualTo(2);
        assertThat(AttributeValues.string(out.buffer(), out.ciscoAvPairOffset(1), out.ciscoAvPairLength(1)))
                .isEqualTo("b=2");
        assertThat(out.has(AccountingFields.EVENT_TIMESTAMP)).isFalse();
        assertThat(Long.bitCount(out.presentMask())).isEqualTo(6);
        assertThat(out.malformedCount()).isZero();
        assertThat(out.droppedCount()).isZero();
    }

    @Test
    void malformedAndDuplicateValuesAreCounted() {
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, 1)
                .attribute(Ietf.ACCT_STATUS_TYPE, new byte[] {1, 2}) // wrong length
                .uint32(Ietf.ACCT_SESSION_TIME, 5)
                .uint32(Ietf.ACCT_SESSION_TIME, 6) // second occurrence ignored
                .attribute(Ietf.USER_NAME, "x");
        AccountingFields out = extractor.extract(finish(), fields);
        assertThat(out.has(AccountingFields.STATUS_TYPE)).isFalse();
        assertThat(out.sessionTime()).isEqualTo(5);
        assertThat(out.malformedCount()).isEqualTo(1);
        assertThat(out.droppedCount()).isEqualTo(1);
    }

    @Test
    void repeatLimitAndReuse() {
        encoder.wrap(buffer, 0).header(RadiusCode.ACCOUNTING_REQUEST, 1);
        for (int i = 0; i < 20; i++) {
            encoder.vendorAttribute(Cisco.VENDOR_ID, Cisco.AVPAIR, "k=" + i);
        }
        AccountingFields out = extractor.extract(finish(), fields);
        assertThat(out.ciscoAvPairCount()).isEqualTo(16);
        assertThat(out.droppedCount()).isEqualTo(4);

        encoder.wrap(buffer, 0).header(RadiusCode.ACCOUNTING_REQUEST, 2).uint32(Ietf.ACCT_STATUS_TYPE, 2);
        extractor.extract(finish(), fields);
        assertThat(fields.ciscoAvPairCount()).isZero();
        assertThat(fields.droppedCount()).isZero();
        assertThat(fields.statusType()).isEqualTo(2);
    }

    @Test
    void unknownVendorsAndTypesAreIgnored() {
        encoder.wrap(buffer, 0)
                .header(RadiusCode.ACCOUNTING_REQUEST, 1)
                .vendorAttribute(99999, 1, "x")
                .vendorAttribute(Cisco.VENDOR_ID, 250, "y")
                .attribute(200, "z");
        AccountingFields out = extractor.extract(finish(), fields);
        assertThat(out.presentMask()).isZero();
    }
}
