/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;

@SuppressWarnings("all")
public final class StateReportEncoder
{
    public static final int BLOCK_LENGTH = 68;
    public static final int TEMPLATE_ID = 7;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final StateReportEncoder parentMessage = this;
    private MutableDirectBuffer buffer;
    private int offset;
    private int limit;

    public int sbeBlockLength()
    {
        return BLOCK_LENGTH;
    }

    public int sbeTemplateId()
    {
        return TEMPLATE_ID;
    }

    public int sbeSchemaId()
    {
        return SCHEMA_ID;
    }

    public int sbeSchemaVersion()
    {
        return SCHEMA_VERSION;
    }

    public String sbeSemanticType()
    {
        return "";
    }

    public MutableDirectBuffer buffer()
    {
        return buffer;
    }

    public int offset()
    {
        return offset;
    }

    public StateReportEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public StateReportEncoder wrapAndApplyHeader(
        final MutableDirectBuffer buffer, final int offset, final MessageHeaderEncoder headerEncoder)
    {
        headerEncoder
            .wrap(buffer, offset)
            .blockLength(BLOCK_LENGTH)
            .templateId(TEMPLATE_ID)
            .schemaId(SCHEMA_ID)
            .version(SCHEMA_VERSION);

        return wrap(buffer, offset + MessageHeaderEncoder.ENCODED_LENGTH);
    }

    public int encodedLength()
    {
        return limit - offset;
    }

    public int limit()
    {
        return limit;
    }

    public void limit(final int limit)
    {
        this.limit = limit;
    }

    public static int correlationIdId()
    {
        return 1;
    }

    public static int correlationIdSinceVersion()
    {
        return 0;
    }

    public static int correlationIdEncodingOffset()
    {
        return 0;
    }

    public static int correlationIdEncodingLength()
    {
        return 8;
    }

    public static String correlationIdMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long correlationIdNullValue()
    {
        return -9223372036854775808L;
    }

    public static long correlationIdMinValue()
    {
        return -9223372036854775807L;
    }

    public static long correlationIdMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder correlationId(final long value)
    {
        buffer.putLong(offset + 0, value, BYTE_ORDER);
        return this;
    }


    public static int appliedId()
    {
        return 2;
    }

    public static int appliedSinceVersion()
    {
        return 0;
    }

    public static int appliedEncodingOffset()
    {
        return 8;
    }

    public static int appliedEncodingLength()
    {
        return 8;
    }

    public static String appliedMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long appliedNullValue()
    {
        return -9223372036854775808L;
    }

    public static long appliedMinValue()
    {
        return -9223372036854775807L;
    }

    public static long appliedMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder applied(final long value)
    {
        buffer.putLong(offset + 8, value, BYTE_ORDER);
        return this;
    }


    public static int duplicatesId()
    {
        return 3;
    }

    public static int duplicatesSinceVersion()
    {
        return 0;
    }

    public static int duplicatesEncodingOffset()
    {
        return 16;
    }

    public static int duplicatesEncodingLength()
    {
        return 8;
    }

    public static String duplicatesMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long duplicatesNullValue()
    {
        return -9223372036854775808L;
    }

    public static long duplicatesMinValue()
    {
        return -9223372036854775807L;
    }

    public static long duplicatesMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder duplicates(final long value)
    {
        buffer.putLong(offset + 16, value, BYTE_ORDER);
        return this;
    }


    public static int staleId()
    {
        return 4;
    }

    public static int staleSinceVersion()
    {
        return 0;
    }

    public static int staleEncodingOffset()
    {
        return 24;
    }

    public static int staleEncodingLength()
    {
        return 8;
    }

    public static String staleMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long staleNullValue()
    {
        return -9223372036854775808L;
    }

    public static long staleMinValue()
    {
        return -9223372036854775807L;
    }

    public static long staleMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder stale(final long value)
    {
        buffer.putLong(offset + 24, value, BYTE_ORDER);
        return this;
    }


    public static int rejectedId()
    {
        return 5;
    }

    public static int rejectedSinceVersion()
    {
        return 0;
    }

    public static int rejectedEncodingOffset()
    {
        return 32;
    }

    public static int rejectedEncodingLength()
    {
        return 8;
    }

    public static String rejectedMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long rejectedNullValue()
    {
        return -9223372036854775808L;
    }

    public static long rejectedMinValue()
    {
        return -9223372036854775807L;
    }

    public static long rejectedMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder rejected(final long value)
    {
        buffer.putLong(offset + 32, value, BYTE_ORDER);
        return this;
    }


    public static int activeSessionsId()
    {
        return 6;
    }

    public static int activeSessionsSinceVersion()
    {
        return 0;
    }

    public static int activeSessionsEncodingOffset()
    {
        return 40;
    }

    public static int activeSessionsEncodingLength()
    {
        return 8;
    }

    public static String activeSessionsMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long activeSessionsNullValue()
    {
        return -9223372036854775808L;
    }

    public static long activeSessionsMinValue()
    {
        return -9223372036854775807L;
    }

    public static long activeSessionsMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder activeSessions(final long value)
    {
        buffer.putLong(offset + 40, value, BYTE_ORDER);
        return this;
    }


    public static int stoppedSessionsId()
    {
        return 7;
    }

    public static int stoppedSessionsSinceVersion()
    {
        return 0;
    }

    public static int stoppedSessionsEncodingOffset()
    {
        return 48;
    }

    public static int stoppedSessionsEncodingLength()
    {
        return 8;
    }

    public static String stoppedSessionsMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long stoppedSessionsNullValue()
    {
        return -9223372036854775808L;
    }

    public static long stoppedSessionsMinValue()
    {
        return -9223372036854775807L;
    }

    public static long stoppedSessionsMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder stoppedSessions(final long value)
    {
        buffer.putLong(offset + 48, value, BYTE_ORDER);
        return this;
    }


    public static int stateDigestId()
    {
        return 8;
    }

    public static int stateDigestSinceVersion()
    {
        return 0;
    }

    public static int stateDigestEncodingOffset()
    {
        return 56;
    }

    public static int stateDigestEncodingLength()
    {
        return 8;
    }

    public static String stateDigestMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long stateDigestNullValue()
    {
        return -9223372036854775808L;
    }

    public static long stateDigestMinValue()
    {
        return -9223372036854775807L;
    }

    public static long stateDigestMaxValue()
    {
        return 9223372036854775807L;
    }

    public StateReportEncoder stateDigest(final long value)
    {
        buffer.putLong(offset + 56, value, BYTE_ORDER);
        return this;
    }


    public static int stateVersionId()
    {
        return 9;
    }

    public static int stateVersionSinceVersion()
    {
        return 0;
    }

    public static int stateVersionEncodingOffset()
    {
        return 64;
    }

    public static int stateVersionEncodingLength()
    {
        return 4;
    }

    public static String stateVersionMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static int stateVersionNullValue()
    {
        return -2147483648;
    }

    public static int stateVersionMinValue()
    {
        return -2147483647;
    }

    public static int stateVersionMaxValue()
    {
        return 2147483647;
    }

    public StateReportEncoder stateVersion(final int value)
    {
        buffer.putInt(offset + 64, value, BYTE_ORDER);
        return this;
    }


    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        return appendTo(new StringBuilder()).toString();
    }

    public StringBuilder appendTo(final StringBuilder builder)
    {
        if (null == buffer)
        {
            return builder;
        }

        final StateReportDecoder decoder = new StateReportDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
