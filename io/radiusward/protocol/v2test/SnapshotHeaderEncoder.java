/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;

@SuppressWarnings("all")
public final class SnapshotHeaderEncoder
{
    public static final int BLOCK_LENGTH = 61;
    public static final int TEMPLATE_ID = 20;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SnapshotHeaderEncoder parentMessage = this;
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

    public SnapshotHeaderEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public SnapshotHeaderEncoder wrapAndApplyHeader(
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

    public static int stateVersionId()
    {
        return 1;
    }

    public static int stateVersionSinceVersion()
    {
        return 0;
    }

    public static int stateVersionEncodingOffset()
    {
        return 0;
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

    public SnapshotHeaderEncoder stateVersion(final int value)
    {
        buffer.putInt(offset + 0, value, BYTE_ORDER);
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
        return 4;
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

    public SnapshotHeaderEncoder applied(final long value)
    {
        buffer.putLong(offset + 4, value, BYTE_ORDER);
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
        return 12;
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

    public SnapshotHeaderEncoder duplicates(final long value)
    {
        buffer.putLong(offset + 12, value, BYTE_ORDER);
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
        return 20;
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

    public SnapshotHeaderEncoder stale(final long value)
    {
        buffer.putLong(offset + 20, value, BYTE_ORDER);
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
        return 28;
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

    public SnapshotHeaderEncoder rejected(final long value)
    {
        buffer.putLong(offset + 28, value, BYTE_ORDER);
        return this;
    }


    public static int stateDigestId()
    {
        return 6;
    }

    public static int stateDigestSinceVersion()
    {
        return 0;
    }

    public static int stateDigestEncodingOffset()
    {
        return 36;
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

    public SnapshotHeaderEncoder stateDigest(final long value)
    {
        buffer.putLong(offset + 36, value, BYTE_ORDER);
        return this;
    }


    public static int sessionCountId()
    {
        return 7;
    }

    public static int sessionCountSinceVersion()
    {
        return 0;
    }

    public static int sessionCountEncodingOffset()
    {
        return 44;
    }

    public static int sessionCountEncodingLength()
    {
        return 8;
    }

    public static String sessionCountMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long sessionCountNullValue()
    {
        return -9223372036854775808L;
    }

    public static long sessionCountMinValue()
    {
        return -9223372036854775807L;
    }

    public static long sessionCountMaxValue()
    {
        return 9223372036854775807L;
    }

    public SnapshotHeaderEncoder sessionCount(final long value)
    {
        buffer.putLong(offset + 44, value, BYTE_ORDER);
        return this;
    }


    public static int exactKeyCountId()
    {
        return 8;
    }

    public static int exactKeyCountSinceVersion()
    {
        return 0;
    }

    public static int exactKeyCountEncodingOffset()
    {
        return 52;
    }

    public static int exactKeyCountEncodingLength()
    {
        return 8;
    }

    public static String exactKeyCountMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long exactKeyCountNullValue()
    {
        return -9223372036854775808L;
    }

    public static long exactKeyCountMinValue()
    {
        return -9223372036854775807L;
    }

    public static long exactKeyCountMaxValue()
    {
        return 9223372036854775807L;
    }

    public SnapshotHeaderEncoder exactKeyCount(final long value)
    {
        buffer.putLong(offset + 52, value, BYTE_ORDER);
        return this;
    }


    public static int timerScheduledId()
    {
        return 9;
    }

    public static int timerScheduledSinceVersion()
    {
        return 0;
    }

    public static int timerScheduledEncodingOffset()
    {
        return 60;
    }

    public static int timerScheduledEncodingLength()
    {
        return 1;
    }

    public static String timerScheduledMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static short timerScheduledNullValue()
    {
        return (short)255;
    }

    public static short timerScheduledMinValue()
    {
        return (short)0;
    }

    public static short timerScheduledMaxValue()
    {
        return (short)254;
    }

    public SnapshotHeaderEncoder timerScheduled(final short value)
    {
        buffer.putByte(offset + 60, (byte)value);
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

        final SnapshotHeaderDecoder decoder = new SnapshotHeaderDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
