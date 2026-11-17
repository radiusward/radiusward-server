/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;

@SuppressWarnings("all")
public final class SnapshotFooterEncoder
{
    public static final int BLOCK_LENGTH = 16;
    public static final int TEMPLATE_ID = 23;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SnapshotFooterEncoder parentMessage = this;
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

    public SnapshotFooterEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public SnapshotFooterEncoder wrapAndApplyHeader(
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

    public static int sessionCountId()
    {
        return 1;
    }

    public static int sessionCountSinceVersion()
    {
        return 0;
    }

    public static int sessionCountEncodingOffset()
    {
        return 0;
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

    public SnapshotFooterEncoder sessionCount(final long value)
    {
        buffer.putLong(offset + 0, value, BYTE_ORDER);
        return this;
    }


    public static int exactKeyCountId()
    {
        return 2;
    }

    public static int exactKeyCountSinceVersion()
    {
        return 0;
    }

    public static int exactKeyCountEncodingOffset()
    {
        return 8;
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

    public SnapshotFooterEncoder exactKeyCount(final long value)
    {
        buffer.putLong(offset + 8, value, BYTE_ORDER);
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

        final SnapshotFooterDecoder decoder = new SnapshotFooterDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
