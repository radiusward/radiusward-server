/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;

@SuppressWarnings("all")
public final class SnapshotHeaderDecoder
{
    public static final int BLOCK_LENGTH = 61;
    public static final int TEMPLATE_ID = 20;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SnapshotHeaderDecoder parentMessage = this;
    private DirectBuffer buffer;
    private int offset;
    private int limit;
    int actingBlockLength;
    int actingVersion;

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

    public DirectBuffer buffer()
    {
        return buffer;
    }

    public int offset()
    {
        return offset;
    }

    public SnapshotHeaderDecoder wrap(
        final DirectBuffer buffer,
        final int offset,
        final int actingBlockLength,
        final int actingVersion)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        this.actingBlockLength = actingBlockLength;
        this.actingVersion = actingVersion;
        limit(offset + actingBlockLength);

        return this;
    }

    public SnapshotHeaderDecoder wrapAndApplyHeader(
        final DirectBuffer buffer,
        final int offset,
        final MessageHeaderDecoder headerDecoder)
    {
        headerDecoder.wrap(buffer, offset);

        final int templateId = headerDecoder.templateId();
        if (TEMPLATE_ID != templateId)
        {
            throw new IllegalStateException("Invalid TEMPLATE_ID: " + templateId);
        }

        return wrap(
            buffer,
            offset + MessageHeaderDecoder.ENCODED_LENGTH,
            headerDecoder.blockLength(),
            headerDecoder.version());
    }

    public SnapshotHeaderDecoder sbeRewind()
    {
        return wrap(buffer, offset, actingBlockLength, actingVersion);
    }

    public int sbeDecodedLength()
    {
        final int currentLimit = limit();
        sbeSkip();
        final int decodedLength = encodedLength();
        limit(currentLimit);

        return decodedLength;
    }

    public int actingVersion()
    {
        return actingVersion;
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

    public int stateVersion()
    {
        return buffer.getInt(offset + 0, BYTE_ORDER);
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

    public long applied()
    {
        return buffer.getLong(offset + 4, BYTE_ORDER);
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

    public long duplicates()
    {
        return buffer.getLong(offset + 12, BYTE_ORDER);
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

    public long stale()
    {
        return buffer.getLong(offset + 20, BYTE_ORDER);
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

    public long rejected()
    {
        return buffer.getLong(offset + 28, BYTE_ORDER);
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

    public long stateDigest()
    {
        return buffer.getLong(offset + 36, BYTE_ORDER);
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

    public long sessionCount()
    {
        return buffer.getLong(offset + 44, BYTE_ORDER);
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

    public long exactKeyCount()
    {
        return buffer.getLong(offset + 52, BYTE_ORDER);
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

    public short timerScheduled()
    {
        return ((short)(buffer.getByte(offset + 60) & 0xFF));
    }


    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        final SnapshotHeaderDecoder decoder = new SnapshotHeaderDecoder();
        decoder.wrap(buffer, offset, actingBlockLength, actingVersion);

        return decoder.appendTo(new StringBuilder()).toString();
    }

    public StringBuilder appendTo(final StringBuilder builder)
    {
        if (null == buffer)
        {
            return builder;
        }

        final int originalLimit = limit();
        limit(offset + actingBlockLength);
        builder.append("[SnapshotHeader](sbeTemplateId=");
        builder.append(TEMPLATE_ID);
        builder.append("|sbeSchemaId=");
        builder.append(SCHEMA_ID);
        builder.append("|sbeSchemaVersion=");
        if (parentMessage.actingVersion != SCHEMA_VERSION)
        {
            builder.append(parentMessage.actingVersion);
            builder.append('/');
        }
        builder.append(SCHEMA_VERSION);
        builder.append("|sbeBlockLength=");
        if (actingBlockLength != BLOCK_LENGTH)
        {
            builder.append(actingBlockLength);
            builder.append('/');
        }
        builder.append(BLOCK_LENGTH);
        builder.append("):");
        builder.append("stateVersion=");
        builder.append(this.stateVersion());
        builder.append('|');
        builder.append("applied=");
        builder.append(this.applied());
        builder.append('|');
        builder.append("duplicates=");
        builder.append(this.duplicates());
        builder.append('|');
        builder.append("stale=");
        builder.append(this.stale());
        builder.append('|');
        builder.append("rejected=");
        builder.append(this.rejected());
        builder.append('|');
        builder.append("stateDigest=");
        builder.append(this.stateDigest());
        builder.append('|');
        builder.append("sessionCount=");
        builder.append(this.sessionCount());
        builder.append('|');
        builder.append("exactKeyCount=");
        builder.append(this.exactKeyCount());
        builder.append('|');
        builder.append("timerScheduled=");
        builder.append(this.timerScheduled());

        limit(originalLimit);

        return builder;
    }
    
    public SnapshotHeaderDecoder sbeSkip()
    {
        sbeRewind();

        return this;
    }
}
