/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;

@SuppressWarnings("all")
public final class StateReportDecoder
{
    public static final int BLOCK_LENGTH = 68;
    public static final int TEMPLATE_ID = 7;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final StateReportDecoder parentMessage = this;
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

    public StateReportDecoder wrap(
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

    public StateReportDecoder wrapAndApplyHeader(
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

    public StateReportDecoder sbeRewind()
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

    public long correlationId()
    {
        return buffer.getLong(offset + 0, BYTE_ORDER);
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

    public long applied()
    {
        return buffer.getLong(offset + 8, BYTE_ORDER);
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

    public long duplicates()
    {
        return buffer.getLong(offset + 16, BYTE_ORDER);
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

    public long stale()
    {
        return buffer.getLong(offset + 24, BYTE_ORDER);
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

    public long rejected()
    {
        return buffer.getLong(offset + 32, BYTE_ORDER);
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

    public long activeSessions()
    {
        return buffer.getLong(offset + 40, BYTE_ORDER);
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

    public long stoppedSessions()
    {
        return buffer.getLong(offset + 48, BYTE_ORDER);
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

    public long stateDigest()
    {
        return buffer.getLong(offset + 56, BYTE_ORDER);
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

    public int stateVersion()
    {
        return buffer.getInt(offset + 64, BYTE_ORDER);
    }


    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        final StateReportDecoder decoder = new StateReportDecoder();
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
        builder.append("[StateReport](sbeTemplateId=");
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
        builder.append("correlationId=");
        builder.append(this.correlationId());
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
        builder.append("activeSessions=");
        builder.append(this.activeSessions());
        builder.append('|');
        builder.append("stoppedSessions=");
        builder.append(this.stoppedSessions());
        builder.append('|');
        builder.append("stateDigest=");
        builder.append(this.stateDigest());
        builder.append('|');
        builder.append("stateVersion=");
        builder.append(this.stateVersion());

        limit(originalLimit);

        return builder;
    }
    
    public StateReportDecoder sbeSkip()
    {
        sbeRewind();

        return this;
    }
}
