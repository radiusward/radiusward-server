/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;

@SuppressWarnings("all")
public final class SessionReportDecoder
{
    public static final int BLOCK_LENGTH = 41;
    public static final int TEMPLATE_ID = 5;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SessionReportDecoder parentMessage = this;
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

    public SessionReportDecoder wrap(
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

    public SessionReportDecoder wrapAndApplyHeader(
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

    public SessionReportDecoder sbeRewind()
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


    public static int statusId()
    {
        return 2;
    }

    public static int statusSinceVersion()
    {
        return 0;
    }

    public static int statusEncodingOffset()
    {
        return 8;
    }

    public static int statusEncodingLength()
    {
        return 1;
    }

    public static String statusMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public short statusRaw()
    {
        return ((short)(buffer.getByte(offset + 8) & 0xFF));
    }

    public SessionStatus status()
    {
        return SessionStatus.get(((short)(buffer.getByte(offset + 8) & 0xFF)));
    }


    public static int nasIdId()
    {
        return 3;
    }

    public static int nasIdSinceVersion()
    {
        return 0;
    }

    public static int nasIdEncodingOffset()
    {
        return 9;
    }

    public static int nasIdEncodingLength()
    {
        return 4;
    }

    public static String nasIdMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static int nasIdNullValue()
    {
        return -2147483648;
    }

    public static int nasIdMinValue()
    {
        return -2147483647;
    }

    public static int nasIdMaxValue()
    {
        return 2147483647;
    }

    public int nasId()
    {
        return buffer.getInt(offset + 9, BYTE_ORDER);
    }


    public static int statusTypeId()
    {
        return 4;
    }

    public static int statusTypeSinceVersion()
    {
        return 0;
    }

    public static int statusTypeEncodingOffset()
    {
        return 13;
    }

    public static int statusTypeEncodingLength()
    {
        return 4;
    }

    public static String statusTypeMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long statusTypeNullValue()
    {
        return 4294967295L;
    }

    public static long statusTypeMinValue()
    {
        return 0L;
    }

    public static long statusTypeMaxValue()
    {
        return 4294967294L;
    }

    public long statusType()
    {
        return (buffer.getInt(offset + 13, BYTE_ORDER) & 0xFFFF_FFFFL);
    }


    public static int sessionTimeId()
    {
        return 5;
    }

    public static int sessionTimeSinceVersion()
    {
        return 0;
    }

    public static int sessionTimeEncodingOffset()
    {
        return 17;
    }

    public static int sessionTimeEncodingLength()
    {
        return 4;
    }

    public static String sessionTimeMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long sessionTimeNullValue()
    {
        return 4294967295L;
    }

    public static long sessionTimeMinValue()
    {
        return 0L;
    }

    public static long sessionTimeMaxValue()
    {
        return 4294967294L;
    }

    public long sessionTime()
    {
        return (buffer.getInt(offset + 17, BYTE_ORDER) & 0xFFFF_FFFFL);
    }


    public static int eventTimestampId()
    {
        return 6;
    }

    public static int eventTimestampSinceVersion()
    {
        return 0;
    }

    public static int eventTimestampEncodingOffset()
    {
        return 21;
    }

    public static int eventTimestampEncodingLength()
    {
        return 4;
    }

    public static String eventTimestampMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long eventTimestampNullValue()
    {
        return 4294967295L;
    }

    public static long eventTimestampMinValue()
    {
        return 0L;
    }

    public static long eventTimestampMaxValue()
    {
        return 4294967294L;
    }

    public long eventTimestamp()
    {
        return (buffer.getInt(offset + 21, BYTE_ORDER) & 0xFFFF_FFFFL);
    }


    public static int inputOctetsId()
    {
        return 7;
    }

    public static int inputOctetsSinceVersion()
    {
        return 0;
    }

    public static int inputOctetsEncodingOffset()
    {
        return 25;
    }

    public static int inputOctetsEncodingLength()
    {
        return 8;
    }

    public static String inputOctetsMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long inputOctetsNullValue()
    {
        return -9223372036854775808L;
    }

    public static long inputOctetsMinValue()
    {
        return -9223372036854775807L;
    }

    public static long inputOctetsMaxValue()
    {
        return 9223372036854775807L;
    }

    public long inputOctets()
    {
        return buffer.getLong(offset + 25, BYTE_ORDER);
    }


    public static int outputOctetsId()
    {
        return 8;
    }

    public static int outputOctetsSinceVersion()
    {
        return 0;
    }

    public static int outputOctetsEncodingOffset()
    {
        return 33;
    }

    public static int outputOctetsEncodingLength()
    {
        return 8;
    }

    public static String outputOctetsMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long outputOctetsNullValue()
    {
        return -9223372036854775808L;
    }

    public static long outputOctetsMinValue()
    {
        return -9223372036854775807L;
    }

    public static long outputOctetsMaxValue()
    {
        return 9223372036854775807L;
    }

    public long outputOctets()
    {
        return buffer.getLong(offset + 33, BYTE_ORDER);
    }


    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        final SessionReportDecoder decoder = new SessionReportDecoder();
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
        builder.append("[SessionReport](sbeTemplateId=");
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
        builder.append("status=");
        builder.append(this.status());
        builder.append('|');
        builder.append("nasId=");
        builder.append(this.nasId());
        builder.append('|');
        builder.append("statusType=");
        builder.append(this.statusType());
        builder.append('|');
        builder.append("sessionTime=");
        builder.append(this.sessionTime());
        builder.append('|');
        builder.append("eventTimestamp=");
        builder.append(this.eventTimestamp());
        builder.append('|');
        builder.append("inputOctets=");
        builder.append(this.inputOctets());
        builder.append('|');
        builder.append("outputOctets=");
        builder.append(this.outputOctets());

        limit(originalLimit);

        return builder;
    }
    
    public SessionReportDecoder sbeSkip()
    {
        sbeRewind();

        return this;
    }
}
