/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;

@SuppressWarnings("all")
public final class SessionReportEncoder
{
    public static final int BLOCK_LENGTH = 41;
    public static final int TEMPLATE_ID = 5;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SessionReportEncoder parentMessage = this;
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

    public SessionReportEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public SessionReportEncoder wrapAndApplyHeader(
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

    public SessionReportEncoder correlationId(final long value)
    {
        buffer.putLong(offset + 0, value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder status(final SessionStatus value)
    {
        buffer.putByte(offset + 8, (byte)value.value());
        return this;
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

    public SessionReportEncoder nasId(final int value)
    {
        buffer.putInt(offset + 9, value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder statusType(final long value)
    {
        buffer.putInt(offset + 13, (int)value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder sessionTime(final long value)
    {
        buffer.putInt(offset + 17, (int)value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder eventTimestamp(final long value)
    {
        buffer.putInt(offset + 21, (int)value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder inputOctets(final long value)
    {
        buffer.putLong(offset + 25, value, BYTE_ORDER);
        return this;
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

    public SessionReportEncoder outputOctets(final long value)
    {
        buffer.putLong(offset + 33, value, BYTE_ORDER);
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

        final SessionReportDecoder decoder = new SessionReportDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
