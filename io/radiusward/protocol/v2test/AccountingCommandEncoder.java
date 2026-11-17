/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;
import org.agrona.DirectBuffer;


/**
 * One accounting event to apply
 */
@SuppressWarnings("all")
public final class AccountingCommandEncoder
{
    public static final int BLOCK_LENGTH = 85;
    public static final int TEMPLATE_ID = 1;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final AccountingCommandEncoder parentMessage = this;
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

    public AccountingCommandEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public AccountingCommandEncoder wrapAndApplyHeader(
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

    public AccountingCommandEncoder correlationId(final long value)
    {
        buffer.putLong(offset + 0, value, BYTE_ORDER);
        return this;
    }


    public static int gatewayIdId()
    {
        return 2;
    }

    public static int gatewayIdSinceVersion()
    {
        return 0;
    }

    public static int gatewayIdEncodingOffset()
    {
        return 8;
    }

    public static int gatewayIdEncodingLength()
    {
        return 4;
    }

    public static String gatewayIdMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static int gatewayIdNullValue()
    {
        return -2147483648;
    }

    public static int gatewayIdMinValue()
    {
        return -2147483647;
    }

    public static int gatewayIdMaxValue()
    {
        return 2147483647;
    }

    public AccountingCommandEncoder gatewayId(final int value)
    {
        buffer.putInt(offset + 8, value, BYTE_ORDER);
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
        return 12;
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

    public AccountingCommandEncoder nasId(final int value)
    {
        buffer.putInt(offset + 12, value, BYTE_ORDER);
        return this;
    }


    public static int sessionKeyHiId()
    {
        return 4;
    }

    public static int sessionKeyHiSinceVersion()
    {
        return 0;
    }

    public static int sessionKeyHiEncodingOffset()
    {
        return 16;
    }

    public static int sessionKeyHiEncodingLength()
    {
        return 8;
    }

    public static String sessionKeyHiMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long sessionKeyHiNullValue()
    {
        return -9223372036854775808L;
    }

    public static long sessionKeyHiMinValue()
    {
        return -9223372036854775807L;
    }

    public static long sessionKeyHiMaxValue()
    {
        return 9223372036854775807L;
    }

    public AccountingCommandEncoder sessionKeyHi(final long value)
    {
        buffer.putLong(offset + 16, value, BYTE_ORDER);
        return this;
    }


    public static int sessionKeyLoId()
    {
        return 5;
    }

    public static int sessionKeyLoSinceVersion()
    {
        return 0;
    }

    public static int sessionKeyLoEncodingOffset()
    {
        return 24;
    }

    public static int sessionKeyLoEncodingLength()
    {
        return 8;
    }

    public static String sessionKeyLoMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long sessionKeyLoNullValue()
    {
        return -9223372036854775808L;
    }

    public static long sessionKeyLoMinValue()
    {
        return -9223372036854775807L;
    }

    public static long sessionKeyLoMaxValue()
    {
        return 9223372036854775807L;
    }

    public AccountingCommandEncoder sessionKeyLo(final long value)
    {
        buffer.putLong(offset + 24, value, BYTE_ORDER);
        return this;
    }


    public static int exactKeyHiId()
    {
        return 6;
    }

    public static int exactKeyHiSinceVersion()
    {
        return 0;
    }

    public static int exactKeyHiEncodingOffset()
    {
        return 32;
    }

    public static int exactKeyHiEncodingLength()
    {
        return 8;
    }

    public static String exactKeyHiMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long exactKeyHiNullValue()
    {
        return -9223372036854775808L;
    }

    public static long exactKeyHiMinValue()
    {
        return -9223372036854775807L;
    }

    public static long exactKeyHiMaxValue()
    {
        return 9223372036854775807L;
    }

    public AccountingCommandEncoder exactKeyHi(final long value)
    {
        buffer.putLong(offset + 32, value, BYTE_ORDER);
        return this;
    }


    public static int exactKeyLoId()
    {
        return 7;
    }

    public static int exactKeyLoSinceVersion()
    {
        return 0;
    }

    public static int exactKeyLoEncodingOffset()
    {
        return 40;
    }

    public static int exactKeyLoEncodingLength()
    {
        return 8;
    }

    public static String exactKeyLoMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long exactKeyLoNullValue()
    {
        return -9223372036854775808L;
    }

    public static long exactKeyLoMinValue()
    {
        return -9223372036854775807L;
    }

    public static long exactKeyLoMaxValue()
    {
        return 9223372036854775807L;
    }

    public AccountingCommandEncoder exactKeyLo(final long value)
    {
        buffer.putLong(offset + 40, value, BYTE_ORDER);
        return this;
    }


    public static int statusTypeId()
    {
        return 8;
    }

    public static int statusTypeSinceVersion()
    {
        return 0;
    }

    public static int statusTypeEncodingOffset()
    {
        return 48;
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

    public AccountingCommandEncoder statusType(final long value)
    {
        buffer.putInt(offset + 48, (int)value, BYTE_ORDER);
        return this;
    }


    public static int flagsId()
    {
        return 9;
    }

    public static int flagsSinceVersion()
    {
        return 0;
    }

    public static int flagsEncodingOffset()
    {
        return 52;
    }

    public static int flagsEncodingLength()
    {
        return 1;
    }

    public static String flagsMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    private final EventFlagsEncoder flags = new EventFlagsEncoder();

    public EventFlagsEncoder flags()
    {
        flags.wrap(buffer, offset + 52);
        return flags;
    }

    public static int sessionTimeId()
    {
        return 10;
    }

    public static int sessionTimeSinceVersion()
    {
        return 0;
    }

    public static int sessionTimeEncodingOffset()
    {
        return 53;
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

    public AccountingCommandEncoder sessionTime(final long value)
    {
        buffer.putInt(offset + 53, (int)value, BYTE_ORDER);
        return this;
    }


    public static int eventTimestampId()
    {
        return 11;
    }

    public static int eventTimestampSinceVersion()
    {
        return 0;
    }

    public static int eventTimestampEncodingOffset()
    {
        return 57;
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

    public AccountingCommandEncoder eventTimestamp(final long value)
    {
        buffer.putInt(offset + 57, (int)value, BYTE_ORDER);
        return this;
    }


    public static int inputOctetsId()
    {
        return 12;
    }

    public static int inputOctetsSinceVersion()
    {
        return 0;
    }

    public static int inputOctetsEncodingOffset()
    {
        return 61;
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

    public AccountingCommandEncoder inputOctets(final long value)
    {
        buffer.putLong(offset + 61, value, BYTE_ORDER);
        return this;
    }


    public static int outputOctetsId()
    {
        return 13;
    }

    public static int outputOctetsSinceVersion()
    {
        return 0;
    }

    public static int outputOctetsEncodingOffset()
    {
        return 69;
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

    public AccountingCommandEncoder outputOctets(final long value)
    {
        buffer.putLong(offset + 69, value, BYTE_ORDER);
        return this;
    }


    public static int futureFieldId()
    {
        return 99;
    }

    public static int futureFieldSinceVersion()
    {
        return 7;
    }

    public static int futureFieldEncodingOffset()
    {
        return 77;
    }

    public static int futureFieldEncodingLength()
    {
        return 8;
    }

    public static String futureFieldMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static long futureFieldNullValue()
    {
        return -9223372036854775808L;
    }

    public static long futureFieldMinValue()
    {
        return -9223372036854775807L;
    }

    public static long futureFieldMaxValue()
    {
        return 9223372036854775807L;
    }

    public AccountingCommandEncoder futureField(final long value)
    {
        buffer.putLong(offset + 77, value, BYTE_ORDER);
        return this;
    }


    public static int sessionIdId()
    {
        return 14;
    }

    public static String sessionIdCharacterEncoding()
    {
        return java.nio.charset.StandardCharsets.UTF_8.name();
    }

    public static String sessionIdMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static int sessionIdHeaderLength()
    {
        return 4;
    }

    public AccountingCommandEncoder putSessionId(final DirectBuffer src, final int srcOffset, final int length)
    {
        if (length > 65535)
        {
            throw new IllegalStateException("length > maxValue for type: " + length);
        }

        final int headerLength = 4;
        final int limit = parentMessage.limit();
        parentMessage.limit(limit + headerLength + length);
        buffer.putInt(limit, length, BYTE_ORDER);
        buffer.putBytes(limit + headerLength, src, srcOffset, length);

        return this;
    }

    public AccountingCommandEncoder putSessionId(final byte[] src, final int srcOffset, final int length)
    {
        if (length > 65535)
        {
            throw new IllegalStateException("length > maxValue for type: " + length);
        }

        final int headerLength = 4;
        final int limit = parentMessage.limit();
        parentMessage.limit(limit + headerLength + length);
        buffer.putInt(limit, length, BYTE_ORDER);
        buffer.putBytes(limit + headerLength, src, srcOffset, length);

        return this;
    }

    public AccountingCommandEncoder sessionId(final String value)
    {
        final byte[] bytes = (null == value || value.isEmpty()) ? org.agrona.collections.ArrayUtil.EMPTY_BYTE_ARRAY : value.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        final int length = bytes.length;
        if (length > 65535)
        {
            throw new IllegalStateException("length > maxValue for type: " + length);
        }

        final int headerLength = 4;
        final int limit = parentMessage.limit();
        parentMessage.limit(limit + headerLength + length);
        buffer.putInt(limit, length, BYTE_ORDER);
        buffer.putBytes(limit + headerLength, bytes, 0, length);

        return this;
    }

    public static int rawAttributesId()
    {
        return 15;
    }

    public static String rawAttributesMetaAttribute(final MetaAttribute metaAttribute)
    {
        if (MetaAttribute.PRESENCE == metaAttribute)
        {
            return "required";
        }

        return "";
    }

    public static int rawAttributesHeaderLength()
    {
        return 4;
    }

    public AccountingCommandEncoder putRawAttributes(final DirectBuffer src, final int srcOffset, final int length)
    {
        if (length > 65535)
        {
            throw new IllegalStateException("length > maxValue for type: " + length);
        }

        final int headerLength = 4;
        final int limit = parentMessage.limit();
        parentMessage.limit(limit + headerLength + length);
        buffer.putInt(limit, length, BYTE_ORDER);
        buffer.putBytes(limit + headerLength, src, srcOffset, length);

        return this;
    }

    public AccountingCommandEncoder putRawAttributes(final byte[] src, final int srcOffset, final int length)
    {
        if (length > 65535)
        {
            throw new IllegalStateException("length > maxValue for type: " + length);
        }

        final int headerLength = 4;
        final int limit = parentMessage.limit();
        parentMessage.limit(limit + headerLength + length);
        buffer.putInt(limit, length, BYTE_ORDER);
        buffer.putBytes(limit + headerLength, src, srcOffset, length);

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

        final AccountingCommandDecoder decoder = new AccountingCommandDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
