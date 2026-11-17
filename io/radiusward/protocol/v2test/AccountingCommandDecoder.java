/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;
import org.agrona.DirectBuffer;


/**
 * One accounting event to apply
 */
@SuppressWarnings("all")
public final class AccountingCommandDecoder
{
    public static final int BLOCK_LENGTH = 85;
    public static final int TEMPLATE_ID = 1;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final AccountingCommandDecoder parentMessage = this;
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

    public AccountingCommandDecoder wrap(
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

    public AccountingCommandDecoder wrapAndApplyHeader(
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

    public AccountingCommandDecoder sbeRewind()
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

    public int gatewayId()
    {
        return buffer.getInt(offset + 8, BYTE_ORDER);
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

    public int nasId()
    {
        return buffer.getInt(offset + 12, BYTE_ORDER);
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

    public long sessionKeyHi()
    {
        return buffer.getLong(offset + 16, BYTE_ORDER);
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

    public long sessionKeyLo()
    {
        return buffer.getLong(offset + 24, BYTE_ORDER);
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

    public long exactKeyHi()
    {
        return buffer.getLong(offset + 32, BYTE_ORDER);
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

    public long exactKeyLo()
    {
        return buffer.getLong(offset + 40, BYTE_ORDER);
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

    public long statusType()
    {
        return (buffer.getInt(offset + 48, BYTE_ORDER) & 0xFFFF_FFFFL);
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

    private final EventFlagsDecoder flags = new EventFlagsDecoder();

    public EventFlagsDecoder flags()
    {
        flags.wrap(buffer, offset + 52, parentMessage.actingVersion);
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

    public long sessionTime()
    {
        return (buffer.getInt(offset + 53, BYTE_ORDER) & 0xFFFF_FFFFL);
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

    public long eventTimestamp()
    {
        return (buffer.getInt(offset + 57, BYTE_ORDER) & 0xFFFF_FFFFL);
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

    public long inputOctets()
    {
        return buffer.getLong(offset + 61, BYTE_ORDER);
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

    public long outputOctets()
    {
        return buffer.getLong(offset + 69, BYTE_ORDER);
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

    public long futureField()
    {
        if (parentMessage.actingVersion < 7)
        {
            return -9223372036854775808L;
        }

        return buffer.getLong(offset + 77, BYTE_ORDER);
    }


    public static int sessionIdId()
    {
        return 14;
    }

    public static int sessionIdSinceVersion()
    {
        return 0;
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

    public int sessionIdLength()
    {
        final int limit = parentMessage.limit();
        return (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
    }

    public int skipSessionId()
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int dataOffset = limit + headerLength;
        parentMessage.limit(dataOffset + dataLength);

        return dataLength;
    }

    public int getSessionId(final MutableDirectBuffer dst, final int dstOffset, final int length)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int bytesCopied = Math.min(length, dataLength);
        parentMessage.limit(limit + headerLength + dataLength);
        buffer.getBytes(limit + headerLength, dst, dstOffset, bytesCopied);

        return bytesCopied;
    }

    public int getSessionId(final byte[] dst, final int dstOffset, final int length)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int bytesCopied = Math.min(length, dataLength);
        parentMessage.limit(limit + headerLength + dataLength);
        buffer.getBytes(limit + headerLength, dst, dstOffset, bytesCopied);

        return bytesCopied;
    }

    public void wrapSessionId(final DirectBuffer wrapBuffer)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        parentMessage.limit(limit + headerLength + dataLength);
        wrapBuffer.wrap(buffer, limit + headerLength, dataLength);
    }

    public String sessionId()
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        parentMessage.limit(limit + headerLength + dataLength);

        if (0 == dataLength)
        {
            return "";
        }

        final byte[] tmp = new byte[dataLength];
        buffer.getBytes(limit + headerLength, tmp, 0, dataLength);

        return new String(tmp, java.nio.charset.StandardCharsets.UTF_8);
    }

    public static int rawAttributesId()
    {
        return 15;
    }

    public static int rawAttributesSinceVersion()
    {
        return 0;
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

    public int rawAttributesLength()
    {
        final int limit = parentMessage.limit();
        return (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
    }

    public int skipRawAttributes()
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int dataOffset = limit + headerLength;
        parentMessage.limit(dataOffset + dataLength);

        return dataLength;
    }

    public int getRawAttributes(final MutableDirectBuffer dst, final int dstOffset, final int length)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int bytesCopied = Math.min(length, dataLength);
        parentMessage.limit(limit + headerLength + dataLength);
        buffer.getBytes(limit + headerLength, dst, dstOffset, bytesCopied);

        return bytesCopied;
    }

    public int getRawAttributes(final byte[] dst, final int dstOffset, final int length)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        final int bytesCopied = Math.min(length, dataLength);
        parentMessage.limit(limit + headerLength + dataLength);
        buffer.getBytes(limit + headerLength, dst, dstOffset, bytesCopied);

        return bytesCopied;
    }

    public void wrapRawAttributes(final DirectBuffer wrapBuffer)
    {
        final int headerLength = 4;
        final int limit = parentMessage.limit();
        final int dataLength = (int)(buffer.getInt(limit, BYTE_ORDER) & 0xFFFF_FFFFL);
        parentMessage.limit(limit + headerLength + dataLength);
        wrapBuffer.wrap(buffer, limit + headerLength, dataLength);
    }

    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        final AccountingCommandDecoder decoder = new AccountingCommandDecoder();
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
        builder.append("[AccountingCommand](sbeTemplateId=");
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
        builder.append("gatewayId=");
        builder.append(this.gatewayId());
        builder.append('|');
        builder.append("nasId=");
        builder.append(this.nasId());
        builder.append('|');
        builder.append("sessionKeyHi=");
        builder.append(this.sessionKeyHi());
        builder.append('|');
        builder.append("sessionKeyLo=");
        builder.append(this.sessionKeyLo());
        builder.append('|');
        builder.append("exactKeyHi=");
        builder.append(this.exactKeyHi());
        builder.append('|');
        builder.append("exactKeyLo=");
        builder.append(this.exactKeyLo());
        builder.append('|');
        builder.append("statusType=");
        builder.append(this.statusType());
        builder.append('|');
        builder.append("flags=");
        final EventFlagsDecoder flags = this.flags();
        if (null != flags)
        {
            flags.appendTo(builder);
        }
        else
        {
            builder.append("null");
        }
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
        builder.append('|');
        builder.append("futureField=");
        builder.append(this.futureField());
        builder.append('|');
        builder.append("sessionId=");
        builder.append('\'').append(sessionId()).append('\'');
        builder.append('|');
        builder.append("rawAttributes=");
        builder.append(skipRawAttributes()).append(" bytes of raw data");

        limit(originalLimit);

        return builder;
    }
    
    public AccountingCommandDecoder sbeSkip()
    {
        sbeRewind();
        skipSessionId();
        skipRawAttributes();

        return this;
    }
}
