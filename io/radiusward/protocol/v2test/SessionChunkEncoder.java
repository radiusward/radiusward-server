/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;

@SuppressWarnings("all")
public final class SessionChunkEncoder
{
    public static final int BLOCK_LENGTH = 0;
    public static final int TEMPLATE_ID = 21;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SessionChunkEncoder parentMessage = this;
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

    public SessionChunkEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;
        limit(offset + BLOCK_LENGTH);

        return this;
    }

    public SessionChunkEncoder wrapAndApplyHeader(
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

    private final SessionsEncoder sessions = new SessionsEncoder(this);

    public static long sessionsId()
    {
        return 1;
    }

    public SessionsEncoder sessionsCount(final int count)
    {
        sessions.wrap(buffer, count);
        return sessions;
    }

    public static final class SessionsEncoder
    {
        public static final int HEADER_SIZE = 4;
        private final SessionChunkEncoder parentMessage;
        private MutableDirectBuffer buffer;
        private int count;
        private int index;
        private int offset;
        private int initialLimit;

        SessionsEncoder(final SessionChunkEncoder parentMessage)
        {
            this.parentMessage = parentMessage;
        }

        public void wrap(final MutableDirectBuffer buffer, final int count)
        {
            if (count < 0 || count > 65534)
            {
                throw new IllegalArgumentException("count outside allowed range: count=" + count);
            }

            if (buffer != this.buffer)
            {
                this.buffer = buffer;
            }

            index = 0;
            this.count = count;
            final int limit = parentMessage.limit();
            initialLimit = limit;
            parentMessage.limit(limit + HEADER_SIZE);
            buffer.putShort(limit + 0, (short)59, BYTE_ORDER);
            buffer.putShort(limit + 2, (short)count, BYTE_ORDER);
        }

        public SessionsEncoder next()
        {
            if (index >= count)
            {
                throw new java.util.NoSuchElementException();
            }

            offset = parentMessage.limit();
            parentMessage.limit(offset + sbeBlockLength());
            ++index;

            return this;
        }

        public int resetCountToIndex()
        {
            count = index;
            buffer.putShort(initialLimit + 2, (short)count, BYTE_ORDER);

            return count;
        }

        public static int countMinValue()
        {
            return 0;
        }

        public static int countMaxValue()
        {
            return 65534;
        }

        public static int sbeHeaderSize()
        {
            return HEADER_SIZE;
        }

        public static int sbeBlockLength()
        {
            return 59;
        }

        public static int keyHiId()
        {
            return 1;
        }

        public static int keyHiSinceVersion()
        {
            return 0;
        }

        public static int keyHiEncodingOffset()
        {
            return 0;
        }

        public static int keyHiEncodingLength()
        {
            return 8;
        }

        public static String keyHiMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static long keyHiNullValue()
        {
            return -9223372036854775808L;
        }

        public static long keyHiMinValue()
        {
            return -9223372036854775807L;
        }

        public static long keyHiMaxValue()
        {
            return 9223372036854775807L;
        }

        public SessionsEncoder keyHi(final long value)
        {
            buffer.putLong(offset + 0, value, BYTE_ORDER);
            return this;
        }


        public static int keyLoId()
        {
            return 2;
        }

        public static int keyLoSinceVersion()
        {
            return 0;
        }

        public static int keyLoEncodingOffset()
        {
            return 8;
        }

        public static int keyLoEncodingLength()
        {
            return 8;
        }

        public static String keyLoMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static long keyLoNullValue()
        {
            return -9223372036854775808L;
        }

        public static long keyLoMinValue()
        {
            return -9223372036854775807L;
        }

        public static long keyLoMaxValue()
        {
            return 9223372036854775807L;
        }

        public SessionsEncoder keyLo(final long value)
        {
            buffer.putLong(offset + 8, value, BYTE_ORDER);
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
            return 16;
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

        public SessionsEncoder nasId(final int value)
        {
            buffer.putInt(offset + 16, value, BYTE_ORDER);
            return this;
        }


        public static int statusId()
        {
            return 4;
        }

        public static int statusSinceVersion()
        {
            return 0;
        }

        public static int statusEncodingOffset()
        {
            return 20;
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

        public SessionsEncoder status(final SessionStatus value)
        {
            buffer.putByte(offset + 20, (byte)value.value());
            return this;
        }

        public static int statusTypeId()
        {
            return 5;
        }

        public static int statusTypeSinceVersion()
        {
            return 0;
        }

        public static int statusTypeEncodingOffset()
        {
            return 21;
        }

        public static int statusTypeEncodingLength()
        {
            return 1;
        }

        public static String statusTypeMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static short statusTypeNullValue()
        {
            return (short)255;
        }

        public static short statusTypeMinValue()
        {
            return (short)0;
        }

        public static short statusTypeMaxValue()
        {
            return (short)254;
        }

        public SessionsEncoder statusType(final short value)
        {
            buffer.putByte(offset + 21, (byte)value);
            return this;
        }


        public static int sessionTimeId()
        {
            return 6;
        }

        public static int sessionTimeSinceVersion()
        {
            return 0;
        }

        public static int sessionTimeEncodingOffset()
        {
            return 22;
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

        public SessionsEncoder sessionTime(final long value)
        {
            buffer.putInt(offset + 22, (int)value, BYTE_ORDER);
            return this;
        }


        public static int eventTimestampId()
        {
            return 7;
        }

        public static int eventTimestampSinceVersion()
        {
            return 0;
        }

        public static int eventTimestampEncodingOffset()
        {
            return 26;
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

        public SessionsEncoder eventTimestamp(final long value)
        {
            buffer.putInt(offset + 26, (int)value, BYTE_ORDER);
            return this;
        }


        public static int inputOctetsId()
        {
            return 8;
        }

        public static int inputOctetsSinceVersion()
        {
            return 0;
        }

        public static int inputOctetsEncodingOffset()
        {
            return 30;
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

        public SessionsEncoder inputOctets(final long value)
        {
            buffer.putLong(offset + 30, value, BYTE_ORDER);
            return this;
        }


        public static int outputOctetsId()
        {
            return 9;
        }

        public static int outputOctetsSinceVersion()
        {
            return 0;
        }

        public static int outputOctetsEncodingOffset()
        {
            return 38;
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

        public SessionsEncoder outputOctets(final long value)
        {
            buffer.putLong(offset + 38, value, BYTE_ORDER);
            return this;
        }


        public static int startKeyId()
        {
            return 10;
        }

        public static int startKeySinceVersion()
        {
            return 0;
        }

        public static int startKeyEncodingOffset()
        {
            return 46;
        }

        public static int startKeyEncodingLength()
        {
            return 4;
        }

        public static String startKeyMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static int startKeyNullValue()
        {
            return -2147483648;
        }

        public static int startKeyMinValue()
        {
            return -2147483647;
        }

        public static int startKeyMaxValue()
        {
            return 2147483647;
        }

        public SessionsEncoder startKey(final int value)
        {
            buffer.putInt(offset + 46, value, BYTE_ORDER);
            return this;
        }


        public static int lastSeenId()
        {
            return 11;
        }

        public static int lastSeenSinceVersion()
        {
            return 0;
        }

        public static int lastSeenEncodingOffset()
        {
            return 50;
        }

        public static int lastSeenEncodingLength()
        {
            return 4;
        }

        public static String lastSeenMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static int lastSeenNullValue()
        {
            return -2147483648;
        }

        public static int lastSeenMinValue()
        {
            return -2147483647;
        }

        public static int lastSeenMaxValue()
        {
            return 2147483647;
        }

        public SessionsEncoder lastSeen(final int value)
        {
            buffer.putInt(offset + 50, value, BYTE_ORDER);
            return this;
        }


        public static int tombstoneUntilId()
        {
            return 12;
        }

        public static int tombstoneUntilSinceVersion()
        {
            return 0;
        }

        public static int tombstoneUntilEncodingOffset()
        {
            return 54;
        }

        public static int tombstoneUntilEncodingLength()
        {
            return 4;
        }

        public static String tombstoneUntilMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static int tombstoneUntilNullValue()
        {
            return -2147483648;
        }

        public static int tombstoneUntilMinValue()
        {
            return -2147483647;
        }

        public static int tombstoneUntilMaxValue()
        {
            return 2147483647;
        }

        public SessionsEncoder tombstoneUntil(final int value)
        {
            buffer.putInt(offset + 54, value, BYTE_ORDER);
            return this;
        }


        public static int flagsId()
        {
            return 13;
        }

        public static int flagsSinceVersion()
        {
            return 0;
        }

        public static int flagsEncodingOffset()
        {
            return 58;
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

        public static short flagsNullValue()
        {
            return (short)255;
        }

        public static short flagsMinValue()
        {
            return (short)0;
        }

        public static short flagsMaxValue()
        {
            return (short)254;
        }

        public SessionsEncoder flags(final short value)
        {
            buffer.putByte(offset + 58, (byte)value);
            return this;
        }

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

        final SessionChunkDecoder decoder = new SessionChunkDecoder();
        decoder.wrap(buffer, offset, BLOCK_LENGTH, SCHEMA_VERSION);

        return decoder.appendTo(builder);
    }
}
