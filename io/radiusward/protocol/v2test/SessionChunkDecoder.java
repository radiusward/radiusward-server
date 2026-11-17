/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;

@SuppressWarnings("all")
public final class SessionChunkDecoder
{
    public static final int BLOCK_LENGTH = 0;
    public static final int TEMPLATE_ID = 21;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final SessionChunkDecoder parentMessage = this;
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

    public SessionChunkDecoder wrap(
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

    public SessionChunkDecoder wrapAndApplyHeader(
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

    public SessionChunkDecoder sbeRewind()
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

    private final SessionsDecoder sessions = new SessionsDecoder(this);

    public static long sessionsDecoderId()
    {
        return 1;
    }

    public static int sessionsDecoderSinceVersion()
    {
        return 0;
    }

    public SessionsDecoder sessions()
    {
        sessions.wrap(buffer);
        return sessions;
    }

    public static final class SessionsDecoder
        implements Iterable<SessionsDecoder>, java.util.Iterator<SessionsDecoder>
    {
        public static final int HEADER_SIZE = 4;
        private final SessionChunkDecoder parentMessage;
        private DirectBuffer buffer;
        private int count;
        private int index;
        private int offset;
        private int blockLength;

        SessionsDecoder(final SessionChunkDecoder parentMessage)
        {
            this.parentMessage = parentMessage;
        }

        public void wrap(final DirectBuffer buffer)
        {
            if (buffer != this.buffer)
            {
                this.buffer = buffer;
            }

            index = 0;
            final int limit = parentMessage.limit();
            parentMessage.limit(limit + HEADER_SIZE);
            blockLength = (buffer.getShort(limit + 0, BYTE_ORDER) & 0xFFFF);
            count = (buffer.getShort(limit + 2, BYTE_ORDER) & 0xFFFF);
        }

        public SessionsDecoder next()
        {
            if (index >= count)
            {
                throw new java.util.NoSuchElementException();
            }

            offset = parentMessage.limit();
            parentMessage.limit(offset + blockLength);
            ++index;

            return this;
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

        public int actingBlockLength()
        {
            return blockLength;
        }

        public int actingVersion()
        {
            return parentMessage.actingVersion;
        }

        public int count()
        {
            return count;
        }

        public java.util.Iterator<SessionsDecoder> iterator()
        {
            return this;
        }

        public void remove()
        {
            throw new UnsupportedOperationException();
        }

        public boolean hasNext()
        {
            return index < count;
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

        public long keyHi()
        {
            return buffer.getLong(offset + 0, BYTE_ORDER);
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

        public long keyLo()
        {
            return buffer.getLong(offset + 8, BYTE_ORDER);
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

        public int nasId()
        {
            return buffer.getInt(offset + 16, BYTE_ORDER);
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

        public short statusRaw()
        {
            return ((short)(buffer.getByte(offset + 20) & 0xFF));
        }

        public SessionStatus status()
        {
            return SessionStatus.get(((short)(buffer.getByte(offset + 20) & 0xFF)));
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

        public short statusType()
        {
            return ((short)(buffer.getByte(offset + 21) & 0xFF));
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

        public long sessionTime()
        {
            return (buffer.getInt(offset + 22, BYTE_ORDER) & 0xFFFF_FFFFL);
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

        public long eventTimestamp()
        {
            return (buffer.getInt(offset + 26, BYTE_ORDER) & 0xFFFF_FFFFL);
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

        public long inputOctets()
        {
            return buffer.getLong(offset + 30, BYTE_ORDER);
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

        public long outputOctets()
        {
            return buffer.getLong(offset + 38, BYTE_ORDER);
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

        public int startKey()
        {
            return buffer.getInt(offset + 46, BYTE_ORDER);
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

        public int lastSeen()
        {
            return buffer.getInt(offset + 50, BYTE_ORDER);
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

        public int tombstoneUntil()
        {
            return buffer.getInt(offset + 54, BYTE_ORDER);
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

        public short flags()
        {
            return ((short)(buffer.getByte(offset + 58) & 0xFF));
        }


        public StringBuilder appendTo(final StringBuilder builder)
        {
            if (null == buffer)
            {
                return builder;
            }

            builder.append('(');
            builder.append("keyHi=");
            builder.append(this.keyHi());
            builder.append('|');
            builder.append("keyLo=");
            builder.append(this.keyLo());
            builder.append('|');
            builder.append("nasId=");
            builder.append(this.nasId());
            builder.append('|');
            builder.append("status=");
            builder.append(this.status());
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
            builder.append('|');
            builder.append("startKey=");
            builder.append(this.startKey());
            builder.append('|');
            builder.append("lastSeen=");
            builder.append(this.lastSeen());
            builder.append('|');
            builder.append("tombstoneUntil=");
            builder.append(this.tombstoneUntil());
            builder.append('|');
            builder.append("flags=");
            builder.append(this.flags());
            builder.append(')');

            return builder;
        }
        
        public SessionsDecoder sbeSkip()
        {

            return this;
        }
    }

    public String toString()
    {
        if (null == buffer)
        {
            return "";
        }

        final SessionChunkDecoder decoder = new SessionChunkDecoder();
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
        builder.append("[SessionChunk](sbeTemplateId=");
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
        builder.append("sessions=[");
        final int sessionsOriginalOffset = sessions.offset;
        final int sessionsOriginalIndex = sessions.index;
        final SessionsDecoder sessions = this.sessions();
        if (sessions.count() > 0)
        {
            while (sessions.hasNext())
            {
                sessions.next().appendTo(builder);
                builder.append(',');
            }
            builder.setLength(builder.length() - 1);
        }
        sessions.offset = sessionsOriginalOffset;
        sessions.index = sessionsOriginalIndex;
        builder.append(']');

        limit(originalLimit);

        return builder;
    }
    
    public SessionChunkDecoder sbeSkip()
    {
        sbeRewind();
        SessionsDecoder sessions = this.sessions();
        if (sessions.count() > 0)
        {
            while (sessions.hasNext())
            {
                sessions.next();
                sessions.sbeSkip();
            }
        }

        return this;
    }
}
