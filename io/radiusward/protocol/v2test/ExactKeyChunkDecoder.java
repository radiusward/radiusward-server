/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;

@SuppressWarnings("all")
public final class ExactKeyChunkDecoder
{
    public static final int BLOCK_LENGTH = 0;
    public static final int TEMPLATE_ID = 22;
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private final ExactKeyChunkDecoder parentMessage = this;
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

    public ExactKeyChunkDecoder wrap(
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

    public ExactKeyChunkDecoder wrapAndApplyHeader(
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

    public ExactKeyChunkDecoder sbeRewind()
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

    private final KeysDecoder keys = new KeysDecoder(this);

    public static long keysDecoderId()
    {
        return 1;
    }

    public static int keysDecoderSinceVersion()
    {
        return 0;
    }

    public KeysDecoder keys()
    {
        keys.wrap(buffer);
        return keys;
    }

    public static final class KeysDecoder
        implements Iterable<KeysDecoder>, java.util.Iterator<KeysDecoder>
    {
        public static final int HEADER_SIZE = 4;
        private final ExactKeyChunkDecoder parentMessage;
        private DirectBuffer buffer;
        private int count;
        private int index;
        private int offset;
        private int blockLength;

        KeysDecoder(final ExactKeyChunkDecoder parentMessage)
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

        public KeysDecoder next()
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
            return 16;
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

        public java.util.Iterator<KeysDecoder> iterator()
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

        public static int keyId()
        {
            return 1;
        }

        public static int keySinceVersion()
        {
            return 0;
        }

        public static int keyEncodingOffset()
        {
            return 0;
        }

        public static int keyEncodingLength()
        {
            return 8;
        }

        public static String keyMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static long keyNullValue()
        {
            return -9223372036854775808L;
        }

        public static long keyMinValue()
        {
            return -9223372036854775807L;
        }

        public static long keyMaxValue()
        {
            return 9223372036854775807L;
        }

        public long key()
        {
            return buffer.getLong(offset + 0, BYTE_ORDER);
        }


        public static int expiryId()
        {
            return 2;
        }

        public static int expirySinceVersion()
        {
            return 0;
        }

        public static int expiryEncodingOffset()
        {
            return 8;
        }

        public static int expiryEncodingLength()
        {
            return 8;
        }

        public static String expiryMetaAttribute(final MetaAttribute metaAttribute)
        {
            if (MetaAttribute.PRESENCE == metaAttribute)
            {
                return "required";
            }

            return "";
        }

        public static long expiryNullValue()
        {
            return -9223372036854775808L;
        }

        public static long expiryMinValue()
        {
            return -9223372036854775807L;
        }

        public static long expiryMaxValue()
        {
            return 9223372036854775807L;
        }

        public long expiry()
        {
            return buffer.getLong(offset + 8, BYTE_ORDER);
        }


        public StringBuilder appendTo(final StringBuilder builder)
        {
            if (null == buffer)
            {
                return builder;
            }

            builder.append('(');
            builder.append("key=");
            builder.append(this.key());
            builder.append('|');
            builder.append("expiry=");
            builder.append(this.expiry());
            builder.append(')');

            return builder;
        }
        
        public KeysDecoder sbeSkip()
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

        final ExactKeyChunkDecoder decoder = new ExactKeyChunkDecoder();
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
        builder.append("[ExactKeyChunk](sbeTemplateId=");
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
        builder.append("keys=[");
        final int keysOriginalOffset = keys.offset;
        final int keysOriginalIndex = keys.index;
        final KeysDecoder keys = this.keys();
        if (keys.count() > 0)
        {
            while (keys.hasNext())
            {
                keys.next().appendTo(builder);
                builder.append(',');
            }
            builder.setLength(builder.length() - 1);
        }
        keys.offset = keysOriginalOffset;
        keys.index = keysOriginalIndex;
        builder.append(']');

        limit(originalLimit);

        return builder;
    }
    
    public ExactKeyChunkDecoder sbeSkip()
    {
        sbeRewind();
        KeysDecoder keys = this.keys();
        if (keys.count() > 0)
        {
            while (keys.hasNext())
            {
                keys.next();
                keys.sbeSkip();
            }
        }

        return this;
    }
}
