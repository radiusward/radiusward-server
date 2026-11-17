/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.DirectBuffer;


/**
 * Which optional RADIUS values were present
 */
@SuppressWarnings("all")
public final class EventFlagsDecoder
{
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final int ENCODED_LENGTH = 1;
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private int offset;
    private DirectBuffer buffer;

    public EventFlagsDecoder wrap(final DirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;

        return this;
    }

    public DirectBuffer buffer()
    {
        return buffer;
    }

    public int offset()
    {
        return offset;
    }

    public int encodedLength()
    {
        return ENCODED_LENGTH;
    }

    public int sbeSchemaId()
    {
        return SCHEMA_ID;
    }

    public int sbeSchemaVersion()
    {
        return SCHEMA_VERSION;
    }

    private int actingVersion = SCHEMA_VERSION;

    public EventFlagsDecoder wrap(final DirectBuffer buffer, final int offset, final int actingVersion)
    {
        wrap(buffer, offset);
        this.actingVersion = actingVersion;

        return this;
    }

    public boolean isEmpty()
    {
        return 0 == buffer.getByte(offset);
    }

    public short getRaw()
    {
        return ((short)(buffer.getByte(offset) & 0xFF));
    }

    public boolean sessionTimePresent()
    {
        return 0 != (buffer.getByte(offset) & (1 << 0));
    }

    public static boolean sessionTimePresent(final byte value)
    {
        return 0 != (value & (1 << 0));
    }

    public boolean eventTimestampPresent()
    {
        return 0 != (buffer.getByte(offset) & (1 << 1));
    }

    public static boolean eventTimestampPresent(final byte value)
    {
        return 0 != (value & (1 << 1));
    }

    public boolean sessionIdPresent()
    {
        return 0 != (buffer.getByte(offset) & (1 << 2));
    }

    public static boolean sessionIdPresent(final byte value)
    {
        return 0 != (value & (1 << 2));
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
        builder.append('{');
        boolean atLeastOne = false;
        if (sessionTimePresent())
        {
            if (atLeastOne)
            {
                builder.append(',');
            }
            builder.append("sessionTimePresent");
            atLeastOne = true;
        }
        if (eventTimestampPresent())
        {
            if (atLeastOne)
            {
                builder.append(',');
            }
            builder.append("eventTimestampPresent");
            atLeastOne = true;
        }
        if (sessionIdPresent())
        {
            if (atLeastOne)
            {
                builder.append(',');
            }
            builder.append("sessionIdPresent");
            atLeastOne = true;
        }
        builder.append('}');

        return builder;
    }
}
