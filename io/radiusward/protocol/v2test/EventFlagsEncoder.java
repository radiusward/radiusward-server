/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

import org.agrona.MutableDirectBuffer;


/**
 * Which optional RADIUS values were present
 */
@SuppressWarnings("all")
public final class EventFlagsEncoder
{
    public static final int SCHEMA_ID = 7101;
    public static final int SCHEMA_VERSION = 7;
    public static final String SEMANTIC_VERSION = "2.0";
    public static final int ENCODED_LENGTH = 1;
    public static final java.nio.ByteOrder BYTE_ORDER = java.nio.ByteOrder.LITTLE_ENDIAN;

    private int offset;
    private MutableDirectBuffer buffer;

    public EventFlagsEncoder wrap(final MutableDirectBuffer buffer, final int offset)
    {
        if (buffer != this.buffer)
        {
            this.buffer = buffer;
        }
        this.offset = offset;

        return this;
    }

    public MutableDirectBuffer buffer()
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

    public EventFlagsEncoder clear()
    {
        buffer.putByte(offset, (byte)(short)0);
        return this;
    }

    public EventFlagsEncoder setRaw(final short value)
    {
        buffer.putByte(offset, (byte)value);
        return this;
    }

    public EventFlagsEncoder sessionTimePresent(final boolean value)
    {
        byte bits = buffer.getByte(offset);
        bits = (byte)(value ? bits | (1 << 0) : bits & ~(1 << 0));
        buffer.putByte(offset, bits);
        return this;
    }

    public static byte sessionTimePresent(final byte bits, final boolean value)
    {
        return (byte)(value ? bits | (1 << 0) : bits & ~(1 << 0));
    }

    public EventFlagsEncoder eventTimestampPresent(final boolean value)
    {
        byte bits = buffer.getByte(offset);
        bits = (byte)(value ? bits | (1 << 1) : bits & ~(1 << 1));
        buffer.putByte(offset, bits);
        return this;
    }

    public static byte eventTimestampPresent(final byte bits, final boolean value)
    {
        return (byte)(value ? bits | (1 << 1) : bits & ~(1 << 1));
    }

    public EventFlagsEncoder sessionIdPresent(final boolean value)
    {
        byte bits = buffer.getByte(offset);
        bits = (byte)(value ? bits | (1 << 2) : bits & ~(1 << 2));
        buffer.putByte(offset, bits);
        return this;
    }

    public static byte sessionIdPresent(final byte bits, final boolean value)
    {
        return (byte)(value ? bits | (1 << 2) : bits & ~(1 << 2));
    }
}
