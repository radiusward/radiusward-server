/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;

@SuppressWarnings("all")
public enum SessionStatus
{
    UNKNOWN((short)0),

    ACTIVE((short)1),

    STOPPED((short)2),

    /**
     * To be used to represent not present or null.
     */
    NULL_VAL((short)255);

    private final short value;

    SessionStatus(final short value)
    {
        this.value = value;
    }

    /**
     * The raw encoded value in the Java type representation.
     *
     * @return the raw value encoded.
     */
    public short value()
    {
        return value;
    }

    /**
     * Lookup the enum value representing the value.
     *
     * @param value encoded to be looked up.
     * @return the enum value representing the value.
     */
    public static SessionStatus get(final short value)
    {
        switch (value)
        {
            case 0: return UNKNOWN;
            case 1: return ACTIVE;
            case 2: return STOPPED;
            case 255: return NULL_VAL;
        }

        throw new IllegalArgumentException("Unknown value: " + value);
    }
}
