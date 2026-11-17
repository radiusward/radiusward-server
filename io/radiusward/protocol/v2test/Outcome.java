/* Generated SBE (Simple Binary Encoding) message codec. */
package io.radiusward.protocol.v2test;


/**
 * Result of applying an accounting event
 */
@SuppressWarnings("all")
public enum Outcome
{

    /**
     * new event, state changed
     */
    APPLIED((short)0),


    /**
     * same event seen before; the NAS gets an ACK
     */
    DUPLICATE((short)1),


    /**
     * older than the stored progress; ACK, not applied
     */
    STALE((short)2),

    /**
     * To be used to represent not present or null.
     */
    NULL_VAL((short)255);

    private final short value;

    Outcome(final short value)
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
    public static Outcome get(final short value)
    {
        switch (value)
        {
            case 0: return APPLIED;
            case 1: return DUPLICATE;
            case 2: return STALE;
            case 255: return NULL_VAL;
        }

        throw new IllegalArgumentException("Unknown value: " + value);
    }
}
