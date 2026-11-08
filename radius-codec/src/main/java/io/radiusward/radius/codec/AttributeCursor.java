/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

import static java.nio.ByteOrder.BIG_ENDIAN;

import org.agrona.DirectBuffer;

/**
 * Allocation-free walk over the attributes of a validated {@link RadiusPacket}.
 *
 * <p>Vendor-Specific attributes (26) are flattened: each vendor sub-attribute is reported as its
 * own entry with {@link #vendorId()} set, using the layout from {@link VendorFormats}. A VSA whose
 * content does not parse with that layout is reported once as an opaque type 26 attribute with
 * vendor id 0, so a quirky vendor can never make the packet unreadable.
 *
 * <pre>{@code
 * cursor.wrap(packet);
 * while (cursor.next()) {
 *     if (cursor.vendorId() == 0 && cursor.type() == 40) { ... cursor.valueOffset() ... }
 * }
 * }</pre>
 *
 * <p>Extended attributes (RFC 6929, types 241–246) are reported as their top-level type with the
 * raw value; {@link #extendedType()} gives the first value byte. Not thread-safe.
 */
public final class AttributeCursor {

    public static final int VENDOR_SPECIFIC = 26;

    private static final int VSA_HEADER_LENGTH = 6; // type, length, 4 byte vendor id

    private final VendorFormats formats;

    private DirectBuffer buffer;
    private int position;
    private int end;

    private int vsaPosition;
    private int vsaEnd;
    private int vsaFormat;

    private int attributeOffset;
    private int attributeLength;
    private int type;
    private int vendorId;
    private int valueOffset;
    private int valueLength;

    public AttributeCursor(VendorFormats formats) {
        this.formats = formats;
    }

    /** Cursor treating every vendor as using the standard VSA layout. */
    public AttributeCursor() {
        this(VendorFormats.ALL_STANDARD);
    }

    /** Positions the cursor before the first attribute of a packet that wrapped with {@link DecodeStatus#OK}. */
    public AttributeCursor wrap(RadiusPacket packet) {
        return wrap(packet.buffer(), packet.attributesOffset(), packet.attributesEnd());
    }

    /** Positions the cursor before an attribute region {@code [start, end)} that is known to be well framed. */
    public AttributeCursor wrap(DirectBuffer buffer, int start, int end) {
        this.buffer = buffer;
        this.position = start;
        this.end = end;
        this.vsaPosition = 0;
        this.vsaEnd = 0;
        this.type = -1;
        this.vendorId = 0;
        return this;
    }

    /** Moves to the next attribute. Returns {@code false} at the end. */
    public boolean next() {
        if (vsaPosition < vsaEnd) {
            readVendorSubAttribute();
            return true;
        }
        if (position + 2 > end) {
            return false;
        }
        int attrType = buffer.getByte(position) & 0xFF;
        int attrLength = buffer.getByte(position + 1) & 0xFF;
        if (attrLength < 2 || position + attrLength > end) {
            // cannot happen for packets validated by RadiusPacket.wrap; stop rather than read out of bounds
            position = end;
            return false;
        }
        attributeOffset = position;
        attributeLength = attrLength;
        position += attrLength;

        if (attrType == VENDOR_SPECIFIC && attrLength > VSA_HEADER_LENGTH) {
            int vendor = buffer.getInt(attributeOffset + 2, BIG_ENDIAN);
            int format = formats.format(vendor);
            int subStart = attributeOffset + VSA_HEADER_LENGTH;
            int subEnd = attributeOffset + attrLength;
            if (vendor != 0 && vendorContentIsWellFormed(subStart, subEnd, format)) {
                vsaPosition = subStart;
                vsaEnd = subEnd;
                vsaFormat = format;
                vendorId = vendor;
                readVendorSubAttribute();
                return true;
            }
        }
        type = attrType;
        vendorId = 0;
        valueOffset = attributeOffset + 2;
        valueLength = attrLength - 2;
        return true;
    }

    private boolean vendorContentIsWellFormed(int start, int stop, int format) {
        int typeLength = VendorFormats.typeLength(format);
        int lengthLength = VendorFormats.lengthLength(format);
        int header = typeLength + lengthLength + (VendorFormats.continuation(format) ? 1 : 0);
        int p = start;
        while (p < stop) {
            int remaining = stop - p;
            if (remaining < header) {
                return false;
            }
            int subLength = lengthLength == 0 ? remaining : readUnsigned(p + typeLength, lengthLength);
            if (subLength < header || subLength > remaining) {
                return false;
            }
            p += subLength;
        }
        return true;
    }

    private void readVendorSubAttribute() {
        int typeLength = VendorFormats.typeLength(vsaFormat);
        int lengthLength = VendorFormats.lengthLength(vsaFormat);
        int header = typeLength + lengthLength + (VendorFormats.continuation(vsaFormat) ? 1 : 0);
        int remaining = vsaEnd - vsaPosition;
        int subLength = lengthLength == 0 ? remaining : readUnsigned(vsaPosition + typeLength, lengthLength);
        type = readUnsigned(vsaPosition, typeLength);
        valueOffset = vsaPosition + header;
        valueLength = subLength - header;
        vsaPosition += subLength;
    }

    private int readUnsigned(int at, int size) {
        return switch (size) {
            case 1 -> buffer.getByte(at) & 0xFF;
            case 2 -> buffer.getShort(at, BIG_ENDIAN) & 0xFFFF;
            default -> buffer.getInt(at, BIG_ENDIAN);
        };
    }

    /** Attribute type; the vendor type for vendor sub-attributes. */
    public int type() {
        return type;
    }

    /** Vendor id of a vendor sub-attribute, or {@code 0} for IETF (and opaque VSA) attributes. */
    public int vendorId() {
        return vendorId;
    }

    /** Whether the current entry is a vendor sub-attribute. */
    public boolean isVendorSpecific() {
        return vendorId != 0;
    }

    /** Absolute offset of the value in {@link #buffer()}. */
    public int valueOffset() {
        return valueOffset;
    }

    public int valueLength() {
        return valueLength;
    }

    /** Absolute offset of the enclosing top-level attribute header (the VSA for vendor sub-attributes). */
    public int attributeOffset() {
        return attributeOffset;
    }

    /** Length of the enclosing top-level attribute including its header. */
    public int attributeLength() {
        return attributeLength;
    }

    /** For RFC 6929 extended attributes: the Extended-Type byte, or {@code -1}. */
    public int extendedType() {
        if (vendorId != 0 || type < 241 || type > 246 || valueLength < 1) {
            return -1;
        }
        return buffer.getByte(valueOffset) & 0xFF;
    }

    public DirectBuffer buffer() {
        return buffer;
    }
}
