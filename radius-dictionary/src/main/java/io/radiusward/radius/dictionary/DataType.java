/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Attribute data types understood by the dictionary parser.
 *
 * <p>Covers the FreeRADIUS v4 type names as well as the v3 aliases still used by most operator
 * dictionaries ({@code integer}, {@code integer64}, {@code signed}, {@code extended}, ...).
 */
public enum DataType {
    STRING(-1, "string"),
    OCTETS(-1, "octets"),
    ABINARY(-1, "abinary"),
    IPV4_ADDR(4, "ipaddr", "ipv4addr"),
    IPV4_PREFIX(6, "ipv4prefix"),
    IPV6_ADDR(16, "ipv6addr"),
    IPV6_PREFIX(-1, "ipv6prefix"),
    COMBO_IP(-1, "combo-ip", "combo-ipaddr"),
    COMBO_PREFIX(-1, "combo-prefix", "combo-ipprefix"),
    IFID(8, "ifid"),
    ETHER(6, "ether"),
    BOOL(1, "bool"),
    UINT8(1, "byte", "uint8"),
    UINT16(2, "short", "uint16"),
    UINT32(4, "integer", "uint32"),
    UINT64(8, "integer64", "uint64"),
    INT8(1, "int8"),
    INT16(2, "int16"),
    INT32(4, "signed", "int32"),
    INT64(8, "int64"),
    FLOAT32(4, "float32"),
    FLOAT64(8, "float64"),
    DATE(4, "date"),
    TIME_DELTA(4, "time_delta"),
    SIZE(8, "size"),
    BIT(-1, "bit"),
    TLV(-1, "tlv"),
    STRUCT(-1, "struct"),
    UNION(-1, "union"),
    GROUP(-1, "group"),
    VSA(-1, "vsa"),
    VENDOR(-1, "vendor"),
    EXTENDED(-1, "extended"),
    LONG_EXTENDED(-1, "long-extended"),
    EVS(-1, "evs");

    private static final Map<String, DataType> BY_NAME = new HashMap<>();

    static {
        for (DataType type : values()) {
            for (String name : type.names) {
                BY_NAME.put(name, type);
            }
        }
    }

    private final int wireLength;
    private final String[] names;

    DataType(int wireLength, String... names) {
        this.wireLength = wireLength;
        this.names = names;
    }

    /** Fixed wire length in bytes, or {@code -1} if the length is variable. */
    public int wireLength() {
        return wireLength;
    }

    /** Canonical dictionary name of this type. */
    public String dictionaryName() {
        return names[0];
    }

    /** Whether attributes of this type can have numbered child attributes. */
    public boolean isStructural() {
        return switch (this) {
            case TLV, STRUCT, UNION, VSA, VENDOR, EXTENDED, LONG_EXTENDED, EVS -> true;
            default -> false;
        };
    }

    /** Whether values of this type are integers that {@code VALUE} lines can name. */
    public boolean isInteger() {
        return switch (this) {
            case BOOL, BIT, UINT8, UINT16, UINT32, UINT64, INT8, INT16, INT32, INT64, DATE, TIME_DELTA, SIZE -> true;
            default -> false;
        };
    }

    /**
     * Looks up a type by its dictionary name, ignoring an optional {@code [length]} suffix.
     *
     * @return the type, or {@code null} if the name is unknown
     */
    public static DataType fromDictionaryName(String name) {
        int bracket = name.indexOf('[');
        String base = bracket >= 0 ? name.substring(0, bracket) : name;
        return BY_NAME.get(base.toLowerCase(Locale.ROOT));
    }
}
