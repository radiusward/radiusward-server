/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.codec;

/** RADIUS packet codes (RFC 2865, 2866, 5176, 5997). */
public final class RadiusCode {

    public static final int ACCESS_REQUEST = 1;
    public static final int ACCESS_ACCEPT = 2;
    public static final int ACCESS_REJECT = 3;
    public static final int ACCOUNTING_REQUEST = 4;
    public static final int ACCOUNTING_RESPONSE = 5;
    public static final int ACCESS_CHALLENGE = 11;
    public static final int STATUS_SERVER = 12;
    public static final int STATUS_CLIENT = 13;
    public static final int DISCONNECT_REQUEST = 40;
    public static final int DISCONNECT_ACK = 41;
    public static final int DISCONNECT_NAK = 42;
    public static final int COA_REQUEST = 43;
    public static final int COA_ACK = 44;
    public static final int COA_NAK = 45;

    private RadiusCode() {}

    /** Human readable name, for logs and tooling. */
    public static String name(int code) {
        return switch (code) {
            case ACCESS_REQUEST -> "Access-Request";
            case ACCESS_ACCEPT -> "Access-Accept";
            case ACCESS_REJECT -> "Access-Reject";
            case ACCOUNTING_REQUEST -> "Accounting-Request";
            case ACCOUNTING_RESPONSE -> "Accounting-Response";
            case ACCESS_CHALLENGE -> "Access-Challenge";
            case STATUS_SERVER -> "Status-Server";
            case STATUS_CLIENT -> "Status-Client";
            case DISCONNECT_REQUEST -> "Disconnect-Request";
            case DISCONNECT_ACK -> "Disconnect-ACK";
            case DISCONNECT_NAK -> "Disconnect-NAK";
            case COA_REQUEST -> "CoA-Request";
            case COA_ACK -> "CoA-ACK";
            case COA_NAK -> "CoA-NAK";
            default -> "Unknown-" + code;
        };
    }

    /**
     * Whether the Request Authenticator of this request code is an MD5 over the packet (accounting,
     * CoA, Disconnect) rather than a random nonce (Access-Request, Status-Server).
     */
    public static boolean hasComputedRequestAuthenticator(int code) {
        return code == ACCOUNTING_REQUEST || code == DISCONNECT_REQUEST || code == COA_REQUEST;
    }
}
