/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.auth;

/**
 * Checks credentials somewhere else — a directory or a domain controller — for users whose store has no password
 * (ADR 0025). The identity stores still supply the user's check items, groups and reply items; a verifier only says
 * whether the credential is right.
 *
 * <p>Called from several gateway workers at once; must return within its own timeouts. {@link
 * StoreUnavailableException} when it cannot tell (the request is then not answered), never a guess.
 */
public interface CredentialVerifier extends AutoCloseable {

    /** The outcome of a check. */
    enum Outcome {
        ACCEPTED,
        REJECTED,
        /** this verifier cannot check this kind of credential */
        UNSUPPORTED
    }

    /**
     * @param outcome the decision
     * @param ntHashHash for an accepted MS-CHAP check, the MD4 of the user's NT hash (the "user session key"), which
     *     the MS-CHAPv2 success message and the MPPE keys are derived from; {@code null} otherwise
     */
    record Result(Outcome outcome, byte[] ntHashHash) {

        public static final Result REJECTED = new Result(Outcome.REJECTED, null);
        public static final Result UNSUPPORTED = new Result(Outcome.UNSUPPORTED, null);

        public static Result accepted(byte[] ntHashHash) {
            return new Result(Outcome.ACCEPTED, ntHashHash);
        }

        public boolean accepted() {
            return outcome == Outcome.ACCEPTED;
        }
    }

    /** PAP: the user name as the NAS sent it and the decrypted password. */
    default Result verifyPassword(String userName, byte[] password) throws StoreUnavailableException {
        return Result.UNSUPPORTED;
    }

    /**
     * MS-CHAP (v1 and v2): the 8-byte challenge the 24-byte NT response answers — for v2 the challenge hash
     * (RFC 2759) — and whether it is v2.
     */
    default Result verifyMsChap(String userName, byte[] challenge, byte[] ntResponse, boolean v2)
            throws StoreUnavailableException {
        return Result.UNSUPPORTED;
    }

    @Override
    void close();
}
