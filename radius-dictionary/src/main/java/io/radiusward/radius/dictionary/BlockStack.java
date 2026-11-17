/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * The open blocks of the files being read: {@code BEGIN PROTOCOL}, {@code BEGIN-VENDOR}, {@code BEGIN}/{@code
 * BEGIN-TLV} blocks, each with the node new attributes go under; and blocks that are skipped (another protocol, an
 * undefined vendor or attribute), whose lines are read only to find their end.
 */
final class BlockStack {

    enum Kind {
        PROTOCOL,
        VENDOR,
        BLOCK,
        SKIP
    }

    /** An open block. */
    static final class Frame {
        final Kind kind;
        final AttributeDef node;
        final String label;
        final String endKeyword;
        /** The last tlv/struct/vsa defined here, for numbers relative to it ({@code .1}). */
        AttributeDef lastStructural;
        /** The struct just defined here, for its MEMBER and VALUE lines. */
        AttributeDef lastStruct;

        int skipDepth;

        Frame(Kind kind, AttributeDef node, String label, String endKeyword) {
            this.kind = kind;
            this.node = node;
            this.label = label;
            this.endKeyword = endKeyword;
        }
    }

    private final Deque<Frame> frames = new ArrayDeque<>();
    private final AttributeDef root;

    /** Starts in the RADIUS protocol, at {@code root}. */
    BlockStack(AttributeDef root) {
        this.root = root;
        frames.push(new Frame(Kind.PROTOCOL, root, DictionaryParser.PROTOCOL_RADIUS, "END-PROTOCOL"));
    }

    Frame top() {
        return frames.peek();
    }

    int depth() {
        return frames.size();
    }

    boolean skipping() {
        return frames.peek().kind == Kind.SKIP;
    }

    void open(Kind kind, AttributeDef node, String label, String endKeyword) {
        frames.push(new Frame(kind, node, label, endKeyword));
    }

    /** A block whose lines are not read, up to {@code endKeyword}. */
    void skip(String label, String endKeyword) {
        frames.push(new Frame(Kind.SKIP, null, label, endKeyword));
    }

    /** Closes the blocks a file left open beyond {@code depth}: the innermost one, or {@code null} if none was. */
    String closeTo(int depth) {
        if (frames.size() == depth) {
            return null;
        }
        String open = frames.peek().kind + " " + frames.peek().label;
        while (frames.size() > depth) {
            frames.pop();
        }
        return open;
    }

    /** A line inside a skipped block: nested blocks of the same kind are counted, its end leaves it. */
    void skipLine(String keyword, String[] t) {
        Frame frame = frames.peek();
        boolean opensSame = switch (frame.endKeyword) {
            case "END-VENDOR" -> keyword.equals("BEGIN-VENDOR");
            case "END-PROTOCOL" ->
                keyword.equals("BEGIN-PROTOCOL")
                        || (keyword.equals("BEGIN") && t.length > 1 && t[1].equalsIgnoreCase("PROTOCOL"));
            default -> keyword.equals("BEGIN") || keyword.equals("BEGIN-TLV");
        };
        if (opensSame) {
            frame.skipDepth++;
        } else if (keyword.equals(frame.endKeyword)) {
            if (frame.skipDepth == 0) {
                frames.pop();
            } else {
                frame.skipDepth--;
            }
        }
    }

    /** {@code BEGIN PROTOCOL <name>} or {@code BEGIN <tlv/struct/vsa>}. */
    void begin(DictionaryFile file, String[] t) {
        if (!file.requireTokens(t, 2)) {
            return;
        }
        if (t[1].equalsIgnoreCase("PROTOCOL")) {
            beginProtocol(file, t, 2);
        } else {
            beginBlock(file, t, 1, "END");
        }
    }

    void beginProtocol(DictionaryFile file, String[] t, int nameIndex) {
        if (!file.requireTokens(t, nameIndex + 1)) {
            return;
        }
        String protocol = t[nameIndex];
        if (!protocol.equalsIgnoreCase(DictionaryParser.PROTOCOL_RADIUS)) {
            file.warn("protocol " + protocol + " ignored");
            frames.push(new Frame(Kind.SKIP, null, protocol, "END-PROTOCOL"));
            return;
        }
        frames.push(new Frame(Kind.PROTOCOL, root, DictionaryParser.PROTOCOL_RADIUS, "END-PROTOCOL"));
    }

    void endProtocol(DictionaryFile file) {
        Frame frame = frames.peek();
        if (frame.kind != Kind.PROTOCOL || frames.size() == 1) {
            file.problem("END-PROTOCOL without BEGIN PROTOCOL");
            return;
        }
        frames.pop();
    }

    /** A block of attributes under {@code t[refIndex]}, a defined tlv/struct/vsa; skipped otherwise. */
    void beginBlock(DictionaryFile file, String[] t, int refIndex, String endKeyword) {
        if (!file.requireTokens(t, refIndex + 1)) {
            return;
        }
        Frame frame = frames.peek();
        AttributeDef target = DictionaryLinker.resolveReference(frame.node, t[refIndex]);
        if (target == null) {
            target = DictionaryLinker.resolveReference(root, t[refIndex]);
        }
        if (target == null || !target.type().isStructural()) {
            file.problem(t[0] + " " + t[refIndex] + ": not a defined tlv/struct/vsa");
            frames.push(new Frame(Kind.SKIP, null, t[refIndex], endKeyword));
            return;
        }
        frames.push(new Frame(Kind.BLOCK, target, t[refIndex], endKeyword));
    }

    void end(DictionaryFile file, String[] t, String keyword) {
        Frame frame = frames.peek();
        if (frame.kind != Kind.BLOCK || !frame.endKeyword.equals(keyword)) {
            file.problem(keyword + " without matching BEGIN");
            return;
        }
        if (t.length > 1 && !t[1].equalsIgnoreCase(frame.label)) {
            file.problem(keyword + " " + t[1] + " does not match BEGIN " + frame.label);
        }
        frames.pop();
    }

    /** {@code END-VENDOR [name]}; {@code named}: the vendor the name refers to, {@code null} without one. */
    void endVendor(DictionaryFile file, String[] t, VendorDef named) {
        Frame frame = frames.peek();
        if (frame.kind != Kind.VENDOR) {
            file.problem("END-VENDOR without BEGIN-VENDOR");
            return;
        }
        if (t.length > 1 && named != frame.node.vendor()) {
            file.problem("END-VENDOR " + t[1] + " does not match BEGIN-VENDOR " + frame.label);
        }
        frames.pop();
    }
}
