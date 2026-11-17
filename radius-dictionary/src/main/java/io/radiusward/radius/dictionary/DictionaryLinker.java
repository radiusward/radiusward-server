/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.radius.dictionary;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.agrona.collections.Int2ObjectHashMap;
import org.agrona.collections.Long2ObjectHashMap;

/**
 * What the parser leaves for the end: ALIAS lines and VALUE lines that may name an attribute defined later (in this
 * file or one included after it), resolved once everything is read; then the dictionary with its vendor-specific
 * index. Name look-ups (by path, from the root, by flat name) are here too, as the parser uses them as it goes.
 */
final class DictionaryLinker {

    private record PendingAlias(
            AttributeDef context, String name, String target, DictionaryFile.Location at, ParseMode mode) {}

    private record PendingValue(
            AttributeDef context,
            String attribute,
            String name,
            String value,
            DictionaryFile.Location at,
            ParseMode mode) {}

    private final AttributeDef root;
    private final Map<String, AttributeDef> flatNames;
    private final List<String> warnings;
    private final List<PendingAlias> pendingAliases = new ArrayList<>();
    private final List<PendingValue> pendingValues = new ArrayList<>();

    DictionaryLinker(AttributeDef root, Map<String, AttributeDef> flatNames, List<String> warnings) {
        this.root = root;
        this.flatNames = flatNames;
        this.warnings = warnings;
    }

    /** An ALIAS, resolved at the end. */
    void aliasLater(AttributeDef context, String name, String target, DictionaryFile.Location at, ParseMode mode) {
        pendingAliases.add(new PendingAlias(context, name, target, at, mode));
    }

    /** A VALUE for an attribute not defined yet, resolved at the end. */
    void valueLater(
            AttributeDef context,
            String attribute,
            String name,
            String value,
            DictionaryFile.Location at,
            ParseMode mode) {
        pendingValues.add(new PendingValue(context, attribute, name, value, at, mode));
    }

    /** {@code ref} from {@code context}, else from the root, else by its flat name; {@code null} if none. */
    AttributeDef lookup(AttributeDef context, String ref) {
        AttributeDef def = resolveReference(context, ref);
        if (def == null && context != root) {
            def = resolveReference(root, ref);
        }
        if (def == null) {
            def = flatNames.get(AttributeDef.key(ref));
        }
        return def;
    }

    /** {@code ref} (a path, {@code @} for one from the root) below {@code context}; {@code null} if none. */
    static AttributeDef resolveReference(AttributeDef context, String ref) {
        String path = ref.startsWith("@") ? ref.substring(1) : ref;
        return Dictionary.resolvePath(context, path);
    }

    /** Adds a VALUE to its attribute: a problem if the value does not fit its type. */
    void addValue(AttributeDef target, String name, String raw, DictionaryFile.Location at, ParseMode mode) {
        Long value = DictionaryNumbers.parseValue(target.type(), raw);
        if (value == null) {
            String message = at + ": VALUE " + name + "=" + raw + " is not valid for " + target;
            if (mode == ParseMode.STRICT) {
                throw new DictionaryException(message);
            }
            warnings.add(message + " (skipped)");
            return;
        }
        target.addValue(name, value);
    }

    /** Resolves what was left for later and builds the dictionary. */
    Dictionary link(
            Int2ObjectHashMap<VendorDef> vendorsById, Map<String, VendorDef> vendorsByName, List<String> loadedFiles) {
        resolveAliases();
        for (PendingValue pending : pendingValues) {
            AttributeDef target = lookup(pending.context(), pending.attribute());
            if (target == null) {
                String message = pending.at() + ": VALUE for undefined attribute " + pending.attribute();
                if (pending.mode() == ParseMode.STRICT) {
                    throw new DictionaryException(message);
                }
                warnings.add(message + " (skipped)");
                continue;
            }
            addValue(target, pending.name(), pending.value(), pending.at(), pending.mode());
        }

        Long2ObjectHashMap<AttributeDef> vsaIndex = new Long2ObjectHashMap<>();
        AttributeDef vsa = root.child(Dictionary.VENDOR_SPECIFIC);
        if (vsa != null) {
            for (AttributeDef vendorNode : vsa.children()) {
                for (AttributeDef attr : vendorNode.children()) {
                    vsaIndex.put(Dictionary.vsaKey(vendorNode.number(), attr.number()), attr);
                }
            }
        }
        Map<String, VendorDef> vendorNames = new HashMap<>(vendorsByName);
        return new Dictionary(
                root,
                vendorsById,
                vendorNames,
                vsaIndex,
                flatNames,
                warnings,
                loadedFiles,
                countAttributes(root, new HashSet<>()));
    }

    private void resolveAliases() {
        List<PendingAlias> remaining = new ArrayList<>(pendingAliases);
        boolean progress = true;
        while (!remaining.isEmpty() && progress) {
            progress = false;
            for (var it = remaining.iterator(); it.hasNext(); ) {
                PendingAlias alias = it.next();
                AttributeDef target = lookup(alias.context(), alias.target());
                if (target != null) {
                    if (!alias.context().hasNameOrAlias(alias.name())) {
                        alias.context().addAlias(alias.name(), target);
                    }
                    flatNames.putIfAbsent(AttributeDef.key(alias.name()), target);
                    it.remove();
                    progress = true;
                }
            }
        }
        for (PendingAlias alias : remaining) {
            String message = alias.at() + ": ALIAS " + alias.name() + " target not found: " + alias.target();
            if (alias.mode() == ParseMode.STRICT) {
                throw new DictionaryException(message);
            }
            warnings.add(message + " (skipped)");
        }
    }

    private static int countAttributes(AttributeDef node, Set<AttributeDef> seen) {
        int count = 0;
        for (AttributeDef child : node.children()) {
            if (!seen.add(child)) {
                continue;
            }
            if (child.type() != DataType.VENDOR) {
                count++;
            }
            count += countAttributes(child, seen);
        }
        return count;
    }
}
