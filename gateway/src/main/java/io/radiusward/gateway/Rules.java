/*
 * Copyright 2026 The radiusward Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package io.radiusward.gateway;

import io.radiusward.auth.AttributeItem;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * A small rule layer (ADR 0051), applied to an Access-Accept after the credentials, limits and pools:
 *
 * <pre>
 * # comment
 * if NAS-Port-Type == Wireless-802.11 &amp;&amp; Group == guests {
 *     reply Session-Timeout := 3600
 *     reply Filter-Id = "guest-%{Called-Station-Id}"
 *     remove Framed-IP-Address
 *     stop
 * }
 * if User-Name =~ "^test-" &amp;&amp; NAS-IP-Address absent {
 *     reject
 * }
 * </pre>
 *
 * Conditions compare request attributes like check items ({@code == != =~ !~ < > <= >=}), test {@code present} or
 * {@code absent}, or ask for a group ({@code Group == name}, {@code Group != name}); all conditions of a rule must hold.
 * Rules run in order; every matching rule applies until {@code reject} or {@code stop}. Reply actions: {@code =} adds
 * if the attribute is absent, {@code :=} replaces, {@code +=} adds; {@code remove} drops all of an attribute.
 * {@code %{Attribute}} in a value is the request's attribute (empty when absent).
 */
final class Rules {

    static final Rules NONE = new Rules(List.of());

    private static final Set<String> COMPARISONS = Set.of("==", "!=", "=~", "!~", "<", ">", "<=", ">=");
    private static final Pattern EXPANSION = Pattern.compile("%\\{([A-Za-z0-9._-]+)}");

    /** A request as rules see it: attribute values as text, and the groups that applied. */
    interface Request {
        /** The value as text, {@code null} if absent or unknown. */
        String value(String attribute);

        boolean inGroup(String group);
    }

    /** A condition of a rule, ready to test: its operator and pattern parsed when the file was read. */
    sealed interface Condition permits InGroup, Presence, Comparison {
        boolean holds(Request request);
    }

    /** {@code Group == name} ({@code member}) or {@code Group != name}. */
    record InGroup(String group, boolean member) implements Condition {
        @Override
        public boolean holds(Request request) {
            return request.inGroup(group) == member;
        }
    }

    /** {@code Attribute present} or {@code Attribute absent}. */
    record Presence(String attribute, boolean present) implements Condition {
        @Override
        public boolean holds(Request request) {
            return (request.value(attribute) != null) == present;
        }
    }

    /** {@code Attribute <op> value} ({@link ValueComparison}); {@code pattern} for {@code =~} and {@code !~}. */
    record Comparison(String attribute, String op, String value, Pattern pattern) implements Condition {
        @Override
        public boolean holds(Request request) {
            return ValueComparison.holds(op, request.value(attribute), value, pattern);
        }
    }

    /** What an action leaves the rest of the rules to do. */
    enum Next {
        GO_ON,
        STOP,
        REJECT
    }

    /** An action of a rule. */
    sealed interface Action permits Reject, Stop, Remove, Reply {
        Next apply(Request request, List<AttributeItem> reply);
    }

    record Reject() implements Action {
        @Override
        public Next apply(Request request, List<AttributeItem> reply) {
            return Next.REJECT;
        }
    }

    record Stop() implements Action {
        @Override
        public Next apply(Request request, List<AttributeItem> reply) {
            return Next.STOP;
        }
    }

    /** {@code remove Attribute}: every one of it. */
    record Remove(String attribute) implements Action {
        @Override
        public Next apply(Request request, List<AttributeItem> reply) {
            reply.removeIf(r -> r.attribute().equalsIgnoreCase(attribute));
            return Next.GO_ON;
        }
    }

    /** How {@code reply} adds: {@code =} if absent, {@code :=} replacing, {@code +=} in any case. */
    enum Mode {
        IF_ABSENT,
        REPLACE,
        ADD
    }

    /** {@code reply Attribute =|:=|+= value}, with {@code %{Attribute}} expanded from the request. */
    record Reply(String attribute, Mode mode, String value) implements Action {
        @Override
        public Next apply(Request request, List<AttributeItem> reply) {
            String expanded = expand(value, request);
            switch (mode) {
                case REPLACE -> {
                    reply.removeIf(r -> r.attribute().equalsIgnoreCase(attribute));
                    reply.add(new AttributeItem(attribute, "=", expanded));
                }
                case IF_ABSENT -> {
                    if (reply.stream().noneMatch(r -> r.attribute().equalsIgnoreCase(attribute))) {
                        reply.add(new AttributeItem(attribute, "=", expanded));
                    }
                }
                case ADD -> reply.add(new AttributeItem(attribute, "+=", expanded));
            }
            return Next.GO_ON;
        }
    }

    record Rule(int line, List<Condition> conditions, List<Action> actions) {}

    private final List<Rule> rules;

    private Rules(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    List<Rule> rules() {
        return rules;
    }

    /**
     * Applies the rules to {@code reply} (changed in place).
     *
     * @return {@code false} if a rule rejected
     */
    boolean apply(Request request, List<AttributeItem> reply) {
        for (Rule rule : rules) {
            if (!matches(rule, request)) {
                continue;
            }
            for (Action action : rule.actions()) {
                Next next = action.apply(request, reply);
                if (next != Next.GO_ON) {
                    return next == Next.STOP;
                }
            }
        }
        return true;
    }

    private static boolean matches(Rule rule, Request request) {
        for (Condition c : rule.conditions()) {
            if (!c.holds(request)) {
                return false;
            }
        }
        return true;
    }

    private static String expand(String value, Request request) {
        if (value.indexOf('%') < 0) {
            return value;
        }
        Matcher m = EXPANSION.matcher(value);
        StringBuilder out = new StringBuilder();
        while (m.find()) {
            String v = request.value(m.group(1));
            m.appendReplacement(out, Matcher.quoteReplacement(v == null ? "" : v));
        }
        m.appendTail(out);
        return out.toString();
    }

    // ---- parsing ------------------------------------------------------------------------------------------------

    /** Thrown for a rules file that does not parse; the message names the line. */
    static final class RuleException extends RuntimeException {
        RuleException(int line, String message) {
            super("line " + line + ": " + message);
        }
    }

    /**
     * Parses a rules file.
     *
     * @param known whether a name is a dictionary attribute (conditions and actions must name one)
     */
    static Rules parse(String text, Function<String, Boolean> known) {
        List<Rule> rules = new ArrayList<>();
        String[] lines = text.split("\r?\n", -1);
        Rule open = null;
        for (int n = 0; n < lines.length; n++) {
            int line = n + 1;
            List<String> tokens = tokens(lines[n], line);
            if (tokens.isEmpty()) {
                continue;
            }
            if (open == null) {
                if (!tokens.get(0).equals("if")
                        || !tokens.get(tokens.size() - 1).equals("{")) {
                    throw new RuleException(line, "expected: if <conditions> {");
                }
                open = new Rule(line, conditions(tokens.subList(1, tokens.size() - 1), line, known), new ArrayList<>());
                continue;
            }
            if (tokens.size() == 1 && tokens.get(0).equals("}")) {
                if (open.actions().isEmpty()) {
                    throw new RuleException(line, "a rule without actions");
                }
                rules.add(new Rule(open.line(), open.conditions(), List.copyOf(open.actions())));
                open = null;
                continue;
            }
            open.actions().add(action(tokens, line, known));
        }
        if (open != null) {
            throw new RuleException(open.line(), "the rule is not closed with }");
        }
        return new Rules(rules);
    }

    private static List<Condition> conditions(List<String> tokens, int line, Function<String, Boolean> known) {
        List<Condition> conditions = new ArrayList<>();
        int at = 0;
        while (true) {
            if (at + 2 > tokens.size()) {
                throw new RuleException(line, "expected: <attribute> <operator> <value>");
            }
            String attribute = tokens.get(at);
            String op = tokens.get(at + 1);
            if (op.equals("present") || op.equals("absent")) {
                attribute(attribute, line, known);
                conditions.add(new Presence(attribute, op.equals("present")));
                at += 2;
            } else {
                if (!COMPARISONS.contains(op) || at + 3 > tokens.size()) {
                    throw new RuleException(line, "expected: <attribute> <operator> <value>");
                }
                conditions.add(comparison(attribute, op, unquote(tokens.get(at + 2)), line, known));
                at += 3;
            }
            if (at == tokens.size()) {
                return conditions;
            }
            if (!tokens.get(at).equals("&&")) {
                throw new RuleException(line, "conditions are joined with &&");
            }
            at++;
        }
    }

    private static Condition comparison(
            String attribute, String op, String value, int line, Function<String, Boolean> known) {
        if (attribute.equalsIgnoreCase("Group")) {
            if (!op.equals("==") && !op.equals("!=")) {
                throw new RuleException(line, "Group takes == or !=");
            }
            return new InGroup(value, op.equals("=="));
        }
        attribute(attribute, line, known);
        Pattern pattern = null;
        if (ValueComparison.isPattern(op)) {
            try {
                pattern = Pattern.compile(value);
            } catch (PatternSyntaxException e) {
                throw new RuleException(line, "invalid pattern " + value);
            }
        }
        return new Comparison(attribute, op, value, pattern);
    }

    private static Action action(List<String> tokens, int line, Function<String, Boolean> known) {
        String kind = tokens.get(0);
        switch (kind) {
            case "reject", "stop" -> {
                if (tokens.size() != 1) {
                    throw new RuleException(line, kind + " takes nothing");
                }
                return kind.equals("reject") ? new Reject() : new Stop();
            }
            case "remove" -> {
                if (tokens.size() != 2) {
                    throw new RuleException(line, "expected: remove <attribute>");
                }
                attribute(tokens.get(1), line, known);
                return new Remove(tokens.get(1));
            }
            case "reply" -> {
                Mode mode = tokens.size() != 4
                        ? null
                        : switch (tokens.get(2)) {
                            case "=" -> Mode.IF_ABSENT;
                            case ":=" -> Mode.REPLACE;
                            case "+=" -> Mode.ADD;
                            default -> null;
                        };
                if (mode == null) {
                    throw new RuleException(line, "expected: reply <attribute> =|:=|+= <value>");
                }
                attribute(tokens.get(1), line, known);
                return new Reply(tokens.get(1), mode, unquote(tokens.get(3)));
            }
            default -> throw new RuleException(line, "unknown action " + kind + " (reply, remove, reject, stop)");
        }
    }

    private static void attribute(String name, int line, Function<String, Boolean> known) {
        if (!known.apply(name)) {
            throw new RuleException(line, "unknown attribute " + name);
        }
    }

    private static String unquote(String token) {
        return token.startsWith("\"") ? token.substring(1) : token;
    }

    /** Words, operators, braces and quoted strings (kept with a leading quote mark), up to a comment. */
    private static List<String> tokens(String line, int number) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        while (i < line.length()) {
            char c = line.charAt(i);
            if (Character.isWhitespace(c)) {
                i++;
            } else if (c == '#') {
                break;
            } else if (c == '"') {
                StringBuilder s = new StringBuilder("\"");
                i++;
                while (true) {
                    if (i >= line.length()) {
                        throw new RuleException(number, "unterminated string");
                    }
                    char d = line.charAt(i++);
                    if (d == '"') {
                        break;
                    }
                    if (d == '\\' && i < line.length()) {
                        d = line.charAt(i++);
                    }
                    s.append(d);
                }
                tokens.add(s.toString());
            } else if (c == '{' || c == '}') {
                tokens.add(String.valueOf(c));
                i++;
            } else {
                int start = i;
                while (i < line.length()
                        && !Character.isWhitespace(line.charAt(i))
                        && line.charAt(i) != '{'
                        && line.charAt(i) != '}'
                        && line.charAt(i) != '"') {
                    i++;
                }
                tokens.add(line.substring(start, i));
            }
        }
        return tokens;
    }
}
