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

    record Condition(String attribute, String op, String value, Pattern pattern) {}

    record Action(String kind, String attribute, String op, String value) {}

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
                switch (action.kind()) {
                    case "reject" -> {
                        return false;
                    }
                    case "stop" -> {
                        return true;
                    }
                    case "remove" -> reply.removeIf(r -> r.attribute().equalsIgnoreCase(action.attribute()));
                    default -> {
                        String value = expand(action.value(), request);
                        boolean present =
                                reply.stream().anyMatch(r -> r.attribute().equalsIgnoreCase(action.attribute()));
                        switch (action.op()) {
                            case ":=" -> {
                                reply.removeIf(r -> r.attribute().equalsIgnoreCase(action.attribute()));
                                reply.add(new AttributeItem(action.attribute(), "=", value));
                            }
                            case "=" -> {
                                if (!present) {
                                    reply.add(new AttributeItem(action.attribute(), "=", value));
                                }
                            }
                            default -> reply.add(new AttributeItem(action.attribute(), "+=", value));
                        }
                    }
                }
            }
        }
        return true;
    }

    private static boolean matches(Rule rule, Request request) {
        for (Condition c : rule.conditions()) {
            if (!holds(c, request)) {
                return false;
            }
        }
        return true;
    }

    private static boolean holds(Condition c, Request request) {
        if (c.attribute().equalsIgnoreCase("Group")) {
            boolean in = request.inGroup(c.value());
            return c.op().equals("==") == in;
        }
        String actual = request.value(c.attribute());
        return switch (c.op()) {
            case "present" -> actual != null;
            case "absent" -> actual == null;
            case "==" -> c.value().equals(actual);
            case "!=" -> !c.value().equals(actual);
            case "=~" -> actual != null && c.pattern().matcher(actual).find();
            case "!~" -> actual == null || !c.pattern().matcher(actual).find();
            default -> numeric(c.op(), actual, c.value());
        };
    }

    private static boolean numeric(String op, String actual, String expected) {
        try {
            long a = Long.parseLong(actual);
            long e = Long.parseLong(expected);
            return switch (op) {
                case "<" -> a < e;
                case ">" -> a > e;
                case "<=" -> a <= e;
                default -> a >= e;
            };
        } catch (NumberFormatException | NullPointerException ex) {
            return false;
        }
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
                conditions.add(new Condition(attribute, op, null, null));
                at += 2;
            } else {
                if (!COMPARISONS.contains(op) || at + 3 > tokens.size()) {
                    throw new RuleException(line, "expected: <attribute> <operator> <value>");
                }
                String value = unquote(tokens.get(at + 2));
                if (attribute.equalsIgnoreCase("Group")) {
                    if (!op.equals("==") && !op.equals("!=")) {
                        throw new RuleException(line, "Group takes == or !=");
                    }
                } else {
                    attribute(attribute, line, known);
                }
                Pattern pattern = null;
                if (op.equals("=~") || op.equals("!~")) {
                    try {
                        pattern = Pattern.compile(value);
                    } catch (PatternSyntaxException e) {
                        throw new RuleException(line, "invalid pattern " + value);
                    }
                }
                conditions.add(new Condition(attribute, op, value, pattern));
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

    private static Action action(List<String> tokens, int line, Function<String, Boolean> known) {
        String kind = tokens.get(0);
        switch (kind) {
            case "reject", "stop" -> {
                if (tokens.size() != 1) {
                    throw new RuleException(line, kind + " takes nothing");
                }
                return new Action(kind, null, null, null);
            }
            case "remove" -> {
                if (tokens.size() != 2) {
                    throw new RuleException(line, "expected: remove <attribute>");
                }
                attribute(tokens.get(1), line, known);
                return new Action(kind, tokens.get(1), null, null);
            }
            case "reply" -> {
                if (tokens.size() != 4 || !Set.of("=", ":=", "+=").contains(tokens.get(2))) {
                    throw new RuleException(line, "expected: reply <attribute> =|:=|+= <value>");
                }
                attribute(tokens.get(1), line, known);
                return new Action(kind, tokens.get(1), tokens.get(2), unquote(tokens.get(3)));
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
