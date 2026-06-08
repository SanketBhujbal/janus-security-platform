// Deliberately inefficient Java code for rule-validation only.
// Each method maps 1:1 to a rule in orchestrator/rules/efficiency/java-*.yml.
// DO NOT use in production. Wired for static analysis only -- no main(),
// no build.gradle; Semgrep parses this file standalone.

package com.aci.speedpay.perf;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class Inefficient {

    // efficiency.java.linear-search-in-loop
    public static List<Integer> findCommonAccountIds(List<Integer> a, List<Integer> b) {
        List<Integer> common = new ArrayList<>();
        for (Integer id : a) {
            if (b.contains(id)) {          // O(n) per probe -> O(n*m)
                common.add(id);
            }
        }
        return common;
    }

    // efficiency.java.nested-loop-same-collection
    public static List<String> findDuplicatePairs(List<Transaction> txs) {
        List<String> pairs = new ArrayList<>();
        for (Transaction a : txs) {
            for (Transaction b : txs) {                    // O(n^2)
                if (!a.id.equals(b.id) && a.userId == b.userId && a.amount == b.amount) {
                    pairs.add(a.id + "+" + b.id);
                }
            }
        }
        return pairs;
    }

    // efficiency.java.string-concat-in-loop
    public static String buildCsvExport(List<String[]> rows) {
        String output = "";
        for (String[] row : rows) {
            output += String.join(",", row) + "\n";        // O(n^2) memory churn
        }
        return output;
    }

    // efficiency.java.regex-recompile-in-loop
    public static List<String> maskPansInLogLines(List<String> lines) {
        List<String> masked = new ArrayList<>();
        for (String line : lines) {
            Pattern pattern = Pattern.compile("\\b(\\d{6})\\d{6}(\\d{4})\\b");
            masked.add(pattern.matcher(line).replaceAll("$1******$2"));
        }
        return masked;
    }

    // efficiency.java.boxing-in-arithmetic-loop
    public static Integer totalAmountCents(List<Transaction> txs) {
        Integer total = 0;                                  // boxed accumulator
        for (Transaction t : txs) {
            total = total + (int)(t.amount * 100);          // autobox each iteration
        }
        return total;
    }

    // Domain stub
    public static class Transaction {
        public String id = "";
        public int userId;
        public double amount;
        public String status = "";
    }
}
