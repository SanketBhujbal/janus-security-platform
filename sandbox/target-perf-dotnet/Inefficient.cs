// Deliberately inefficient C# code for rule-validation only.
// Each method maps 1:1 to a rule in orchestrator/rules/efficiency/dotnet-*.yml.
// DO NOT use in production. Wired for static analysis only -- no Program.cs,
// no .csproj; Semgrep parses these files standalone.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace TargetPerfDotnet;

public static class Inefficient
{
    // efficiency.dotnet.linear-search-in-loop
    public static List<int> FindCommonAccountIds(List<int> a, List<int> b)
    {
        var common = new List<int>();
        foreach (var id in a)
        {
            if (b.Contains(id))   // O(n) per probe -> O(n*m)
            {
                common.Add(id);
            }
        }
        return common;
    }

    // efficiency.dotnet.nested-loop-same-collection
    public static List<(string, string)> FindDuplicatePairs(List<Transaction> txs)
    {
        var pairs = new List<(string, string)>();
        foreach (var a in txs)
        {
            foreach (var b in txs)     // O(n^2)
            {
                if (a.Id != b.Id && a.UserId == b.UserId && a.Amount == b.Amount)
                {
                    pairs.Add((a.Id, b.Id));
                }
            }
        }
        return pairs;
    }

    // efficiency.dotnet.string-concat-in-loop
    public static string BuildCsvExport(List<string[]> rows)
    {
        string output = "";
        foreach (var row in rows)
        {
            output += string.Join(",", row) + "\n";   // O(n^2) memory churn
        }
        return output;
    }

    // efficiency.dotnet.regex-recompile-in-loop
    public static List<string> MaskPansInLogLines(List<string> lines)
    {
        var masked = new List<string>();
        foreach (var line in lines)
        {
            var pattern = new Regex(@"\b(\d{6})\d{6}(\d{4})\b");  // re-compiled per line
            masked.Add(pattern.Replace(line, "$1******$2"));
        }
        return masked;
    }

    // efficiency.dotnet.linq-count-vs-any
    public static bool HasAnyApprovedPayment(IEnumerable<Transaction> txs)
    {
        return txs.Where(t => t.Status == "approved").Count() > 0;  // .Any() is cheaper
    }

    // efficiency.dotnet.tolist-before-filter
    public static List<Transaction> RecentLargeTransactions(IQueryable<Transaction> source)
    {
        return source.ToList().Where(t => t.Amount > 1000m).ToList();
        // materializes the whole table before filtering
    }
}

public class Transaction
{
    public string Id { get; set; } = "";
    public int UserId { get; set; }
    public decimal Amount { get; set; }
    public string Status { get; set; } = "";
}

// Stub so the file is self-contained from Semgrep's POV; not actually used.
public interface IQueryable<T> : IEnumerable<T> { }
