using System.Text.Json;

namespace OTS.Firewall79X.Core;

/// <summary>
/// Bounded validation for the official OSV querybatch response format. Each page
/// must have exactly as many results as the queries submitted in that request.
/// Pagination tokens are untrusted opaque data: never execute, display or log them.
/// No empty result is represented as a security assurance.
/// </summary>
public static class OsvBatchValidator
{
    public sealed record Finding(string Name, string Version, IReadOnlyList<string> AdvisoryIds, bool NeedsAnotherPage);
    public sealed record Summary(int Queried, int PackagesAffected, int AdvisoryCount, bool Complete, IReadOnlyList<Finding> Findings);
    public sealed record PageResult(IReadOnlyList<string> AdvisoryIds, string? NextPageToken);
    public sealed record Page(IReadOnlyList<PageResult> Results);

    public static Page ParsePage(string body, int expectedCount)
    {
        if (body is null || body.Length > 1024 * 1024 || expectedCount is < 1 or > 100)
            throw new InvalidDataException("OSV response or query count exceeded budget");
        using var data = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 20 });
        if (data.RootElement.ValueKind != JsonValueKind.Object ||
            !data.RootElement.TryGetProperty("results", out var results) ||
            results.ValueKind != JsonValueKind.Array ||
            results.GetArrayLength() != expectedCount)
            throw new InvalidDataException("OSV response does not match submitted package count");

        List<PageResult> parsed = new(expectedCount);
        foreach (var result in results.EnumerateArray())
        {
            if (result.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("OSV result must be an object");

            string? token = null;
            if (result.TryGetProperty("next_page_token", out var continuation))
            {
                if (continuation.ValueKind != JsonValueKind.String)
                    throw new InvalidDataException("OSV pagination token is not a string");
                token = continuation.GetString();
                if (token is { Length: > 0 } && (token.Length > 4096 ||
                    token.Any(c => !char.IsAsciiLetterOrDigit(c) &&
                        c is not ('+' or '/' or '=' or '-' or '_'))))
                    throw new InvalidDataException("OSV pagination token is oversized or contains control characters");
                if (string.IsNullOrEmpty(token)) token = null;
            }

            var ids = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            if (result.TryGetProperty("vulns", out var vulns))
            {
                if (vulns.ValueKind != JsonValueKind.Array || vulns.GetArrayLength() > 4096)
                    throw new InvalidDataException("OSV advisory list is invalid or too large");
                foreach (var entry in vulns.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.Object ||
                        !entry.TryGetProperty("id", out var id) ||
                        id.ValueKind != JsonValueKind.String)
                        throw new InvalidDataException("OSV advisory is missing an ID");
                    var value = id.GetString() ?? "";
                    if (value.Length is < 1 or > 100 ||
                        !value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'))
                        throw new InvalidDataException("Invalid OSV advisory identifier");
                    ids.Add(value);
                }
            }
            parsed.Add(new(ids.ToArray(), token));
        }
        return new(parsed);
    }

    // Compatibility entrypoint used by existing pure regression checks.
    public static Summary Parse(string body, IReadOnlyList<NuGetLockParser.Package> packages)
    {
        if (packages is null) throw new ArgumentNullException(nameof(packages));
        var page = ParsePage(body, packages.Count);
        List<Finding> findings = [];
        int affected = 0, count = 0;
        bool complete = true;
        for (int i = 0; i < page.Results.Count; i++)
        {
            var result = page.Results[i];
            if (result.NextPageToken is not null) complete = false;
            if (result.AdvisoryIds.Count > 0) affected++;
            count += result.AdvisoryIds.Count;
            if (result.AdvisoryIds.Count > 0 || result.NextPageToken is not null)
                findings.Add(new(packages[i].Name, packages[i].Version,
                    result.AdvisoryIds, result.NextPageToken is not null));
        }
        return new(packages.Count, affected, count, complete, findings);
    }
}
