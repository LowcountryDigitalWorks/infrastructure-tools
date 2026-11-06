using System.Security.Cryptography;
using System.Text;

namespace LDW.AdminBroker;

/// <summary>
/// #186 source-only non-authorizing immutable Git blob/package/catalog byte proof.
/// This function verifies supplied snapshots against supplied expected identities.
/// It does NOT authenticate their origin, authorize privileged operations, read
/// external files, fetch from GitHub, modify protected state, or install packages.
/// </summary>
internal static class PromotionImmutableByteProof
{
    internal const int MaxPackageBytes = 16_777_216;
    internal const int MaxCatalogBytes = 65_536;

    private static PromotionDataCheck Block(string reason) => new("BLOCKED", reason);

    internal static PromotionDataCheck Check(
        PromotionCommentFacts? facts,
        byte[]? packageBytes,
        byte[]? catalogBytes)
    {
        if (facts is null || packageBytes is null || catalogBytes is null)
            return Block("BYTE_INPUT_UNAVAILABLE");

        // Size ceilings before snapshot/copy/hashing. Input arrays are caller
        // controlled; copy to one local snapshot for consistent digest reads.
        if (packageBytes.Length is <= 0 or > MaxPackageBytes ||
            catalogBytes.Length is <= 0 or > MaxCatalogBytes)
            return Block("BYTE_INPUT_OUT_OF_BOUNDS");
        if (facts.PackageLength != packageBytes.LongLength)
            return Block("PACKAGE_LENGTH_MISMATCH");

        var packageSnapshot = packageBytes.ToArray();
        var catalogSnapshot = catalogBytes.ToArray();

        // Both digests are required. SHA-1 is ONLY Git's canonical object ID,
        // not a security digest; SHA-256 and independently accepted provenance
        // are separate mandatory gates. This proof does not trust supplied facts.
        var sha256 = Convert.ToHexString(SHA256.HashData(packageSnapshot)).ToLowerInvariant();
        if (!string.Equals(sha256, facts.PackageSha256, StringComparison.Ordinal))
            return Block("PACKAGE_SHA256_MISMATCH");

        using var gitBlobHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        var header = Encoding.ASCII.GetBytes($"blob {packageSnapshot.Length}\0");
        gitBlobHash.AppendData(header);
        gitBlobHash.AppendData(packageSnapshot);
        var gitBlobSha1 = Convert.ToHexString(gitBlobHash.GetHashAndReset()).ToLowerInvariant();
        if (!string.Equals(gitBlobSha1, facts.PackageBlobSha1, StringComparison.Ordinal))
            return Block("GIT_BLOB_SHA1_MISMATCH");

        var catalogSha256 = Convert.ToHexString(SHA256.HashData(catalogSnapshot)).ToLowerInvariant();
        if (!string.Equals(catalogSha256, facts.CatalogSha256, StringComparison.Ordinal))
            return Block("CATALOG_SHA256_MISMATCH");

        // Matching untrusted data cannot substitute for an authenticated
        // 165-W authorization, source review, package ACL/reparse validation,
        // data-only catalog schema verification, or protected stage/readback.
        return new PromotionDataCheck(
            "DATA_ONLY_BYTES_MATCH_NOT_AUTHORIZED", "EXTERNAL_TRUST_GATES_REQUIRED");
    }
}
