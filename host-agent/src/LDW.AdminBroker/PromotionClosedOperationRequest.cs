using System.Text.Json;

namespace LDW.AdminBroker;

internal sealed record PromotionClosedOperationRequestResult(
    string Classification,
    string ReasonCode);

/// <summary>
/// Pure shape check for one future closed operation. It does not register,
/// enable, invoke, or authorize that operation. Caller bytes are untrusted.
/// </summary>
internal static class PromotionClosedOperationRequest
{
    internal const int MaxDocumentBytes = 4096;
    internal const string FixedIntent = "DRAGONFLY_V2_PUBLISH_REVIEWED";
    private const string DataOnly = "DATA_ONLY_REQUEST_SHAPE_NOT_AUTHORIZED";

    private static PromotionClosedOperationRequestResult Block(string reason) =>
        new("BLOCKED", reason);

    internal static PromotionClosedOperationRequestResult Validate(byte[]? input)
    {
        if (input is null || input.Length == 0 || input.Length > MaxDocumentBytes)
            return Block("REQUEST_ABSENT_OR_OVERSIZED");
        if (input.Length >= 3 && input[0] == 0xEF && input[1] == 0xBB && input[2] == 0xBF)
            return Block("REQUEST_ENCODING_REJECTED");

        try
        {
            var reader = new Utf8JsonReader(input, new JsonReaderOptions
            {
                CommentHandling = JsonCommentHandling.Disallow,
                AllowTrailingCommas = false,
                MaxDepth = 4
            });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
                return Block("REQUEST_NOT_OBJECT");

            var seen = new HashSet<string>(StringComparer.Ordinal);
            int? schema = null;
            string? intent = null;
            bool sawArguments = false;
            bool argumentsEmpty = false;
            string? forbidden = null;

            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                    break;
                if (reader.TokenType != JsonTokenType.PropertyName)
                    return Block("REQUEST_MALFORMED");

                var name = reader.GetString();
                if (string.IsNullOrEmpty(name) || !seen.Add(name))
                    return Block("DUPLICATE_OR_INVALID_FIELD");
                if (!reader.Read())
                    return Block("REQUEST_MALFORMED");

                switch (name)
                {
                    case "schema":
                        if (reader.TokenType != JsonTokenType.Number ||
                            !reader.TryGetInt32(out var schemaValue) || schemaValue != 1)
                            return Block("SCHEMA_MISMATCH");
                        schema = schemaValue;
                        break;
                    case "intent":
                        if (reader.TokenType != JsonTokenType.String)
                            return Block("OPERATION_MISMATCH");
                        intent = reader.GetString();
                        break;
                    case "arguments":
                        sawArguments = true;
                        if (reader.TokenType != JsonTokenType.StartArray)
                        {
                            forbidden ??= "ARGUMENTS_AMBIGUOUS";
                            ConsumeValue(ref reader);
                            break;
                        }
                        if (!reader.Read())
                            return Block("REQUEST_MALFORMED");
                        if (reader.TokenType == JsonTokenType.EndArray)
                            argumentsEmpty = true;
                        else
                        {
                            forbidden ??= "CALLER_SELECTED_ARGUMENTS";
                            while (reader.TokenType != JsonTokenType.EndArray)
                            {
                                ConsumeValue(ref reader);
                                if (!reader.Read())
                                    return Block("REQUEST_MALFORMED");
                            }
                        }
                        break;
                    default:
                        forbidden ??= ClassifyForbidden(name);
                        ConsumeValue(ref reader);
                        break;
                }
            }

            if (reader.TokenType != JsonTokenType.EndObject)
                return Block("REQUEST_MALFORMED");
            if (reader.BytesConsumed != input.Length)
                return Block("REQUEST_TRAILING_DATA");
            if (forbidden is not null)
                return Block(forbidden);
            if (schema != 1)
                return Block("SCHEMA_MISMATCH");
            if (!sawArguments || !argumentsEmpty)
                return Block("ARGUMENTS_AMBIGUOUS");
            if (!string.Equals(intent, FixedIntent, StringComparison.Ordinal))
                return Block("OPERATION_MISMATCH");

            // Shape agreement is not an issuer, review, disable, or launch decision.
            return new PromotionClosedOperationRequestResult(
                DataOnly, "EXTERNAL_TRUST_GATES_REQUIRED");
        }
        catch (JsonException)
        {
            return Block("REQUEST_MALFORMED");
        }
    }

    private static string ClassifyForbidden(string name) => name switch
    {
        "executable" or "command" or "program" => "CALLER_SELECTED_EXECUTABLE",
        "script" => "CALLER_SELECTED_SCRIPT",
        "path" or "file" or "workingDirectory" => "CALLER_SELECTED_PATH",
        "gitRef" or "ref" or "commit" or "tree" => "CALLER_SELECTED_GIT_REF",
        "url" or "endpointUrl" => "CALLER_SELECTED_URL",
        "packageDigest" or "packageSha256" or "digest" => "CALLER_SELECTED_PACKAGE_DIGEST",
        "providerAuthorization" or "authorization" or "token" => "PROVIDER_AUTHORIZATION_NOT_ACCEPTED",
        "environment" or "environmentExecutable" => "ENVIRONMENT_PROVIDED_EXECUTABLE",
        "requestId" or "actor" or "author" or "correlationId" or "replay" or "nonce"
            or "ttl" or "expiresUtc" or "issuedAt" => "IDENTITY_REPLAY_OR_TTL_AMBIGUOUS",
        _ => "UNKNOWN_FIELD"
    };

    private static void ConsumeValue(ref Utf8JsonReader reader)
    {
        if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
            reader.Skip();
    }
}
