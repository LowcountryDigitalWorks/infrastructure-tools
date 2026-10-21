using System.Text.Json;

namespace LDW.AdminBroker;

public sealed record CodyncBotDefinition(
    string BotId,
    string Name,
    string Description,
    string EndpointUrl,
    IReadOnlyList<string> Capabilities,
    DateTime LastUpdatedUtc);

public sealed class CodyncBotStore
{
    private readonly string _filePath;
    private readonly object _lock = new();

    public CodyncBotStore(string? customPath = null)
    {
        _filePath = !string.IsNullOrWhiteSpace(customPath)
            ? customPath
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "LowcountryDigitalWorks",
                "AdminBroker",
                "codync-bots.json");
    }

    public bool TryGetBot(string botId, out CodyncBotDefinition? bot)
    {
        lock (_lock)
        {
            var bots = LoadBots();
            return bots.TryGetValue(botId, out bot);
        }
    }

    public bool SaveBot(CodyncBotDefinition bot)
    {
        lock (_lock)
        {
            var bots = LoadBots();
            bots[bot.BotId] = bot;
            return SaveBots(bots);
        }
    }

    public bool DeleteBot(string botId)
    {
        lock (_lock)
        {
            var bots = LoadBots();
            if (!bots.Remove(botId))
                return false;

            return SaveBots(bots);
        }
    }

    private Dictionary<string, CodyncBotDefinition> LoadBots()
    {
        if (!File.Exists(_filePath))
            return new Dictionary<string, CodyncBotDefinition>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var json = File.ReadAllText(_filePath);
            var list = JsonSerializer.Deserialize<List<CodyncBotDefinition>>(json);
            if (list is null)
                return new Dictionary<string, CodyncBotDefinition>(StringComparer.OrdinalIgnoreCase);

            return list.ToDictionary(b => b.BotId, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, CodyncBotDefinition>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private bool SaveBots(Dictionary<string, CodyncBotDefinition> bots)
    {
        try
        {
            var directory = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var options = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(bots.Values, options);
            File.WriteAllText(_filePath, json);
            return true;
        }
        catch
        {
            return false;
        }
    }
}

public sealed class CodyncBotHandler
{
    private readonly CodyncBotStore _store;

    public CodyncBotHandler(CodyncBotStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public AdminBrokerResponse HandleCreate(AdminBrokerRequest request)
    {
        var botId = request.TargetIdentity;
        if (!IsValidBotId(botId))
        {
            return Failure(request, "InvalidTarget", "BotId is invalid.", "INVALID_TARGET_IDENTITY");
        }

        if (_store.TryGetBot(botId, out _))
        {
            return Failure(request, "AlreadyExists", $"Bot '{botId}' already exists.", "BOT_ALREADY_EXISTS");
        }

        if (!TryParseBotParams(request, out var name, out var description, out var endpointUrl, out var capabilities, out var paramError))
        {
            return Failure(request, "InvalidParameters", paramError ?? "Invalid bot parameters.", "INVALID_PARAMETERS");
        }

        var newBot = new CodyncBotDefinition(
            botId,
            name,
            description,
            endpointUrl,
            capabilities,
            DateTime.UtcNow);

        if (!_store.SaveBot(newBot))
        {
            return Failure(request, "StorageFailure", "Failed to persist bot definition.", "STORAGE_ERROR");
        }

        var details = CreateBotDetailsDict(newBot, "Created");
        return Success(request, "Created", $"Codync bot '{botId}' created successfully.", details);
    }

    public AdminBrokerResponse HandleUpdate(AdminBrokerRequest request)
    {
        var botId = request.TargetIdentity;
        if (!IsValidBotId(botId))
        {
            return Failure(request, "InvalidTarget", "BotId is invalid.", "INVALID_TARGET_IDENTITY");
        }

        if (!_store.TryGetBot(botId, out var existingBot) || existingBot is null)
        {
            return Failure(request, "NotFound", $"Bot '{botId}' does not exist.", "BOT_NOT_FOUND");
        }

        if (!TryParseBotParams(request, out var name, out var description, out var endpointUrl, out var capabilities, out var paramError))
        {
            return Failure(request, "InvalidParameters", paramError ?? "Invalid bot parameters.", "INVALID_PARAMETERS");
        }

        var updatedBot = existingBot with
        {
            Name = name,
            Description = description,
            EndpointUrl = endpointUrl,
            Capabilities = capabilities,
            LastUpdatedUtc = DateTime.UtcNow
        };

        if (!_store.SaveBot(updatedBot))
        {
            return Failure(request, "StorageFailure", "Failed to update bot definition.", "STORAGE_ERROR");
        }

        var details = CreateBotDetailsDict(updatedBot, "Updated");
        return Success(request, "Updated", $"Codync bot '{botId}' updated successfully.", details);
    }

    public AdminBrokerResponse HandleDelete(AdminBrokerRequest request)
    {
        var botId = request.TargetIdentity;
        if (!IsValidBotId(botId))
        {
            return Failure(request, "InvalidTarget", "BotId is invalid.", "INVALID_TARGET_IDENTITY");
        }

        if (!_store.TryGetBot(botId, out var existingBot) || existingBot is null)
        {
            return Failure(request, "NotFound", $"Bot '{botId}' does not exist.", "BOT_NOT_FOUND");
        }

        if (!_store.DeleteBot(botId))
        {
            return Failure(request, "StorageFailure", "Failed to delete bot definition.", "STORAGE_ERROR");
        }

        var details = new Dictionary<string, string>
        {
            ["botId"] = botId,
            ["previousName"] = existingBot.Name,
            ["status"] = "Deleted"
        };

        return Success(request, "Deleted", $"Codync bot '{botId}' deleted successfully.", details);
    }

    public static bool IsValidBotId(string botId) =>
        !string.IsNullOrWhiteSpace(botId)
        && botId.Length is >= 3 and <= 64
        && botId.All(c => char.IsLetterOrDigit(c) || c == '-' || c == '_');

    private static bool TryParseBotParams(
        AdminBrokerRequest request,
        out string name,
        out string description,
        out string endpointUrl,
        out IReadOnlyList<string> capabilities,
        out string? errorMessage)
    {
        name = string.Empty;
        description = string.Empty;
        endpointUrl = string.Empty;
        capabilities = Array.Empty<string>();
        errorMessage = null;

        if (request.Parameters is null)
        {
            errorMessage = "Missing parameters dictionary.";
            return false;
        }

        if (!request.Parameters.TryGetValue("name", out var nameElement) || nameElement.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(nameElement.GetString()))
        {
            errorMessage = "Parameter 'name' is required and must be a non-empty string.";
            return false;
        }
        name = nameElement.GetString()!;

        if (request.Parameters.TryGetValue("description", out var descElement) && descElement.ValueKind == JsonValueKind.String)
        {
            description = descElement.GetString() ?? string.Empty;
        }

        if (!request.Parameters.TryGetValue("endpointUrl", out var urlElement) || urlElement.ValueKind != JsonValueKind.String || !Uri.IsWellFormedUriString(urlElement.GetString(), UriKind.Absolute))
        {
            errorMessage = "Parameter 'endpointUrl' is required and must be a valid absolute URI.";
            return false;
        }
        endpointUrl = urlElement.GetString()!;

        if (request.Parameters.TryGetValue("capabilities", out var capsElement) && capsElement.ValueKind == JsonValueKind.Array)
        {
            var capsList = new List<string>();
            foreach (var item in capsElement.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(item.GetString()))
                {
                    capsList.Add(item.GetString()!);
                }
            }
            capabilities = capsList;
        }

        return true;
    }

    private static Dictionary<string, string> CreateBotDetailsDict(CodyncBotDefinition bot, string status) =>
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["botId"] = bot.BotId,
            ["name"] = bot.Name,
            ["description"] = bot.Description,
            ["endpointUrl"] = bot.EndpointUrl,
            ["capabilities"] = string.Join(",", bot.Capabilities),
            ["lastUpdatedUtc"] = bot.LastUpdatedUtc.ToString("o"),
            ["status"] = status
        };

    private static AdminBrokerResponse Success(AdminBrokerRequest request, string state, string summary, IReadOnlyDictionary<string, string> details) =>
        new(AdminBrokerContract.Version, request.RequestId, request.Operation, true, request.TargetIdentity, state, summary, null, DateTime.UtcNow, details);

    private static AdminBrokerResponse Failure(AdminBrokerRequest request, string state, string summary, string errorCode) =>
        new(AdminBrokerContract.Version, request.RequestId, request.Operation, false, request.TargetIdentity, state, summary, errorCode, DateTime.UtcNow, null);
}
