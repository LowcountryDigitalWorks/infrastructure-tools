internal static class ContractTestPlatform
{
    internal const string SkippedLinuxOnlyPrefix = "SKIPPED_LINUX_ONLY";

    internal static void SkipLinuxOnly(string contractName, string reason)
    {
        Console.WriteLine($"{SkippedLinuxOnlyPrefix}: {contractName} — {reason} Hosted Linux CI retains full contract strength.");
    }
}
