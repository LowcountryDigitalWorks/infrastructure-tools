using LDW.LocalSecretStore;

if (args.Length != 0)
{
    Console.Error.WriteLine("INVALID");
    return 2;
}

var secret = Environment.GetEnvironmentVariable(CorsairNeonLauncher.SecretEnvironmentVariable);
if (string.IsNullOrEmpty(secret))
{
    Console.Error.WriteLine("SECRET_MISSING");
    return 1;
}

Console.WriteLine("SECRET_PRESENT");
return 0;
