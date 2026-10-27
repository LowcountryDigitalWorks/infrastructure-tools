namespace LDW.OperationsBridge.Core;

public static class BridgeOperationSchema
{
    public static bool IsValid(BridgeOperation operation, IReadOnlyDictionary<string, string> args)
    {
        if (operation is BridgeOperation.DragonflyRunnerStatus
            or BridgeOperation.DragonflyRunnerStart
            or BridgeOperation.DragonflyRunnerDrain)
        {
            return args.Count == 0;
        }

        // Preserve the already-accepted browser/Codync argument behavior exactly.
        return CodyncOperationSchema.IsValid(operation, args);
    }
}
