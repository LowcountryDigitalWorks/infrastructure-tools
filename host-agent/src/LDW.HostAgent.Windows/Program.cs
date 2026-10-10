namespace LDW.HostAgent.Windows;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        if (WindowsPrivilege.IsElevated())
        {
            MessageBox.Show(
                "LDW Host Agent is intentionally a normal-user tray process and will not run elevated.",
                "LDW Host Agent — privilege boundary",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }
        Application.Run(new HostAgentContext());
    }
}
