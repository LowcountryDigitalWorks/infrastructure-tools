using LDW.HostAgent.Core;
using System.Runtime.InteropServices;

namespace LDW.HostAgent.Windows;

internal static class TrayIconFactory
{
    public static Icon Create(StatusColor color)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        using (var path = new System.Drawing.Drawing2D.GraphicsPath())
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);
            using var background = new SolidBrush(Color.FromArgb(22, 44, 68));
            graphics.FillRoundedRectangle(background, new Rectangle(1, 1, 30, 30), 7);
            using var brand = new SolidBrush(Color.FromArgb(93, 202, 181));
            graphics.FillPolygon(brand, [new Point(8, 8), new Point(13, 8), new Point(13, 20), new Point(22, 20), new Point(22, 25), new Point(8, 25)]);
            using var badge = new SolidBrush(StateColor(color));
            graphics.FillEllipse(badge, 20, 3, 10, 10);
            using var pen = new Pen(Color.White, 1.6f) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
            switch (color)
            {
                case StatusColor.Green:
                    graphics.DrawLines(pen, [new Point(22, 8), new Point(24, 10), new Point(28, 5)]); break;
                case StatusColor.Blue:
                    graphics.FillPolygon(Brushes.White, [new Point(23, 5), new Point(28, 8), new Point(23, 11)]); break;
                case StatusColor.Purple:
                    graphics.DrawLines(pen, [new Point(25, 4), new Point(23, 8), new Point(26, 8), new Point(24, 11)]); break;
                case StatusColor.Yellow:
                    graphics.DrawLine(pen, 25, 5, 25, 8); graphics.FillEllipse(Brushes.White, 24.3f, 9, 1.5f, 1.5f); break;
                case StatusColor.Red:
                    graphics.DrawLine(pen, 23, 6, 27, 10); graphics.DrawLine(pen, 27, 6, 23, 10); break;
                default:
                    graphics.DrawLine(pen, 25, 5, 25, 8); graphics.FillEllipse(Brushes.White, 24.3f, 9, 1.5f, 1.5f); break;
            }
        }
        var handle = bitmap.GetHicon();
        try { using var icon = Icon.FromHandle(handle); return (Icon)icon.Clone(); }
        finally { DestroyIcon(handle); }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    private static Color StateColor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.FromArgb(19, 160, 112),
        StatusColor.Blue => Color.FromArgb(54, 132, 221),
        StatusColor.Purple => Color.FromArgb(147, 91, 180),
        StatusColor.Yellow => Color.FromArgb(229, 166, 45),
        StatusColor.Red => Color.FromArgb(214, 70, 70),
        _ => Color.FromArgb(125, 139, 151),
    };
}

internal static class GraphicsExtensions
{
    public static void FillRoundedRectangle(this Graphics graphics, Brush brush, Rectangle bounds, int radius)
    {
        using var path = new System.Drawing.Drawing2D.GraphicsPath();
        var d = radius * 2;
        path.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
        path.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
        path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
        path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        graphics.FillPath(brush, path);
    }
}
