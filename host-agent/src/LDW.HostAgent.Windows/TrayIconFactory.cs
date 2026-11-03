using LDW.HostAgent.Core;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace LDW.HostAgent.Windows;

internal static class TrayIconFactory
{
    private static readonly Color EstuaryNavy = Color.FromArgb(16, 42, 58);
    private static readonly Color CypressTeal = Color.FromArgb(47, 118, 111);
    private static readonly Color WarmOyster = Color.FromArgb(243, 239, 230);

    public static Icon Create(StatusColor color)
    {
        using var bitmap = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            Configure(graphics);
            DrawBrandMark(graphics, new RectangleF(1, 1, 30, 30));
            DrawStateBadge(graphics, color);
        }

        var handle = bitmap.GetHicon();
        try
        {
            using var icon = Icon.FromHandle(handle);
            return (Icon)icon.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    public static Bitmap CreateBrandBitmap(int size)
    {
        if (size < 16 || size > 256) throw new ArgumentOutOfRangeException(nameof(size));
        var bitmap = new Bitmap(size, size);
        using var graphics = Graphics.FromImage(bitmap);
        Configure(graphics);
        DrawBrandMark(graphics, new RectangleF(1, 1, size - 2, size - 2));
        return bitmap;
    }

    private static void Configure(Graphics graphics)
    {
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;
        graphics.Clear(Color.Transparent);
    }

    private static void DrawBrandMark(Graphics graphics, RectangleF bounds)
    {
        var state = graphics.Save();
        try
        {
            graphics.TranslateTransform(bounds.X, bounds.Y);
            graphics.ScaleTransform(bounds.Width / 30f, bounds.Height / 30f);

            using var background = new SolidBrush(EstuaryNavy);
            graphics.FillRoundedRectangle(background, new RectangleF(0, 0, 30, 30), 7f);

            // Two simple tidal strokes are more legible than lettering at 16 px and
            // stay recognizable when reused in the window header at larger sizes.
            using var tide = new Pen(CypressTeal, 3.5f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round,
                LineJoin = LineJoin.Round
            };
            using var tidePath = new GraphicsPath();
            tidePath.AddBezier(4.5f, 11.5f, 8.5f, 6.2f, 11.5f, 16.8f, 15f, 11.5f);
            tidePath.AddBezier(15f, 11.5f, 18.5f, 6.2f, 21.5f, 16.8f, 25.5f, 11.5f);
            graphics.DrawPath(tide, tidePath);

            using var shoreline = new Pen(WarmOyster, 2.25f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round
            };
            using var shorelinePath = new GraphicsPath();
            shorelinePath.AddBezier(5.5f, 20f, 9f, 16.3f, 12.5f, 23.7f, 16f, 20f);
            shorelinePath.AddBezier(16f, 20f, 19.5f, 16.3f, 22.5f, 23.7f, 25f, 20f);
            graphics.DrawPath(shoreline, shorelinePath);
        }
        finally
        {
            graphics.Restore(state);
        }
    }

    private static void DrawStateBadge(Graphics graphics, StatusColor color)
    {
        var badgeColor = StateColor(color);
        using var fill = new SolidBrush(badgeColor);
        using var white = new Pen(Color.White, 1.7f)
        {
            StartCap = LineCap.Round,
            EndCap = LineCap.Round,
            LineJoin = LineJoin.Round
        };

        switch (color)
        {
            case StatusColor.Yellow:
                graphics.FillPolygon(fill, [new PointF(25, 2), new PointF(30, 11), new PointF(20, 11)]);
                graphics.DrawLine(white, 25, 5.0f, 25, 7.8f);
                graphics.FillEllipse(Brushes.White, 24.2f, 8.7f, 1.6f, 1.6f);
                break;

            case StatusColor.Purple:
                graphics.FillPolygon(fill, [new PointF(25, 2), new PointF(30, 7), new PointF(25, 12), new PointF(20, 7)]);
                graphics.DrawLines(white, [new PointF(26.4f, 4.2f), new PointF(23.6f, 7.0f), new PointF(26.2f, 7.0f), new PointF(23.8f, 10f)]);
                break;

            case StatusColor.Gray:
                graphics.FillRoundedRectangle(fill, new RectangleF(20, 2, 10, 10), 2.4f);
                graphics.DrawEllipse(white, 23.1f, 4.1f, 3.8f, 3.8f);
                graphics.FillEllipse(Brushes.White, 24.2f, 9f, 1.6f, 1.6f);
                break;

            default:
                graphics.FillEllipse(fill, 20, 2, 10, 10);
                switch (color)
                {
                    case StatusColor.Green:
                        graphics.DrawLines(white, [new PointF(22.1f, 7.2f), new PointF(24.4f, 9.3f), new PointF(28.2f, 4.8f)]);
                        break;
                    case StatusColor.Blue:
                        graphics.FillPolygon(Brushes.White, [new PointF(23.2f, 4.4f), new PointF(28.1f, 7), new PointF(23.2f, 9.6f)]);
                        break;
                    case StatusColor.Red:
                        graphics.DrawLine(white, 22.8f, 4.8f, 27.2f, 9.2f);
                        graphics.DrawLine(white, 27.2f, 4.8f, 22.8f, 9.2f);
                        break;
                    default:
                        graphics.DrawEllipse(white, 23.1f, 4.1f, 3.8f, 3.8f);
                        break;
                }
                break;
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    private static Color StateColor(StatusColor color) => color switch
    {
        StatusColor.Green => Color.FromArgb(27, 148, 104),
        StatusColor.Blue => Color.FromArgb(48, 111, 181),
        StatusColor.Purple => Color.FromArgb(126, 79, 151),
        StatusColor.Yellow => Color.FromArgb(205, 137, 24),
        StatusColor.Red => Color.FromArgb(196, 61, 67),
        _ => Color.FromArgb(111, 124, 134),
    };
}

internal static class GraphicsExtensions
{
    public static void FillRoundedRectangle(this Graphics graphics, Brush brush, Rectangle bounds, int radius) =>
        graphics.FillRoundedRectangle(brush, new RectangleF(bounds.X, bounds.Y, bounds.Width, bounds.Height), radius);

    public static void FillRoundedRectangle(this Graphics graphics, Brush brush, RectangleF bounds, float radius)
    {
        using var path = new GraphicsPath();
        var d = radius * 2;
        path.AddArc(bounds.X, bounds.Y, d, d, 180, 90);
        path.AddArc(bounds.Right - d, bounds.Y, d, d, 270, 90);
        path.AddArc(bounds.Right - d, bounds.Bottom - d, d, d, 0, 90);
        path.AddArc(bounds.X, bounds.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        graphics.FillPath(brush, path);
    }
}
