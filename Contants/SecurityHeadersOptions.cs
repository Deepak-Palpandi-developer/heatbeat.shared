namespace HeatBeat.Shared.Contants;

public sealed class SecurityHeadersOptions
{
    public bool IsEnableSecurityHeaders { get; set; } = true;

    // Core Security Headers
    public string XContentTypeOptions { get; set; } = "nosniff";
    public string XFrameOptions { get; set; } = "DENY";
    public string XXssProtection { get; set; } = "1; mode=block";
    public string ReferrerPolicy { get; set; } = "strict-origin-when-cross-origin";
    public string PermissionsPolicy { get; set; }
        = "geolocation=(), microphone=(), camera=()";

    // Content Security Policy
    public string ContentSecurityPolicy { get; set; } =
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data: https:; " +
        "font-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'";

    // HSTS
    public bool EnableHsts { get; set; } = true;
    public int HstsMaxAge { get; set; } = 31536000;
    public bool IncludeSubDomains { get; set; } = true;

    // Header Cleanup
    public bool RemoveServerHeader { get; set; } = true;
    public bool RemoveXPoweredByHeader { get; set; } = true;

    // Custom Static Headers
    public Dictionary<string, string> StaticHeaders { get; set; } = new();
}