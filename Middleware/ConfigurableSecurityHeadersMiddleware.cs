using HeatBeat.Shared.Contants;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace HeatBeat.Shared.Middleware;

public class ConfigurableSecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SecurityHeadersOptions _options;

    public ConfigurableSecurityHeadersMiddleware(
        RequestDelegate next,
        IOptions<SecurityHeadersOptions> options
    )
    {
        _next = next;
        _options = options.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_options.IsEnableSecurityHeaders)
        {
            context.Response.Headers.TryAdd("X-Content-Type-Options", _options.XContentTypeOptions);
            context.Response.Headers.TryAdd("X-Frame-Options", _options.XFrameOptions);
            context.Response.Headers.TryAdd("X-XSS-Protection", _options.XXssProtection);
            context.Response.Headers.TryAdd("Referrer-Policy", _options.ReferrerPolicy);
            context.Response.Headers.TryAdd("Permissions-Policy", _options.PermissionsPolicy);
            context.Response.Headers.TryAdd(
                "Content-Security-Policy",
                _options.ContentSecurityPolicy
            );

            if (_options.EnableHsts)
            {
                var hstsValue =
                    $"max-age={_options.HstsMaxAge}"
                    + (_options.IncludeSubDomains ? "; includeSubDomains" : string.Empty);

                context.Response.Headers.TryAdd("Strict-Transport-Security", hstsValue);
            }

            if (_options.RemoveServerHeader)
                context.Response.Headers.Remove("Server");

            if (_options.RemoveXPoweredByHeader)
                context.Response.Headers.Remove("X-Powered-By");
        }

        // Static custom headers
        foreach (var header in _options.StaticHeaders)
        {
            context.Response.Headers.TryAdd(header.Key, header.Value);
        }

        await _next(context);
    }
}
