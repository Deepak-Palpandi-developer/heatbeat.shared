using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Serilog.Context;

namespace HeatBeat.Shared.Middleware;

public class SerilogContextMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IWebHostEnvironment _env;

    public SerilogContextMiddleware(
        RequestDelegate next,
        IWebHostEnvironment env)
    {
        _next = next;
        _env = env;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var userId = context.User?.FindFirst("user_id")?.Value
                     ?? context.User?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        using (LogContext.PushProperty("UserId", userId ?? "anonymous"))
        using (LogContext.PushProperty("RequestId", context.TraceIdentifier))
        using (LogContext.PushProperty("TraceId", Activity.Current?.TraceId.ToString()))
        using (LogContext.PushProperty("Path", context.Request.Path.Value))
        using (LogContext.PushProperty("Method", context.Request.Method))
        using (LogContext.PushProperty("Environment", _env.EnvironmentName))
        using (LogContext.PushProperty("MachineName", Environment.MachineName))
        {
            await _next(context);

            // Capture status code AFTER request is processed
            LogContext.PushProperty("StatusCode", context.Response.StatusCode);
        }
    }
}