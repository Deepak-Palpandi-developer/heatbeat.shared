using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using HeatBeat.Shared.Contants;
using HeatBeat.Shared.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace heatbeat.shared.Middleware;

public class AuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private readonly IServiceProvider _serviceProvider;

    public AuthenticationMiddleware(
        RequestDelegate next,
        IConfiguration configuration,
        IServiceProvider serviceProvider
    )
    {
        _next = next;
        _configuration = configuration;
        _serviceProvider = serviceProvider;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip authentication for /auth/login and /auth/refresh endpoints
        var path = context.Request.Path.Value?.ToLower();
        if (path != null && path.Contains("/auth/login"))
        {
            await _next(context);
            return;
        }

        // Resolve IUserSessionService per request
        var userSessionService = context.RequestServices.GetRequiredService<IUserSessionService>();

        // 1. Validate JWT
        if (
            !context.Request.Headers.TryGetValue("Authorization", out StringValues authHeader)
            || !authHeader.ToString().StartsWith("Bearer ")
        )
        {
            await Respond401(context, true, false);
            return;
        }
        var token = CommonHelper.Decrypt(authHeader.ToString().Substring("Bearer ".Length));
        var handler = new JwtSecurityTokenHandler();
        SecurityToken validatedToken;
        ClaimsPrincipal? principal = null;
        if (path != null && !path.Contains("/auth/refresh"))
        {
            try
            {
                principal = handler.ValidateToken(
                    token,
                    new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(
                                _configuration[EnvironmentCodes.JwtSecretKey] ?? string.Empty
                            )
                        ),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ClockSkew = TimeSpan.Zero,
                    },
                    out validatedToken
                );
            }
            catch (SecurityTokenExpiredException)
            {
                await Respond401(context, false, true);
                return;
            }
            catch
            {
                await Respond401(context, true, false);
                return;
            }
        }

        // 2. Validate session_token
        if (
            !context.Request.Headers.TryGetValue(
                "session_token",
                out StringValues sessionTokenHeader
            )
        )
        {
            await Respond401(context, true, false);
            return;
        }
        var sessionToken = sessionTokenHeader.ToString();
        long userId = 0;
        if (context.Request.Headers.TryGetValue("user_id", out StringValues userIdHeader))
        {
            long.TryParse(userIdHeader.ToString(), out userId);
        }
        var session = await userSessionService.GetSessionAsync(sessionToken, userId);
        if (
            session == null
            || !session.IsActive
            || session.Revoked
            || session.Expiry < DateTime.UtcNow
        )
        {
            if (session != null)
            {
                session.Revoked = true;
                session.IsActive = false;
                await userSessionService.RevokeSessionAsync(session);
            }
            await Respond401(context, true, false);
            return;
        }

        context.Response.Headers.TryAdd("session_token", session.SessionToken);
        context.Response.Headers.TryAdd(
            "user_id",
            userId > 0 ? userId.ToString() : string.Empty
        );
        // 3. Allow request
        await _next(context);
    }

    private async Task Respond401(HttpContext context, bool invalidToken, bool tokenExpired)
    {
        context.Response.StatusCode = 401;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(
                new
                {
                    message = invalidToken ? "Invalid session token. Please log in again."
                    : tokenExpired ? "Token expired. Please refresh your token."
                    : "Unauthorized access.",
                    needLogin = invalidToken,
                    needRefresh = tokenExpired,
                }
            )
        );
    }
}

public interface IUserSessionService
{
    Task<UserSessionMiddlewareModel?> GetSessionAsync(string sessionToken, long userId);
    Task RevokeSessionAsync(UserSessionMiddlewareModel session);
}

public class UserSessionMiddlewareModel
{
    public string SessionToken { get; set; } = string.Empty;
    public bool IsActive { get; set; }
    public bool Revoked { get; set; }
    public DateTimeOffset Expiry { get; set; }
}
