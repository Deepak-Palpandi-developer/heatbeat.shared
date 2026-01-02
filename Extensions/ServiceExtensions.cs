
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.RateLimiting;
using HeatBeat.Shared.Cache;
using HeatBeat.Shared.Contants;
using HeatBeat.Shared.Helpers;
using HeatBeat.Shared.Helpers.Repositories;
using HeatBeat.Shared.Helpers.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.PostgreSQL;

namespace HeatBeat.Shared.Extensions;

public static class ServiceExtensions
{
    public static IServiceCollection AddInitialServiceCollections(this IServiceCollection _services)
    {
        _services.AddScoped(typeof(IGenericRepository<>), typeof(GenericRepository<>));

        _services.AddScoped(typeof(IGenericService<,>), typeof(GenericService<,>));

        _services.AddSingleton<IPayloadEncryptionService, PayloadEncryptionService>();

        return _services;
    }

    public static IServiceCollection CustomAddCors(this IServiceCollection _services, string _cors, string _delemeter)
    {
        var __cors = _cors
            .Split(_delemeter, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

        _services.AddCors(_options =>
            _options.AddDefaultPolicy(
                _builder => _builder.WithOrigins(__cors)
                    .SetIsOriginAllowedToAllowWildcardSubdomains()
                    .AllowCredentials()
                    .AllowAnyMethod()
                    .AllowAnyHeader()));

        return _services;
    }

    public static IMvcBuilder CustomAddControllers(this IServiceCollection _service)
    {
        return _service.AddControllers(_options =>
            _options.Conventions.Add(new RouteTokenTransformerConvention(new SlugifyParameterTransformer())))
            .AddJsonOptions(_options =>
            {
                var _jsonOptions = _options.JsonSerializerOptions;
                _jsonOptions.Converters.Add(new JsonStringEnumConverter());
                _jsonOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                _jsonOptions.PropertyNameCaseInsensitive = true;
                _jsonOptions.AllowTrailingCommas = true;
            });
    }

    public static IServiceCollection CustomAddPostgresqlDbContext<T>(this IServiceCollection _service, string _connectionString, string _assembly) where T : DbContext
    {
        AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);

        _service.AddDbContext<T>(_options =>
        _options.UseNpgsql(_connectionString, _b =>
        {
            if (!string.IsNullOrEmpty(_assembly))
                _b.MigrationsAssembly(_assembly);
            _b.UseQuerySplittingBehavior(QuerySplittingBehavior.SingleQuery);
        }));

        return _service;
    }

    public static IServiceCollection CustomAddRedisCache(this IServiceCollection _service, string _port, string _instanceName)
    {
        _service.AddSingleton<RedisCache>()
            .AddDistributedMemoryCache()
            .AddStackExchangeRedisCache(options =>
            {
                options.Configuration = _port;
                options.InstanceName = _instanceName;
            });

        return _service;
    }

    public static WebApplicationBuilder CustomAddPostgresLog(this WebApplicationBuilder builder, string connectionString, string tableName = "logs")
    {
        builder.Logging.ClearProviders();

        var columnWriters = new Dictionary<string, ColumnWriterBase>
        {
            ["timestamp"] = new TimestampColumnWriter(),
            ["level"] = new LevelColumnWriter(true, NpgsqlTypes.NpgsqlDbType.Varchar),
            ["message"] = new RenderedMessageColumnWriter(),
            ["exception"] = new ExceptionColumnWriter(),
            ["properties"] = new PropertiesColumnWriter(NpgsqlTypes.NpgsqlDbType.Jsonb),
            ["user_id"] = new SinglePropertyColumnWriter(
        "UserId",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["request_id"] = new SinglePropertyColumnWriter(
        "RequestId",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["trace_id"] = new SinglePropertyColumnWriter(
        "TraceId",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["path"] = new SinglePropertyColumnWriter(
        "Path",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["http_method"] = new SinglePropertyColumnWriter(
        "Method",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["status_code"] = new SinglePropertyColumnWriter(
        "StatusCode",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Integer),

            ["environment"] = new SinglePropertyColumnWriter(
        "Environment",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar),

            ["machine_name"] = new SinglePropertyColumnWriter(
        "MachineName",
        PropertyWriteMethod.ToString,
        NpgsqlTypes.NpgsqlDbType.Varchar)
        };

        builder.Host.UseSerilog((context, services, config) =>
        {
            var logPath = builder.Configuration.GetValue<string>(EnvironmentCodes.LogFilePath) ?? "Logs";

            config
                .MinimumLevel.Information()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .Enrich.FromLogContext()

                // =========================
                // INFO → info-yyyy-mm-dd.json
                // =========================
                .WriteTo.Logger(lc => lc
                    .Filter.ByIncludingOnly(e => e.Level == LogEventLevel.Information)
                    .WriteTo.File(
                        new Serilog.Formatting.Json.JsonFormatter(),
                        Path.Combine(logPath, "info", "info-.json"),
                        rollingInterval: RollingInterval.Day))

                // =========================
                // WARN → warn-yyyy-mm-dd.json
                // =========================
                .WriteTo.Logger(lc => lc
                    .Filter.ByIncludingOnly(e => e.Level == LogEventLevel.Warning)
                    .WriteTo.File(
                        new Serilog.Formatting.Json.JsonFormatter(),
                        Path.Combine(logPath, "warn", "warn-.json"),
                        rollingInterval: RollingInterval.Day))

                // =========================
                // ERROR/FATAL → error-yyyy-mm-dd.json
                // =========================
                .WriteTo.Logger(lc => lc
                    .Filter.ByIncludingOnly(e =>
                        e.Level == LogEventLevel.Error ||
                        e.Level == LogEventLevel.Fatal)
                    .WriteTo.File(
                        new Serilog.Formatting.Json.JsonFormatter(),
                        Path.Combine(logPath, "error", "error-.json"),
                        rollingInterval: RollingInterval.Day))

                // =========================
                // DATABASE → Error & Fatal ONLY
                // =========================
                .WriteTo.PostgreSQL(
                    connectionString: connectionString,
                    tableName: tableName,
                    columnOptions: columnWriters,
                    restrictedToMinimumLevel: LogEventLevel.Error,
                    needAutoCreateTable: true,
                    batchSizeLimit: 50,
                    period: TimeSpan.FromSeconds(5));
        });

        return builder;
    }


    public static IServiceCollection AddCustomRateLimiter(this IServiceCollection _services)
    {
        _services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            options.OnRejected = async (context, token) =>
            {
                context.HttpContext.Response.ContentType = "application/json";

                await context.HttpContext.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    errorCode = ResponseCodes.StatusMessageCodes.TooManyRequests,
                    message = ResponseCodes.StatusMessages.TooManyRequests
                }, token);
            };

            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                httpContext =>
                {
                    var userId = httpContext.User?
                        .FindFirst(ClaimTypes.NameIdentifier)?.Value
                        ?? httpContext.User?.FindFirst("sub")?.Value;

                    var partitionKey = !string.IsNullOrWhiteSpace(userId)
                        ? $"user:{userId}"
                        : $"ip:{httpContext.Connection.RemoteIpAddress}";

                    return RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey,
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 100,
                            Window = TimeSpan.FromMinutes(1),
                            AutoReplenishment = true,
                            QueueLimit = 0
                        });
                });
        });

        return _services;
    }

    public static IServiceCollection AddCustomAuthentication(this IServiceCollection _services, IConfiguration _configuration)
    {
        var jwtSettings = new
        {
            SecretKey = _configuration.GetValue<string>(EnvironmentCodes.JwtSecretKey) ?? string.Empty,
            Issuer = _configuration.GetValue<string>(EnvironmentCodes.JwtIssuer) ?? string.Empty,
            Audience = _configuration.GetValue<string>(EnvironmentCodes.JwtAudience) ?? string.Empty,
            ExpiryMinutes = _configuration.GetValue<int>(EnvironmentCodes.JwtExpiryMinutes, 60)
        };

        if (string.IsNullOrWhiteSpace(jwtSettings.SecretKey) ||
            string.IsNullOrWhiteSpace(jwtSettings.Issuer) ||
            string.IsNullOrWhiteSpace(jwtSettings.Audience))
        {
            throw new InvalidOperationException(ResponseCodes.CustomStatusMessages.JwtNotInitialzeErrorMessage);
        }

        var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);

        _ = _services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.SaveToken = true;
            var requireHttpsMetadata = !_configuration.GetValue<bool>("JWT_ALLOW_HTTP", false);
            options.RequireHttpsMetadata = requireHttpsMetadata; // keep true by default; allow opt-out for local HTTP
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero // Remove default 5 minute tolerance
            };

            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                    {
                        context.Response.Headers["Token-Expired"] = "true";
                    }
                    return Task.CompletedTask;
                },
                OnChallenge = async context =>
                {
                    context.HandleResponse();
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    context.Response.ContentType = "application/json";

                    await context.Response.WriteAsJsonAsync(new
                    {
                        success = false,
                        errorCode = ResponseCodes.StatusMessageCodes.Unauthorized,
                        message = ResponseCodes.StatusMessages.Unauthorized
                    });
                },
                OnForbidden = async context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    context.Response.ContentType = "application/json";

                    await context.Response.WriteAsJsonAsync(new
                    {
                        success = false,
                        errorCode = ResponseCodes.StatusMessageCodes.Forbidden,
                        message = ResponseCodes.StatusMessages.Forbidden
                    });
                }
            };
        });

        return _services;
    }

    public static IServiceCollection AddCustomAuthorization(this IServiceCollection _services)
    {
        _services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build();

            options.AddPolicy("AdminOnly", policy =>
                policy.RequireRole("Admin"));

        });

        return _services;
    }

    #region  PRIVATE METHODS
    private class SlugifyParameterTransformer : IOutboundParameterTransformer
    {
        public string TransformOutbound(object? _value)
        {
            if (_value == null)
                return string.Empty;

            var slug = Regex.Replace(_value.ToString() ?? string.Empty, "([a-z])([A-Z])", "$1-$2");
            return slug.ToLowerInvariant();
        }
    }
    #endregion
}

