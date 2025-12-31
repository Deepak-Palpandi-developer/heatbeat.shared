using HeatBeat.Shared.Middleware;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace HeatBeat.Shared.Extensions;

public static class ApplicationExtensions
{
    public static void MigratePostgresqlDatabase<T>(this WebApplication _app) where T : DbContext
    {
        using (var _scope = _app.Services.CreateScope())
        {
            var _context = _scope.ServiceProvider.GetRequiredService<T>();
            _context.Database.SetCommandTimeout(600);
            _context.Database.Migrate();
        }
    }

    public static WebApplication CustomUseSwagger(this WebApplication _app)
    {
        if (_app.Environment.IsDevelopment())
        {
            _app.UseSwagger();
            _app.UseSwaggerUI();
        }

        return _app;
    }

    public static IApplicationBuilder CustomUseForwardedHeaders(this WebApplication _app)
    {
        _app.UseForwardedHeaders(new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
        });

        return _app;
    }

    public static IApplicationBuilder UseErrorHandling(this IApplicationBuilder _app)
    {
        return _app.UseMiddleware<ErrorHandlerMiddleware>();
    }

    public static IApplicationBuilder UseDataEncryptionDecryptionHandling(this IApplicationBuilder _app)
    {
        return _app.UseMiddleware<DataEncryptionDecryptionMiddleware>();
    }
}
