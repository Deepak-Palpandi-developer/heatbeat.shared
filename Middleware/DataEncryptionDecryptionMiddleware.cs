using System.Text;
using HeatBeat.Shared.Contants;
using HeatBeat.Shared.Helpers;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HeatBeat.Shared.Middleware;

public class DataEncryptionDecryptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<DataEncryptionDecryptionMiddleware> _logger;
    private readonly IPayloadEncryptionService _encryptionService;

    public DataEncryptionDecryptionMiddleware(
        RequestDelegate next,
        ILogger<DataEncryptionDecryptionMiddleware> logger,
        IPayloadEncryptionService encryptionService)
    {
        _next = next;
        _logger = logger;
        _encryptionService = encryptionService;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var shouldEncrypt = context.Request.Headers.TryGetValue("X-Encrypt-Data", out var encryptHeader) &&
                            string.Equals(encryptHeader, "true", StringComparison.OrdinalIgnoreCase);

        if (!shouldEncrypt)
        {
            await _next(context);
            return;
        }

        var decrypted = await TryDecryptRequestAsync(context);
        if (!decrypted)
        {
            return;
        }

        var originalBodyStream = context.Response.Body;
        await using var responseBody = new MemoryStream();
        context.Response.Body = responseBody;

        try
        {
            await _next(context);
            await EncryptResponseAsync(context, originalBodyStream);
        }
        finally
        {
            context.Response.Body = originalBodyStream;
        }
    }

    private async Task<bool> TryDecryptRequestAsync(HttpContext context)
    {
        if (context.Request.ContentLength > 0 &&
            (context.Request.Method == HttpMethods.Post ||
             context.Request.Method == HttpMethods.Put ||
             context.Request.Method == HttpMethods.Patch))
        {
            try
            {
                context.Request.EnableBuffering();

                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                var encryptedBody = await reader.ReadToEndAsync();

                if (!string.IsNullOrWhiteSpace(encryptedBody))
                {
                    var decryptedBody = _encryptionService.Decrypt(encryptedBody);

                    var requestContent = Encoding.UTF8.GetBytes(decryptedBody);
                    context.Request.Body = new MemoryStream(requestContent);
                    context.Request.Body.Position = 0;
                    context.Request.ContentLength = requestContent.Length;

                    _logger.LogInformation("Request body decrypted successfully");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to decrypt request body");
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    success = false,
                    errorCode = ResponseCodes.CustomStatusMessageCodes.DecryptionFailed,
                    message = ResponseCodes.CustomStatusMessages.DecryptionFailed
                });
                return false;
            }
        }

        return true;
    }

    private async Task EncryptResponseAsync(HttpContext context, Stream originalBodyStream)
    {
        try
        {
            context.Response.Body.Seek(0, SeekOrigin.Begin);
            var responseBody = await new StreamReader(context.Response.Body).ReadToEndAsync();
            context.Response.Body.Seek(0, SeekOrigin.Begin);

            if (!string.IsNullOrWhiteSpace(responseBody))
            {
                var encryptedResponse = _encryptionService.Encrypt(responseBody);

                context.Response.ContentLength = null;
                context.Response.Headers.Remove("Content-Length");
                context.Response.Headers["X-Data-Encrypted"] = "true";

                await originalBodyStream.WriteAsync(Encoding.UTF8.GetBytes(encryptedResponse));

                _logger.LogInformation("Response body encrypted successfully");
            }
            else
            {
                await context.Response.Body.CopyToAsync(originalBodyStream);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to encrypt response body");
            throw;
        }
    }

}
