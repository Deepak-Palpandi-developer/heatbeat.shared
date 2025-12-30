using System.Net;
using System.Text.Json;
using HeatBeat.Shared.Contants;
using HeatBeat.Shared.Dto;
using HeatBeat.Shared.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace HeatBeat.Shared.Middleware;

public class ErrorHandlerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlerMiddleware> _logger;

    public ErrorHandlerMiddleware(RequestDelegate next, ILogger<ErrorHandlerMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception error)
        {
            var response = context.Response;
            response.ContentType = "application/json";

            response.StatusCode = error switch
            {
                NotFoundExceptions => (int)HttpStatusCode.NotFound,
                DuplicateExceptions => (int)HttpStatusCode.BadRequest,
                BadRequestExceptions => (int)HttpStatusCode.BadRequest,
                UnauthorizedAccessExceptions => (int)HttpStatusCode.Unauthorized,
                TimeoutExceptions => (int)HttpStatusCode.RequestTimeout,
                _ => (int)HttpStatusCode.InternalServerError
            };

            _logger.Log(
                error is NotFoundExceptions or DuplicateExceptions or BadRequestExceptions ? LogLevel.Warning : LogLevel.Error,
                error,
                error.Message
            );
            
            string _statusCode = error switch
            {
                NotFoundExceptions => ResponseCodes.StatusMessageCodes.NotFound,
                DuplicateExceptions => ResponseCodes.StatusMessageCodes.Conflict,
                BadRequestExceptions => ResponseCodes.StatusMessageCodes.BadRequest,
                UnauthorizedAccessExceptions => ResponseCodes.StatusMessageCodes.Unauthorized,
                TimeoutExceptions => ResponseCodes.StatusMessageCodes.RequestTimeout,
                _ => ResponseCodes.StatusMessageCodes.InternalServerError
            };

            string _statusMessage = error switch
            {
                NotFoundExceptions => ResponseCodes.StatusMessages.NotFound,
                DuplicateExceptions => ResponseCodes.StatusMessages.Conflict,
                BadRequestExceptions => ResponseCodes.StatusMessages.BadRequest,
                UnauthorizedAccessExceptions => ResponseCodes.StatusMessages.Unauthorized,
                TimeoutExceptions => ResponseCodes.StatusMessages.RequestTimeout,
                _ => ResponseCodes.StatusMessages.InternalServerError
            };

            var errorResponse = ApiResponseDto<object>.FailureResponse(error?.Message ?? "FAILED", error, _statusCode, _statusMessage);

            var result = JsonSerializer.Serialize(errorResponse);

            await response.WriteAsync(result);
        }
    }
}
