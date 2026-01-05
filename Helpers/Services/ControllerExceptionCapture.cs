using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using System.Net;

namespace HeatBeat.Shared.Helpers.Services;

public class ControllerExceptionCaptureAttribute : ExceptionFilterAttribute
{
    public override void OnException(ExceptionContext context)
    {
        var logger = context.HttpContext.RequestServices.GetService(typeof(ILogger<ControllerExceptionCaptureAttribute>)) as ILogger<ControllerExceptionCaptureAttribute>;

        logger?.LogError(context.Exception, "Unhandled exception in controller: {Controller}", context.ActionDescriptor.DisplayName);

        var problemDetails = new ProblemDetails
        {
            Status = (int)HttpStatusCode.InternalServerError,
            Title = "An unexpected error occurred.",
            Detail = context.Exception.Message,
            Instance = context.HttpContext.Request.Path
        };

        context.Result = new ObjectResult(problemDetails)
        {
            StatusCode = (int)HttpStatusCode.InternalServerError
        };

        context.ExceptionHandled = true;
    }
}

