using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using System.Net;
using HeatBeat.Shared.Dto;
using Microsoft.AspNetCore.Mvc.Controllers;

namespace HeatBeat.Shared.Services
{
    public class ControllerExceptionCaptureAttribute : ActionFilterAttribute, IExceptionFilter
    {
        public void OnException(ExceptionContext context)
        {
            var logger = context.HttpContext.RequestServices.GetService(typeof(ILogger<ControllerExceptionCaptureAttribute>)) as ILogger;
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

        public override void OnActionExecuted(ActionExecutedContext context)
        {
            if (context.Exception == null && context.ModelState != null && !context.ModelState.IsValid)
            {
                var errors = context.ModelState
                    .Where(x => x.Value?.Errors.Count > 0)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray()
                    );

                var apiResponseType = typeof(ApiResponseDto<>);
                var returnType = context.ActionDescriptor is ControllerActionDescriptor cad && cad.MethodInfo.ReturnType.IsGenericType
                    ? cad.MethodInfo.ReturnType.GetGenericArguments()[0]
                    : typeof(object);

                var responseType = apiResponseType.MakeGenericType(returnType);
                var failureMethod = responseType.GetMethod("FailureResponse", new[] { typeof(string), typeof(object), typeof(string), typeof(string) });
                var apiResponse = failureMethod?.Invoke(null, new object[]
                {
                    "Validation failed.",
                    errors,
                    ((int)HttpStatusCode.BadRequest).ToString(),
                    "BadRequest"
                });

                context.Result = new ObjectResult(apiResponse)
                {
                    StatusCode = (int)HttpStatusCode.BadRequest
                };
                context.ExceptionHandled = true;
            }
            base.OnActionExecuted(context);
        }
    }
}
