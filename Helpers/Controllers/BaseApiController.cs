using HeatBeat.Shared.Contants;
using HeatBeat.Shared.Dto;
using Microsoft.AspNetCore.Mvc;

namespace HeatBeat.Shared.Helpers.Controllers;

[ApiController]
[Route("[controller]")]
public abstract class BaseApiController : ControllerBase
{
    protected IActionResult Ok<T>(T data, string message = "Success")
    {
        var response = ApiResponseDto<T>.SuccessResponse(data, message, ResponseCodes.StatusMessageCodes.OK, ResponseCodes.StatusMessages.OK);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.Ok(response);
    }

    protected IActionResult Created<T>(T data, string message = "Created successfully")
    {
        var response = ApiResponseDto<T>.SuccessResponse(data, message, ResponseCodes.StatusMessageCodes.Created, ResponseCodes.StatusMessages.Created);
        response.TraceId = HttpContext.TraceIdentifier;
        return StatusCode(201, response);
    }

    protected IActionResult BadRequest<T>(string message, List<string>? errors = null)
    {
        var response = ApiResponseDto<T>.FailureResponse(message, errors, ResponseCodes.StatusMessageCodes.BadRequest, ResponseCodes.StatusMessages.BadRequest);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.BadRequest(response);
    }

    protected IActionResult BadRequest<T>(string message, string error)
    {
        var response = ApiResponseDto<T>.FailureResponse(message, error, ResponseCodes.StatusMessageCodes.BadRequest, ResponseCodes.StatusMessages.BadRequest);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.BadRequest(response);
    }

    protected IActionResult NotFound<T>(string message = "Resource not found")
    {
        var response = ApiResponseDto<T>.FailureResponse(message, null, ResponseCodes.StatusMessageCodes.NotFound, ResponseCodes.StatusMessages.NotFound);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.NotFound(response);
    }

    protected IActionResult Unauthorized<T>(string message = "Unauthorized access")
    {
        var response = ApiResponseDto<T>.FailureResponse(message, null, ResponseCodes.StatusMessageCodes.Unauthorized, ResponseCodes.StatusMessages.Unauthorized);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.Unauthorized(response);
    }

    protected IActionResult Forbidden<T>(string message = "Forbidden")
    {
        var response = ApiResponseDto<T>.FailureResponse(message, null, ResponseCodes.StatusMessageCodes.Forbidden, ResponseCodes.StatusMessages.Forbidden);
        response.TraceId = HttpContext.TraceIdentifier;
        return StatusCode(403, response);
    }

    protected IActionResult InternalServerError<T>(string message = "Internal server error")
    {
        var response = ApiResponseDto<T>.FailureResponse(message, null, ResponseCodes.StatusMessageCodes.InternalServerError, ResponseCodes.StatusMessages.InternalServerError);
        response.TraceId = HttpContext.TraceIdentifier;
        return StatusCode(500, response);
    }

    protected IActionResult PagedOk<T>(T data, PaginationMetadata pagination, string message = "Success")
    {
        var response = PagedApiResponseDto<T>.SuccessResponse(data, pagination, message, ResponseCodes.StatusMessageCodes.OK, ResponseCodes.StatusMessages.OK);
        response.TraceId = HttpContext.TraceIdentifier;
        return base.Ok(response);
    }
}