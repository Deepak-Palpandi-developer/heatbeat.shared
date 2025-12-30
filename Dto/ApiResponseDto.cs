namespace HeatBeat.Shared.Dto;

public class ApiResponseDto<T>
{
    public bool Success { get; set; }
    public string? StatusCode { get; set; } = string.Empty;
    public string? StatusMessage { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public T? Data { get; set; }
    public Object? Errors { get; set; } = new();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? TraceId { get; set; }

    public static ApiResponseDto<T> SuccessResponse(T data, string message = "Success", string? statusCode = null, string? statusMessage = null)
    {
        return new ApiResponseDto<T>
        {
            StatusCode = statusCode,
            StatusMessage = statusMessage,
            Success = true,
            Message = message,
            Data = data
        };
    }

    public static ApiResponseDto<T> FailureResponse(string message, Object? errors, string? statusCode = null, string? statusMessage = null)
    {
        return new ApiResponseDto<T>
        {
            StatusCode = statusCode,
            StatusMessage = statusMessage,
            Success = false,
            Message = message,
            Errors = errors
        };
    }
}

public class PagedApiResponseDto<T> : ApiResponseDto<T>
{
    public PaginationMetadata? Pagination { get; set; }

    public static PagedApiResponseDto<T> SuccessResponse(T data, PaginationMetadata pagination, string message = "Success", string? statusCode = null, string? statusMessage = null)
    {
        return new PagedApiResponseDto<T>
        {
            StatusCode = statusCode,
            StatusMessage = statusMessage,
            Success = true,
            Message = message,
            Data = data,
            Pagination = pagination
        };
    }
}

public class PaginationMetadata
{
    public int CurrentPage { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
    public int TotalCount { get; set; }
    public bool HasPrevious { get; set; }
    public bool HasNext { get; set; }
}