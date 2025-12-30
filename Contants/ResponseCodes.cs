namespace HeatBeat.Shared.Contants;

public static class ResponseCodes
{
    public static class StatusMessageCodes
    {
        public const string Continue = "CONTINUE";
        public const string SwitchingProtocols = "SWITCHING_PROTOCOLS";
        public const string Processing = "PROCESSING";
        public const string EarlyHints = "EARLY_HINTS";

        public const string OK = "OK";
        public const string Created = "CREATED";
        public const string Accepted = "ACCEPTED";
        public const string NonAuthoritativeInformation = "NON_AUTHORITATIVE_INFORMATION";
        public const string NoContent = "NO_CONTENT";
        public const string ResetContent = "RESET_CONTENT";
        public const string PartialContent = "PARTIAL_CONTENT";
        public const string MultiStatus = "MULTI_STATUS";
        public const string AlreadyReported = "ALREADY_REPORTED";
        public const string IMUsed = "IM_USED";

        public const string MultipleChoices = "MULTIPLE_CHOICES";
        public const string MovedPermanently = "MOVED_PERMANENTLY";
        public const string Found = "FOUND";
        public const string SeeOther = "SEE_OTHER";
        public const string NotModified = "NOT_MODIFIED";
        public const string UseProxy = "USE_PROXY";
        public const string SwitchProxy = "SWITCH_PROXY";
        public const string TemporaryRedirect = "TEMPORARY_REDIRECT";
        public const string PermanentRedirect = "PERMANENT_REDIRECT";

        public const string BadRequest = "BAD_REQUEST";
        public const string Unauthorized = "UNAUTHORIZED";
        public const string PaymentRequired = "PAYMENT_REQUIRED";
        public const string Forbidden = "FORBIDDEN";
        public const string NotFound = "NOT_FOUND";
        public const string MethodNotAllowed = "METHOD_NOT_ALLOWED";
        public const string NotAcceptable = "NOT_ACCEPTABLE";
        public const string ProxyAuthenticationRequired = "PROXY_AUTHENTICATION_REQUIRED";
        public const string RequestTimeout = "REQUEST_TIMEOUT";
        public const string Conflict = "CONFLICT";
        public const string Gone = "GONE";
        public const string LengthRequired = "LENGTH_REQUIRED";
        public const string PreconditionFailed = "PRECONDITION_FAILED";
        public const string PayloadTooLarge = "PAYLOAD_TOO_LARGE";
        public const string URITooLong = "URI_TOO_LONG";
        public const string UnsupportedMediaType = "UNSUPPORTED_MEDIA_TYPE";
        public const string RangeNotSatisfiable = "RANGE_NOT_SATISFIABLE";
        public const string ExpectationFailed = "EXPECTATION_FAILED";
        public const string ImATeapot = "IM_A_TEAPOT";
        public const string MisdirectedRequest = "MISDIRECTED_REQUEST";
        public const string UnprocessableEntity = "UNPROCESSABLE_ENTITY";
        public const string Locked = "LOCKED";
        public const string FailedDependency = "FAILED_DEPENDENCY";
        public const string TooEarly = "TOO_EARLY";
        public const string UpgradeRequired = "UPGRADE_REQUIRED";
        public const string PreconditionRequired = "PRECONDITION_REQUIRED";
        public const string TooManyRequests = "TOO_MANY_REQUESTS";
        public const string RequestHeaderFieldsTooLarge = "REQUEST_HEADER_FIELDS_TOO_LARGE";
        public const string UnavailableForLegalReasons = "UNAVAILABLE_FOR_LEGAL_REASONS";

        public const string InternalServerError = "INTERNAL_SERVER_ERROR";
        public const string NotImplemented = "NOT_IMPLEMENTED";
        public const string BadGateway = "BAD_GATEWAY";
        public const string ServiceUnavailable = "SERVICE_UNAVAILABLE";
        public const string GatewayTimeout = "GATEWAY_TIMEOUT";
        public const string HTTPVersionNotSupported = "HTTP_VERSION_NOT_SUPPORTED";
        public const string VariantAlsoNegotiates = "VARIANT_ALSO_NEGOTIATES";
        public const string InsufficientStorage = "INSUFFICIENT_STORAGE";
        public const string LoopDetected = "LOOP_DETECTED";
        public const string NotExtended = "NOT_EXTENDED";
        public const string NetworkAuthenticationRequired = "NETWORK_AUTHENTICATION_REQUIRED";
    }

    public static class StatusMessages
    {
        public const string Continue = "The server has received the request headers and the client should proceed to send the request body.";
        public const string SwitchingProtocols = "The server is switching protocols as requested by the client.";
        public const string Processing = "The server has received and is processing the request, but no response is available yet.";
        public const string EarlyHints = "The server is sending some response headers before the final response.";

        public const string OK = "The request was successful.";
        public const string Created = "created successfully.";
        public const string Accepted = "The request has been accepted for processing, but the processing has not been completed.";
        public const string NonAuthoritativeInformation = "The request was successful but the returned information may be from another source.";
        public const string NoContent = "The request was successful but there is no content to return.";
        public const string ResetContent = "The request was successful and the client should reset the document view.";
        public const string PartialContent = "The server is delivering only part of the resource due to a range header sent by the client.";
        public const string MultiStatus = "The message body contains multiple status codes for different operations.";
        public const string AlreadyReported = "The members of a DAV binding have already been enumerated in a previous reply.";
        public const string IMUsed = "The server has fulfilled a request for the resource with instance manipulations applied.";

        public const string MultipleChoices = "Multiple options for the resource are available.";
        public const string MovedPermanently = "The resource has been moved permanently to a new location.";
        public const string Found = "The resource has been found at a different location.";
        public const string SeeOther = "The response can be found at a different URI using a GET method.";
        public const string NotModified = "The resource has not been modified since the last request.";
        public const string UseProxy = "The requested resource must be accessed through the specified proxy.";
        public const string SwitchProxy = "Subsequent requests should use the specified proxy.";
        public const string TemporaryRedirect = "The resource has been temporarily moved to a different location.";
        public const string PermanentRedirect = "The resource has been permanently moved to a different location.";

        public const string BadRequest = "The request could not be understood or was missing required parameters.";
        public const string Unauthorized = "Authentication is required and has failed or has not been provided.";
        public const string PaymentRequired = "Payment is required to access this resource.";
        public const string Forbidden = "You do not have permission to access this resource.";
        public const string NotFound = "The requested resource could not be found.";
        public const string MethodNotAllowed = "The HTTP method used is not allowed for this resource.";
        public const string NotAcceptable = "The resource is not available in a format acceptable to the client.";
        public const string ProxyAuthenticationRequired = "Authentication with the proxy is required.";
        public const string RequestTimeout = "The request took too long to process.";
        public const string Conflict = "The request could not be completed due to a conflict with the current state of the resource.";
        public const string Gone = "The requested resource is no longer available and will not be available again.";
        public const string LengthRequired = "The request did not specify the length of its content.";
        public const string PreconditionFailed = "One or more conditions in the request header fields evaluated to false.";
        public const string PayloadTooLarge = "The request payload is larger than the server is willing or able to process.";
        public const string URITooLong = "The URI provided was too long for the server to process.";
        public const string UnsupportedMediaType = "The media type of the request is not supported by the server.";
        public const string RangeNotSatisfiable = "The range specified in the request cannot be satisfied.";
        public const string ExpectationFailed = "The expectation given in the request header could not be met.";
        public const string ImATeapot = "I'm a teapot. The server refuses to brew coffee because it is a teapot.";
        public const string MisdirectedRequest = "The request was directed at a server that is not able to produce a response.";
        public const string UnprocessableEntity = "The request was well-formed but contains semantic errors.";
        public const string Locked = "The resource that is being accessed is locked.";
        public const string FailedDependency = "The request failed due to failure of a previous request.";
        public const string TooEarly = "The server is unwilling to risk processing a request that might be replayed.";
        public const string UpgradeRequired = "The client should switch to a different protocol.";
        public const string PreconditionRequired = "The server requires the request to be conditional.";
        public const string TooManyRequests = "Too many requests. Please try again later.";
        public const string RequestHeaderFieldsTooLarge = "The request header fields are too large.";
        public const string UnavailableForLegalReasons = "The resource is unavailable for legal reasons.";

        public const string InternalServerError = "An internal server error occurred. Please try again later.";
        public const string NotImplemented = "The server does not support the functionality required to fulfill the request.";
        public const string BadGateway = "The server received an invalid response from an upstream server.";
        public const string ServiceUnavailable = "The service is temporarily unavailable. Please try again later.";
        public const string GatewayTimeout = "The server did not receive a timely response from an upstream server.";
        public const string HTTPVersionNotSupported = "The HTTP version used in the request is not supported by the server.";
        public const string VariantAlsoNegotiates = "The server has an internal configuration error.";
        public const string InsufficientStorage = "The server is unable to store the representation needed to complete the request.";
        public const string LoopDetected = "The server detected an infinite loop while processing the request.";
        public const string NotExtended = "Further extensions to the request are required for the server to fulfill it.";
        public const string NetworkAuthenticationRequired = "Network authentication is required to access this resource.";
    }

    public static class CustomStatusMessageCodes
    {
        public const string DecryptionFailed = "DECRYPTION_FAILED";
    }

    public static class CustomStatusMessages
    {
        public const string JwtNotInitialzeErrorMessage = "JWT configuration is missing. Please set JWT_SECRET_KEY, JWT_ISSUER, and JWT_AUDIENCE.";
        public const string DecryptionFailed = "";
    }
}
