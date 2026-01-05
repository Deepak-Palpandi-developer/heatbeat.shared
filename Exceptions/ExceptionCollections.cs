namespace HeatBeat.Shared.Exceptions;

public class BadRequestExceptions : Exception
{
    public BadRequestExceptions(string message) : base(message)
    {
    }
}

public class DuplicateExceptions : Exception
{
    public DuplicateExceptions(string message) : base(message)
    {
    }
}

public class NotFoundExceptions : Exception
{
    public NotFoundExceptions(string message) : base(message)
    {
    }
}

public class TimeoutExceptions : Exception
{
    public TimeoutExceptions(string message) : base(message)
    {
    }
}

public class UnauthorizedAccessExceptions : Exception
{
    public UnauthorizedAccessExceptions(string message) : base(message)
    {
    }
}