namespace HeatBeat.Shared.Dto;

public class BaseDto
{
    public bool IsActive { get; set; } = true;

    public long CreatedBy { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public DateTimeOffset? UpdatedAt { get; set; }

    public long? UpdatedBy { get; set; }
}
