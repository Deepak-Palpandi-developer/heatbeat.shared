namespace HeatBeat.Shared.Entities;

public class BaseEntity
{
    public bool IsActive { get; set; } = true;

    public long CreatedBy { get; set; }

    public DateTimeOffset CreatedAt { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }

    public long? UpdatedBy { get; set; }
}
