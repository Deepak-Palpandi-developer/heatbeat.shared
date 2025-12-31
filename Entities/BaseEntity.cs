namespace HeatBeat.Shared.Entities;

public class BaseEntity
{
    public bool IsActive { get; set; } = true;

    public long CreatedBy { get; set; }

    public DateTime CreatedAt { get; set; }

    public DateTime? UpdatedAt { get; set; }

    public long? UpdatedBy { get; set; }
}
