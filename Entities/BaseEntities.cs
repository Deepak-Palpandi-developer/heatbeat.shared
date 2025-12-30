namespace HeatBeat.Shared.Entities;

public class BaseEntities
{
    public bool IsActive { get; set; } = true;

    public long CreatedBy { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime? UpdatedAt { get; set; }

    public long? UpdatedBy { get; set; }
}
