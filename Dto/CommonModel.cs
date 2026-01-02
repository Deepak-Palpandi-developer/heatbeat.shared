namespace HeatBeat.Shared.Dto;

public class UnauthorizeModel
{
    public string Message { get; set; } = string.Empty;
    public bool Success { get; set; }
    public bool NeedLogin { get; set; }
    public bool NeedRefresh { get; set; }
}
