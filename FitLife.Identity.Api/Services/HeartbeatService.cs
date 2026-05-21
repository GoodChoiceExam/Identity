namespace FitLife.Identity.Api.Services;

public class HeartbeatService(ILogger<HeartbeatService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            logger.LogInformation("Heartbeat");
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }
    }
}
