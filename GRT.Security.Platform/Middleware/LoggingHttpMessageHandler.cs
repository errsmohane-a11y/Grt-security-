using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Middleware
{
    public class LoggingHttpMessageHandler : DelegatingHandler
    {
        private readonly IServiceProvider _serviceProvider;

        public LoggingHttpMessageHandler(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Log outgoing request
            using (var scope = _serviceProvider.CreateScope())
            {
                var aiThreatService = scope.ServiceProvider.GetRequiredService<AIThreatService>();
                var securityService = scope.ServiceProvider.GetRequiredService<SecurityService>();

                // Extract details
                var url = request.RequestUri?.ToString() ?? "unknown";
                var method = request.Method.ToString();
                var ipAddress = "outgoing"; // Since it's outgoing, IP is not relevant, but we can use a placeholder
                var deviceId = "system"; // System making the request
                var userId = "system"; // Or null for system requests

                // Calculate threat score for outgoing request (could be based on URL patterns)
                var threatScore = await securityService.CalculateThreatScoreAsync(userId, ipAddress, deviceId);

                await aiThreatService.LogRequestHistoryAsync(new Models.RequestHistory
                {
                    UserId = userId,
                    Direction = "Outgoing",
                    HttpMethod = method,
                    Path = url,
                    IpAddress = ipAddress,
                    DeviceId = deviceId,
                    Timestamp = DateTime.UtcNow,
                    RiskScore = (int)(threatScore * 100),
                    Details = $"Outgoing request to external service"
                });
            }

            // Proceed with the request
            return await base.SendAsync(request, cancellationToken);
        }
    }
}