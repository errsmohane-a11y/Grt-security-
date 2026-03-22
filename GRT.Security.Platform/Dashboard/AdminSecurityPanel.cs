using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Dashboard
{
    [ApiController]
    [Route("api/dashboard")]
    [Authorize(Roles = "Admin")]
    public class AdminSecurityPanelController : ControllerBase
    {
        private readonly SecurityService _securityService;
        private readonly AIThreatService _aiThreatService;
        private readonly DeviceService _deviceService;

        public AdminSecurityPanelController(
            SecurityService securityService,
            AIThreatService aiThreatService,
            DeviceService deviceService)
        {
            _securityService = securityService;
            _aiThreatService = aiThreatService;
            _deviceService = deviceService;
        }

        [HttpGet("overview")]
        public async Task<IActionResult> GetSecurityOverview()
        {
            var systemStatus = await _aiThreatService.AnalyzeSystemStatusAsync();
            var anomalies = await _securityService.GetAnomaliesAsync();

            return Ok(new
            {
                SystemStatus = systemStatus,
                Anomalies = anomalies,
                ActiveDevices = await GetActiveDevicesCountAsync()
            });
        }

        [HttpGet("alerts")]
        public async Task<IActionResult> GetActiveAlerts()
        {
            var anomalies = await _securityService.GetAnomaliesAsync();
            var alerts = new List<object>();

            foreach (var anomaly in anomalies)
            {
                alerts.Add(new
                {
                    Type = "Anomaly",
                    Message = $"Suspicious activity detected: {anomaly.EventType}",
                    UserId = anomaly.UserId,
                    IPAddress = anomaly.IPAddress,
                    TimeStamp = anomaly.TimeStamp
                });
            }

            return Ok(alerts);
        }

        [HttpPost("block-ip")]
        public async Task<IActionResult> BlockIP([FromBody] BlockIPRequest request)
        {
            // In a real implementation, you'd add to a blacklist
            await _securityService.LogSecurityEventAsync(null, "IPBlocked", request.IPAddress, null);
            return Ok(new { Message = $"IP {request.IPAddress} blocked successfully" });
        }

        [HttpGet("devices")]
        public async Task<IActionResult> GetAllDevices()
        {
            // This would require admin access to all devices
            // For demo purposes, return empty list
            return Ok(new List<object>());
        }

        private async Task<int> GetActiveDevicesCountAsync()
        {
            // In a real implementation, you'd query active devices
            return 0;
        }
    }

    public class BlockIPRequest
    {
        public string? IPAddress { get; set; }
    }
}