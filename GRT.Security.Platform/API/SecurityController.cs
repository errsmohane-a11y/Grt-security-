using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.API
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class SecurityController : ControllerBase
    {
        private readonly SecurityService _securityService;
        private readonly AIThreatService _aiThreatService;

        public SecurityController(SecurityService securityService, AIThreatService aiThreatService)
        {
            _securityService = securityService;
            _aiThreatService = aiThreatService;
        }

        [HttpGet("logs")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetSecurityLogs([FromQuery] string? userId = null, [FromQuery] DateTime? startDate = null, [FromQuery] DateTime? endDate = null)
        {
            var logs = await _securityService.GetSecurityLogsAsync(userId, startDate, endDate);
            return Ok(logs);
        }

        [HttpGet("threat-score")]
        public async Task<IActionResult> GetThreatScore()
        {
            var userId = User.FindFirst("sub")?.Value;
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var deviceId = Request.Headers["Device-ID"].ToString();

            var score = await _securityService.CalculateThreatScoreAsync(userId, ipAddress, deviceId);
            return Ok(new { ThreatScore = score });
        }

        [HttpGet("anomalies")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAnomalies()
        {
            var anomalies = await _securityService.GetAnomaliesAsync();
            return Ok(anomalies);
        }

        [HttpPost("alert")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> SendAlert([FromBody] AlertRequest request)
        {
            await _securityService.SendAlertAsync(request.UserId, request.AlertType, request.Message);
            return Ok(new { Message = "Alert sent successfully" });
        }

        [HttpPost("policy/banking-mode")]
        [Authorize(Roles = "Admin")]
        public IActionResult SetBankingMode([FromBody] BankingModeRequest request)
        {
            _securityService.SetBankingMode(request.Enabled);
            return Ok(new { Message = $"Banking mode set to {(request.Enabled ? "ON" : "OFF")}" });
        }

        [HttpPost("policy/restricted-mode")]
        [Authorize(Roles = "Admin")]
        public IActionResult SetRestrictedMode([FromBody] RestrictedModeRequest request)
        {
            _securityService.SetRestrictedMode(request.Enabled);
            return Ok(new { Message = $"Restricted mode set to {(request.Enabled ? "ON" : "OFF")}" });
        }

        [HttpPost("policy/block-country")]
        [Authorize(Roles = "Admin")]
        public IActionResult BlockCountry([FromBody] CountryPolicyRequest request)
        {
            _securityService.AddBlockedCountry(request.CountryCode);
            return Ok(new { Message = $"Country blocked: {request.CountryCode}" });
        }

        [HttpPost("policy/unblock-country")]
        [Authorize(Roles = "Admin")]
        public IActionResult UnblockCountry([FromBody] CountryPolicyRequest request)
        {
            _securityService.RemoveBlockedCountry(request.CountryCode);
            return Ok(new { Message = $"Country unblocked: {request.CountryCode}" });
        }

        [HttpGet("policy/allowed-countries")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetAllowedCountries()
        {
            var countries = _securityService.GetAllowedCountries();
            return Ok(new { AllowedCountries = countries });
        }

        [HttpGet("policy/blocked-countries")]
        [Authorize(Roles = "Admin")]
        public IActionResult GetBlockedCountries()
        {
            var countries = _securityService.GetBlockedCountries();
            return Ok(new { BlockedCountries = countries });
        }
    }

    public class AlertRequest
    {
        public string? UserId { get; set; }
        public string? AlertType { get; set; }
        public string? Message { get; set; }
    }

    public class BankingModeRequest
    {
        public bool Enabled { get; set; }
    }

    public class RestrictedModeRequest
    {
        public bool Enabled { get; set; }
    }

    public class CountryPolicyRequest
    {
        public string? CountryCode { get; set; }
    }
}