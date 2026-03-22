using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.API
{
    [ApiController]
    [Route("api/ai")]
    [Authorize]
    public class AIController : ControllerBase
    {
        private readonly AIThreatService _aiThreatService;

        public AIController(AIThreatService aiThreatService)
        {
            _aiThreatService = aiThreatService;
        }

        [HttpPost("security/analyze")]
        public async Task<IActionResult> AnalyzeSecurity([FromBody] SecurityAnalysisRequest request)
        {
            var threatLevel = await _aiThreatService.PredictThreatLevelAsync(request.UserId, request.IPAddress, request.DeviceId);
            var action = await _aiThreatService.SuggestSecurityActionAsync(threatLevel);

            return Ok(new
            {
                ThreatLevel = threatLevel,
                SuggestedAction = action,
                RiskCategory = GetRiskCategory(threatLevel)
            });
        }

        [HttpPost("threat/predict")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> PredictThreat([FromBody] ThreatPredictionRequest request)
        {
            var threatLevel = await _aiThreatService.PredictThreatLevelAsync(request.UserId, request.IPAddress, request.DeviceId);
            var anomalies = await _aiThreatService.DetectAnomaliesAsync();

            return Ok(new
            {
                ThreatLevel = threatLevel,
                AnomaliesDetected = anomalies,
                RiskAssessment = GetRiskAssessment(threatLevel)
            });
        }

        [HttpGet("system/status")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetSystemStatus()
        {
            var status = await _aiThreatService.AnalyzeSystemStatusAsync();
            return Ok(status);
        }

        [HttpGet("history")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetRequestHistory()
        {
            var history = await _aiThreatService.GetRequestHistoryAsync();
            return Ok(history);
        }

        [HttpPost("retrain")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Retrain()
        {
            await _aiThreatService.RetrainModelAsync();
            return Ok(new { Message = "Model retrained successfully" });
        }

        private string GetRiskCategory(float threatLevel)
        {
            if (threatLevel < 0.3) return "Safe";
            if (threatLevel < 0.6) return "Suspicious";
            if (threatLevel < 0.8) return "Dangerous";
            return "Critical";
        }

        private string GetRiskAssessment(float threatLevel)
        {
            if (threatLevel < 0.3) return "Low risk - proceed normally";
            if (threatLevel < 0.6) return "Medium risk - additional verification recommended";
            if (threatLevel < 0.8) return "High risk - block and investigate";
            return "Critical risk - immediate security response required";
        }
    }

    public class SecurityAnalysisRequest
    {
        public string? UserId { get; set; }
        public string? IPAddress { get; set; }
        public string? DeviceId { get; set; }
    }

    public class ThreatPredictionRequest
    {
        public string? UserId { get; set; }
        public string? IPAddress { get; set; }
        public string? DeviceId { get; set; }
    }
}