using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using GRT.Security.Platform.Models;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.API
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly DeviceService _deviceService;
        private readonly AIThreatService _aiThreatService;

        public AuthController(AuthService authService, DeviceService deviceService, AIThreatService aiThreatService)
        {
            _authService = authService;
            _deviceService = deviceService;
            _aiThreatService = aiThreatService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var result = await _authService.RegisterUserAsync(request.Email, request.Password, request.FirstName, request.LastName);

            if (result.Succeeded)
            {
                return Ok(new { Message = "User registered successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var deviceId = Request.Headers["Device-ID"].ToString();

            // AI Threat Analysis
            var threatScore = await _aiThreatService.PredictThreatLevelAsync(null, ipAddress, deviceId);
            var action = await _aiThreatService.SuggestSecurityActionAsync(threatScore);

            if (threatScore > 0.8)
            {
                return Unauthorized(new { Message = "Access blocked due to high threat score", Action = action });
            }

            var result = await _authService.LoginUserAsync(request.Email, request.Password, ipAddress, deviceId);

            if (result.Succeeded)
            {
                var user = await _authService.GetUserByEmailAsync(request.Email);
                var token = await _authService.GenerateJwtTokenAsync(user);

                // Register device if not already registered
                var device = await _deviceService.GetDeviceByIdAsync(deviceId);
                if (device == null)
                {
                    await _deviceService.RegisterDeviceAsync(deviceId, request.DeviceName, ipAddress, "Unknown", user.Id);
                }

                return Ok(new
                {
                    Token = token,
                    ThreatScore = threatScore,
                    Action = action
                });
            }

            return Unauthorized(new { Message = "Invalid credentials", ThreatScore = threatScore });
        }

        [HttpPost("mfa/verify")]
        public async Task<IActionResult> VerifyMfa([FromBody] MfaRequest request)
        {
            var isValid = await _authService.ValidateMfaCodeAsync(request.UserId, request.Code);

            if (isValid)
            {
                return Ok(new { Message = "MFA verified successfully" });
            }

            return BadRequest(new { Message = "Invalid MFA code" });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirst("sub")?.Value;
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var deviceId = Request.Headers["Device-ID"].ToString();

            await _authService.LogoutUserAsync(userId, ipAddress, deviceId);

            return Ok(new { Message = "Logged out successfully" });
        }
    }

    public class RegisterRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
    }

    public class LoginRequest
    {
        public string? Email { get; set; }
        public string? Password { get; set; }
        public string? DeviceName { get; set; }
    }

    public class MfaRequest
    {
        public string? UserId { get; set; }
        public string? Code { get; set; }
    }
}