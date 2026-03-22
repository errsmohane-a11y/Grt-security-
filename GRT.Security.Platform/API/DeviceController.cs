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
    public class DeviceController : ControllerBase
    {
        private readonly DeviceService _deviceService;

        public DeviceController(DeviceService deviceService)
        {
            _deviceService = deviceService;
        }

        [HttpGet]
        public async Task<IActionResult> GetUserDevices()
        {
            var userId = User.FindFirst("sub")?.Value;
            var devices = await _deviceService.GetUserDevicesAsync(userId);
            return Ok(devices);
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterDevice([FromBody] DeviceRegistrationRequest request)
        {
            var userId = User.FindFirst("sub")?.Value;
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            var device = await _deviceService.RegisterDeviceAsync(
                request.DeviceId,
                request.DeviceName,
                ipAddress,
                request.Location,
                userId);

            return Ok(device);
        }

        [HttpDelete("{deviceId}")]
        public async Task<IActionResult> DeactivateDevice(string deviceId)
        {
            await _deviceService.DeactivateDeviceAsync(deviceId);
            return Ok(new { Message = "Device deactivated successfully" });
        }
    }

    public class DeviceRegistrationRequest
    {
        public string? DeviceId { get; set; }
        public string? DeviceName { get; set; }
        public string? Location { get; set; }
    }
}