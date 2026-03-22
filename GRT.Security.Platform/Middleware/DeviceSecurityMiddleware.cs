using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using GRT.Security.Platform.Models;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Middleware
{
    public class DeviceSecurityMiddleware
    {
        private readonly RequestDelegate _next;

        public DeviceSecurityMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context, DeviceService deviceService, SecurityService securityService, AIThreatService aiThreatService, IGeoIPService geoIPService)
        {
            var deviceId = context.Request.Headers["Device-ID"].ToString();
            var ipAddress = context.Connection.RemoteIpAddress?.ToString();

            async Task<string> GetCountryFromIpAsync(string ip)
            {
                if (string.IsNullOrEmpty(ip))
                    return "Unknown";

                return await geoIPService.GetCountryCodeAsync(ip);
            }

            if (string.IsNullOrEmpty(deviceId))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Device ID required");
                return;
            }

            // Check IP and country policies
            if (!string.IsNullOrEmpty(ipAddress) && await securityService.IsIpBlockedAsync(ipAddress))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("IP address blocked");
                return;
            }

            var countryCode = await GetCountryFromIpAsync(ipAddress);

            if (!await securityService.IsLocationAllowedAsync(countryCode))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync($"Country not allowed: {countryCode}");
                return;
            }

            if (securityService.IsCountryBlocked(countryCode))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync($"Country blocked: {countryCode}");
                return;
            }

            if (securityService.IsBankingModeEnabled())
            {
                var userIdClaim = context.User.FindFirst("sub")?.Value;
                if (await securityService.EvaluateCountryHopAsync(userIdClaim, countryCode))
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("Country hopping detected in banking mode");
                    return;
                }
            }

            // Validate device
            if (!await deviceService.IsDeviceAuthorizedAsync(deviceId))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Device not authorized");
                return;
            }

            // Update last login for device
            await deviceService.UpdateDeviceLastLoginAsync(deviceId);

            // Record incoming request in request history for learning
            var userId = context.User.FindFirst("sub")?.Value;
            var threatScore = await aiThreatService.PredictThreatLevelAsync(userId, ipAddress, deviceId);
            await aiThreatService.LogRequestHistoryAsync(new RequestHistory
            {
                UserId = userId,
                Direction = "Incoming",
                HttpMethod = context.Request.Method,
                Path = context.Request.Path,
                IpAddress = ipAddress ?? "unknown",
                DeviceId = deviceId,
                Timestamp = DateTime.UtcNow,
                RiskScore = (int)(threatScore * 100),
                Details = $"BankingMode={securityService.IsBankingModeEnabled()} country:{await GetCountryFromIpAsync(ipAddress)}"
            });

            await _next(context);
        }
    }
}