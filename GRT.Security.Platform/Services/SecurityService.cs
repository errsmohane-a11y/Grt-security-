using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using GRT.Security.Platform.Database;
using GRT.Security.Platform.Models;

namespace GRT.Security.Platform.Services
{
    public class SecurityService
    {
        private readonly SecurityDbContext _context;
        private readonly IConfiguration _configuration;

        private string[] _allowedCountries;
        private string[] _blockedCountries;
        private bool _bankingModeEnabled;
        private bool _restrictedMode;
        private readonly int _countryHopWindowMinutes;
        private readonly int _maxCountryHops;

        public SecurityService(SecurityDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;

            _allowedCountries = _configuration.GetSection("Security:AllowedCountries").Get<string[]>() ?? Array.Empty<string>();
            _blockedCountries = _configuration.GetSection("Security:BlockedCountries").Get<string[]>() ?? Array.Empty<string>();
            _bankingModeEnabled = _configuration.GetValue<bool>("Security:BankingModeEnabled");
            _restrictedMode = _configuration.GetValue<bool>("Security:RestrictedMode");
            _countryHopWindowMinutes = _configuration.GetValue<int>("Security:CountryHopWindowMinutes");
            _maxCountryHops = _configuration.GetValue<int>("Security:MaxCountryHops");
        }

        public async Task LogSecurityEventAsync(string? userId, string? eventType, string? ipAddress, string? deviceId)
        {
            var log = new SecurityLog
            {
                UserId = userId,
                EventType = eventType,
                IPAddress = ipAddress,
                DeviceId = deviceId,
                TimeStamp = DateTime.UtcNow
            };

            _context.SecurityLogs.Add(log);
            await _context.SaveChangesAsync();
        }

        public async Task<IEnumerable<SecurityLog>> GetSecurityLogsAsync(string? userId = null, DateTime? startDate = null, DateTime? endDate = null)
        {
            var query = _context.SecurityLogs.AsQueryable();

            if (!string.IsNullOrEmpty(userId))
                query = query.Where(l => l.UserId == userId);

            if (startDate.HasValue)
                query = query.Where(l => l.TimeStamp >= startDate.Value);

            if (endDate.HasValue)
                query = query.Where(l => l.TimeStamp <= endDate.Value);

            return await query.OrderByDescending(l => l.TimeStamp).ToListAsync();
        }

        public async Task<bool> IsIpBlockedAsync(string ipAddress)
        {
            // Implement IP blocking logic
            // Check against a blacklist or rate limiting
            var recentFailedAttempts = await _context.SecurityLogs
                .Where(l => l.IPAddress == ipAddress &&
                           l.EventType.Contains("Failed") &&
                           l.TimeStamp > DateTime.UtcNow.AddMinutes(-15))
                .CountAsync();

            return recentFailedAttempts > 5; // Block after 5 failed attempts in 15 minutes
        }

        public bool IsLocationAllowed(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode))
                return false;

            if (_blockedCountries.Contains(countryCode, StringComparer.OrdinalIgnoreCase))
                return false;

            if (_allowedCountries.Length > 0 && !_allowedCountries.Contains(countryCode, StringComparer.OrdinalIgnoreCase))
                return false;

            return true;
        }

        public async Task<bool> IsLocationAllowedAsync(string countryCode)
        {
            return IsLocationAllowed(countryCode);
        }

        public bool IsBankingModeEnabled() => _bankingModeEnabled;

        public bool IsRestrictedModeEnabled() => _restrictedMode;

        public void SetBankingMode(bool enabled)
        {
            _bankingModeEnabled = enabled;
        }

        public void SetRestrictedMode(bool enabled)
        {
            _restrictedMode = enabled;
        }

        public void AddBlockedCountry(string? countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode)) return;
            if (_blockedCountries.Contains(countryCode.ToUpperInvariant())) return;
            var list = _blockedCountries.ToList();
            list.Add(countryCode.ToUpperInvariant());
            _blockedCountries = list.ToArray();
        }

        public void RemoveBlockedCountry(string? countryCode)
        {
            if (string.IsNullOrWhiteSpace(countryCode)) return;
            var list = _blockedCountries.ToList();
            list.RemoveAll(c => c.Equals(countryCode, StringComparison.OrdinalIgnoreCase));
            _blockedCountries = list.ToArray();
        }

        public void SetAllowedCountries(string[] countries)
        {
            _allowedCountries = (countries ?? Array.Empty<string>()).Select(c => c.ToUpperInvariant()).ToArray();
        }

        public string[] GetAllowedCountries()
        {
            return _allowedCountries;
        }

        public string[] GetBlockedCountries()
        {
            return _blockedCountries;
        }

        public async Task<bool> EvaluateCountryHopAsync(string userId, string newCountry)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(newCountry))
                return false;

            var windowStart = DateTime.UtcNow.AddMinutes(-_countryHopWindowMinutes);
            var recentHosts = await _context.SecurityLogs
                .Where(l => l.UserId == userId && l.TimeStamp >= windowStart)
                .OrderByDescending(l => l.TimeStamp)
                .Select(l => l.CountryCode)
                .Distinct()
                .ToListAsync();

            if (!recentHosts.Contains(newCountry, StringComparer.OrdinalIgnoreCase))
            {
                recentHosts.Insert(0, newCountry);
            }

            return recentHosts.Count > _maxCountryHops;
        }

        public bool IsCountryBlocked(string countryCode)
        {
            if (string.IsNullOrEmpty(countryCode))
                return false;

            return _blockedCountries.Contains(countryCode, StringComparer.OrdinalIgnoreCase);
        }

        public async Task<int> CalculateThreatScoreAsync(string? userId, string? ipAddress, string? deviceId)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(ipAddress) || string.IsNullOrEmpty(deviceId))
                return 0;

            int score = 0;

            // Check login frequency
            var recentLogins = await _context.SecurityLogs
                .Where(l => l.UserId == userId && l.EventType == "SuccessfulLogin" && l.TimeStamp > DateTime.UtcNow.AddHours(-1))
                .CountAsync();

            if (recentLogins > 3) score += 20; // Unusual login frequency

            // Check failed login attempts
            var recentFailed = await _context.SecurityLogs
                .Where(l => l.IPAddress == ipAddress && l.EventType.Contains("Failed") && l.TimeStamp > DateTime.UtcNow.AddMinutes(-30))
                .CountAsync();

            score += recentFailed * 10;

            // Check device changes
            var userDevices = await _context.Devices.Where(d => d.UserId == userId).Select(d => d.DeviceId).ToListAsync();
            if (!userDevices.Contains(deviceId)) score += 30; // New device

            // Check location changes
            var lastLogin = await _context.SecurityLogs
                .Where(l => l.UserId == userId && l.EventType == "SuccessfulLogin")
                .OrderByDescending(l => l.TimeStamp)
                .FirstOrDefaultAsync();

            if (lastLogin != null && lastLogin.IPAddress != ipAddress) score += 15; // Different IP

            return Math.Min(score, 100);
        }

        public async Task SendAlertAsync(string? userId, string? alertType, string? message)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(alertType) || string.IsNullOrEmpty(message))
                return;

            // Implement alert system (email, SMS, etc.)
            // For now, just log it
            await LogSecurityEventAsync(userId, $"Alert_{alertType}", null, null);
        }

        public async Task<IEnumerable<SecurityLog>> GetAnomaliesAsync()
        {
            // Simple anomaly detection: multiple failed logins from same IP
            var anomalies = await _context.SecurityLogs
                .Where(l => l.EventType.Contains("Failed"))
                .GroupBy(l => l.IPAddress)
                .Where(g => g.Count() > 3)
                .SelectMany(g => g)
                .ToListAsync();

            return anomalies;
        }
    }
}