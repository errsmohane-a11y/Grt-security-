using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Dashboard
{
    [Route("admin")]
    [Authorize(Roles = "Admin")]
    public class AdminDashboardController : Controller
    {
        private readonly SecurityService _securityService;
        private readonly AIThreatService _aiThreatService;

        public AdminDashboardController(SecurityService securityService, AIThreatService aiThreatService)
        {
            _securityService = securityService;
            _aiThreatService = aiThreatService;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            var systemStatus = await _aiThreatService.AnalyzeSystemStatusAsync();
            var anomalies = await _securityService.GetAnomaliesAsync();
            var allowedCountries = _securityService.GetAllowedCountries();
            var blockedCountries = _securityService.GetBlockedCountries();

            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <title>Security Admin Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .section {{ margin-bottom: 30px; border: 1px solid #ccc; padding: 20px; }}
        .status {{ color: green; }}
        .alert {{ color: red; }}
        button {{ margin: 5px; padding: 10px; }}
        input {{ margin: 5px; padding: 5px; }}
    </style>
</head>
<body>
    <h1>Security Admin Dashboard</h1>

    <div class='section'>
        <h2>System Status</h2>
        <p>Total Logins: {systemStatus["TotalLogins"]}</p>
        <p>Failed Logins: {systemStatus["FailedLogins"]}</p>
        <p>Unique IPs: {systemStatus["UniqueIPs"]}</p>
        <p>Incoming Requests: {systemStatus["IncomingRequests"]}</p>
        <p>Outgoing Requests: {systemStatus["OutgoingRequests"]}</p>
        <p>Anomalies: {systemStatus["AnomaliesCount"]}</p>
        <p>Success Rate: {systemStatus["SuccessRate"]:P}</p>
        <p>Banking Mode: {(_securityService.IsBankingModeEnabled() ? "ON" : "OFF")}</p>
        <p>Restricted Mode: {(_securityService.IsRestrictedModeEnabled() ? "ON" : "OFF")}</p>
    </div>

    <div class='section'>
        <h2>Policy Management</h2>
        <button onclick='toggleBankingMode()'>Toggle Banking Mode</button>
        <button onclick='toggleRestrictedMode()'>Toggle Restricted Mode</button>
        <br><br>
        <h3>Allowed Countries</h3>
        <ul>{string.Join("", allowedCountries.Select(c => $"<li>{c}</li>"))}</ul>
        <h3>Blocked Countries</h3>
        <ul>{string.Join("", blockedCountries.Select(c => $"<li>{c}</li>"))}</ul>
        <input type='text' id='countryCode' placeholder='Country Code'>
        <button onclick='blockCountry()'>Block Country</button>
        <button onclick='unblockCountry()'>Unblock Country</button>
    </div>

    <div class='section'>
        <h2>Recent Anomalies</h2>
        <ul>
            {string.Join("", anomalies.Take(10).Select(a => $"<li>{a.TimeStamp}: {a.EventType} - {a.IPAddress}</li>"))}
        </ul>
    </div>

    <script>
        async function toggleBankingMode() {{
            const response = await fetch('/api/security/policy/banking-mode', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ enabled: !{(_securityService.IsBankingModeEnabled() ? "true" : "false")} }})
            }});
            if (response.ok) location.reload();
        }}

        async function toggleRestrictedMode() {{
            const response = await fetch('/api/security/policy/restricted-mode', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ enabled: !{(_securityService.IsRestrictedModeEnabled() ? "true" : "false")} }})
            }});
            if (response.ok) location.reload();
        }}

        async function blockCountry() {{
            const code = document.getElementById('countryCode').value;
            const response = await fetch('/api/security/policy/block-country', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ countryCode: code }})
            }});
            if (response.ok) location.reload();
        }}

        async function unblockCountry() {{
            const code = document.getElementById('countryCode').value;
            const response = await fetch('/api/security/policy/unblock-country', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ countryCode: code }})
            }});
            if (response.ok) location.reload();
        }}
    </script>
</body>
</html>";

            return Content(html, "text/html");
        }
    }
}