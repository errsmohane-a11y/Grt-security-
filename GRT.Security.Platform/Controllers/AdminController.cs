using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Controllers
{
    [Authorize(Roles = "Admin")]
    public class AdminController : Controller
    {
        private readonly SecurityService _securityService;
        private readonly AIThreatService _aiThreatService;
        private readonly DeviceService _deviceService;

        public AdminController(
            SecurityService securityService,
            AIThreatService aiThreatService,
            DeviceService deviceService)
        {
            _securityService = securityService;
            _aiThreatService = aiThreatService;
            _deviceService = deviceService;
        }

        public async Task<IActionResult> Index()
        {
            var systemStatus = await _aiThreatService.AnalyzeSystemStatusAsync();
            var anomalies = await _securityService.GetAnomaliesAsync();
            var activeDevices = await GetActiveDevicesCountAsync();

            ViewBag.SystemStatus = systemStatus;
            ViewBag.Anomalies = anomalies;
            ViewBag.ActiveDevices = activeDevices;

            return View();
        }

        public async Task<IActionResult> SecurityLogs()
        {
            var logs = await _securityService.GetSecurityLogsAsync();
            return View(logs);
        }

        public async Task<IActionResult> Policies()
        {
            ViewBag.BankingMode = _securityService.IsBankingModeEnabled();
            ViewBag.RestrictedMode = _securityService.IsRestrictedModeEnabled();
            ViewBag.AllowedCountries = _securityService.GetAllowedCountries();
            ViewBag.BlockedCountries = _securityService.GetBlockedCountries();

            return View();
        }

        public async Task<IActionResult> ThreatAnalysis()
        {
            var systemStatus = await _aiThreatService.AnalyzeSystemStatusAsync();
            return View(systemStatus);
        }

        [HttpPost]
        public IActionResult ToggleBankingMode(bool enabled)
        {
            _securityService.SetBankingMode(enabled);
            return RedirectToAction("Policies");
        }

        [HttpPost]
        public IActionResult ToggleRestrictedMode(bool enabled)
        {
            _securityService.SetRestrictedMode(enabled);
            return RedirectToAction("Policies");
        }

        [HttpPost]
        public IActionResult BlockCountry(string countryCode)
        {
            _securityService.AddBlockedCountry(countryCode);
            return RedirectToAction("Policies");
        }

        [HttpPost]
        public IActionResult UnblockCountry(string countryCode)
        {
            _securityService.RemoveBlockedCountry(countryCode);
            return RedirectToAction("Policies");
        }

        private async Task<int> GetActiveDevicesCountAsync()
        {
            var devices = await _deviceService.GetAllDevicesAsync();
            return devices.Count(d => d.Status == "Active");
        }
    }
}