using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.ML;
using Microsoft.ML.Data;
using Microsoft.EntityFrameworkCore;
using GRT.Security.Platform.Database;
using GRT.Security.Platform.Models;

namespace GRT.Security.Platform.Services
{
    public class AIThreatService
    {
        private readonly SecurityDbContext _context;
        private readonly SecurityService _securityService;
        private readonly MLContext _mlContext;
        private ITransformer? _model;

        public AIThreatService(SecurityDbContext context, SecurityService securityService)
        {
            _context = context;
            _securityService = securityService;
            _mlContext = new MLContext();
            LoadOrTrainModel();
        }

        private void LoadOrTrainModel()
        {
            // For demonstration, we'll create a simple model
            // In production, you'd load a pre-trained model or train on historical data
            var trainingData = new List<SecurityData>
            {
                new SecurityData { LoginAttempts = 1, FailedAttempts = 0, IsKnownDevice = 1, IsKnownLocation = 1, ThreatLevel = false },
                new SecurityData { LoginAttempts = 5, FailedAttempts = 3, IsKnownDevice = 0, IsKnownLocation = 0, ThreatLevel = true },
                new SecurityData { LoginAttempts = 10, FailedAttempts = 8, IsKnownDevice = 0, IsKnownLocation = 0, ThreatLevel = true }
            };

            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);

            var pipeline = _mlContext.Transforms.Concatenate("Features", "LoginAttempts", "FailedAttempts", "IsKnownDevice", "IsKnownLocation")
                .Append(_mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(labelColumnName: "ThreatLevel", featureColumnName: "Features"));

            _model = pipeline.Fit(dataView);
        }

        public async Task<float> PredictThreatLevelAsync(string? userId, string? ipAddress, string? deviceId)
        {
            if (string.IsNullOrEmpty(ipAddress) || string.IsNullOrEmpty(deviceId))
                return 0.5f; // Medium risk if missing data

            // Gather features for prediction
            var recentLogs = await _context.SecurityLogs
                .Where(l => l.UserId == userId && l.TimeStamp > DateTime.UtcNow.AddHours(-24))
                .ToListAsync();

            var loginAttempts = recentLogs.Count(l => l.EventType.Contains("Login"));
            var failedAttempts = recentLogs.Count(l => l.EventType.Contains("Failed"));

            var userDevices = await _context.Devices.Where(d => d.UserId == userId).ToListAsync();
            var isKnownDevice = userDevices.Any(d => d.DeviceId == deviceId) ? 1 : 0;

            // Simple location check (in production, use geo-IP database)
            var isKnownLocation = userDevices.Any(d => d.IPAddress == ipAddress) ? 1 : 0;

            if (_model == null)
                return 0.5f; // Default medium risk

            var predictionData = new SecurityData
            {
                LoginAttempts = loginAttempts,
                FailedAttempts = failedAttempts,
                IsKnownDevice = isKnownDevice,
                IsKnownLocation = isKnownLocation
            };

            var predictionEngine = _mlContext.Model.CreatePredictionEngine<SecurityData, ThreatPrediction>(_model);
            var prediction = predictionEngine.Predict(predictionData);

            return prediction.Probability;
        }

        public async Task<Dictionary<string, object>> AnalyzeSystemStatusAsync()
        {
            var last24Hours = DateTime.UtcNow.AddHours(-24);

            var totalLogins = await _context.SecurityLogs.CountAsync(l => l.TimeStamp > last24Hours && l.EventType.Contains("Login"));
            var failedLogins = await _context.SecurityLogs.CountAsync(l => l.TimeStamp > last24Hours && l.EventType.Contains("Failed"));
            var uniqueIPs = await _context.SecurityLogs.Where(l => l.TimeStamp > last24Hours).Select(l => l.IPAddress).Distinct().CountAsync();
            var incoming = await _context.RequestHistories.CountAsync(r => r.Timestamp > last24Hours && r.Direction == "Incoming");
            var outgoing = await _context.RequestHistories.CountAsync(r => r.Timestamp > last24Hours && r.Direction == "Outgoing");
            var anomalies = await DetectAnomaliesAsync();

            return new Dictionary<string, object>
            {
                ["TotalLogins"] = totalLogins,
                ["FailedLogins"] = failedLogins,
                ["UniqueIPs"] = uniqueIPs,
                ["IncomingRequests"] = incoming,
                ["OutgoingRequests"] = outgoing,
                ["AnomaliesCount"] = anomalies.Count(),
                ["SuccessRate"] = totalLogins > 0 ? (totalLogins - failedLogins) / (double)totalLogins : 0
            };
        }

        public async Task LogRequestHistoryAsync(RequestHistory entry)
        {
            _context.RequestHistories.Add(entry);
            await _context.SaveChangesAsync();

            if (entry.RiskScore > 60)
                await _securityService.SendAlertAsync(entry.UserId, "HighRiskRequest", $"High risk request {entry.Path} score {entry.RiskScore}");

            await RetrainModelAsync();
        }

        public async Task RetrainModelAsync()
        {
            var history = await _context.RequestHistories
                .OrderByDescending(r => r.Timestamp)
                .Take(1000)
                .ToListAsync();

            var trainingData = new List<SecurityData>();

            foreach (var record in history)
            {
                trainingData.Add(new SecurityData
                {
                    LoginAttempts = record.Direction == "Incoming" ? 1 : 0,
                    FailedAttempts = record.RiskScore / 10.0f,
                    IsKnownDevice = await _context.Devices.AnyAsync(d => d.DeviceId == record.DeviceId) ? 1 : 0,
                    IsKnownLocation = await _context.Devices.AnyAsync(d => d.IPAddress == record.IpAddress) ? 1 : 0,
                    ThreatLevel = record.RiskScore > 60
                });
            }

            var dataView = _mlContext.Data.LoadFromEnumerable(trainingData);
            var pipeline = _mlContext.Transforms.Concatenate("Features", "LoginAttempts", "FailedAttempts", "IsKnownDevice", "IsKnownLocation")
                .Append(_mlContext.BinaryClassification.Trainers.SdcaLogisticRegression(labelColumnName: "ThreatLevel", featureColumnName: "Features"));

            _model = pipeline.Fit(dataView);
        }

        public async Task<IEnumerable<SecurityLog>> DetectAnomaliesAsync()
        {
            // Simple anomaly detection based on patterns
            var anomalies = new List<SecurityLog>();

            // High frequency failed logins from same IP
            var suspiciousIPs = await _context.SecurityLogs
                .Where(l => l.EventType.Contains("Failed") && l.TimeStamp > DateTime.UtcNow.AddHours(-1))
                .GroupBy(l => l.IPAddress)
                .Where(g => g.Count() > 5)
                .Select(g => g.Key)
                .ToListAsync();

            foreach (var ip in suspiciousIPs)
            {
                var logs = await _context.SecurityLogs
                    .Where(l => l.IPAddress == ip && l.TimeStamp > DateTime.UtcNow.AddHours(-1))
                    .ToListAsync();
                anomalies.AddRange(logs);
            }

            // Unusual login times (e.g., 2 AM - 4 AM)
            var unusualTimeLogs = await _context.SecurityLogs
                .Where(l => l.EventType == "SuccessfulLogin" &&
                           (l.TimeStamp.Hour >= 2 && l.TimeStamp.Hour <= 4) &&
                           l.TimeStamp > DateTime.UtcNow.AddDays(-7))
                .ToListAsync();

            anomalies.AddRange(unusualTimeLogs);

            return anomalies.Distinct();
        }

        public async Task<string> SuggestSecurityActionAsync(float threatScore)
        {
            if (threatScore < 0.3)
                return "Allow access";
            else if (threatScore < 0.6)
                return "Require additional verification (MFA)";
            else if (threatScore < 0.8)
                return "Block access temporarily and send alert";
            else
                return "Block access and initiate security protocol";
        }

        public async Task<IEnumerable<RequestHistory>> GetRequestHistoryAsync()
        {
            return await _context.RequestHistories
                .OrderByDescending(r => r.Timestamp)
                .Take(1000)
                .ToListAsync();
        }
    }

    public class SecurityData
    {
        [LoadColumn(0)]
        public float LoginAttempts { get; set; }

        [LoadColumn(1)]
        public float FailedAttempts { get; set; }

        [LoadColumn(2)]
        public float IsKnownDevice { get; set; }

        [LoadColumn(3)]
        public float IsKnownLocation { get; set; }

        [LoadColumn(4)]
        public bool ThreatLevel { get; set; }
    }

    public class ThreatPrediction
    {
        [ColumnName("PredictedLabel")]
        public bool IsThreat { get; set; }

        public float Probability { get; set; }

        public float Score { get; set; }
    }
}