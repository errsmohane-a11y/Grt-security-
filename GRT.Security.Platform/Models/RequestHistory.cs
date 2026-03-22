using System;

namespace GRT.Security.Platform.Models
{
    public class RequestHistory
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? Direction { get; set; } // "Incoming" or "Outgoing"
        public string? HttpMethod { get; set; }
        public string? Path { get; set; }
        public string? IpAddress { get; set; }
        public string? DeviceId { get; set; }
        public DateTime Timestamp { get; set; }
        public int RiskScore { get; set; }
        public string? Details { get; set; }
    }
}