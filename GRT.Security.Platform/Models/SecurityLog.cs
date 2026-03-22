using System;

namespace GRT.Security.Platform.Models
{
    public class SecurityLog
    {
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string? EventType { get; set; }
        public string? IPAddress { get; set; }
        public string? DeviceId { get; set; }
        public string? CountryCode { get; set; }
        public DateTime TimeStamp { get; set; }
        public string? Details { get; set; }
    }
}