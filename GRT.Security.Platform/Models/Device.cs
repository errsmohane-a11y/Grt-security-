using System;

namespace GRT.Security.Platform.Models
{
    public class Device
    {
        public int Id { get; set; }
        public string? DeviceId { get; set; }
        public string? DeviceName { get; set; }
        public string? IPAddress { get; set; }
        public string? Location { get; set; }
        public string? Status { get; set; }
        public DateTime LastLogin { get; set; }
        public string? UserId { get; set; }
        public User? User { get; set; }
    }
}