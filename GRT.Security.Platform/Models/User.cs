using Microsoft.AspNetCore.Identity;
using System;

namespace GRT.Security.Platform.Models
{
    public class User : IdentityUser
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime LastLoginDate { get; set; }
        public bool IsActive { get; set; }
        public string? PreferredLanguage { get; set; }
        public ICollection<Device>? Devices { get; set; }
        public ICollection<SecurityLog>? SecurityLogs { get; set; }
    }
}