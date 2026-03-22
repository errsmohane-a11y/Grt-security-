using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using GRT.Security.Platform.Database;
using GRT.Security.Platform.Models;

namespace GRT.Security.Platform.Services
{
    public class DeviceService
    {
        private readonly SecurityDbContext _context;

        public DeviceService(SecurityDbContext context)
        {
            _context = context;
        }

        public async Task<Device> RegisterDeviceAsync(string? deviceId, string? deviceName, string? ipAddress, string? location, string? userId)
        {
            if (string.IsNullOrEmpty(deviceId) || string.IsNullOrEmpty(deviceName) || string.IsNullOrEmpty(userId))
                throw new ArgumentException("DeviceId, DeviceName, and UserId are required");

            var device = new Device
            {
                DeviceId = deviceId,
                DeviceName = deviceName,
                IPAddress = ipAddress,
                Location = location,
                Status = "Registered",
                LastLogin = DateTime.UtcNow,
                UserId = userId
            };

            _context.Devices.Add(device);
            await _context.SaveChangesAsync();

            // Log the registration
            await LogSecurityEventAsync(userId, "DeviceRegistered", ipAddress, deviceId);

            return device;
        }

        public async Task<Device> GetDeviceByIdAsync(string deviceId)
        {
            return await _context.Devices.FirstOrDefaultAsync(d => d.DeviceId == deviceId);
        }

        public async Task<bool> IsDeviceAuthorizedAsync(string deviceId)
        {
            var device = await GetDeviceByIdAsync(deviceId);
            return device != null && device.Status == "Registered";
        }

        public async Task UpdateDeviceLastLoginAsync(string deviceId)
        {
            var device = await GetDeviceByIdAsync(deviceId);
            if (device != null)
            {
                device.LastLogin = DateTime.UtcNow;
                await _context.SaveChangesAsync();
            }
        }

        public async Task<IEnumerable<Device>> GetUserDevicesAsync(string? userId)
        {
            if (string.IsNullOrEmpty(userId))
                return new List<Device>();

            return await _context.Devices.Where(d => d.UserId == userId).ToListAsync();
        }

        public async Task<IEnumerable<Device>> GetAllDevicesAsync()
        {
            return await _context.Devices.ToListAsync();
        }

        public async Task DeactivateDeviceAsync(string deviceId)
        {
            var device = await GetDeviceByIdAsync(deviceId);
            if (device != null)
            {
                device.Status = "Deactivated";
                await _context.SaveChangesAsync();
            }
        }

        private async Task LogSecurityEventAsync(string userId, string eventType, string ipAddress, string deviceId)
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
    }
}