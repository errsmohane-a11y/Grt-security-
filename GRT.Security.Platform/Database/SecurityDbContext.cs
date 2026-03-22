using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using GRT.Security.Platform.Models;

namespace GRT.Security.Platform.Database
{
    public class SecurityDbContext : IdentityDbContext<User>
    {
        public SecurityDbContext(DbContextOptions<SecurityDbContext> options)
            : base(options)
        {
        }

        public DbSet<Device> Devices { get; set; }
        public DbSet<SecurityLog> SecurityLogs { get; set; }
        public DbSet<RequestHistory> RequestHistories { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure relationships
            builder.Entity<User>()
                .HasMany(u => u.Devices)
                .WithOne()
                .HasForeignKey("UserId");

            builder.Entity<User>()
                .HasMany(u => u.SecurityLogs)
                .WithOne()
                .HasForeignKey("UserId");

            // Configure indexes for performance
            builder.Entity<Device>()
                .HasIndex(d => d.DeviceId)
                .IsUnique();

            builder.Entity<SecurityLog>()
                .HasIndex(sl => sl.TimeStamp);

            builder.Entity<SecurityLog>()
                .HasIndex(sl => new { sl.UserId, sl.TimeStamp });
        }
    }
}