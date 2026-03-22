using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using AspNetCoreRateLimit;
using GRT.Security.Platform.Services;

namespace GRT.Security.Platform.Middleware
{
    public class ApiSecurityMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IIpPolicyStore _ipPolicyStore;

        public ApiSecurityMiddleware(RequestDelegate next, IIpPolicyStore ipPolicyStore)
        {
            _next = next;
            _ipPolicyStore = ipPolicyStore;
        }

        public async Task Invoke(HttpContext context)
        {
            // Rate limiting is handled by AspNetCoreRateLimit package
            // Additional security checks can be added here

            var path = context.Request.Path.Value.ToLower();

            // Block suspicious paths
            if (path.Contains("admin") && !context.User.IsInRole("Admin"))
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access denied");
                return;
            }

            // Add security headers
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["X-Frame-Options"] = "DENY";
            context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
            context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

            await _next(context);
        }
    }
}