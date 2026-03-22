using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using GRT.Security.Platform.Models;

namespace GRT.Security.Platform.Services
{
    public class AuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly SecurityService _securityService;

        public AuthService(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            IConfiguration configuration,
            SecurityService securityService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _securityService = securityService;
        }

        public async Task<IdentityResult> RegisterUserAsync(string email, string password, string firstName, string lastName)
        {
            var user = new User
            {
                UserName = email,
                Email = email,
                FirstName = firstName,
                LastName = lastName,
                CreatedDate = DateTime.UtcNow,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user, password);
            return result;
        }

        public async Task<SignInResult> LoginUserAsync(string email, string password, string ipAddress, string deviceId)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                await _securityService.LogSecurityEventAsync(null, "FailedLogin_InvalidUser", ipAddress, deviceId);
                return SignInResult.Failed;
            }

            var result = await _signInManager.PasswordSignInAsync(user, password, false, true);

            if (result.Succeeded)
            {
                user.LastLoginDate = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
                await _securityService.LogSecurityEventAsync(user.Id, "SuccessfulLogin", ipAddress, deviceId);
            }
            else if (result.IsLockedOut)
            {
                await _securityService.LogSecurityEventAsync(user.Id, "AccountLocked", ipAddress, deviceId);
            }
            else
            {
                await _securityService.LogSecurityEventAsync(user.Id, "FailedLogin_InvalidPassword", ipAddress, deviceId);
            }

            return result;
        }

        public async Task<string> GenerateJwtTokenAsync(User user)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("FirstName", user.FirstName),
                new Claim("LastName", user.LastName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<bool> ValidateMfaCodeAsync(string userId, string code)
        {
            // Implement MFA validation logic here
            // For now, return true for demonstration
            await _securityService.LogSecurityEventAsync(userId, "MFAValidated", null, null);
            return true;
        }

        public async Task LogoutUserAsync(string? userId, string? ipAddress, string? deviceId)
        {
            if (string.IsNullOrEmpty(userId))
                return;

            await _signInManager.SignOutAsync();
            await _securityService.LogSecurityEventAsync(userId, "Logout", ipAddress, deviceId);
        }

        public async Task<User> GetUserByEmailAsync(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }
    }
}