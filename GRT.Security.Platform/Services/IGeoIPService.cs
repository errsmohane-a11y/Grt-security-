using System.Net.Http.Json;

namespace GRT.Security.Platform.Services;

public interface IGeoIPService
{
    Task<string> GetCountryCodeAsync(string ipAddress);
}

public class GeoIPService : IGeoIPService
{
    private readonly HttpClient _httpClient;

    public GeoIPService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<string> GetCountryCodeAsync(string ipAddress)
    {
        try
        {
            // Using free IP-API service
            var response = await _httpClient.GetFromJsonAsync<IpApiResponse>($"http://ip-api.com/json/{ipAddress}");
            return response?.CountryCode ?? "Unknown";
        }
        catch
        {
            // Fallback to unknown if API fails
            return "Unknown";
        }
    }

    private class IpApiResponse
    {
        public string? CountryCode { get; set; }
    }
}