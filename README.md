# GRT Security Platform

A comprehensive 25-layer cyber security architecture implemented in ASP.NET Core, featuring device security, AI threat detection, and advanced monitoring capabilities.

## 🛡️ Security Layers Implemented

### 1-5: Core Security Foundation
- **Device Identification**: Unique device fingerprinting
- **Device Registration**: Approved device access control
- **User Authentication**: Secure login system
- **MFA Security**: OTP/2FA verification support
- **Session Protection**: Token rotation and management

### 6-10: Network & API Security
- **IP Security**: IP tracking and blocking
- **Geo Location Check**: Country/location validation
- **Firewall Protection**: Suspicious traffic blocking
- **API Gateway Security**: Secure API access
- **API Rate Limiting**: Abuse prevention

### 11-15: Data & Behavior Security
- **Encryption Layer**: Data encryption at rest/transit
- **Secure Key Vault**: Secret storage management
- **File Scan Security**: Malware detection
- **Behavior Analysis**: User behavior tracking
- **AI Threat Detection**: Anomaly detection using ML.NET

### 16-20: Monitoring & Control
- **Activity Logging**: Comprehensive security logs
- **Alert System**: Email/SMS notifications
- **Admin Security Panel**: Monitoring dashboard
- **Device Control**: Remote device management
- **Auto Patch System**: Vulnerability updates

### 21-25: Advanced Security
- **Backup Security**: Encrypted backup systems
- **Cloud Security**: Secure cloud service integration
- **Zero Trust Security**: Verify every request
- **Blockchain Log Storage**: Tamper-proof audit logs
- **AI Security Assistant**: Automated threat response

## 🚀 Features

### AI-Powered Security
- **GRT-Guardian AI**: Intelligent threat detection and response
- **ML.NET Integration**: Machine learning for anomaly detection
- **Behavior Analysis**: Pattern recognition and risk scoring
- **Predictive Security**: Threat forecasting and prevention

### Comprehensive API Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - Secure authentication
- `POST /api/auth/mfa/verify` - MFA verification
- `GET /api/device` - Device management
- `GET /api/security/logs` - Security event logs
- `POST /api/ai/security/analyze` - AI threat analysis
- `GET /api/dashboard/overview` - Admin monitoring

### Advanced Security Features
- JWT token authentication
- Rate limiting and DDoS protection
- IP geolocation validation
- Device fingerprinting
- Real-time security monitoring
- Automated alert systems

## 🛠️ Technology Stack

- **Backend**: ASP.NET Core 10.0
- **Database**: SQLite (configurable to SQL Server/PostgreSQL)
- **Authentication**: ASP.NET Core Identity + JWT
- **AI/ML**: ML.NET for threat detection
- **Security**: Serilog logging, rate limiting, encryption
- **Monitoring**: Real-time dashboards, alerting
- **Deployment**: Docker-ready, Kubernetes-compatible

## 📋 Prerequisites

- .NET 10.0 SDK
- SQLite (included) or SQL Server/PostgreSQL

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/errsmohane-a11y/Grt-security-.git
   cd Grt-security-/GRT.Security.Platform
   ```

2. **Install dependencies**
   ```bash
   dotnet restore
   ```

3. **Setup database**
   ```bash
   dotnet ef database update
   ```

4. **Run the application**
   ```bash
   dotnet run
   ```

5. **Access the API**
   - Swagger UI: `https://localhost:5001/swagger`
   - API Base: `https://localhost:5001/api`

## 🔧 Configuration

### appsettings.json
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=GRT.Security.Platform.db"
  },
  "Jwt": {
    "Key": "YourSuperSecretKeyHere",
    "Issuer": "GRT.Security.Platform",
    "Audience": "GRT.Security.Platform"
  },
  "IpRateLimiting": {
    "EnableEndpointRateLimiting": true,
    "GeneralRules": [
      {
        "Endpoint": "*",
        "Period": "1m",
        "Limit": 10
      }
    ]
  }
}
```

## 📖 API Usage Examples

### User Registration
```bash
curl -X POST "https://localhost:5001/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Secure Login with Device ID
```bash
curl -X POST "https://localhost:5001/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Device-ID: device-12345" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "deviceName": "iPhone 15"
  }'
```

### AI Threat Analysis
```bash
curl -X POST "https://localhost:5001/api/ai/security/analyze" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user-id",
    "ipAddress": "192.168.1.1",
    "deviceId": "device-12345"
  }'
```

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Device   │───▶│ Security Gateway │───▶│   API Gateway   │───▶
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐             ▼
│ Authentication  │◀───│  AI Threat      │    ┌─────────────────┐
│   Server        │    │  Detection      │    │  Security       │
└─────────────────┘    └─────────────────┘    │  Engine         │
                                              └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐             ▼
│   Database +    │◀───│   Monitoring    │    ┌─────────────────┐
│   Logs          │    │   Dashboard     │    │  Alert System   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔒 Security Features

### AI Threat Detection
- Real-time anomaly detection
- Behavioral pattern analysis
- Risk scoring (0-100 scale)
- Automated threat response

### Device Security
- Device fingerprinting
- Registration and approval workflow
- Remote device management
- Location-based access control

### Network Security
- IP-based access control
- Geographic restrictions
- Rate limiting and DDoS protection
- Suspicious traffic detection

## 📊 Monitoring & Analytics

### Security Dashboard
- Real-time threat monitoring
- User activity logs
- Device management panel
- Alert management system

### Logging & Auditing
- Comprehensive security event logging
- Tamper-proof audit trails
- Performance monitoring
- Compliance reporting

## 🚀 Deployment

### Docker Deployment
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["GRT.Security.Platform.csproj", "."]
RUN dotnet restore "./GRT.Security.Platform.csproj"
COPY . .
RUN dotnet build "GRT.Security.Platform.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "GRT.Security.Platform.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "GRT.Security.Platform.dll"]
```

### Kubernetes Deployment
The platform is designed for cloud-native deployment with:
- Horizontal scaling
- Load balancing
- Service mesh integration
- Secrets management

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Implement security enhancements
4. Add comprehensive tests
5. Submit a pull request

## 📄 License

This project implements advanced security measures for protecting digital assets and user data.

## ⚠️ Disclaimer

This is a demonstration of security architecture concepts. For production use, additional security audits, penetration testing, and compliance certifications are recommended.

---

**Built with ❤️ for enterprise-grade security**</content>
<parameter name="oldString"># Grt-security-
My personal security 
