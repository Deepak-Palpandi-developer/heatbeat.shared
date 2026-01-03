using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeatBeat.Shared.Contants;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace HeatBeat.Shared.Helpers;

public class CommonHelper
{

    public static IConfiguration _configuration = new ConfigurationBuilder().AddEnvironmentVariables(EnvironmentCodes.ApplicationPrefix).Build();

    public static string ToSnake(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return name ?? string.Empty;
        }

        return string.Concat(name.Select((c, i) =>
            i > 0 && char.IsUpper(c) ? "_" + char.ToLowerInvariant(c) : char.ToLowerInvariant(c).ToString()));
    }

    public static class PasswordHelper
    {
        public static (string Hash, string Salt) CreatePassword(string password)
        {
            using var hmac = new HMACSHA256();
            var salt = Convert.ToBase64String(hmac.Key);
            var hash = Convert.ToBase64String(
                hmac.ComputeHash(Encoding.UTF8.GetBytes(password))
            );

            return (hash, salt);
        }

        public static bool VerifyPassword(string password, string storedHash, string storedSalt)
        {
            using var hmac = new HMACSHA256(Convert.FromBase64String(storedSalt));
            var computedHash = Convert.ToBase64String(
                hmac.ComputeHash(Encoding.UTF8.GetBytes(password))
            );

            return computedHash == storedHash;
        }
    }

    public class TokenHelper
    {
        public static (string token, DateTimeOffset expireAt) GenerateJwtToken(Dictionary<string, string> claims)
        {
            var secretKey = _configuration.GetValue<string>(EnvironmentCodes.JwtSecretKey) ?? throw new InvalidOperationException("JWT secret key is not configured.");

            var expireMinutesString = _configuration.GetValue<string>(EnvironmentCodes.JwtExpiryMinutes) ?? "60";
            if (!int.TryParse(expireMinutesString, out int expireMinutes))
            {
                expireMinutes = 60;
            }

            var issuer = _configuration.GetValue<string>(EnvironmentCodes.JwtIssuer);
            var audience = _configuration.GetValue<string>(EnvironmentCodes.JwtAudience);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var jwtClaims = new List<Claim>();

            if (claims != null)
            {
                foreach (var claim in claims)
                {
                    jwtClaims.Add(new Claim(claim.Key, claim.Value));
                }
            }

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: jwtClaims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(expireMinutes),
                signingCredentials: credentials
            );

            return (new JwtSecurityTokenHandler().WriteToken(token), token.ValidTo);
        }

        public static string GenerateRefreshToken()
        {
            return GenerateSecureToken(64);
        }

        public static string GenerateSessionToken()
        {
            return GenerateSecureToken(32);
        }

        private static string GenerateSecureToken(int byteLength)
        {
            var randomBytes = new byte[byteLength];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            return Convert.ToBase64String(randomBytes)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }
    }

    public static string Encrypt(string plainText)
    {
        var _key = _configuration.GetValue<string>(EnvironmentCodes.EncryptionKey) ?? throw new InvalidOperationException("Encryption key is not configured.");

        if (string.IsNullOrEmpty(plainText))
            return plainText;

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(_key);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();

        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var msEncrypt = new MemoryStream();
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
        }

        var cipherBytes = msEncrypt.ToArray();

        // Prefix a version byte plus the IV so decrypt can extract per-message IVs; fall back to configured IV when absent.
        var payload = new byte[1 + aes.IV.Length + cipherBytes.Length];
        payload[0] = 1; // version marker
        Buffer.BlockCopy(aes.IV, 0, payload, 1, aes.IV.Length);
        Buffer.BlockCopy(cipherBytes, 0, payload, 1 + aes.IV.Length, cipherBytes.Length);

        return Convert.ToBase64String(payload);
    }

    public static string Decrypt(string cipherText)
    {
        var _key = _configuration.GetValue<string>(EnvironmentCodes.EncryptionKey) ?? throw new InvalidOperationException("Encryption key is not configured.");
        var _iv = _configuration.GetValue<string>(EnvironmentCodes.EncryptionIV) ?? throw new InvalidOperationException("Encryption IV is not configured.");

        if (string.IsNullOrEmpty(cipherText))
            return cipherText;

        var buffer = Convert.FromBase64String(cipherText);

        byte[] iv;
        byte[] cipherBytes;

        if (buffer.Length > 1 && buffer[0] == 1 && buffer.Length > 1 + 16)
        {
            iv = new byte[16];
            Buffer.BlockCopy(buffer, 1, iv, 0, iv.Length);
            cipherBytes = new byte[buffer.Length - 1 - iv.Length];
            Buffer.BlockCopy(buffer, 1 + iv.Length, cipherBytes, 0, cipherBytes.Length);
        }
        else
        {
            iv = Convert.FromBase64String(_iv);
            cipherBytes = buffer;
        }

        if (cipherBytes.Length == 0)
            return string.Empty;

        using var aes = Aes.Create();
        aes.Key = Convert.FromBase64String(_key);
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var msDecrypt = new MemoryStream(cipherBytes);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var srDecrypt = new StreamReader(csDecrypt);

        return srDecrypt.ReadToEnd();
    }

    public static class JsonHelper
    {
        public static JsonDocument SerializeToJsonDocument<T>(T obj)
        {
            var jsonString = System.Text.Json.JsonSerializer.Serialize(obj);
            return JsonDocument.Parse(jsonString);
        }

        public static T? DeserializeFromJsonDocument<T>(JsonDocument jsonDocument)
        {
            var jsonString = jsonDocument.RootElement.GetRawText();
            return System.Text.Json.JsonSerializer.Deserialize<T>(jsonString);
        }
    }

    public static class NetworkHelper
    {
        public static IPAddress GetIpAddress(HttpContext httpContext)
        {
            if (httpContext == null)
            {
                return IPAddress.None;
            }

            var forwardedFor = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrEmpty(forwardedFor))
            {
                var ips = forwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries);
                if (ips.Length > 0)
                {
                    var ipString = ips[0].Trim();
                    if (IPAddress.TryParse(ipString, out var ipAddress))
                    {
                        return ipAddress;
                    }
                }
            }

            var realIp = httpContext.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrEmpty(realIp))
            {
                if (IPAddress.TryParse(realIp.Trim(), out var ipAddress))
                {
                    return ipAddress;
                }
            }

            var remoteIpAddress = httpContext.Connection.RemoteIpAddress;
            if (remoteIpAddress != null)
            {
                if (remoteIpAddress.Equals(IPAddress.IPv6Loopback))
                {
                    return IPAddress.Loopback; // 127.0.0.1
                }

                return remoteIpAddress;
            }

            return IPAddress.None;
        }

        public static string GetUserAgent(HttpContext httpContext)
        {
            if (httpContext == null)
            {
                return string.Empty;
            }

            var userAgent = httpContext.Request.Headers["User-Agent"].FirstOrDefault();
            return userAgent ?? string.Empty;
        }

        public static string GetDeviceType(HttpContext? httpContext)
        {
            if (httpContext == null)
                return "Unknown";

            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            return string.IsNullOrWhiteSpace(userAgent)
                ? "Unknown"
                : userAgent.Contains("Mobile", StringComparison.OrdinalIgnoreCase)
                    ? "Mobile"
                    : userAgent.Contains("Tablet", StringComparison.OrdinalIgnoreCase)
                        ? "Tablet"
                        : "Desktop";
        }

        public static string GetOperatingSystem(HttpContext? httpContext)
        {
            if (httpContext == null)
                return "Unknown";

            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            return string.IsNullOrWhiteSpace(userAgent)
                ? "Unknown"
                : userAgent.Contains("Windows NT", StringComparison.OrdinalIgnoreCase)
                    ? "Windows"
                    : userAgent.Contains("Mac OS X", StringComparison.OrdinalIgnoreCase)
                        ? "macOS"
                        : userAgent.Contains("Android", StringComparison.OrdinalIgnoreCase)
                            ? "Android"
                            : userAgent.Contains("iPhone", StringComparison.OrdinalIgnoreCase) ||
                              userAgent.Contains("iPad", StringComparison.OrdinalIgnoreCase)
                                ? "iOS"
                                : userAgent.Contains("Linux", StringComparison.OrdinalIgnoreCase)
                                    ? "Linux"
                                    : "Other";
        }

        public static string GetBrowser(HttpContext? httpContext)
        {
            if (httpContext == null)
                return "Unknown";
            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();
            return string.IsNullOrWhiteSpace(userAgent)
                ? "Unknown"
                : userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase) &&
                  !userAgent.Contains("Edg", StringComparison.OrdinalIgnoreCase) &&
                  !userAgent.Contains("OPR", StringComparison.OrdinalIgnoreCase)
                    ? "Chrome"
                    : userAgent.Contains("Firefox", StringComparison.OrdinalIgnoreCase)
                        ? "Firefox"
                        : userAgent.Contains("Safari", StringComparison.OrdinalIgnoreCase) &&
                          !userAgent.Contains("Chrome", StringComparison.OrdinalIgnoreCase)
                            ? "Safari"
                            : userAgent.Contains("Edg", StringComparison.OrdinalIgnoreCase)
                                ? "Edge"
                                : userAgent.Contains("OPR", StringComparison.OrdinalIgnoreCase) ||
                                  userAgent.Contains("Opera", StringComparison.OrdinalIgnoreCase)
                                    ? "Opera"
                                    : "Other";
        }

        public static string GetDeviceName(HttpContext? httpContext)
        {
            if (httpContext == null)
                return "Unknown";

            var userAgent = httpContext.Request.Headers["User-Agent"].ToString();

            return string.IsNullOrWhiteSpace(userAgent)
                ? "Unknown"
                : userAgent;
        }
    }
}