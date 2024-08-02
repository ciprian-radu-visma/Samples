using System.Collections.Generic;
using System.Text.Json;

namespace ConsoleCibaClient;

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

static class DPoPHeaderGenerator
{
    private static readonly RsaSecurityKey RsaSecurityKey = GenerateRsaKey();
    private static readonly JwtHeader JwtHeader = GetJwtHeader();

    private static RsaSecurityKey GenerateRsaKey()
    {
        var rsa = RSA.Create(2048);
        var rsaSecurityKey = new RsaSecurityKey(rsa);
        return rsaSecurityKey;
    }

    private static JwtHeader GetJwtHeader()
    {
        var rsaSecurityKey = RsaSecurityKey;
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaSecurityKey);
        jwk.Alg = "RS256";

        // Remove private key components
        jwk.D = null;
        jwk.P = null;
        jwk.Q = null;
        jwk.DP = null;
        jwk.DQ = null;
        jwk.QI = null;

        return new JwtHeader(new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256), null, "dpop+jwt")
        {
            { "jwk", JsonSerializer.Deserialize<Dictionary<string, object>>(JsonSerializer.Serialize(jwk)) }
        };
    }

    public static string CreateDPoPHeaderValue(string httpMethod, string httpUri)
    {
        // Create JWT payload
        var payload = new JwtPayload
        {
            { "htm", httpMethod },
            { "htu", httpUri },
            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
            { "jti", Guid.NewGuid().ToString() }
        };

        // Create and sign the JWT
        var token = new JwtSecurityToken(JwtHeader, payload);
        var tokenHandler = new JwtSecurityTokenHandler();
        return tokenHandler.WriteToken(token);
    }
}