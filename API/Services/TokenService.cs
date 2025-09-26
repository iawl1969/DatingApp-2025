using System;
using API.Entities;
using API.Interfaces;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Claims;

namespace API.Services;

public class TokenService : ITokenService
{
    private readonly SymmetricSecurityKey key;

    public TokenService(IConfiguration config)
    {
        var tokenKey = config["TokenKey"] ?? throw new Exception("TokenKey not found in configuration");
        if (tokenKey.Length < 64)
            throw new Exception("TokenKey must be at least 64 characters long");
        key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenKey));

        // Claims should be created in the CreateToken method using the user parameter.
    }

    public string CreateToken(AppUser user)
    {
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        };

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddDays(7),
            SigningCredentials = creds
        };

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return tokenHandler.WriteToken(token);
    }
}
