using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace TargetDotnet.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly string _conn;
    private readonly ILogger<AuthController> _log;

    public AuthController(IConfiguration cfg, ILogger<AuthController> log)
    {
        _conn = cfg.GetConnectionString("Default");
        _log = log;
    }

    // SEEDED: payments.dotnet.sql-injection -- interpolated SqlCommand text
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest req)
    {
        using var c = new SqlConnection(_conn);
        c.Open();
        using var cmd = new SqlCommand($"SELECT Id, Username FROM Users WHERE Username = '{req.Username}' AND Password = '{req.Password}'", c);
        using var r = cmd.ExecuteReader();
        if (!r.Read()) return Unauthorized();
        return Ok(new { token = "fake-token", userId = r.GetInt32(0) });
    }
}

public record LoginRequest(string Username, string Password);

// SEEDED: payments.dotnet.weak-jwt-validation -- multiple disabled validations
public static class JwtSetup
{
    public static void Configure(IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(opts =>
            {
                opts.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    RequireExpirationTime = false,
                };
            });
    }
}
