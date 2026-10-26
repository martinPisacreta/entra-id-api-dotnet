using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var tenantId = builder.Configuration["Entra:TenantId"];
var audience = builder.Configuration["Entra:Audience"];
if (!Guid.TryParse(tenantId, out var parsedTenantId) || parsedTenantId == Guid.Empty)
    throw new InvalidOperationException("Configure Entra:TenantId with your directory tenant GUID.");
if (string.IsNullOrWhiteSpace(audience))
    throw new InvalidOperationException("Configure Entra:Audience with the API client ID for v2 access tokens.");

var issuer = $"https://login.microsoftonline.com/{parsedTenantId:D}/v2.0";
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = issuer;
        options.Audience = audience;
        options.RequireHttpsMetadata = true;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            NameClaimType = "name",
            RoleClaimType = "roles"
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ApiRead", policy => policy
        .RequireAuthenticatedUser()
        .RequireAssertion(context => context.User.FindAll("scp")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Contains("api.read", StringComparer.Ordinal)));

    options.AddPolicy("OrdersWrite", policy => policy
        .RequireAuthenticatedUser()
        .RequireRole("Orders.Write"));
});

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }))
    .AllowAnonymous();
app.MapGet("/api/read", () => Results.Ok(new { message = "Read access granted" }))
    .RequireAuthorization("ApiRead");
app.MapPost("/orders", () => Results.Ok(new { message = "Order write access granted" }))
    .RequireAuthorization("OrdersWrite");

app.Run();

public partial class Program { }
