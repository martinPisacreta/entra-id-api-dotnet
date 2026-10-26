using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Xunit;

public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    public const string Tenant = "11111111-1111-4111-8111-111111111111";
    public const string Audience = "22222222-2222-4222-8222-222222222222";
    public const string Issuer = "https://login.microsoftonline.com/" + Tenant + "/v2.0";
    private readonly RSA signingRsa = RSA.Create(2048);
    private readonly RSA untrustedRsa = RSA.Create(2048);

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Entra:TenantId", Tenant);
        builder.UseSetting("Entra:Audience", Audience);
        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<JwtBearerOptions>(
                JwtBearerDefaults.AuthenticationScheme, options =>
                {
                    var configuration = new OpenIdConnectConfiguration
                    {
                        Issuer = Issuer
                    };
                    configuration.SigningKeys.Add(new RsaSecurityKey(
                        signingRsa.ExportParameters(false)) { KeyId = "local-test-key" });
                    // Replace only discovery and keys. Keep production validation
                    // flags, issuer, audience, algorithms and authorization policies.
                    options.Configuration = configuration;
                    options.ConfigurationManager =
                        new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
                    options.Backchannel = new HttpClient(new RejectNetworkHandler());
                });
        });
    }

    public string Token(string scenario)
    {
        var claims = new List<Claim> { new("sub", "test-client") };
        if (scenario != "missing-scope")
            claims.Add(new Claim("scp", scenario == "similar-scope"
                ? "api.read.extra" : "profile api.read"));
        if (scenario != "missing-role")
            claims.Add(new Claim("roles", "Orders.Write"));

        var rsa = scenario == "untrusted-signature" ? untrustedRsa : signingRsa;
        var key = new RsaSecurityKey(rsa) { KeyId = "local-test-key" };
        var now = DateTime.UtcNow;
        var token = new JwtSecurityToken(
            issuer: scenario == "wrong-issuer" ? "https://untrusted.example/v2.0" : Issuer,
            audience: scenario == "wrong-audience" ? "another-api" : Audience,
            claims: claims,
            notBefore: now.AddHours(-1),
            expires: scenario == "expired" ? now.AddMinutes(-10) : now.AddMinutes(5),
            signingCredentials: new SigningCredentials(key, SecurityAlgorithms.RsaSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            signingRsa.Dispose();
            untrustedRsa.Dispose();
        }
    }

    private sealed class RejectNetworkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Identity network access is forbidden in these tests.");
    }
}

public sealed class AuthorizationTests : IClassFixture<TestApiFactory>
{
    private readonly TestApiFactory factory;

    public AuthorizationTests(TestApiFactory factory) => this.factory = factory;

    [Theory]
    [InlineData("/health", "GET", "anonymous", 200)]
    [InlineData("/api/read", "GET", "anonymous", 401)]
    [InlineData("/orders", "POST", "anonymous", 401)]
    [InlineData("/api/read", "GET", "valid", 200)]
    [InlineData("/orders", "POST", "valid", 200)]
    [InlineData("/api/read", "GET", "wrong-audience", 401)]
    [InlineData("/api/read", "GET", "expired", 401)]
    [InlineData("/api/read", "GET", "wrong-issuer", 401)]
    [InlineData("/api/read", "GET", "untrusted-signature", 401)]
    [InlineData("/api/read", "GET", "missing-scope", 403)]
    [InlineData("/api/read", "GET", "similar-scope", 403)]
    [InlineData("/orders", "POST", "missing-role", 403)]
    [InlineData("/api/read", "GET", "missing-role", 200)]
    [InlineData("/orders", "POST", "missing-scope", 200)]
    public async Task Enforces_authentication_and_independent_permissions(
        string path, string method, string scenario, int expectedStatus)
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (scenario != "anonymous")
            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", factory.Token(scenario));

        using var response = await client.SendAsync(request);

        Assert.Equal((HttpStatusCode)expectedStatus, response.StatusCode);
        if (expectedStatus == 401)
            Assert.Contains(response.Headers.WwwAuthenticate, header => header.Scheme == "Bearer");
    }
}
