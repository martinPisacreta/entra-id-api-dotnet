# ASP.NET Core 8 API with Microsoft Entra ID

[![.NET tests](https://github.com/martinPisacreta/entra-id-api-dotnet/actions/workflows/dotnet.yml/badge.svg)](https://github.com/martinPisacreta/entra-id-api-dotnet/actions/workflows/dotnet.yml)

Minimal API demonstrating JWT bearer authentication and independent scope and application-role policies. Requires the .NET 8 SDK. No real credentials are included.

| Endpoint | Permission |
| --- | --- |
| `GET /health` | Public |
| `GET /api/read` | Delegated scope `api.read` |
| `POST /orders` | Application role `Orders.Write` |

Invalid or missing tokens return **401**; authenticated callers missing the required permission receive **403**. Validation checks issuer, audience, RS256 signature and expiration, with 30 seconds of clock tolerance. Scope matching uses complete, case-sensitive values.

## Register the API in Entra ID

1. Create a single-tenant app registration. Record its Directory (tenant) ID and Application (client) ID. Configure `api.requestedAccessTokenVersion` as `2` in the app manifest.
2. Under **Expose an API**, set the Application ID URI to `api://<API_CLIENT_ID>` and add the delegated scope `api.read`.
3. Under **App roles**, create an enabled role with value `Orders.Write` and allowed member type **Applications**.
4. Register a separate caller application. For delegated access, add this API's `api.read` permission and obtain consent using an appropriate interactive OAuth flow. For application access, add the `Orders.Write` application permission, grant administrator consent and request a client-credentials token using `api://<API_CLIENT_ID>/.default`. Keep caller credentials outside this repository. The API itself needs no client secret.

## Configure and run

In `src/EntraApi/appsettings.json`, set `Entra:TenantId` to the directory tenant GUID and `Entra:Audience` to the API's Application (client) ID GUID, matching the `aud` claim in a v2 access token. Both fields are initially empty; startup requires configuration. Environment variables `Entra__TenantId` and `Entra__Audience` override these settings.

```bash
dotnet run --project src/EntraApi --urls http://localhost:5080
curl http://localhost:5080/health
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:5080/api/read
curl -X POST -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:5080/orders
```

Production authentication retrieves signing keys through HTTPS discovery at the configured tenant's v2 authority. Deploy behind HTTPS before sending real tokens.

## Tests and CI

```bash
dotnet test EntraApi.sln --configuration Release
```

The 14 xUnit integration cases exercise the real JWT middleware using ephemeral local RSA keys and static discovery; identity-network requests are blocked. Coverage includes public health, valid scope and role access, missing tokens, incorrect audience or issuer, expired tokens, untrusted signatures, missing permissions and exact scope matching. Production validation settings remain enabled.

All 14 tests passed locally. No live Microsoft tenant or real credentials were used; live Entra integration remains unverified. GitHub Actions runs the same Release tests when this directory is the repository root; execution on GitHub remains pending publication.

## License

MIT; see `LICENSE`.
