# OPA
## Sessie 1 voor 4/10
Onderaan kan je zien wat ik hebben liggen aanpassen na onze les waarin we alles nog besproken hebben. Ik heb mijn laatste files niet meer geüpload, maar ze staan vanonder mee in de readme gequoteerd.

Ik heb er een 4 tal uurtjes mee bezig geweest om te zoeken naar stap 4 en 5, helaas heb ik dit nog steeds niet succesvol tot een einde kunnen brengen.
Hieronder zal ik even uitleggen wat ik allemaal geprobeerd heb.

Wat me eerst opviel was het feit dat in de directory OPA/ 2 directories stonden, zijnde config.yaml en opa.rego wat mij fout leek. Hier heb ik dan besloten om deze om te zetten naar files.
Ik ben het meeste tijd kwijt geraakt door te denken dat mijn programma werktte, terwijl dit niet het geval was. Toen ik bier bestelde met een account dat onder 18 was kreeg ik connection refused waardoor ik dacht dat mijn opa.rego werktte. Dit bleek dat de server gewoon trager was waardoor ik sowieso connection refused kreeg. Hierna heb ik nog wat liggen experimenteren maar niks bleek te werken.
Dit zijn mijn finale configuraties (de opa.rego staat niet in mijn files aangezien ik eerst een makkelijke werkend wou krijgen): 

## config.yaml
```
services:
  - name: "app"
    url: "http://localhost:8181/v1/data/app"

labels:
  - name: "example"
    value: "policy"
```
## opa.rego
```
package app.abac

default allow := false

allowed_paths = {
    "GET": ["/api/bar"],
    "POST": ["/api/bar"]
}

allow if {
    user_is_customer
    user_is_adult
    http_method_check
    http_path_check
    http_body_check
}

http_method_check if input.method in allowed_paths

http_path_check if input.path in allowed_paths[input.method]

http_body_check if {
    input.body.drink_type == "beer"  # Check for drink type in body
}

user_is_customer if data.user_attributes[input.user].title == "customer"

user_is_adult if data.user_attributes[input.user].age > 18

deny_message := "Permission Denied"

decision = {
    "allow": allow,
    "message": deny_message
} if not allow

```
## Program.cs
```
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Read values from appsettings.json
var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var corsOrigin = builder.Configuration["Cors:Origin"];

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.Authority = jwtAuthority;
    options.Audience = jwtAudience;
});

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// Add HTTP client for OPA
builder.Services.AddHttpClient("opa", client =>
{
    client.BaseAddress = new Uri("http://localhost:8181/v1/data/app/abac");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors(options => options
    .WithOrigins(corsOrigin)
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();
app.UseAuthorization();

// Custom Middleware for OPA decision-making
app.Use(async (context, next) =>
{
    // Extract JWT claims from the authenticated user
    var user = context.User;
    if (user.Identity != null && user.Identity.IsAuthenticated)
    {
        var claims = user.Claims.ToDictionary(c => c.Type, c => c.Value);

        // Prepare the input for OPA
        var opaInput = new
        {
            input = new
            {
                jwt = new
                {
                    claims = new
                    {
                        role = claims["role"],  // Adjust as necessary based on your JWT claims structure
                        age = int.Parse(claims["age"])  // Assuming age is present in the claims
                    }
                },
                method = context.Request.Method,
                path = context.Request.Path.ToString(),
                body = await new StreamReader(context.Request.Body).ReadToEndAsync() // Read the request body
            }
        };

        // Call OPA to evaluate the policy
        var httpClientFactory = context.RequestServices.GetRequiredService<IHttpClientFactory>();
        var client = httpClientFactory.CreateClient("opa");

        var response = await client.PostAsJsonAsync("", opaInput);
        var decision = await response.Content.ReadFromJsonAsync<OpaDecision>();

        if (decision != null && decision.allow)
        {
            // Proceed with the request if OPA allows it
            await next();
        }
        else
        {
            // Deny access if OPA denies it
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Permission Denied");
        }
    }
    else
    {
        // Deny access if user is not authenticated
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Unauthorized");
    }
});

app.MapControllers();

app.Run();
```


# Sessie 2

Ik ben opnieuw begonnen vanop de checkpoint en heb alle configuratie aangepast zodat deze met mijn auth0 werkt. Helaas kreeg ik na 2u lang proberen nog steeds een 403 forbidden, nalang zoeken op authorization kant wat het kon zijn heb ik opgegeven met dit als mijn laatste configuratie van bestanden.


### opa.rego

```
package barmanagement

import future.keywords

default allow := false

iss := "https://dev-fmcp2mpbn7fb2ugn.us.auth0.com"
aud := "bar-auth0-api"

# Check if the request is for ordering Fristi
allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Fristi"
    some r in claims.role
    r == "customer"
}

# Check if the request is for ordering Beer
allow if {
    input.request.path == "/api/bar"
    input.request.method == "POST"
    input.request.body.DrinkName == "Beer"
    some r in claims.role
    r == "customer"
    to_number(claims.age) >= 16
}

# Check if the request is for managing the bar
allow if {
    input.request.path == "/api/managebar"
    input.request.method == "POST"
    some r in claims.role
    r == "bartender"
}

```
### Program.cs
```
using Build.Security.AspNetCore.Middleware.Extensions;
using Build.Security.AspNetCore.Middleware.Request;
using Microsoft.AspNetCore.Authentication.JwtBearer;

var builder = WebApplication.CreateBuilder(args);

// Read values from appsettings.json
var jwtAuthority = builder.Configuration["Jwt:Authority"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var corsOrigin = builder.Configuration["Cors:Origin"];
var opaBaseAddress = builder.Configuration["OPA:BaseAddress"];

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.Authority = jwtAuthority;
    options.Audience = jwtAudience;

});

//Add OPA integration
builder.Services.AddBuildAuthorization(options =>
{
    options.Enable = true;
    options.BaseAddress = opaBaseAddress;
    options.PolicyPath = "/barmanagement/allow";
    options.AllowOnFailure = false;
    options.Timeout = 5;
    options.IncludeHeaders = true;
    options.IncludeBody = true;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseCors(options => options
    .WithOrigins(corsOrigin)
    .AllowAnyMethod()
    .AllowAnyHeader());

app.UseAuthentication();

// Add OPA integration
app.UseBuildAuthorization();

app.MapControllers();

app.Run();

```


