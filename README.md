# OPA

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
// Class to handle OPA response structure
public class OpaDecision
{
    public bool allow { get; set; }
    public string message { get; set; } // If you want to send a custom message back
}
