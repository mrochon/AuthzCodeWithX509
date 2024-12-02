using AuthzCodeWithX509;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(options =>
    {
        builder.Configuration.Bind("AzureAd", options);
        //var onRedirect = options.Events.OnRedirectToIdentityProvider;
        //options.Events.OnRedirectToIdentityProvider = context =>
        //{
        //    if(context.Properties.Items.ContainsKey("claims"))
        //    {
        //        context.ProtocolMessage.SetParameter("claims", JsonSerializer.Serialize(new { id_token = new {acrs = new { essential = true, value = context.Properties.Items["claims"] } }}));
        //    }
        //    onRedirect(context);
        //    return Task.CompletedTask;
        //};
        options.Events.OnAuthorizationCodeReceived = context =>
        {
            context.SetClientAssertion(options);
            return Task.CompletedTask;
        };
    });

builder.Services.AddControllersWithViews(options =>
{
    var policy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});
builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

builder.Services.AddMicrosoftIdentityConsentHandler();

builder.Services.Configure<OpenIdConnectOptions>(options =>
{
    options.Events.OnRedirectToIdentityProvider = context =>
    {
        return Task.CompletedTask;
    };
    options.Events.OnAuthorizationCodeReceived = context =>
    {
        var code = context.ProtocolMessage.Code;
        return Task.CompletedTask;
    };
});

var app = builder.Build();


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");
app.MapRazorPages();

app.Run();
