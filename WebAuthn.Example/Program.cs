using WebAuthn;
using WebAuthn.Example;

var userFactory = new UserFactory("users.json");
var app         = WebApplication.Create(args);

var sc = new ServiceCollection();
sc.AddSingleton<IWebAuthnUserFactory, UserFactory>(_ => userFactory);
sc.AddSingleton(new WebAuthnSettings(Guid.Parse("02FE72DD-52C5-4F6A-918A-9082D2732ECD").ToByteArray(), "localhost", "http://localhost:5000"));
sc.AddWebAuthn();

#region Registration endpoints (page on GET and POST after successfull initialization of token)

app.MapGet("/reg", async ctx =>
                   {
                       var reg = ctx.RequestServices.GetRequiredService<IWebAuthnRegistrator>();
                       ctx.Response.ContentType = "text/html";
                       await ctx.Response.WriteAsync("<html>"                                                                   +
                                                     $"<head><script>{WebAuthnScript.Get()}</script></head>"                    +
                                                     "<body>"                                                                   +
                                                     "<script>"                                                                 +
                                                     "function callbackSuccess() { alert('Registration success') }"             +
                                                     "function callbackFailed(r) { alert('Registration failed: ' + r); }"       +
                                                     $"{reg.GetScript("/reg", "callbackSuccess", "callbackFailed", "denisio")}" +
                                                     "</script>"                                                                +
                                                     "</body></html>");
                   });

app.MapPost("/reg", async (WebAuthnRegisterParams parms, HttpContext ctx) =>
                    {
                        var reg = ctx.RequestServices.GetRequiredService<IWebAuthnRegistrator>();
                        var r   = reg.Register(parms!, out var rr);
                        if (r == WebAuthnResult.OK)
                        {
                            userFactory.Set(rr);
                            await ctx.Response.WriteAsJsonAsync(new {ok = true});
                        }
                        else
                            ctx.Response.StatusCode = 400;
                    });

#endregion

#region Authentication endpoints (page on GET and POST after successfull authentication of token)

app.MapGet("/auth", async ctx =>
                    {
                        var auth = ctx.RequestServices.GetRequiredService<IWebAuthnAuthenticator>();
                        ctx.Response.ContentType = "text/html";
                        
                        var user = userFactory.GetUser("denisio");
                        await ctx.Response.WriteAsync("<html>"                                                                +
                                                      $"<head><script>{WebAuthnScript.Get()}</script></head>"                 +
                                                      "<body>"                                                                +
                                                      "<script>"                                                              +
                                                      "function callbackSuccess() { alert('Auth success') }"                  +
                                                      "function callbackFailed(r) { alert('Auth failed: ' + r); }"            +
                                                      $"{auth.GetScript("/auth", "callbackSuccess", "callbackFailed", user)}" +
                                                      "</script>"                                                             +
                                                      "</body></html>");
                    });

app.MapPost("/auth", async (WebAuthnAuthenticateParams parms, HttpContext ctx) =>
                     {
                         var auth = ctx.RequestServices.GetRequiredService<IWebAuthnAuthenticator>();
                         var r    = auth.Authenticate(parms);
                         if (r == WebAuthnResult.OK)
                         {
                             await ctx.Response.WriteAsJsonAsync(new {ok = true});
                         }
                         else
                             ctx.Response.StatusCode = 403;
                     });

#endregion

app.Run();