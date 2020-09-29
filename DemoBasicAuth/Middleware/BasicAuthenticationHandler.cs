using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace DemoBasicAuth.API.Middleware
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Auth Header value not found");
            var authHeaderValue = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            var byteAuthValue = Convert.FromBase64String(authHeaderValue.Parameter);
            string[] plainAuthValues = Encoding.UTF8.GetString(byteAuthValue).Split(":");

            if("Test1".Equals(plainAuthValues[0]) && "Password".Equals(plainAuthValues[1]))
            {
                Claim[] claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, plainAuthValues[0]),
                    new Claim(ClaimTypes.Role, "Admin")
                };

                var identity = new ClaimsIdentity(claims, Scheme.Name);
                var principle = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principle, Scheme.Name);
                return AuthenticateResult.Success(ticket);
            }
            return AuthenticateResult.Fail("Not Authenticated");
        }
    }
}
