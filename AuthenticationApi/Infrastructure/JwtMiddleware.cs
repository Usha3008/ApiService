using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthenticationApi.Infrastructure
{
    public class JwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly AppSettings _settings;
        private IUserServiceAsync _service;

        public JwtMiddleware(RequestDelegate next, IOptions<AppSettings> options)
        {
            _next = next;
            _settings = options.Value;
        }

        public async Task Invoke(HttpContext context, [FromServices] IUserServiceAsync service)
        {

            _service = service;
            // extract the Authorization header from the Request Headers
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last(); // this accesses the request header and extracts the token value form it as it is the last key.
            if (!string.IsNullOrEmpty(token))
            {
                var user = TokenManager.GetUserFromToken(token, _settings, _service);
                if (user is not null)
                {
                    context.Items["User"] = user;
                }
            }
            await _next(context);
        }
    }
}
