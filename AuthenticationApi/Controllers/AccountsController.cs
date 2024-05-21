using AuthenticationApi.Infrastructure;
using AuthenticationClassLibrary;
using AuthenticationClassLibrary.Models;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace AuthenticationApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableCors]
    public class AccountsController : ControllerBase
    {
        private readonly AppSettings _settings;
        private readonly IUserServiceAsync _userService;

        public AccountsController(IOptions<AppSettings> options, IUserServiceAsync service)
        {
            _settings = options.Value;
            _userService = service;
        }
        [HttpPost]
        public async Task<ActionResult<AuthenticationResponse>> Login(AuthenticationRequest model)
        {
            if (!ModelState.IsValid)
            {
                // Returning ModelState in a JSON formatted response
                return BadRequest(new { message = "Invalid data", Details = ModelState });
            }

            if (model.Username == null || model.Password == null)
            {
                // Returning a plain text error message as a JSON object
                return BadRequest(new { message = "Bad Username/Password. Please check your credentials and try again." });
            }

            var user = await _userService.AuthenticateAsync(model);
            if (user == null)
            {
                // Consistently formatting the error message as JSON
                return BadRequest(new { message = "Bad Username/Password. Please check your credentials and try again." });
            }

            var token = TokenManager.GenerateWebToken(user, _settings);
            var authResponse = new AuthenticationResponse(user, token);

            // Return a successful authentication response, the object will be serialized to JSON by default
            return Ok(authResponse);
        }


        // URL: api/accounts/validate
        [HttpGet(template: "validate")]
        public async Task<ActionResult<User>> Validate()
        {
            var user = HttpContext.Items["User"] as User;
            if (user is null)
            {
                return Unauthorized("You are not authorized to access this application.");
            }
            return user;
        }

        [HttpPost("changePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] PasswordChangeModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new { message = "Invalid request.", errors = ModelState.Values.SelectMany(v => v.Errors.Select(b => b.ErrorMessage)) });
            }

            if (string.IsNullOrWhiteSpace(model.NewPassword) || model.NewPassword.Length < 6)
            {
                return BadRequest(new { message = "New password must be at least 6 characters long." });
            }

            var result = await _userService.UpdatePassword(model.Username, model.NewPassword);
            if (!result)
            {
                return BadRequest(new { message = "Failed to update password. Please ensure the username is correct and try again." });
            }

            return Ok(new { message = "Password updated successfully." });
        }

    }
}