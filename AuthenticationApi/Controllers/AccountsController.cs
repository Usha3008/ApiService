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
                return BadRequest(ModelState);
            }
            if (model.Username == null || model.Password == null)
            {
                return BadRequest("Bad Username/Password. Please check your credentials and try again.");
            }

            var user = await _userService.AuthenticateAsync(model);
            if (user is null)
            {
                return BadRequest("Bad Username/Password. Please check your credentials and try again.");
            }

            // Check if it's the first login by examining the MustChangePassword property
            //var mustChangePassword = user.MustChangePassword;

            var token = TokenManager.GenerateWebToken(user, _settings);
            var authResponse = new AuthenticationResponse(user, token);

            return Ok(authResponse);
        }
        //[HttpPost]
        //public async Task<ActionResult<AuthenticationResponse>> Login(AuthenticationRequest model)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }
        //    if(model.Username == null || model.Password == null)
        //    {
        //        return BadRequest("Bad Username/Password. Please Check your Credentials and Try Again.");
        //    }
        //    var user = await _userService.AuthenticateAsync(model);
        //    if (user is null)
        //    {
        //        return BadRequest("Bad Username/Password. Please Check your Credentials and Try Again.");
        //    }
        //    var token = TokenManager.GenerateWebToken(user, _settings);
        //    var authResponse = new AuthenticationResponse(user, token);
        //    return authResponse;
        //}

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
                return BadRequest(ModelState);
            }

            if (string.IsNullOrWhiteSpace(model.NewPassword) || model.NewPassword.Length < 6)
            {
                return BadRequest("New password must be at least 6 characters long.");
            }

            var result = await _userService.UpdatePassword(model.Username, model.NewPassword);
            if (!result)
            {
                return BadRequest("Failed to update password. Please ensure the username is correct and try again.");
            }

            return Ok("Password updated successfully.");
        }

    }
}
