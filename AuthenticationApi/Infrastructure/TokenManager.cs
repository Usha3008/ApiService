using AuthenticationClassLibrary.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationApi.Infrastructure
{
    public class TokenManager
    {
        const string UserId = "UserId";

        public static string GenerateWebToken(User model, AppSettings settings)
        {
            // 1. Create a Claims set
            var claimsSet = new List<Claim>
            {
                new Claim(UserId, model.UserId.ToString()),
            };

            // 2. Create an identity based on the Claims set
            // Identity Creation: A ClaimsIdentity object is created using the claims set. This represents the identity of the user.
            var userIdentity = new ClaimsIdentity(claimsSet);

            // 3. Key Generation: The secret key from the app settings is converted into bytes. This key will be used to sign the JWT.
            // Get the Bytes from the AppSettings Secret Key
            var keyBytes = Encoding.UTF8.GetBytes(settings.AppSecret);

            // 4. Signing Credentials Definition: The signing credentials for the JWT are defined using the secret key and the algorithm specified in the app settings.
            //Define the Signing credentials for JWT
            var signingCredentials = new SigningCredentials(
                key: new SymmetricSecurityKey(keyBytes),  // keyBytes is the key, that will be used to encrypt the identity
                algorithm: settings.Algorithm);

            // 5. Security Token Descriptor Definition: A SecurityTokenDescriptor object is defined, which includes the user identity, the token expiration time (set to 1 day from the current time), and the signing credentials.
            //Define the SecurityDescriptor - Payload
            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
            {
                Subject = userIdentity,
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = signingCredentials,
            };

            // 6. Token Generation: A JwtSecurityTokenHandler is used to create the token using the descriptor, and then to convert the token into a writable string format.
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            var preToken = handler.CreateToken(descriptor);
            var writeableToken = handler.WriteToken(preToken);

            return writeableToken;
        }
        public static User GetUserFromToken(string token, AppSettings settings, IUserServiceAsync service)
        {
            var keyBytes = Encoding.UTF8.GetBytes(settings.AppSecret);
            var signInKey = new SymmetricSecurityKey(keyBytes);
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = signInKey,
                ValidateIssuerSigningKey = true,
                ValidateIssuer = false,
                ValidateAudience = false,
                ClockSkew = TimeSpan.Zero,
            };
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(
                token: token,
                validationParameters: validationParameters,
                validatedToken: out SecurityToken validatedToken
                );
            var outputToken = validatedToken as JwtSecurityToken;
            var userId = outputToken?.Claims.FirstOrDefault(c => c.Type == UserId)?.Value;

            var user = service.GetUserDetails(Convert.ToInt32(userId)).Result;
            return user;
        }
    }
}
