using Grpc.Core;

namespace Shop.PasswordHasher.Services
{
    public class PasswordHasherService : PasswordHasher.PasswordHasherBase
    {
        public override Task<PasswordHashReply> GeneratePasswordHash(PasswordRequest password, ServerCallContext context)
        {
            var passwordHash = BCrypt.Net.BCrypt.EnhancedHashPassword(password.Password);
            return Task.FromResult(new PasswordHashReply
            {
                PasswordHash = passwordHash
            });
        }

        public override Task<PasswordVerificationReply> VerifyPassword(PasswordVerificationRequest request, ServerCallContext context)
        {
            var isPasswordVerify = BCrypt.Net.BCrypt.Verify(request.Password, request.HashedPassword);
            return Task.FromResult(new PasswordVerificationReply
            {
                IsPasswordVerify = isPasswordVerify.ToString()
            });
        }
    }
}
