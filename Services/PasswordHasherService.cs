﻿using Grpc.Core;

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
            // Проверка пароля
            var isPasswordVerify = BCrypt.Net.BCrypt.EnhancedVerify(request.Password, request.HashedPassword);
            Console.WriteLine("p:" + request.Password + " h:" + request.HashedPassword);
            Console.WriteLine(isPasswordVerify);

            // Возвращаем результат в виде строки
            return Task.FromResult(new PasswordVerificationReply
            {
                IsPasswordVerify = isPasswordVerify.ToString()
            });
        }
    }
}
