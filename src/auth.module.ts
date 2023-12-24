import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { CacheModule } from '@nestjs/cache-manager';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from './utils/prisma.service';
import { JWTStrategy } from './jwt-strategy';
import { GoogleStrategy } from './google-strategy';
import { MailModule } from './mail/mail.module';
import { OtpService } from './otp/otp.service';
import { OtpController } from './otp/otp.controller';
import { UsersService } from './users/users.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    CacheModule.register({ isGlobal: true }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: '240s' },
      }),
      inject: [ConfigService],
    }),
    MailModule,
  ],
  controllers: [AuthController, OtpController],
  providers: [AuthService, PrismaService, JWTStrategy, GoogleStrategy, OtpService, UsersService],
})
export class AuthServiceModule {}
