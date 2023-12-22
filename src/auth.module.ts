import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { CacheModule } from '@nestjs/cache-manager';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaService } from './utils/prisma.service';
import { JWTStrategy } from './jwt-strategy';
import { EmailService } from './email/email.service';
import { GoogleStrategy } from './google-strategy';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    // CacheModule.register({ isGlobal: true }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: { expiresIn: '240s' },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PrismaService,
    JWTStrategy,
    GoogleStrategy,
    EmailService,
  ],
})
export class AuthServiceModule {}
