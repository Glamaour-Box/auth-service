import {
  Injectable,
  ConflictException,
  BadRequestException,
  HttpException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

import { CreateUser, SigninUser, GoogleAuthRequest } from 'src/types';

import { PrismaService } from 'src/utils/prisma.service';
import {
  signinSchema,
  signupSchema,
} from 'src/validation-schemas/signup.validation';
import { z } from 'zod';
import { transformZodErrors } from './utils/transformZodErrors';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { MailService } from './mail/mail.service';
import { OtpService } from './otp/otp.service';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private mailService: MailService,
    private otpService: OtpService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 15);
  }

  async signup(data: CreateUser): Promise<Omit<User, 'password'>> {
    const { email, password, ..._ } = signupSchema.parse(data);

    try {
      const foundUser = await this.prisma.user.findUnique({ where: { email } });

      if (foundUser)
        throw new ConflictException('email has already been registered');
    } catch (error) {
      throw new HttpException(error.message, error.status);
    }

    try {
      // encrypt password
      const encryptedPassword = await this.hashPassword(password);

      const createdUser = await this.prisma.user.create({
        data: { ...data, password: encryptedPassword },
      });

      delete createdUser.password;

      // send OTP to phone or email
      this.otpService.sendOtp(createdUser.email);
      // make actions based on user role = vendor, user, etc
      // create a store if user role = vendor

      return createdUser;
    } catch (error) {
      if (error instanceof z.ZodError) {
        throw new BadRequestException(transformZodErrors(error.errors));
      } else {
        throw new HttpException(error.message, error.status);
      }
    }
  }

  async comparePassword(
    password: string,
    encryptedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, encryptedPassword);
  }

  async validatedUser(email: string, password: string): Promise<User> {
    const foundUser = await this.prisma.user.findUnique({ where: { email } });

    if (!foundUser) return null;

    const passwordsMatch = await this.comparePassword(
      password,
      foundUser.password,
    );

    if (!passwordsMatch) return null;

    return foundUser;
  }

  async signin(
    data: SigninUser,
  ): Promise<{ token: string } & Omit<User, 'password'>> {
    try {
      const { email, password } = signinSchema.parse(data);

      const { password: _, ...user } = await this.validatedUser(
        email,
        password,
      );

      if (!user) throw new UnauthorizedException();

      const jwt = await this.jwtService.signAsync({
        id: user.id,
        role: user.role,
      });

      return {
        ...user,
        token: jwt,
      };
    } catch (error) {
      console.error('Signin Error => ', error);

      if (error instanceof z.ZodError) {
        throw new BadRequestException(transformZodErrors(error));
      } else {
        throw new HttpException(error.message, error.status);
      }
    }
  }

  async verifyJwt(
    token: string,
  ): Promise<{ exp: any; id: string; role: string }> {
    if (!token) throw new UnauthorizedException();

    try {
      const { exp, id, role } = await this.jwtService.verifyAsync(token);
      return { exp, id, role };
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  async googleLogin(
    req: GoogleAuthRequest,
  ): Promise<User & { token?: string }> {
    if (!req.user) throw new UnauthorizedException('no user from google');

    try {
      // search for user and create if not found
      const foundUser = await this.prisma.user.findUnique({
        where: { email: req.user.email },
      });

      if (!foundUser) {
        const createdUser = await this.prisma.user.create({
          data: {
            email: req.user.email,
            name: req.user.name,
            role: 'vendor',
            o_auth: true,
          },
        });

        delete createdUser.password;

        return createdUser;
      }

      const jwt = await this.jwtService.signAsync({ id: foundUser.id });

      return {
        ...foundUser,
        token: jwt,
      };
    } catch (error) {
      throw new HttpException(error.message, error.status);
    }
  }
}
