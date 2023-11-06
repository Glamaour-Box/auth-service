import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { HttpStatus, ServiceResponse, CreateUser, SigninUser } from 'src/types';

import { PrismaService } from 'src/utils/prisma.service';
import {
  signinSchema,
  signupSchema,
} from 'src/validation-schemas/signup.validation';
import { z } from 'zod';
import { transformZodErrors } from './utils/transformZodErrors';
import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import { Payload } from '@nestjs/microservices';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 15);
  }

  async signup(
    data: CreateUser,
  ): Promise<ServiceResponse<Omit<User, 'password'>>> {
    try {
      const { email, password, ...rest } = signupSchema.parse(data);

      const foundUser = await this.prisma.user.findUnique({ where: { email } });

      if (foundUser)
        return {
          message: 'email has already been registered',
          status: HttpStatus.CONFLICT,
          data: null,
        };

      // encrypt password
      const encryptedPassword = await this.hashPassword(password);

      const createdUser = await this.prisma.user.create({
        data: { ...data, password: encryptedPassword },
      });

      delete createdUser.password;

      return {
        data: createdUser,
        message: 'user signed up successfully',
        status: HttpStatus.CREATED,
      };
    } catch (error) {
      if (error instanceof z.ZodError) {
        return {
          data: null,
          status: HttpStatus.BAD_REQUEST,
          message: transformZodErrors(error.errors),
        };
      } else {
        console.error(error);
        return {
          data: null,
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'an error occured',
        };
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

  async signin(data: SigninUser): Promise<ServiceResponse<{ token: string }>> {
    try {
      const { email, password } = signinSchema.parse(data);

      const user = await this.validatedUser(email, password);

      if (!user)
        return {
          message: 'unauthorized',
          status: HttpStatus.UNAUTHORIZED,
          data: null,
        };

      const jwt = await this.jwtService.signAsync({ id: user.id });

      return {
        data: { token: jwt },
        message: 'Signed in successfully',
        status: HttpStatus.OK,
      };
    } catch (error) {
      console.error('Signin Error => ', error);

      if (error instanceof z.ZodError) {
        return {
          data: null,
          status: HttpStatus.BAD_REQUEST,
          message: transformZodErrors(error.errors),
        };
      } else {
        return {
          data: null,
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'an error occured',
        };
      }
    }
  }

  async verifyJwt(token: string): Promise<ServiceResponse> {
    if (!token)
      return {
        status: HttpStatus.UNAUTHORIZED,
        data: null,
        message: 'unauthorized',
      };

    try {
      const { exp } = await this.jwtService.verifyAsync(token);

      console.log('verifyJwt exp => ', exp);

      return { data: { exp }, status: HttpStatus.OK, message: '' };
    } catch (error) {
      console.log('verifyJwt ERROR => ', error);

      return {
        status: HttpStatus.UNAUTHORIZED,
        data: null,
        message: error.message,
      };
    }
  }
}
