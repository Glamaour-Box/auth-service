import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  UseGuards,
  HttpCode,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

import { AuthService } from './auth.service';
import { CreateUser, GoogleAuthRequest, SigninUser } from './types';
import { CreateUserDto } from './dto/create-user.dto';

@Controller('auth')
// @UseInterceptors(CacheInterceptor)
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get()
  getHello() {
    return 'Hello World!';
  }

  @Post('/signup')
  async signup(@Body() input: CreateUserDto) {
    return await this.authService.signup(input);
  }

  @Post('/signin')
  @HttpCode(200)
  async signin(@Body() input?: SigninUser) {
    return await this.authService.signin(input);
  }

  @Post('/verify-token')
  @HttpCode(200)
  async verifyJWT(@Body() input?: { token: string }) {
    return await this.authService.verifyJwt(input.token);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  googleAuth(@Req() req: GoogleAuthRequest) {}

  @Get('/google/redirect')
  @UseGuards(AuthGuard('google'))
  async googleAuthRedirect(@Req() req: GoogleAuthRequest) {
    return await this.authService.googleLogin(req);
  }
}
