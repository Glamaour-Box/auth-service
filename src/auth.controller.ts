import { Controller, Get } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { CreateUser, SigninUser } from './types';

@Controller()
export class AuthController {
  constructor(private authService: AuthService) {}

  @Get()
  getHello() {
    return 'Hello World!';
  }

  @MessagePattern({ cmd: 'SIGNUP' })
  async signup(input: CreateUser) {
    return await this.authService.signup(input);
  }

  @MessagePattern({ cmd: 'SIGNIN' })
  async signin(@Payload() input?: SigninUser) {
    return await this.authService.signin(input);
  }

  @MessagePattern({ cmd: 'VERIFY_JWT' })
  async verifyJWT(@Payload() input?: { token: string }) {
    return await this.authService.verifyJwt(input.token);
  }
}
