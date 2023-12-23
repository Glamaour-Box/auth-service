import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { OtpService } from './otp.service';

@Controller('otp')
export class OtpController {
  constructor(private otpService: OtpService) {}
  @Post('/send-otp')
  @HttpCode(200)
  async sendOtp(@Body() input: { email: string }) {
    return await this.otpService.sendOtp(input.email);
  }

  @Post('/verify-otp')
  @HttpCode(200)
  async verifyOtp(@Body() input: { otp: string }) {
    return await this.otpService.verifyOtp(input.otp);
  }
}
