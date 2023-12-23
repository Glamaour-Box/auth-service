import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class OtpService {
  private static readonly CHARS =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  constructor(private mailService: MailService) {}

  generateOtp(size = 6): string {
    let result = '';
    const randomBytesLength = size > 6 ? size : 6;
    const randomBytesSize = randomBytesLength * 3;
    for (let i = 0; i < randomBytesSize; i += 3) {
      const code = randomBytes(1)[0] % OtpService.CHARS.length;
      result += OtpService.CHARS[code];
    }
    return result.substring(0, size);
  }

  verify(input: string, correct: string): boolean {
    return input === correct;
  }

  /**
   * Should send otp to users who are not verified.
   */
  async sendOtp(email: string) {
    const otp = this.generateOtp(6);
    // check if user exists and send email
    try {
      await this.mailService.sendMail({
        to: email,
        template: './email-otp.template',
        context: {
          otp,
        },
      });
    } catch (error) {
      console.log('SEND OTP ERROR => ', error);
    }
  }

  async verifyOtp(otp: string) {}
}
