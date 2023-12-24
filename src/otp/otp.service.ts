import { CACHE_MANAGER } from '@nestjs/cache-manager';
import {
  BadRequestException,
  HttpException,
  Inject,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { Cache } from 'cache-manager';
import { randomBytes } from 'crypto';
import { MailService } from 'src/mail/mail.service';
import { UsersService } from 'src/users/users.service';
import { PrismaService } from 'src/utils/prisma.service';

@Injectable()
export class OtpService {
  private static readonly CHARS =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  constructor(
    private mailService: MailService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private usersService: UsersService,
    private prismaService: PrismaService,
  ) {}

  generateOtp(): number {
    return randomBytes(4).readUint32BE() % 1000000;
  }

  async verifyMailOtp(email: string, input: string): Promise<boolean> {
    const cacheKey = `mailOtp:${email}`;
    try {
      const value = await this.cacheManager.get(`mailOtp:${email}`);

      if (!value || value != input)
        throw new BadRequestException('otp doesnt match');

      await this.cacheManager.del(cacheKey);

      await this.prismaService.user.update({
        where: { email },
        data: { email_verified: true },
      });

      return value == input;
    } catch (error) {
      console.log('VERIFY OTP ERROR => ', error);
      throw new InternalServerErrorException(error.message, error.statusCode);
    }
  }

  /**
   * Should send mail otp to users who are not verified.
   */
  async sendMailOtp(email: string) {
    const otp = this.generateOtp();
    const cacheKey = `mailOtp:${email}`;
    try {
      const user = await this.usersService.findByEmail(email);

      if (!user)
        throw new NotFoundException(`user with email ${email} does not exist`);

      // invalidate preexisting cache's with same key
      if (await this.cacheManager.get(cacheKey))
        await this.cacheManager.del(cacheKey);
      //  store otp in cache
      await this.cacheManager.set(cacheKey, otp, 0);

      await this.mailService.sendMail({
        to: email,
        template: './email-otp',
        subject: 'Email Verification',
        context: {
          name: user.name,
          otp,
        },
      });
    } catch (error) {
      console.log('SEND OTP ERROR => ', error);
      throw new InternalServerErrorException(
        error.message,
        error.status || error.statusCode,
      );
    }
  }
}
