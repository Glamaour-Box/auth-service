import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { join } from 'path';

@Injectable()
export class MailService {
  constructor(private mailService: MailerService) {}
  async sendMail(options: ISendMailOptions) {
    this.mailService
      .sendMail({
        to: 'daxowam680@vasteron.com',
        template: './email-otp',
        subject: 'Email verification',
        context: {
          otp: 7877565,
          name: 'Daxowam680',
        },
      })
      .then(() => {})
      .catch((error) => console.log('MAIL ERROR => ', error));
  }
}
