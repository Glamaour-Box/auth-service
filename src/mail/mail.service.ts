import { ISendMailOptions, MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  constructor(private mailService: MailerService) {}
  async sendMail(options: ISendMailOptions) {
    this.mailService
      .sendMail(options)
      .then(() => {})
      .catch((error) => console.log('MAIL ERROR => ', error));
  }
}
