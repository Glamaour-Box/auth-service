import { ConfigService } from '@nestjs/config';
import axios from 'axios';

export const gateway = axios.create({
  baseURL: process.env.GATEWAY_BASE_URL,
});

export class MyAxios {
  constructor(private configService: ConfigService) {}

  gateway() {
    return axios.create({
      baseURL: this.configService.get('GATEWAY_BASE_URL'),
    });
  }
  ecommerce() {
    return axios.create({
      baseURL: this.configService.get('ECOMMERCE_BASE_URL'),
    });
  }
}
