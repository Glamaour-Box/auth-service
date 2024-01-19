import 'dotenv/config';
import * as compression from 'compression';

import { NestFactory } from '@nestjs/core';
import { AuthServiceModule } from 'src/auth.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const port = process.env.PORT || 8079;

  const app = await NestFactory.create(AuthServiceModule);
  app.enableCors({
    origin: ['http://localhost:3000', 'http://localhost:3001'],
  });
  app.useGlobalPipes(new ValidationPipe());
  app.use(compression());

  await app.listen(port);
  console.log('Auth Service running on: ', await app.getUrl());
}

bootstrap();
