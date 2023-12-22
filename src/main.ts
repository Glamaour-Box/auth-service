import 'dotenv/config';
import * as compression from 'compression';

import { NestFactory } from '@nestjs/core';
import { AuthServiceModule } from 'src/auth.module';

async function bootstrap() {
  const port = process.env.PORT ? Number(process.env.PORT) : 8079;
  const host = process.env.HOST ? Number(process.env.HOST) : 'localhost';

  const app = await NestFactory.create(AuthServiceModule);
  app.use(compression());

  await app.listen(port);
  console.log('Auth Service running on: ', await app.getUrl());
}

bootstrap();
