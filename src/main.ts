import 'dotenv/config';

import { NestFactory } from '@nestjs/core';
import { Transport } from '@nestjs/microservices';
import { AuthServiceModule } from 'src/auth.module';

async function bootstrap() {
  const port = process.env.PORT ? Number(process.env.PORT) : 8079;

  const app = await NestFactory.createMicroservice(AuthServiceModule, {
    transport: Transport.TCP,
    options: {
      host: '0.0.0.0',
      port,
    },
  });

  await app.listen();
  console.log('Auth Service listening on port: ', port);
}

bootstrap();
