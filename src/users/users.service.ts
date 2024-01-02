import {
  Injectable,
  InternalServerErrorException,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/utils/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string) {
    try {
      const user = await this.prisma.user.findUnique({ where: { email } });

      if (!user) return null;

      return user;
    } catch (error) {
      console.log('findUserByEmail Error =>', error);
      throw new InternalServerErrorException(error);
    }
  }
}
