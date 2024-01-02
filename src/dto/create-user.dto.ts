import { UserRole, Service } from '@prisma/client';
import { ApiProperty } from '@nestjs/swagger';
import {
  IsArray,
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
} from 'class-validator';

export class CreateUserDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  email: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiProperty({
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsString()
  password?: string | null;

  @ApiProperty({
    required: false,
    nullable: true,
  })
  @IsOptional()
  @IsString()
  phone?: string | null;

  @ApiProperty({
    enum: UserRole,
    default: 'USER',
  })
  @IsOptional()
  role?: UserRole;

  @ApiProperty({
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @ApiProperty({
    enum: Service,
  })
  @IsNotEmpty()
  @IsArray()
  services: Service[];

  @ApiProperty({
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  oAuth?: boolean;

  @ApiProperty({
    default: false,
  })
  @IsOptional()
  @IsBoolean()
  isProfileSetup?: boolean;
}
