
import {Service} from '@prisma/client'
import {ApiProperty} from '@nestjs/swagger'
import {IsArray,IsOptional,IsString} from 'class-validator'




export class UpdateUserDto {
  @ApiProperty({
  required: false,
})
@IsOptional()
@IsString()
email?: string ;
@ApiProperty({
  required: false,
})
@IsOptional()
@IsString()
name?: string ;
@ApiProperty({
  required: false,
  nullable: true,
})
@IsOptional()
@IsString()
password?: string  | null;
@ApiProperty({
  required: false,
  nullable: true,
})
@IsOptional()
@IsString()
phone?: string  | null;
@ApiProperty({
  enum: Service,
  required: false,
})
@IsOptional()
@IsArray()
services?: Service[] ;
}
