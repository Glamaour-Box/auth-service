
import {UserRole,Service} from '@prisma/client'
import {ApiProperty} from '@nestjs/swagger'


export class UserDto {
  @ApiProperty()
id: string ;
@ApiProperty()
email: string ;
@ApiProperty()
name: string ;
@ApiProperty({
  nullable: true,
})
password: string  | null;
@ApiProperty({
  nullable: true,
})
phone: string  | null;
@ApiProperty({
  enum: UserRole,
})
role: UserRole ;
@ApiProperty()
emailVerified: boolean ;
@ApiProperty({
  enum: Service,
})
services: Service[] ;
@ApiProperty()
oAuth: boolean ;
@ApiProperty()
isProfileSetup: boolean ;
}
