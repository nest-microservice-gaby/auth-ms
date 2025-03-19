import { IsEmail, IsNotEmpty, IsString, IsStrongPassword } from "class-validator";

export class RegisterUserDto {

    @IsString()
    name: string;

    @IsString()
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsNotEmpty()
    @IsStrongPassword()
    password: string;
}