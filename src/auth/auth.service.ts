
import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcryp from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayloadAuth } from './interfaces/jwt-payload';
import { envs } from 'src/config';


@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    private readonly logger = new Logger(AuthService.name);

    constructor(
        private readonly jwtService : JwtService
    ) {
        super();
    }

    async onModuleInit() {
        await this.$connect();
        this.logger.log('Connected to the database auth mongo');
    }

    async registerUser(registerUserDto: RegisterUserDto) {
        try {
            const { email, name, password } = registerUserDto;

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            })

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email: email,
                    password: bcryp.hashSync(password, 10),
                    name: name,
                }
            });

            const { password:__, ...userWithOutPassword } = newUser;
            return {
                userWithOutPassword,
                token: await this.singJWT(userWithOutPassword)
            };

        } catch (error) {
            throw new RpcException({
                status:400,
                message: error.message,
            });
        }
    }

    async singJWT(payload: JwtPayloadAuth){
        return  this.jwtService.sign(payload)
    }

    async loginUser(loginUserDto: LoginUserDto) {
        try {
            const { email, password } = loginUserDto;

            const user = await this.user.findUnique({
                where: {
                    email
                }
            })

            if (!user) {
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: 'User/password not valid'
                });
            }

            const isPasswordaValid = bcryp.compareSync(password, user.password);

            if(!isPasswordaValid){
                throw new RpcException({
                    status: HttpStatus.BAD_REQUEST,
                    message: "User/password not valid"
                })
            }


            const { password:__, ...userWithOutPassword } = user;
            return {
                userWithOutPassword,
                token: await this.singJWT(userWithOutPassword)
            };

        } catch (error) {
            throw new RpcException({
                status:400,
                message: error.message,
            });
        }
    }
    async verifyToken(token: string){
        try{
            const  { sub, iat, exp, ...user} = this.jwtService.verify(token,{
                secret: envs.jwtSecret
            })

            return {
                user,
                token: await this.singJWT(user)
            }
            

        } catch(err){
            this.logger.error(err)
            throw new RpcException({
                status: HttpStatus.UNAUTHORIZED,
                message: 'Invalid token'
            })
        }
    }
}
