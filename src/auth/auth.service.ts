import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';

import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayloadInterface } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');
  onModuleInit() {
    this.$connect();
    this.logger.log('MongoDB connected');
  }

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async signJWT(payload: JwtPayloadInterface) {
    return this.jwtService.sign(payload);
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;

    const user = await this.user.findUnique({
      where: { email },
    });

    if (user) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'User with this email already registered',
      });
    }

    const newUser = await this.user.create({
      data: {
        name,
        email,
        password: bcrypt.hashSync(password, 10),
      },
    });

    const { password: __, ...rest } = newUser;

    return {
      user: rest,
      token: await this.signJWT(rest),
    };
  }

  async login(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    const user = await this.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'Invalid credentials.',
      });
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      throw new RpcException({
        status: HttpStatus.BAD_REQUEST,
        message: 'User/Password not valid.',
      });
    }

    const { password: __, ...rest } = user;

    return {
      user: rest,
      token: await this.signJWT(rest),
    };
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });
      console.log(sub);

      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (error) {
      throw new RpcException({
        status: HttpStatus.UNAUTHORIZED,
        message: 'Invalid token',
      });
    }
  }
}
