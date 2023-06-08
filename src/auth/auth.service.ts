import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';


@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService, 
        private jwtService: JwtService
    ) {}

    async signIn(username, pass) {
        const user = await this.usersService.find(username);
        const cryptedPassword = await bcrypt.hash(user?.password, 10);

        if (cryptedPassword !== pass) {
          throw new UnauthorizedException();
        }
        const payload = { sub: user._id, username: user.name };
        return {
          access_token: await this.jwtService.signAsync(payload),
        };
    }
}
