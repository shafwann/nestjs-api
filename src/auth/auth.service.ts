import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }

    async signup(dto: AuthDto) {
        try {
            // generate a hash of the password
            const hash = await argon.hash(dto.password);

            // save the user to the database
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash,
                },
            });

            delete user.hash;

            // return the saved user
            return user;
        } catch (error) {
            if (error instanceof PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException('Credentials taken');
                }
            }
            throw error;
        }
    }

    signin() {
        return { msg: 'signed in' };
    }
};