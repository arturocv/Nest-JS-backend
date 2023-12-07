import { CreateUserDto } from './dto/create-user.dto';
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';

import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {

    constructor(
        @InjectModel(User.name) 
        private userModel: Model<User>,
    ) {}


    async create(createUserDto: CreateUserDto): Promise<User> {

        try {
            const {password, ...userData} = createUserDto;
            const newUser = new this.userModel({
                password: bcryptjs.hashSync(password, 10),
                ...userData            
            });

            return await newUser.save();            
            
        } catch (error) {
            if(error.code === 1100){
                throw new BadRequestException(`${createUserDto.email} ya existe!`);            
            }

            throw new InternalServerErrorException('Error interno del servidor');
            
        }

        //1 - Encriptar la contraseña


        //2 - Guardar el usuario


        //3 - Generar el JWT
    }


    async login(loginDto: LoginDto){
        const {email, password} = loginDto;

        const user = await this.userModel.findOne({email});

        if(!user){
            throw new UnauthorizedException('Email no valido')
        }

        if(!bcryptjs.compareSync(password, user.password)){
            throw new UnauthorizedException('Password incorrecto')
        }
        
        const {password:_, ...rest} = user.toJSON();

        return {
            user: rest,
            token: 'ABC-123'
        };
        
    }

    findAll() {
        return `This action returns all auth`;
    }



    findOne(id: number) {
        return `This action returns a #${id} auth`;
    }

    update(id: number, updateAuthDto: UpdateAuthDto) {
        return `This action updates a #${id} auth`;
    }

    remove(id: number) {
        return `This action removes a #${id} auth`;
    }
}
