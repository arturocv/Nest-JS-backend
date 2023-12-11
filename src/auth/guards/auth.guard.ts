import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt.payload';
import { AuthService } from '../auth.service';



@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService:JwtService,
      private authService: AuthService
    ){};

  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {
      const request = context.switchToHttp().getRequest();

      const token = this.extractTokenFromHeader(request);

      if (!token) {
        throw new UnauthorizedException('Token no existe');
      }      
      
      try {
        const payload = await this.jwtService.verifyAsync<JwtPayload>(
          token, { secret: process.env.JWR_SEED }
        );  

        const user = await this.authService.findUserById(payload.id);
          if(!user) throw new UnauthorizedException('Usuario no existe');
          if(!user.isActive) throw new UnauthorizedException('Usuario no está activo');

        request['user'] = user;
        
      } catch (error) {
        throw new UnauthorizedException('Token no valido')        
      }

      return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}

