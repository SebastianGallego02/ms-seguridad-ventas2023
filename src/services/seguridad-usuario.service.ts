import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {ConfiguracionSeguridad} from '../config/seguridad.config';
import {Credenciales, FactorDeAutenticacionPorCodigo, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
const generator = require('generate-password');
const MD5 = require("crypto-js/md5");
const jwt = require('jsonwebtoken');


@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) { }

  /*
   * Add service methods here
   */

  /**
   * Crear una clave aleatoria
   * @returns cadena aleatoria de  caracteres
   */
  crearTextoAleatorio(n: Number): string {
    let clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

  /**
   * cifrar una cadena con MD5
   * @param cadena texto a cifrar
   * @returns cadena cifrada con MD5
   */
  cifrarTexto(cadena: string): string {
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada;
  }

  /**
   * se busca un usuario por sus credenciales de acceso
   * @param credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null> {
    let usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario;
  }
  /**
   * valida un código de 2fa para un usuario
   * @param credenciales2fa del usuario con el código del 2fa
   * @returns el registro de login o null
   */
  async validarCodigo2fa(credenciales2fa: FactorDeAutenticacionPorCodigo): Promise<Usuario | null> {
    let login = await this.repositorioLogin.findOne({
      where: {
        usuarioId: credenciales2fa.usuarioId,
        codigo2fa: credenciales2fa.codigo2fa,
        estadoCodigo2fa: false
      }
    });
    if (login) {
      let usuario = await this.repositorioUsuario.findById(credenciales2fa.usuarioId);
      return usuario;
    }
    return null
  }

  /**
   *  generación de jwt
   * @param usuario información del uuario
   * @returns token
   */
  crearToken(usuario: Usuario): string {
    let datos = {
      name: `${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido} ${usuario.correo} ${usuario.celular} ${usuario.clave}`,
      role: usuario.rolId,
      email: usuario.correo
    }
    let token = jwt.sign(datos, ConfiguracionSeguridad.ClaveJWT);
    return token;
  }
}
