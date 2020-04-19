import * as crypto from 'crypto';
import {
  DataTypeAbstract,
  DefineAttributeColumnOptions,
  Instance,
} from 'sequelize';

type Key = string;

export interface FieldOptions {
  algorithm?: string;
  iv_length?: number;
  extraDecryptionKeys?: Key | Key[];
}

export interface SequelizeConstants {
  BLOB: DataTypeAbstract;
  VIRTUAL: DataTypeAbstract;
}

export class EncryptedField {
  _algorithm: string;
  _iv_length: number;
  encrypted_field_name: string | undefined = undefined;
  encryptionKey: Buffer;
  decryptionKeys: Buffer[];
  Sequelize: SequelizeConstants;

  constructor(Sequelize: SequelizeConstants, key: Key, opt?: FieldOptions) {
    opt = opt || {};
    this._algorithm = opt.algorithm || 'aes-256-cbc';
    this._iv_length = opt.iv_length || 16;

    let extraDecryptionKeys: Key[] = [];
    if (opt.extraDecryptionKeys) {
      extraDecryptionKeys = Array.isArray(opt.extraDecryptionKeys)
        ? opt.extraDecryptionKeys
        : Array(opt.extraDecryptionKeys);
    }
    this.decryptionKeys = [key].concat(extraDecryptionKeys).map(function (key) {
      return Buffer.from(key, 'hex');
    });
    this.encryptionKey = this.decryptionKeys[0];
    this.Sequelize = Sequelize;
  }

  vault(name: string): DefineAttributeColumnOptions {
    if (this.encrypted_field_name) {
      throw new Error('vault already initialized');
    }

    this.encrypted_field_name = name;

    const self = this;

    return {
      type: self.Sequelize.BLOB,
      get: function (this: Instance<unknown>) {
        const stored: string | null = this.getDataValue(name);
        if (!stored) {
          return {};
        }

        const previous: Buffer = Buffer.from(stored);

        function decrypt(key: Buffer) {
          const iv = previous.slice(0, self._iv_length);
          const content = previous.slice(self._iv_length, previous.length);
          const decipher = crypto.createDecipheriv(self._algorithm, key, iv);

          const json =
            decipher.update(content, undefined, 'utf8') +
            decipher.final('utf8');
          return JSON.parse(json);
        }

        const keyCount = self.decryptionKeys.length;
        for (let i = 0; i < keyCount; i++) {
          try {
            return decrypt(self.decryptionKeys[i]);
          } catch (error) {
            if (i >= keyCount - 1) {
              throw error;
            }
          }
        }
      },
      set: function (this: Instance<unknown>, value: any) {
        // if new data is set, we will use a new IV
        const new_iv = crypto.randomBytes(self._iv_length);

        const cipher = crypto.createCipheriv(
          self._algorithm,
          self.encryptionKey,
          new_iv,
        );

        cipher.end(JSON.stringify(value), 'utf-8');
        const enc_final = Buffer.concat([new_iv, cipher.read()]);
        this.setDataValue(name, enc_final);
      },
    };
  }

  field(name: string): DefineAttributeColumnOptions {
    if (!this.encrypted_field_name) {
      throw new Error(
        'you must initialize the vault field before using encrypted fields',
      );
    }

    const encrypted_field_name = this.encrypted_field_name;

    return {
      type: this.Sequelize.VIRTUAL,
      set: function (this: any, val) {
        // the proxying breaks if you don't use this local
        const encrypted = this[encrypted_field_name];
        encrypted[name] = val;
        this[encrypted_field_name] = encrypted;
      },
      get: function (this: any) {
        return this[encrypted_field_name][name];
      },
    };
  }
}
