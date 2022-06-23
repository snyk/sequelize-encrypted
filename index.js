const crypto = require('crypto');

function EncryptedField(Sequelize, key, opt) {
  if (!(this instanceof EncryptedField)) {
    return new EncryptedField(Sequelize, key, opt);
  }

  const self = this;

  opt = opt || {};
  self._algorithm = opt.algorithm || 'aes-256-cbc';
  self._iv_length = opt.iv_length || 16;
  self.encrypted_field_name = undefined;

  let extraDecryptionKeys = [];
  if (opt.extraDecryptionKeys) {
    extraDecryptionKeys = Array.isArray(opt.extraDecryptionKeys)
      ? opt.extraDecryptionKeys
      : Array(opt.extraDecryptionKeys);
  }
  self.decryptionKeys = [key].concat(extraDecryptionKeys).map(function (key) {
    return new Buffer.from(key, 'hex');
  });
  self.encryptionKey = self.decryptionKeys[0];
  self.Sequelize = Sequelize;
}

EncryptedField.prototype.vault = function (name) {
  const self = this;

  if (self.encrypted_field_name) {
    throw new Error('vault already initialized');
  }

  self.encrypted_field_name = name;

  return {
    type: self.Sequelize.BLOB,
    get: function () {
      let previous = this.getDataValue(name);
      if (!previous) {
        return {};
      }

      previous = new Buffer.from(previous);

      function decrypt(key) {
        const iv = previous.slice(0, self._iv_length);
        const content = previous.slice(self._iv_length, previous.length);
        const decipher = crypto.createDecipheriv(self._algorithm, key, iv);

        const json =
          decipher.update(content, undefined, 'utf8') + decipher.final('utf8');
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
    set: function (value) {
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
};

EncryptedField.prototype.field = function (name) {
  const self = this;

  if (!self.encrypted_field_name) {
    throw new Error(
      'you must initialize the vault field before using encrypted fields',
    );
  }
  const encrypted_field_name = self.encrypted_field_name;

  return {
    type: self.Sequelize.VIRTUAL,
    set: function set_encrypted(val) {
      // use `this` not self because we need to reference the sequelize instance
      // not our EncryptedField instance
      const encrypted = this[encrypted_field_name];
      encrypted[name] = val;
      this[encrypted_field_name] = encrypted;
    },
    get: function get_encrypted() {
      const encrypted = this[encrypted_field_name];
      return encrypted[name];
    },
  };
};

module.exports = EncryptedField;
