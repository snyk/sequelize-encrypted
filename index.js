var crypto = require('crypto');

function EncryptedField(Sequelize, key, opt) {
    if (!(this instanceof EncryptedField)) {
        return new EncryptedField(Sequelize, key, opt);
    }

    var self = this;
    var extraDecryptionKeys = Array.isArray(opt && opt.extraDecryptionKeys) ?
        opt.extraDecryptionKeys :
        [];
    self.decryptionKeys = ([key].concat(extraDecryptionKeys))
        .map(function (key) {
            return new Buffer(key, 'hex');
        });
    self.encryptionKey = self.decryptionKeys[0];
    self.Sequelize = Sequelize;

    opt = opt || {};
    self._algorithm = opt.algorithm || 'aes-256-cbc';
    self._iv_length = opt.iv_length || 16;
    self.encrypted_field_name = undefined;
};

EncryptedField.prototype.vault = function(name) {
    var self = this;

    if (self.encrypted_field_name) {
        throw new Error('vault already initialized');
    }

    self.encrypted_field_name = name;

    return {
        type: self.Sequelize.BLOB,
        get: function() {
            var previous = this.getDataValue(name);
            if (!previous) {
                return {};
            }

            previous = new Buffer(previous);

            function decrypt(key) {
                var iv = previous.slice(0, self._iv_length);
                var content = previous.slice(self._iv_length, previous.length);
                var decipher = crypto.createDecipheriv(self._algorithm, key, iv);

                var json = decipher.update(content, undefined, 'utf8') + decipher.final('utf8');
                return JSON.parse(json);
            }

            var keyCount = self.decryptionKeys.length;
            for (var i = 0; i < keyCount; i++) {
                try {
                    return decrypt(self.decryptionKeys[i]);
                } catch (error) {
                    if (i >= keyCount - 1) {
                        throw error;
                    }
                }
            }
        },
        set: function(value) {
            // if new data is set, we will use a new IV
            var new_iv = crypto.randomBytes(self._iv_length);

            var cipher = crypto.createCipheriv(self._algorithm, self.encryptionKey, new_iv);

            cipher.end(JSON.stringify(value), 'utf-8');
            var enc_final = Buffer.concat([new_iv, cipher.read()]);
            var previous = this.setDataValue(name, enc_final);
        }
    }
};

EncryptedField.prototype.field = function(name, config) {
    var self = this;
    config = config || {};
    config.validate = config.validate || {};

    var hasValidations = [undefined,null].indexOf(typeof config.validate) === -1;

    if (!self.encrypted_field_name) {
        throw new Error('you must initialize the vault field before using encrypted fields');
    }

    var encrypted_field_name = self.encrypted_field_name;

    return {
        type: self.Sequelize.VIRTUAL(config.type || null),
        set: function set_encrypted(val) {

            if (hasValidations) {
                this.setDataValue(name, val);
            }

            // use `this` not self because we need to reference the sequelize instance
            // not our EncryptedField instance
            var encrypted = this[encrypted_field_name];
            encrypted[name] = val;
            this[encrypted_field_name] = encrypted;
        },
        get: function get_encrypted() {
            var encrypted = this[encrypted_field_name];
            var val = encrypted[name];
            return ([undefined, null].indexOf(val) === -1) ? val : config.defaultValue;
        },
        allowNull: ([undefined, null].indexOf(config.allowNull) === -1) ? config.allowNull : true,
        validate: config.validate
    }
};

module.exports = EncryptedField;
