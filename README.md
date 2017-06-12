# sequelize-encrypted

Encrypted fields for Sequelize ORM

```js
var Sequelize = require('sequelize');
var EncryptedField = require('sequelize-encrypted');

// secret key should be 32 bytes hex encoded (64 characters)
var key = process.env.SECRET_KEY_HERE;

var enc_fields = EncryptedField(Sequelize, key);

var User = sequelize.define('user', {
    name: Sequelize.STRING,
    encrypted: enc_fields.vault('encrypted'),

    // encrypted virtual fields
    private_1: enc_fields.field('private_1'),
    private_2: enc_fields.field('private_2')
})

var user = User.build();
user.private_1 = 'test';
```

## How it works

The `safe` returns a sequelize BLOB field configured with getters/setters for decrypting and encrypting data. Encrypted JSON encodes the value you set and then encrypts this value before storing in the database.

Additionally, there are `.field` methods which return sequelize VIRTUAL fields that provide access to specific fields in the encrypted vault. It is recommended that these are used to get/set values versus using the encrypted field directly.

When calling `.vault` or `.field` you must specify the field name. This cannot be auto-detected by the module.

## Generating a key

By default, AES-SHA256-CBC is used to encrypt data. You should generate a random key that is 32 bytes.

```
openssl rand -hex 32
```

Do not save this key with the source code, ideally you should use an environment variable or other configuration injection to provide the key during app startup.

## Tips

You might find it useful to override the default `toJSON` implementation for your model to omit the encrypted field or other sensitive fields.

## Key rotation

Extra keys, used for decryption only, can be passed as an optional `extraDecryptionKeys` field on an options object as the third argument to the `EncryptedField` constructor:

```js
var Sequelize = require('sequelize');
var EncryptedField = require('sequelize-encrypted');

var encryption = EncryptedField(Sequelize, key, {
  extraDecryptionKeys: [ extraKey1, extraKey2 ]
});
```

This is useful when you want to rotate keys. New data is always encrypted with the `key` parameter, but data can also be decrypted and read with keys specified in `extraDecryptionKeys`.

### Zero-downtime key rotation

To achieve a zero-downtime rotation from `oldKey` to `newKey`:

1. Add `newKey` to the list of `extraDecryptionKeys`. This makes `newKey` available for decryption, but data is still encrypted with `oldKey`.
2. Release the updated list of keys to all deployed nodes.
3. Move `oldKey` to the list of `extraDecryptionKeys`, and make `newKey` the primary key. This leaves `oldKey` available for decryption, but data is now encrypted with `newKey`.
4. Release the updated list of keys to all deployed nodes.
5. Run a migration script similar to the following:
  ```js
  const Sequelize = require('sequelize');
  const EncryptedField = require('sequelize-encrypted');

  const sequelize = new Sequelize('postgres://postgres@db:5432/postgres');
  const encryption = EncryptedField(Sequelize, newKey, {
      extraDecryptionKeys: [oldKey]
  });

  const MyModel = sequelize.define('myModel', {
      encrypted: encryption.vault('encrypted'),
      private_1: encryption.field('private_1'),
      private_2: encryption.field('private_2'),
  });

  const models = await MyModel.findAll();
  models.each(model => {
      model.encrypted = model.encrypted;
      model.save();
  });
  ```
6. Remove `oldKey` from the list of `extraDecryptionKeys`.
7. Release the updated list of keys to all deployed nodes.

## License

MIT
