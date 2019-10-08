import * as Sequelize from 'sequelize';
const EncryptedField = require('../');

const dbHost = process.env.DB_HOST || 'db';
const sequelize = new Sequelize(`postgres://postgres@${dbHost}:5432/postgres`);

const key1 = 'a593e7f567d01031d153b5af6d9a25766b95926cff91c6be3438c7f7ac37230e';
const key2 = 'a593e7f567d01031d153b5af6d9a25766b95926cff91c6be3438c7f7ac37230f';

const v1 = EncryptedField(Sequelize, key1);
const v2 = EncryptedField(Sequelize, key2);

const User = sequelize.define('user', {
  name: Sequelize.STRING,
  encrypted: v1.vault('encrypted'),
  another_encrypted: v2.vault('another_encrypted'),

  // encrypted virtual fields
  private_1: v1.field('private_1'),
  private_2: v2.field('private_2'),
});

beforeAll(async () => {
  await User.sync({ force: true });
});

test('should save an encrypted field', async () => {
  const user: any = User.build();
  user.private_1 = 'test';

  await user.save();
  const found: any = await User.findById(user.id);
  expect(found.private_1).toEqual(user.private_1);
});

test('should support multiple encrypted fields', async () => {
  const user: any = User.build();
  user.private_1 = 'baz';
  user.private_2 = 'foobar';
  await user.save();

  const vault = EncryptedField(Sequelize, key2);

  const AnotherUser = sequelize.define('user', {
    name: Sequelize.STRING,
    another_encrypted: vault.vault('another_encrypted'),
    private_2: vault.field('private_2'),
    private_1: vault.field('private_1'),
  });

  const found: any = await AnotherUser.findById(user.id);
  expect(found.private_2).toEqual(user.private_2);

  // encrypted with key1 and different field originally
  // and thus can't be recovered with key2
  expect(found.private_1).toBeUndefined();
});

test('should throw error on decryption using invalid key', async () => {
  // attempt to use key2 for vault encrypted with key1
  const badEncryptedField = EncryptedField(Sequelize, key2);
  const BadEncryptionUser = sequelize.define('user', {
    name: Sequelize.STRING,
    encrypted: badEncryptedField.vault('encrypted'),
    private_1: badEncryptedField.field('private_1'),
  });

  const model: any = User.build();
  model.private_1 = 'secret!';
  await model.save();

  let threw;
  try {
    const found: any = await BadEncryptionUser.findById(model.id);
    found.private_1; // trigger decryption
  } catch (error) {
    threw = error;
  }

  expect(threw && /bad decrypt$/.test(threw.message)).toBeTruthy();
});

test('should support extra decryption keys (to facilitate key rotation)', async () => {
  const keyOneEncryptedField = EncryptedField(Sequelize, key1);
  const keyTwoAndOneEncryptedField = EncryptedField(Sequelize, key2, {
    extraDecryptionKeys: [key1],
  });

  // models both access the same table, with different encryption keys
  const KeyOneModel = sequelize.define('rotateMe', {
    encrypted: keyOneEncryptedField.vault('encrypted'),
    private: keyOneEncryptedField.field('private'),
  });
  const KeyTwoAndOneModel = sequelize.define('rotateMe', {
    encrypted: keyTwoAndOneEncryptedField.vault('encrypted'),
    private: keyTwoAndOneEncryptedField.field('private'),
  });

  await KeyOneModel.sync({ force: true });

  const modelUsingKeyOne: any = KeyOneModel.build();
  const modelUsingKeyTwo: any = KeyTwoAndOneModel.build();
  modelUsingKeyOne.private = 'secret!';
  modelUsingKeyTwo.private = 'also secret!';
  await Promise.all([modelUsingKeyOne.save(), modelUsingKeyTwo.save()]);

  // note: both sets of data accessed via KeyTwoAndOneModel
  const foundFromKeyOne: any = await KeyTwoAndOneModel.findById(
    modelUsingKeyOne.id,
  );
  const foundFromKeyTwo: any = await KeyTwoAndOneModel.findById(
    modelUsingKeyTwo.id,
  );

  expect(foundFromKeyOne.private).toEqual(modelUsingKeyOne.private);
  expect(foundFromKeyTwo.private).toEqual(modelUsingKeyTwo.private);
});
