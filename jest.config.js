module.exports = {
  testEnvironment: 'node',
  transform: {
    '^.+\\.(ts)?$': 'ts-jest',
  },
  testRegex: '(/test/.*|(\\.|/)(spec.jest))(?<!.d)\\.(js?|ts?)$',
  collectCoverageFrom: ['*.ts'],
  coverageReporters: ['text-summary', 'html'],
  moduleFileExtensions: ['ts', 'js'],
};
