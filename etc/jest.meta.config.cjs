/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  clearMocks: true,
  collectCoverage: true,
  collectCoverageFrom: ['<rootDir>/test/helpers.ts'],
  coveragePathIgnorePatterns: ['\\.test\\.ts'],
  coverageDirectory: '<rootDir>/dist/.coverage/meta',
  coverageProvider: 'babel',
  logHeapUsage: true,
  passWithNoTests: true,
  preset: 'ts-jest',
  randomize: true,
  resetModules: true,
  restoreMocks: false,
  rootDir: '..',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/helpers.test.ts'],
  transform: {
    '\\.ts$': 'ts-jest',
  },
  verbose: true,
  maxWorkers: 1,
};
