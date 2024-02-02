/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  clearMocks: true,
  collectCoverage: false,
  logHeapUsage: true,
  passWithNoTests: true,
  preset: 'ts-jest',
  randomize: true,
  resetModules: true,
  restoreMocks: false,
  rootDir: '..',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/regression/**/*.test.ts'],
  transform: {
    '\\.ts$': 'ts-jest',
  },
  verbose: true,
  maxWorkers: 1,
};
