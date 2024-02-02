/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  clearMocks: true,
  collectCoverage: true,
  collectCoverageFrom: ['<rootDir>/src/**/*.ts', '<rootDir>/test/unit/**/*.ts'],
  coveragePathIgnorePatterns: ['\\.test\\.ts'],
  coverageDirectory: '<rootDir>/dist/.coverage',
  coverageProvider: 'babel',
  logHeapUsage: true,
  passWithNoTests: true,
  preset: 'ts-jest',
  randomize: true,
  resetModules: true,
  restoreMocks: false,
  rootDir: '..',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/test/unit/**/*.test.ts'],
  transform: {
    '\\.ts$': 'ts-jest',
  },
  verbose: true,
  maxWorkers: 1,
};
