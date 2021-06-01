export default {
  testEnvironment: 'node',
  testMatch: ['<rootDir>/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    '^(\\..*)\\.jsx?$': '$1',
  },
  extensionsToTreatAsEsm: ['.ts'],
};
