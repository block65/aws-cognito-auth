export default function factory() {
  return {
    verbose: true,
    files: ['./__tests__/**/*.ava.ts'],
    extensions: {
      ts: 'module',
    },
    nodeArguments: [
      '--experimental-import-meta-resolve',
      '--loader=@block65/typesmock/loader',
    ],
  };
}
