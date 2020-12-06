import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import { terser } from 'rollup-plugin-terser';
import babel from '@rollup/plugin-babel';
import manifest from './package.json';

const extensions = ['.ts'];

export default [
  {
    input: 'dist/index.js',
    watch: {
      clearScreen: false,
    },
    plugins: [
      resolve({
        extensions,
        jsnext: true,
        preferBuiltins: true,
        browser: true,
      }),
      commonjs(),
      babel({
        extensions,
        babelHelpers: 'runtime',
        exclude: ['node_modules/**'],
      }),
      terser(),
    ],
    output: {
      file: manifest.main,
      format: 'cjs',
      sourcemap: true,
    },
    external: [/@babel\/runtime/, ...Object.keys(manifest.dependencies)],
  },
];
