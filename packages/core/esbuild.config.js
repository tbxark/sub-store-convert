import esbuild from 'esbuild';
import fs from 'node:fs';
import process from 'node:process';
import alias from 'esbuild-plugin-alias'
import path from 'node:path';
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const dependenciesLoader = (path) => (
  Object.keys(JSON.parse(fs.readFileSync(path).toString()).dependencies)
)

const createPackageJsonPlugin = ({source, target, extra}) => ({
  name: 'create-package-json',
  setup(build) {
    build.onEnd(() => {
      const packageJson = {
        ...(JSON.parse(fs.readFileSync(source).toString())),
        ...extra
      }
      delete packageJson.scripts
      delete packageJson.exports
      fs.writeFileSync(target, JSON.stringify(packageJson, null, 2))
    })
  }
})

esbuild.build({
  entryPoints: ['src/index.js'],
  target: 'esnext',
  bundle: true,
  minify: false,
  outfile: './build/index.js',
  format: 'esm',
  loader: { '.peg': 'text' },
  external: [
    ...dependenciesLoader('./package.json')
  ],
  alias: {
    '@/core/app': './src/core/app',
  },
  plugins: [
    createPackageJsonPlugin({
      source: './package.json',
      target: './build/package.json',
      extra: {
        "name": "sub-store-convert",
        "module": "./index.js",
        "main": "./index.js",
        "files": [
          "index.js",
        ],
        "devDependencies": {},
      }
    }),
    alias({
      'ip-address': path.resolve(__dirname, 'src/pkg/ip-address/index.js'),
    })
  ],
}).catch(() => process.exit(1))

