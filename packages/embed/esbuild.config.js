import esbuild from 'esbuild'

esbuild.build({
  entryPoints: ['src/index.js'],
  target: 'es2020',
  bundle: true,
  minify: true,
  outfile: './build/bundle.js',
  format: 'iife',
  platform: 'neutral',
  mainFields: ['module', 'main'],
  banner: { js: "var console = globalThis.console || { log() {}, info() {}, warn() {}, error() {}, debug() {} }; if (!globalThis.console) globalThis.console = console;" },
}).catch(() => process.exit(1))
