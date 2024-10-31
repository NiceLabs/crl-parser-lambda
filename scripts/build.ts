#!/usr/bin/env npx tsx
import esbuild from 'esbuild'
import AdmZip from 'adm-zip'
import fs from 'fs/promises'

async function main() {
  await fs.rm('dist', { recursive: true, force: true })
  await esbuild.build({
    format: 'esm',
    bundle: true,
    minify: false,
    keepNames: true,
    sourcemap: true,
    sourcesContent: true,
    target: ['node20'],
    platform: 'node',
    outfile: 'dist/index.mjs',
    entryPoints: ['src/lambda.ts'],
    external: ['aws-lambda'],
  })
  const bundle = new AdmZip()
  await bundle.addLocalFolderPromise('dist', { zipPath: '.' })
  await bundle.writeZipPromise('./dist/lambda.zip')
}

main()
