import type { APIGatewayProxyHandler } from 'aws-lambda'
import { endOfWeek } from 'date-fns/endOfWeek'
import { spawn } from 'node:child_process'
import { HTTPError } from './errors'
import { format as formatCacheControl } from '@tusbar/cache-control'

export const handler: APIGatewayProxyHandler = async (event) => {
  try {
    if (event.httpMethod !== 'GET') throw new HTTPError(405, 'Method Not Allowed')
    return {
      statusCode: 200,
      body: await parseCRL(event.pathParameters?.proxy),
      headers: {
        'Content-Type': 'text/plain',
        'X-Content-Type-Options': 'nosniff',
        'Expires': endOfWeek(Date.now()).toString(),
        'Cache-Control': formatCacheControl({
          public: true,
          immutable: true,
          sharedMaxAge: 7 * 24 * 60 * 60,
        }),
      },
    }
  } catch (error: unknown) {
    if (error instanceof HTTPError) {
      return error.toJSON()
    } else if (error instanceof Error) {
      return { statusCode: 500, body: error.message }
    }
    return {
      statusCode: 500,
      body: String(error),
    }
  }
}

async function parseCRL(url: string | undefined) {
  if (url === undefined || !/^https?:/.test(url)) throw new HTTPError(400, 'Invalid CRL URL')
  const response = await fetch(url, {
    method: 'GET',
    cache: 'no-cache',
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) throw new HTTPError(response.status, response.statusText)

  let stdin = Buffer.from(await response.arrayBuffer())
  let inform: 'DER' | 'PEM'
  if (stdin[0] === 0x30) {
    inform = 'DER'
  } else if (stdin.includes('BEGIN X509 CRL') && stdin.includes('END X509 CRL')) {
    inform = 'PEM'
  } else {
    inform = 'DER'
    stdin = Buffer.from(stdin.toString('utf8'), 'base64')
  }

  return new Promise<string>((resolve, reject) => {
    const args = ['crl', '-text', '-inform', inform]
    if (process.env.NAME_OPTIONS) {
      args.push('-nameopt', process.env.NAME_OPTIONS)
    }

    const p = spawn('openssl', args, { stdio: 'pipe' })
    p.stdin.write(stdin)
    p.stdin.end()

    const chunks: Uint8Array[] = []
    p.stdout.on('data', (chunk) => chunks.push(chunk))
    p.stdout.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')))
    p.stdout.on('error', () => reject(p.stdout.errored))
  })
}
