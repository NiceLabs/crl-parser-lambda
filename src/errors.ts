import type { APIGatewayProxyResult } from 'aws-lambda'

export class HTTPError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message)
  }

  toJSON(): APIGatewayProxyResult {
    return {
      statusCode: this.statusCode,
      body: this.message,
    }
  }
}
