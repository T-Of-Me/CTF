import { NextResponse } from 'next/server'

export async function GET() {
  return NextResponse.json({
    message: 'Secret endpoint found!',
    secret_key: process.env.SECRET_KEY,
    instruction: 'Create a JWT token with payload {"role": "admin"} using this secret key',
    next_step: 'Send the token to /api/flag with Authorization: Bearer <token>'
  })
}