import { NextResponse } from 'next/server'

export function middleware(request) {
  const authCookie = request.cookies.get('auth')
  
  if (!authCookie || authCookie.value !== 'authenticated') {
    return NextResponse.redirect(new URL('/', request.url))
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*'],
}


