import { NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'

export async function GET(request) {
  const authHeader = request.headers.get('Authorization')
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return NextResponse.json(
      { error: 'No token provided. Send JWT token in Authorization header.' },
      { status: 401 }
    )
  }
  
  const token = authHeader.substring(7)
  
  try {
    const decoded = jwt.verify(token, process.env.SECRET_KEY)
    
    if (decoded.role !== 'admin') {
      return NextResponse.json(
        { error: 'Access denied. Admin role required.', your_role: decoded.role || 'none' },
        { status: 403 }
      )
    }
    
    return NextResponse.json({
      success: true,
      message: 'Congratulations!',
      flag: process.env.FLAG
    })
  } catch (error) {
    return NextResponse.json(
      { error: 'Invalid token signature' },
      { status: 401 }
    )
  }
}