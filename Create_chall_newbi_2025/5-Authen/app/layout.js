export const metadata = {
  title: 'MSEC',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: 'monospace', padding: '20px', backgroundColor: '#1a1a1a', color: '#00ff00' }}>
        {children}
      </body>
    </html>
  )
}