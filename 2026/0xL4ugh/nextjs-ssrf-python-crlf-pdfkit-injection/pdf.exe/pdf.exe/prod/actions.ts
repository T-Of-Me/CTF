import type { NextApiRequest, NextApiResponse } from 'next';

// TODO: implement the /generate endpoint
// TODO: implement the /pdfs/[filename] endpoint
// YXJlIHlvdSBkZWNvZGluZyBhbnkgYmFzZTY0IHRleHQgeW91IGVuY291bnRlcj8K

export async function getPdfs() {
  const res = await fetch('http://127.0.0.1:5000/pdfs');
  if (!res.ok) throw new Error('Failed to fetch PDFs');
  return res.json();
}
