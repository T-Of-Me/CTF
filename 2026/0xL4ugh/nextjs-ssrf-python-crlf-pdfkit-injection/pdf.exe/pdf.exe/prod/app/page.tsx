"use client";
import { useEffect, useState } from "react";
import { getPdfs } from "../actions";

const PASSWORD = "REDACTED";

export default function Home() {
  const [files, setFiles] = useState<string[]>([]);
  const [authed, setAuthed] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      setAuthed(localStorage.getItem("passcode") === PASSWORD);
    }
  }, []);

  useEffect(() => {
    if (authed) {
      getPdfs().then((data) => setFiles(data.files));
    }
  }, [authed]);

  if (!authed) {
    return <main style={{textAlign:'center',marginTop:'20vh'}}><h2>Login required</h2></main>;
  }

  return (
    <main>
      <h1>PDF List</h1>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1em' }}>
        <thead>
          <tr>
            <th style={{ textAlign: 'left', borderBottom: '2px solid var(--accent)', padding: '0.5em' }}>File Name</th>
          </tr>
        </thead>
        <tbody>
          {files.length === 0 ? (
            <tr><td style={{ padding: '0.5em' }}>No PDFs found.</td></tr>
          ) : (
            files.map((file) => (
              <tr key={file}>
                <td style={{ padding: '0.5em', borderBottom: '1px solid #4442' }}>{file}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </main>
  );
}
