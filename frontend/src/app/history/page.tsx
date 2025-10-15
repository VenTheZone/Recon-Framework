"use client";

import { useState, useEffect } from 'react';
import Link from 'next/link';

interface Scan {
  id: number;
  url: string;
  result: string;
}

export default function History() {
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);

  useEffect(() => {
    const fetchScanHistory = async () => {
      const response = await fetch('/api/scans');
      const data = await response.json();
      setScanHistory(data);
    };
    fetchScanHistory();
  }, []);

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm lg:flex">
        <p className="fixed left-0 top-0 flex w-full justify-center border-b border-gray-300 bg-gradient-to-b from-zinc-200 pb-6 pt-8 backdrop-blur-2xl dark:border-neutral-800 dark:bg-zinc-800/30 dark:from-inherit lg:static lg:w-auto  lg:rounded-xl lg:border lg:bg-gray-200 lg:p-4 lg:dark:bg-zinc-800/30">
          Scan History
        </p>
        <Link href="/" className="text-blue-500 hover:underline">
          Back to Scan
        </Link>
      </div>

      <div className="w-full max-w-5xl">
        <table className="w-full table-auto">
          <thead>
            <tr>
              <th className="px-4 py-2">ID</th>
              <th className="px-4 py-2">URL</th>
              <th className="px-4 py-2">Result</th>
              <th className="px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {scanHistory.map((scan) => (
              <tr key={scan.id}>
                <td className="border px-4 py-2">{scan.id}</td>
                <td className="border px-4 py-2">{scan.url}</td>
                <td className="border px-4 py-2">
                  <pre className="h-32 overflow-y-auto">{scan.result}</pre>
                </td>
                <td className="border px-4 py-2">
                  <a href={`/report/${scan.id}/html`} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline mr-2">
                    HTML
                  </a>
                  <a href={`/report/${scan.id}/pdf`} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">
                    PDF
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="mb-32 grid text-center lg:mb-0 lg:w-full lg:max-w-5xl lg:grid-cols-4 lg:text-left">
        {/* Add navigation to other pages here */}
      </div>
    </main>
  );
}
