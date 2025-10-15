"use client";

import { useState, useEffect } from 'react';
import { Rnd } from 'react-rnd';
import Link from 'next/link';
import { v4 as uuidv4 } from 'uuid';

interface ScanWindowProps {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
}

const ScanWindow: React.FC<ScanWindowProps> = ({ title, children, onClose }) => (
  <Rnd
    default={{
      x: 0,
      y: 0,
      width: 500,
      height: 400,
    }}
    minWidth={200}
    minHeight={200}
    bounds="parent"
    className="overflow-hidden rounded-lg bg-gray-800 border border-green-500 shadow-lg"
  >
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between bg-gray-900 p-2">
        <h2 className="text-sm font-bold text-green-400">{title}</h2>
        <button onClick={onClose} className="text-red-500">
          X
        </button>
      </div>
      <div className="flex-grow overflow-auto p-4 text-white">{children}</div>
    </div>
  </Rnd>
);

interface Scan {
  id: number;
  url: string;
  scan_type: string;
  result: string;
}

interface ChatMessage {
  sender: 'user' | 'ai';
  text: string;
}

const Navbar = () => (
  <nav className="bg-gray-800 p-4">
    <div className="container mx-auto flex justify-between">
      <Link href="/" className="text-white text-lg font-bold">
        Web Penetration Tool
      </Link>
      <div>
        <Link href="/scanners" className="text-gray-300 hover:text-white mr-4">
          Scanners
        </Link>
        <Link href="/history" className="text-gray-300 hover:text-white mr-4">
          History
        </Link>
        <Link href="/settings" className="text-gray-300 hover:text-white">
          Settings
        </Link>
      </div>
    </div>
  </nav>
);

export default function Scanners() {
  const [windows, setWindows] = useState<{ id: number; type: string }[]>([]);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [selectedScans, setSelectedScans] = useState<number[]>([]);

  useEffect(() => {
    const fetchScanHistory = async () => {
      const response = await fetch('/api/scans');
      const data = await response.json();
      setScanHistory(data);
    };
    fetchScanHistory();
  }, []);


  const addWindow = (type: string) => {
    const newWindow = {
      id: Date.now(),
      type,
    };
    setWindows([...windows, newWindow]);
  };

  const closeWindow = (id: number) => {
    setWindows(windows.filter((win) => win.id !== id));
  };

  const toggleScanSelection = (id: number) => {
    setSelectedScans(
      selectedScans.includes(id)
        ? selectedScans.filter((scanId) => scanId !== id)
        : [...selectedScans, id]
    );
  };

  return (
    <div>
      <Navbar />
      <main className="relative h-screen w-screen overflow-hidden bg-black">
        <div className="absolute top-0 left-0 z-10 flex w-full items-center justify-between p-4">
          <div>
            <button onClick={() => addWindow('bypass')} className="mr-2 rounded bg-blue-500 px-4 py-2 text-white">
              New Bypass Scan
            </button>
            <button onClick={() => addWindow('xss')} className="mr-2 rounded bg-green-500 px-4 py-2 text-white">
              New XSS Scan
            </button>
            <button onClick={() => addWindow('surface')} className="mr-2 rounded bg-purple-500 px-4 py-2 text-white">
              New Surface Scan
            </button>
            <button onClick={() => addWindow('port')} className="mr-2 rounded bg-red-500 px-4 py-2 text-white">
              New Port Scan
            </button>
            <button onClick={() => addWindow('crawl')} className="rounded bg-yellow-500 px-4 py-2 text-white">
              New Crawl
            </button>
          </div>
        </div>

        <div className="absolute inset-0 pt-16 flex">
          <div className="w-3/4 h-full">
            {windows.map((win) => (
              <ScanWindow key={win.id} title={`${win.type.toUpperCase()} Scan ${win.id}`} onClose={() => closeWindow(win.id)}>
                {win.type === 'bypass' && <BypassScan />}
                {win.type === 'xss' && <XssScan />}
                {win.type === 'surface' && <SurfaceScan />}
                {win.type === 'port' && <PortScan />}
                {win.type === 'crawl' && <Crawl />}
              </ScanWindow>
            ))}
          </div>
          <div className="w-1/4 h-full bg-gray-900 p-4">
            <RtfAssistant scanHistory={scanHistory} selectedScans={selectedScans} onSelectScan={toggleScanSelection} />
          </div>
        </div>
      </main>
    </div>
  );
}

const BypassScan = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const startScan = async () => {
    setIsLoading(true);
    const res = await fetch('/scan/bypass', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    setResult(await res.json());
    setIsLoading(false);
  };

  return (
    <div>
      <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" className="w-full rounded border bg-gray-700 p-2 text-white" />
      <button onClick={startScan} disabled={isLoading} className="mt-2 rounded bg-blue-500 px-4 py-2 text-white">
        {isLoading ? 'Scanning...' : 'Start Bypass Scan'}
      </button>
      {result && <pre className="mt-4 overflow-auto rounded bg-gray-900 p-2">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
};

const XssScan = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const startScan = async () => {
    setIsLoading(true);
    const res = await fetch('/scan/xss', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    setResult(await res.json());
    setIsLoading(false);
  };

  return (
    <div>
      <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" className="w-full rounded border bg-gray-700 p-2 text-white" />
      <button onClick={startScan} disabled={isLoading} className="mt-2 rounded bg-green-500 px-4 py-2 text-white">
        {isLoading ? 'Scanning...' : 'Start XSS Scan'}
      </button>
      {result && <pre className="mt-4 overflow-auto rounded bg-gray-900 p-2">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
};

const SurfaceScan = () => {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const startScan = async () => {
    setIsLoading(true);
    const res = await fetch('/scan/surface', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    setResult(await res.json());
    setIsLoading(false);
  };

  return (
    <div>
      <input type="text" value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="Enter Domain" className="w-full rounded border bg-gray-700 p-2 text-white" />
      <button onClick={startScan} disabled={isLoading} className="mt-2 rounded bg-purple-500 px-4 py-2 text-white">
        {isLoading ? 'Scanning...' : 'Start Surface Scan'}
      </button>
      {result && <pre className="mt-4 overflow-auto rounded bg-gray-900 p-2">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
};

const PortScan = () => {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const startScan = async () => {
    setIsLoading(true);
    const res = await fetch('/scan/port', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    setResult(await res.json());
    setIsLoading(false);
  };

  return (
    <div>
      <input type="text" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="Enter Target IP or Domain" className="w-full rounded border bg-gray-700 p-2 text-white" />
      <button onClick={startScan} disabled={isLoading} className="mt-2 rounded bg-red-500 px-4 py-2 text-white">
        {isLoading ? 'Scanning...' : 'Start Port Scan'}
      </button>
      {result && <pre className="mt-4 overflow-auto rounded bg-gray-900 p-2">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
}

const Crawl = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const startCrawl = async () => {
    setIsLoading(true);
    const res = await fetch('/crawl', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, allowed_domain: new URL(url).hostname }),
    });
    setResult(await res.json());
    setIsLoading(false);
  };

  return (
    <div>
      <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter URL" className="w-full rounded border bg-gray-700 p-2 text-white" />
      <button onClick={startCrawl} disabled={isLoading} className="mt-2 rounded bg-yellow-500 px-4 py-2 text-white">
        {isLoading ? 'Crawling...' : 'Start Crawl'}
      </button>
      {result && <pre className="mt-4 overflow-auto rounded bg-gray-900 p-2">{JSON.stringify(result, null, 2)}</pre>}
    </div>
  );
};

const RtfAssistant = ({ scanHistory, selectedScans, onSelectScan }) => {
  const [sessionId] = useState(uuidv4());
  const [chatHistory, setChatHistory] = useState<ChatMessage[]>([]);
  const [message, setMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [fileContent, setFileContent] = useState('');

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setFileContent(e.target?.result as string);
      };
      reader.readAsText(file);
    }
  };

  const sendMessage = async () => {
    setIsLoading(true);
    const userMessage = { sender: 'user', text: message };
    setChatHistory([...chatHistory, userMessage]);

    let context = fileContent;
    if (selectedScans.length > 0) {
      const selectedScanResults = scanHistory.filter(scan => selectedScans.includes(scan.id));
      context += `\n\n${JSON.stringify(selectedScanResults, null, 2)}`;
    }

    const res = await fetch('/api/assistant', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: sessionId,
        scan_context: context,
        user_question: message,
      }),
    });
    const data = await res.json();
    const aiMessage = { sender: 'ai', text: data.response };
    setChatHistory([...chatHistory, userMessage, aiMessage]);
    setMessage('');
    setFileContent('');
    setIsLoading(false);
  };

  return (
    <div className="flex flex-col h-full bg-gray-800 p-4 rounded-lg">
      <h2 className="text-lg font-bold text-green-400 mb-4">R-T-F_Assistant</h2>
      <div className="flex-grow overflow-y-auto mb-4 border border-green-500 p-2">
        {chatHistory.map((chat, index) => (
          <div key={index} className={`mb-2 ${chat.sender === 'user' ? 'text-right' : 'text-left'}`}>
            <span className={`p-2 rounded ${chat.sender === 'user' ? 'bg-blue-500' : 'bg-gray-700'}`}>
              {chat.text}
            </span>
          </div>
        ))}
      </div>
      <div>
        <h3 className="text-md font-bold text-green-400 mb-2">Select Scan Context:</h3>
        <div className="flex flex-wrap mb-2">
          {scanHistory.map(scan => (
            <label key={scan.id} className="mr-2">
              <input
                type="checkbox"
                checked={selectedScans.includes(scan.id)}
                onChange={() => onSelectScan(scan.id)}
              />
              Scan #{scan.id}
            </label>
          ))}
        </div>
        <div className="mb-2">
          <label className="block text-white mb-2" htmlFor="file-upload">Upload a file:</label>
          <input id="file-upload" type="file" onChange={handleFileChange} />
        </div>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Ask R-T-F_Assistant..."
          className="w-full rounded border bg-gray-700 p-2 text-white"
          rows={3}
        />
        <button onClick={sendMessage} disabled={isLoading} className="mt-2 rounded bg-green-500 px-4 py-2 text-white">
          {isLoading ? 'Thinking...' : 'Send'}
        </button>
      </div>
    </div>
  );
};
