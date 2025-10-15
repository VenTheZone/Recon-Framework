"use client";

import { useState, useEffect } from 'react';
import Link from 'next/link';

export default function Settings() {
  const [apiKey, setApiKey] = useState('');
  const [modelId, setModelId] = useState('');

  useEffect(() => {
    const fetchSettings = async () => {
      const response = await fetch('/api/settings');
      const data = await response.json();
      setApiKey(data.api_key);
      setModelId(data.model_id);
    };
    fetchSettings();
  }, []);

  const saveSettings = async () => {
    await fetch('/api/settings', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ api_key: apiKey, model_id: modelId }),
    });
    alert('Settings saved!');
  };

  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <div className="z-10 w-full max-w-5xl items-center justify-between font-mono text-sm lg:flex">
        <p className="fixed left-0 top-0 flex w-full justify-center border-b border-gray-300 bg-gradient-to-b from-zinc-200 pb-6 pt-8 backdrop-blur-2xl dark:border-neutral-800 dark:bg-zinc-800/30 dark:from-inherit lg:static lg:w-auto  lg:rounded-xl lg:border lg:bg-gray-200 lg:p-4 lg:dark:bg-zinc-800/30">
          Settings
        </p>
        <Link href="/" className="text-blue-500 hover:underline">
          Back to Main
        </Link>
      </div>

      <div className="relative flex flex-col items-center">
        <div className="mb-4">
          <label className="block text-white mb-2" htmlFor="api-key">Hugging Face API Key</label>
          <input
            id="api-key"
            type="text"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Enter your Hugging Face API key"
            className="w-full max-w-lg rounded-md border border-gray-300 p-2 text-black"
          />
        </div>
        <div className="mb-4">
          <label className="block text-white mb-2" htmlFor="model-id">Hugging Face Model ID</label>
          <input
            id="model-id"
            type="text"
            value={modelId}
            onChange={(e) => setModelId(e.target.value)}
            placeholder="e.g., Qwen/Qwen3-Coder-480B-A35B-Instruct"
            className="w-full max-w-lg rounded-md border border-gray-300 p-2 text-black"
          />
           <a href="https://huggingface.co/models" target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline text-sm">
            Find a model on Hugging Face
          </a>
        </div>
        <button
          onClick={saveSettings}
          className="rounded-md bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
        >
          Save Settings
        </button>
      </div>

      <div className="mb-32 grid text-center lg:mb-0 lg:w-full lg:max-w-5xl lg:grid-cols-4 lg:text-left">
      </div>
    </main>
  );
}
