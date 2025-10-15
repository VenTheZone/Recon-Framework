"use client";

import Link from 'next/link';

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

export default function Home() {
  return (
    <div>
      <Navbar />
      <main className="p-4">
        <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
        <p>Welcome to the Web Penetration Tool. Select a scanner from the navigation to begin.</p>
      </main>
    </div>
  );
}
