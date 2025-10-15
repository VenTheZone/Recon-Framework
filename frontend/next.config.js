/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://localhost:5000/api/:path*',
      },
      {
        source: '/scan/:path*',
        destination: 'http://localhost:5000/scan/:path*',
      },
      {
        source: '/report/:path*',
        destination: 'http://localhost:5000/report/:path*',
      },
      {
        source: '/results/:path*',
        destination: 'http://localhost:5000/results/:path*',
      },
      {
        source: '/crawl',
        destination: 'http://localhost:5000/crawl',
      }
    ]
  },
};

module.exports = nextConfig;
