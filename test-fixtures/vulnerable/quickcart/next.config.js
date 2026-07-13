/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // No security headers configured, and wide-open CORS with credentials.
  async headers() {
    return [
      {
        source: '/api/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Credentials', value: 'true' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
