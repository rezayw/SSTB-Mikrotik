import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SSTB - Smart Security & Threat Blocker',
  description: 'Sistem keamanan proaktif MikroTik berbasis threat intelligence',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="id">
      <body className="bg-cyber-dark text-gray-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
