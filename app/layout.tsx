import "@/styles/global.css";
import type { Metadata } from "next";
import { AuthProvider } from "@/hooks/use-auth";
import { Sidebar } from "@/components/sidebar";

export const metadata: Metadata = {
  title: "MalGuard AI - Forensic Threat Detection Platform",
  description: "AI-powered static binary analysis and threat classification for Windows PE executables.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased min-h-screen text-foreground selection:bg-primary/30 selection:text-white">
        <AuthProvider>
          <div className="flex min-h-screen">
            {/* Nav sidebar visible once user is authenticated */}
            <Sidebar />
            <main className="flex-1 w-full relative min-h-screen px-4 py-8 md:p-8 lg:p-12 overflow-y-auto">
              <div className="max-w-7xl mx-auto space-y-6">
                {children}
              </div>
            </main>
          </div>
        </AuthProvider>
      </body>
    </html>
  );
}
