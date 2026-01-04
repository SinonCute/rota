import type { Metadata } from "next";
import { Fira_Code } from "next/font/google";
import { ThemeProvider } from "@/components/theme-provider";
import { ConfigProvider } from "@/components/config-provider";
import { Toaster } from "@/components/ui/sonner";
import "./globals.css";

const firaCode = Fira_Code({
  subsets: ["latin"],
  variable: "--font-fira-code",
  weight: ["300", "400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "Rota - Proxy Rotation Dashboard",
  description: "Intelligent proxy rotation and management system",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Read API URL from environment at runtime (server-side)
  // This allows changing it without rebuilding - just restart the container
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${firaCode.variable} font-mono antialiased`}>
        <ConfigProvider apiUrl={apiUrl}>
          <ThemeProvider
            attribute="class"
            defaultTheme="dark"
            enableSystem
            disableTransitionOnChange
          >
            {children}
            <Toaster />
          </ThemeProvider>
        </ConfigProvider>
      </body>
    </html>
  );
}
