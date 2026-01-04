"use client"

import { useEffect } from "react"

declare global {
  interface Window {
    __ROTA_CONFIG__?: {
      apiUrl: string
    }
  }
}

interface ConfigProviderProps {
  apiUrl: string
  children: React.ReactNode
}

export function ConfigProvider({ apiUrl, children }: ConfigProviderProps) {
  useEffect(() => {
    // Inject runtime config into window object
    if (typeof window !== "undefined") {
      window.__ROTA_CONFIG__ = { apiUrl }
    }
  }, [apiUrl])

  return <>{children}</>
}

