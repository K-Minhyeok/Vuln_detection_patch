"use client"

import type React from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Upload, Terminal, Shield } from "lucide-react"
import { useRef } from "react"

interface UploadPageProps {
  onFileSelect: (file: File) => void
}

export function UploadPage({ onFileSelect }: UploadPageProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      onFileSelect(file)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-8">
      {/* Header */}
      <div className="text-center mb-12">
        <div className="flex items-center justify-center gap-4 mb-6">
          <Terminal className="w-12 h-12 text-green-400" />
          <Shield className="w-12 h-12 text-green-400" />
        </div>
        <h1 className="text-4xl font-bold text-green-400 mb-2 text-center">ELF VULNERABILITY ANALYZER</h1>
        <p className="text-green-300 text-lg text-center">Advanced Binary Security Assessment System</p>
        <div className="text-center mt-4 text-green-500">
          <div>
            {">"} MATRIX SECURITY PROTOCOL ACTIVE {"<"}
          </div>
          <div>
            {">"} NEURAL NETWORK ANALYSIS READY {"<"}
          </div>
        </div>
      </div>

      {/* Upload Section */}
      <Card className="w-full max-w-2xl bg-black/80 border-green-400 border-2">
        <CardContent className="p-8 text-center">
          <div className="mb-6">
            <Upload className="w-16 h-16 mx-auto text-green-400 mb-4" />
            <h2 className="text-2xl font-bold text-green-400 mb-2 text-center">UPLOAD ELF BINARY</h2>
            <p className="text-green-300 text-center">Select your ELF (.bin) file for vulnerability analysis</p>
          </div>

          <Button
            onClick={() => fileInputRef.current?.click()}
            className="w-full bg-green-900/50 hover:bg-green-800/50 border-green-400 border text-green-400 text-lg py-6"
          >
            <Upload className="w-6 h-6 mr-2" />
            Choose ELF File
          </Button>
        </CardContent>
      </Card>

      <input ref={fileInputRef} type="file" accept=".bin,.elf,*" onChange={handleFileUpload} className="hidden" />
    </div>
  )
}
