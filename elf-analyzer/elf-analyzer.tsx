"use client"

import type React from "react"

import { useState, useRef, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Upload, Terminal } from "lucide-react"

interface AnalysisResult {
  timestamp: string
  filename: string
  filesize: string
  architecture: string
  vulnerabilities: {
    critical: number
    high: number
    medium: number
    low: number
  }
  details: string[]
  mitigations: string[]
}

export default function ElfAnalyzer() {
  const [terminalOutput, setTerminalOutput] = useState<string[]>([
    "ELF Vulnerability Analyzer v2.1.0",
    "Copyright (c) 2024 Security Research Lab",
    "Type 'help' for available commands",
    "",
  ])
  const [currentCommand, setCurrentCommand] = useState("")
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [uploadedFile, setUploadedFile] = useState<File | null>(null)
  const scrollAreaRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const scrollToBottom = () => {
    if (scrollAreaRef.current) {
      const scrollContainer = scrollAreaRef.current.querySelector("[data-radix-scroll-area-viewport]")
      if (scrollContainer) {
        scrollContainer.scrollTop = scrollContainer.scrollHeight
      }
    }
  }

  useEffect(() => {
    scrollToBottom()
  }, [terminalOutput])

  const addToOutput = (lines: string | string[]) => {
    const newLines = Array.isArray(lines) ? lines : [lines]
    setTerminalOutput((prev) => [...prev, ...newLines])
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      setUploadedFile(file)
      addToOutput([
        `$ upload ${file.name}`,
        `File uploaded: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`,
        "Ready for analysis. Type 'analyze' to start.",
        "",
      ])
    }
  }

  const simulateAnalysis = async (): Promise<AnalysisResult> => {
    const mockResult: AnalysisResult = {
      timestamp: new Date().toISOString(),
      filename: uploadedFile?.name || "sample.bin",
      filesize: uploadedFile ? `${(uploadedFile.size / 1024).toFixed(2)} KB` : "245.7 KB",
      architecture: "x86_64",
      vulnerabilities: {
        critical: Math.floor(Math.random() * 3),
        high: Math.floor(Math.random() * 5),
        medium: Math.floor(Math.random() * 8),
        low: Math.floor(Math.random() * 12),
      },
      details: [
        "Stack canary protection: DISABLED",
        "NX bit protection: ENABLED",
        "ASLR support: PARTIAL",
        "RELRO protection: PARTIAL",
        "PIE enabled: NO",
        "Fortify source: NO",
        "Stripped symbols: YES",
      ],
      mitigations: [
        "Enable stack canary protection (-fstack-protector-strong)",
        "Compile with PIE support (-fPIE -pie)",
        "Enable full RELRO (-Wl,-z,relro,-z,now)",
        "Use fortify source (-D_FORTIFY_SOURCE=2)",
      ],
    }

    return new Promise((resolve) => {
      setTimeout(() => resolve(mockResult), 3000)
    })
  }

  const executeCommand = async (cmd: string) => {
    const command = cmd.trim().toLowerCase()

    addToOutput(`$ ${cmd}`)

    switch (command) {
      case "help":
        addToOutput([
          "Available commands:",
          "  help          - Show this help message",
          "  upload        - Upload ELF file for analysis",
          "  analyze       - Analyze uploaded ELF file",
          "  clear         - Clear terminal output",
          "  exit          - Exit analyzer",
          "",
        ])
        break

      case "upload":
        fileInputRef.current?.click()
        break

      case "analyze":
        if (!uploadedFile) {
          addToOutput(["ERROR: No file uploaded. Use 'upload' command first.", ""])
          break
        }

        setIsAnalyzing(true)
        addToOutput([
          "Starting ELF vulnerability analysis...",
          "Loading binary sections...",
          "Checking security mitigations...",
          "Scanning for known vulnerabilities...",
          "",
        ])

        // Simulate analysis progress
        const progressSteps = [
          "Analyzing ELF header... [████████████████████] 100%",
          "Checking program headers... [████████████████████] 100%",
          "Scanning section headers... [████████████████████] 100%",
          "Analyzing symbol table... [████████████████████] 100%",
          "Checking dynamic linking... [████████████████████] 100%",
          "Vulnerability assessment... [████████████████████] 100%",
        ]

        for (let i = 0; i < progressSteps.length; i++) {
          await new Promise((resolve) => setTimeout(resolve, 500))
          addToOutput(progressSteps[i])
        }

        const result = await simulateAnalysis()

        addToOutput([
          "",
          "═══════════════════════════════════════════════════════════",
          "                    ANALYSIS COMPLETE                     ",
          "═══════════════════════════════════════════════════════════",
          "",
          `File: ${result.filename}`,
          `Size: ${result.filesize}`,
          `Architecture: ${result.architecture}`,
          `Timestamp: ${result.timestamp}`,
          "",
          "VULNERABILITY SUMMARY:",
          `  🔴 Critical: ${result.vulnerabilities.critical}`,
          `  🟠 High:     ${result.vulnerabilities.high}`,
          `  🟡 Medium:   ${result.vulnerabilities.medium}`,
          `  🟢 Low:      ${result.vulnerabilities.low}`,
          "",
          "SECURITY ANALYSIS:",
          ...result.details.map((detail) => `  • ${detail}`),
          "",
          "RECOMMENDED MITIGATIONS:",
          ...result.mitigations.map((mitigation, idx) => `  ${idx + 1}. ${mitigation}`),
          "",
          "Analysis complete. Type 'help' for more commands.",
          "",
        ])

        setIsAnalyzing(false)
        break

      case "clear":
        setTerminalOutput([
          "ELF Vulnerability Analyzer v2.1.0",
          "Copyright (c) 2024 Security Research Lab",
          "Type 'help' for available commands",
          "",
        ])
        break

      case "exit":
        addToOutput(["Goodbye!", "Connection closed.", ""])
        break

      default:
        addToOutput([`bash: ${cmd}: command not found`, "Type 'help' for available commands", ""])
    }
  }

  const handleCommandSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (currentCommand.trim() && !isAnalyzing) {
      executeCommand(currentCommand)
      setCurrentCommand("")
    }
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Terminal Header */}
      <div className="bg-gray-800 border-b border-gray-600 px-4 py-2 flex items-center gap-2">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
        </div>
        <div className="flex items-center gap-2 ml-4">
          <Terminal className="w-4 h-4" />
          <span className="text-white text-sm">ELF Vulnerability Analyzer</span>
        </div>
        <div className="ml-auto flex items-center gap-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
            className="text-green-400 hover:text-green-300 hover:bg-gray-700"
          >
            <Upload className="w-4 h-4 mr-2" />
            Upload ELF
          </Button>
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex flex-col h-[calc(100vh-60px)]">
        <ScrollArea ref={scrollAreaRef} className="flex-1 p-4">
          <div className="space-y-1">
            {terminalOutput.map((line, index) => (
              <div key={index} className="whitespace-pre-wrap">
                {line.includes("🔴") || line.includes("🟠") || line.includes("🟡") || line.includes("🟢") ? (
                  <span className="text-white">{line}</span>
                ) : line.includes("ERROR:") ? (
                  <span className="text-red-400">{line}</span>
                ) : line.includes("═") || line.includes("ANALYSIS COMPLETE") ? (
                  <span className="text-cyan-400 font-bold">{line}</span>
                ) : line.startsWith("$") ? (
                  <span className="text-yellow-400">{line}</span>
                ) : line.includes("[████████████████████]") ? (
                  <span className="text-blue-400">{line}</span>
                ) : (
                  <span>{line}</span>
                )}
              </div>
            ))}
            {isAnalyzing && (
              <div className="flex items-center gap-2 text-yellow-400">
                <div className="animate-spin">⟳</div>
                <span>Analyzing...</span>
              </div>
            )}
          </div>
        </ScrollArea>

        {/* Command Input */}
        <div className="border-t border-gray-600 p-4">
          <form onSubmit={handleCommandSubmit} className="flex items-center gap-2">
            <span className="text-green-400">root@analyzer:~#</span>
            <Input
              value={currentCommand}
              onChange={(e) => setCurrentCommand(e.target.value)}
              className="flex-1 bg-transparent border-none text-green-400 font-mono focus:ring-0 focus:outline-none p-0"
              placeholder="Enter command..."
              disabled={isAnalyzing}
              autoFocus
            />
          </form>
        </div>
      </div>

      {/* Hidden File Input */}
      <input ref={fileInputRef} type="file" accept=".bin,.elf,*" onChange={handleFileUpload} className="hidden" />
    </div>
  )
}
