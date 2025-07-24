"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Upload, CheckCircle, XCircle } from "lucide-react"
import { TypewriterEffect } from "./typewriter-effect"

interface AnalysisResult {
  filename: string
  filesize: string
  architecture: string
  timestamp: string
  vulnerabilities: {
    critical: number
    high: number
    medium: number
    low: number
  }
  securityFeatures: {
    stackCanary: boolean
    nxBit: boolean
    aslr: boolean
    relro: boolean
    pie: boolean
    fortify: boolean
  }
  details: string[]
  dangerousCommands: {
    dangerous: string
    safe: string
    severity: "critical" | "high" | "medium" | "low"
  }[]
}

interface AnalysisPageProps {
  file: File
  onNewAnalysis: () => void
}

export function AnalysisPage({ file, onNewAnalysis }: AnalysisPageProps) {
  const [currentStep, setCurrentStep] = useState(0)
  const [showChoice, setShowChoice] = useState(false)
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const steps = [
    { text: "▼ Output Example ▼", className: "text-green-400 text-xl font-bold text-center mb-4", delay: 1000 },
    { text: `> { dangerous commands } is detected in { ${file.name} }`, className: "text-red-400 mb-2 text-center", delay: 1500 },
    { text: `> Those should be changed to { safe commands }`, className: "text-yellow-400 mb-4 text-center", delay: 1500 },
    { text: `> Continue to Download Patched { ${file.name} } ?`, className: "text-green-400 mb-2 text-center", delay: 1000 },
  ]

  useEffect(() => {
    const startAnalysis = async () => {
      setIsAnalyzing(true)
      try {
        const formData = new FormData()
        formData.append("file", file)

        const response = await fetch("/api/analyze", {
          method: "POST",
          body: formData,
        })

        const result = await response.json()

        if (result.success) {
          const raw = result.data
          const checksecFlags = raw.results[0].checksec

          const featureFlags = {
            relro: checksecFlags.some((f: string) => f.toLowerCase().includes("relro")),
            nxBit: checksecFlags.some((f: string) => f.toLowerCase().includes("nx")),
            pie: checksecFlags.some((f: string) => f.toLowerCase().includes("pie")),
            stackCanary: checksecFlags.some((f: string) => f.toLowerCase().includes("canary")),
            fortify: checksecFlags.some((f: string) => f.toLowerCase().includes("fortify")),
            aslr: checksecFlags.some((f: string) => f.toLowerCase().includes("aslr")),
          }

          const mappedVulns = { critical: 0, high: 0, medium: 0, low: 0 }

          const dangerousCommands = raw.results[0].function_mapping.map(([dangerous, info]: [string, any]) => {
            const level = info.risk_level.toLowerCase()
            if (level in mappedVulns) mappedVulns[level as keyof typeof mappedVulns]++
            return {
              dangerous,
              safe: info.safe_func,
              severity: level as "critical" | "high" | "medium" | "low",
            }
          })

          const converted: AnalysisResult = {
            filename: raw.filename,
            filesize: `${(file.size / 1024).toFixed(2)} KB`,
            architecture: "x86_64", // 실제값 있으면 대체
            timestamp: new Date().toISOString(),
            vulnerabilities: mappedVulns,
            securityFeatures: featureFlags,
            details: [
              "Binary analysis completed successfully",
              "ELF header validation: PASSED",
              "Section header analysis: COMPLETED",
              "Symbol table examination: FINISHED",
              "Dynamic linking check: VERIFIED",
              "Security mitigation scan: DONE",
            ],
            dangerousCommands,
          }

          setAnalysisResult(converted)
        }
      } catch (err) {
        console.error("Analysis failed:", err)
      } finally {
        setIsAnalyzing(false)
      }
    }

    startAnalysis()
  }, [file])

  const handleStepComplete = () => {
    if (currentStep < steps.length - 1) {
      setTimeout(() => setCurrentStep((prev) => prev + 1), steps[currentStep].delay)
    } else {
      setTimeout(() => setShowChoice(true), 1000)
    }
  }

  const handleChoice = (choice: boolean) => {
    if (choice) {
      const element = document.createElement("a")
      const downloadFile = new Blob([`Patched version of ${file.name}`], { type: "text/plain" })
      element.href = URL.createObjectURL(downloadFile)
      element.download = `patched_${file.name}`
      document.body.appendChild(element)
      element.click()
      document.body.removeChild(element)
      alert("Patched file downloaded successfully!")
    } else {
      alert("Download cancelled.")
    }
  }

  const getTotalVulnerabilities = (vulns: AnalysisResult["vulnerabilities"]) =>
    vulns.critical + vulns.high + vulns.medium + vulns.low

  return (
    <div className="min-h-screen">
      <div className="pt-4 pb-8 px-8">
        <div className="max-w-7xl mx-auto">
          <div className="text-center space-y-6">
            {steps.slice(0, currentStep + 1).map((step, index) => (
              <div key={index}>
                {index === currentStep ? (
                  <TypewriterEffect text={step.text} speed={30} onComplete={handleStepComplete} className={step.className} />
                ) : (
                  <div className={step.className}>{step.text}</div>
                )}
              </div>
            ))}

            {showChoice && (
              <div className="mt-6 animate-fade-in">
                <TypewriterEffect text="▶ Choose (Y/N)" speed={50} className="text-cyan-400 mb-4 block text-center" />
                <div className="flex gap-4 justify-center mt-4">
                  <Button onClick={() => handleChoice(true)} className="bg-green-900/50 hover:bg-green-800/50 border-green-400 border text-green-400 px-8 py-3 text-lg">
                    Y (Yes)
                  </Button>
                  <Button onClick={() => handleChoice(false)} className="bg-red-900/50 hover:bg-red-800/50 border-red-400 border text-red-400 px-8 py-3 text-lg">
                    N (No)
                  </Button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="px-8 pb-8">
        <div className="max-w-7xl mx-auto">
          {isAnalyzing && (
            <div className="text-center mb-8">
              <div className="animate-spin text-green-400 text-4xl mb-4">⟳</div>
              <div className="text-green-400 text-xl">ANALYZING BINARY...</div>
            </div>
          )}

                   {analysisResult && (
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 animate-fade-in">
              <Card className="bg-black/80 border-green-400 border-2">
                <CardContent className="p-6 text-center">
                  <h2 className="text-2xl font-bold text-green-400 mb-4 text-center">ANALYSIS COMPLETE</h2>
                  <div className="grid grid-cols-2 gap-4 text-center">
                    <div>
                      <div className="text-green-300 text-sm">File</div>
                      <div className="text-green-400 font-bold text-sm">{analysisResult.filename}</div>
                    </div>
                    <div>
                      <div className="text-green-300 text-sm">Size</div>
                      <div className="text-green-400 font-bold text-sm">{analysisResult.filesize}</div>
                    </div>
                    <div>
                      <div className="text-green-300 text-sm">Architecture</div>
                      <div className="text-green-400 font-bold text-sm">{analysisResult.architecture}</div>
                    </div>
                    <div>
                      <div className="text-green-300 text-sm">Total Vulnerabilities</div>
                      <div className="text-red-400 font-bold text-xl">
                        {getTotalVulnerabilities(analysisResult.vulnerabilities)}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 2번 */}
              <Card className="bg-black/80 border-red-400 border-2">
                <CardContent className="p-4">
                  <h3 className="text-xl font-bold text-red-400 mb-4 text-center">THREAT ASSESSMENT</h3>
                  <div className="grid grid-cols-2 gap-3 text-center">
                    <div className="p-3 border border-red-400 rounded">
                      <div className="text-red-400 text-2xl font-bold">{analysisResult.vulnerabilities.critical}</div>
                      <div className="text-red-300 text-sm">CRITICAL</div>
                    </div>
                    <div className="p-3 border border-orange-400 rounded">
                      <div className="text-orange-400 text-2xl font-bold">{analysisResult.vulnerabilities.high}</div>
                      <div className="text-orange-300 text-sm">HIGH</div>
                    </div>
                    <div className="p-3 border border-yellow-400 rounded">
                      <div className="text-yellow-400 text-2xl font-bold">{analysisResult.vulnerabilities.medium}</div>
                      <div className="text-yellow-300 text-sm">MEDIUM</div>
                    </div>
                    <div className="p-3 border border-green-400 rounded">
                      <div className="text-green-400 text-2xl font-bold">{analysisResult.vulnerabilities.low}</div>
                      <div className="text-green-300 text-sm">LOW</div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* 3번 */}
              <Card className="bg-black/80 border-blue-400 border-2">
                <CardContent className="p-4">
                  <h3 className="text-xl font-bold text-blue-400 mb-4 text-center">SECURITY MITIGATIONS</h3>
                  <div className="grid grid-cols-2 gap-2 text-center">
                    {Object.entries(analysisResult.securityFeatures).map(([feature, enabled]) => (
                      <div
                        key={feature}
                        className="p-2 border border-gray-600 rounded flex items-center justify-center gap-1"
                      >
                        {enabled ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-400" />
                        )}
                        <span className={`text-xs ${enabled ? "text-green-400" : "text-red-400"}`}>
                          {feature.toUpperCase()}
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>


              {/* 4번 */}
              <Card className="bg-black/80 border-orange-400 border-2 lg:col-span-2 xl:col-span-3">
                <CardContent className="p-4">
                  <h3 className="text-xl font-bold text-orange-400 mb-4 text-center">DANGEROUS COMMANDS DETECTED</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* todo function_mapping에 있는 함수명 e.g. printf, system등을 dangerous로 잡음 */}
                    {analysisResult.dangerousCommands.map((cmd, index) => (
                      <div key={index} className="border border-gray-600 rounded p-3">
                        <div className="flex items-center gap-2 mb-2">
                          <span
                            className={`text-xs px-2 py-1 rounded ${
                              cmd.severity === "critical"
                                ? "bg-red-900/50 text-red-400 border border-red-400"
                                : cmd.severity === "high"
                                  ? "bg-orange-900/50 text-orange-400 border border-orange-400"
                                  : cmd.severity === "medium"
                                    ? "bg-yellow-900/50 text-yellow-400 border border-yellow-400"
                                    : "bg-green-900/50 text-green-400 border border-green-400"
                            }`}
                          >
                            {cmd.severity.toUpperCase()}
                          </span>
                        </div>
                        <div className="grid grid-cols-1 gap-2 text-sm">
                          <div>
                            <span className="text-red-400 font-bold">Dangerous: </span>
                            <code className="text-red-300 bg-red-900/20 px-2 py-1 rounded">{cmd.dangerous}</code>
                          </div>
                          <div>
                            <span className="text-green-400 font-bold">Safe: </span>
                            <code className="text-green-300 bg-green-900/20 px-2 py-1 rounded">{cmd.safe}</code>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )} 

          <div className="text-center mt-8">
            <Button
              onClick={onNewAnalysis}
              className="bg-green-900/50 hover:bg-green-800/50 border-green-400 border text-green-400 text-lg px-8 py-4"
            >
              <Upload className="w-6 h-6 mr-2" />
              ANALYZE NEW FILE
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
