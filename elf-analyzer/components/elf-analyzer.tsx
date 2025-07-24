"use client"
import { useState } from "react"
import MatrixBackground from "./matrix-background"
import { UploadPage } from "./upload-page"
import { AnalysisPage } from "./analysis-page"

export default function ElfAnalyzer() {
  const [currentPage, setCurrentPage] = useState<"upload" | "analysis">("upload")
  const [selectedFile, setSelectedFile] = useState<File | null>(null)

  const handleFileSelect = (file: File) => {
    setSelectedFile(file)
    setCurrentPage("analysis")
  }

  const handleNewAnalysis = () => {
    setSelectedFile(null)
    setCurrentPage("upload")
  }

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono relative overflow-hidden">
      <MatrixBackground />

      <div className="relative z-10">
        {currentPage === "upload" && <UploadPage onFileSelect={handleFileSelect} />}
        {currentPage === "analysis" && selectedFile && (
          <AnalysisPage file={selectedFile} onNewAnalysis={handleNewAnalysis} />
        )}
      </div>
    </div>
  )
}
