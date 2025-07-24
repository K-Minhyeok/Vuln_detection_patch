"use client"

import { useState } from "react"
import { TypewriterEffect } from "./typewriter-effect"
import { Button } from "@/components/ui/button"

interface AnalysisOutputProps {
  filename: string
  onComplete?: () => void
}

export function AnalysisOutput({ filename, onComplete }: AnalysisOutputProps) {
  const [currentStep, setCurrentStep] = useState(0)
  const [showChoice, setShowChoice] = useState(false)

  const steps = [
    {
      text: "▼ Output Example ▼",
      className: "text-green-400 text-xl font-bold text-center mb-4",
      delay: 1000,
    },
    {
      text: `> { dangerous commands } is detected in { ${filename} }`,
      className: "text-red-400 mb-2",
      delay: 1500,
    },
    {
      text: `> Those should be changed to { safe commands }`,
      className: "text-yellow-400 mb-4",
      delay: 1500,
    },
    {
      text: `> Continue to Download Patched { ${filename} } ?`,
      className: "text-green-400 mb-2",
      delay: 1000,
    },
  ]

  const handleStepComplete = () => {
    if (currentStep < steps.length - 1) {
      setTimeout(() => {
        setCurrentStep((prev) => prev + 1)
      }, steps[currentStep].delay)
    } else {
      setTimeout(() => {
        setShowChoice(true)
      }, 1000)
    }
  }

  const handleChoice = (choice: boolean) => {
    if (choice) {
      // Simulate download
      const element = document.createElement("a")
      const file = new Blob([`Patched version of ${filename}`], { type: "text/plain" })
      element.href = URL.createObjectURL(file)
      element.download = `patched_${filename}`
      document.body.appendChild(element)
      element.click()
      document.body.removeChild(element)

      alert("Patched file downloaded successfully!")
    } else {
      alert("Download cancelled.")
    }

    // Complete the analysis output
    if (onComplete) {
      setTimeout(() => {
        onComplete()
      }, 1000)
    }
  }

  return (
    <div className="text-center space-y-4 mb-8">
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
          <TypewriterEffect text="▶ Choose (Y/N)" speed={50} className="text-cyan-400 mb-4 block" />
          <div className="flex gap-4 justify-center mt-4">
            <Button
              onClick={() => handleChoice(true)}
              className="bg-green-900/50 hover:bg-green-800/50 border-green-400 border text-green-400 px-8 py-3 text-lg"
            >
              Y (Yes)
            </Button>
            <Button
              onClick={() => handleChoice(false)}
              className="bg-red-900/50 hover:bg-red-800/50 border-red-400 border text-red-400 px-8 py-3 text-lg"
            >
              N (No)
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
