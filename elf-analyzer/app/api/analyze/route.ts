import { type NextRequest, NextResponse } from "next/server"
import { exec } from 'child_process';
import path from 'path';
import axios from "axios";
import FormData from "form-data"
export async function GET() {
  const scriptPath = path.join(process.cwd(), 'analysis', 'analyze.py');

  return new Promise((resolve) => {
    exec(`python3 ${scriptPath}`, (error, stdout, stderr) => {
      if (error) {
        console.error('Error:', stderr);
        resolve(NextResponse.json({ error: 'Python 실행 오류', stderr }, { status: 500 }));
      } else {
        try {
          const result = JSON.parse(stdout);
          resolve(NextResponse.json(result));
        } catch (e) {
          resolve(NextResponse.json({ error: 'JSON 파싱 오류', raw: stdout }, { status: 500 }));
        }
      }
    });
  });
}


export async function POST(request: NextRequest) {
  try {
    const form = await request.formData()
    const file = form.get("file") as File

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 })
    }

    const arrayBuffer = await file.arrayBuffer()
    const buffer = Buffer.from(arrayBuffer)

    const formData = new FormData()
    formData.append("file", buffer, file.name)

    const result = await axios.post(
      `${process.env.NEXT_API_URL}/analyze`,
      formData,
      {
        headers: {
          ...formData.getHeaders(),
        },
      }
    )

    return NextResponse.json({
      success: true,
      data: result.data,
    })
  } catch (error) {
    console.error("Analysis error:", error)
    return NextResponse.json({ error: "Analysis failed" }, { status: 500 })
  }
}
