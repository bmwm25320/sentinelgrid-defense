import { GoogleGenAI } from '@google/genai';

const GEMINI_MODELS = ['gemini-3.8-flash', 'gemini-3-flash-preview'] as const;

export function getActiveGeminiKey(overrideKey?: string): string {
  return (
    (overrideKey || '').trim() ||
    (typeof localStorage !== 'undefined' ? (localStorage.getItem('sentinelgrid_gemini_api_key') || '').trim() : '') ||
    (import.meta.env.VITE_GEMINI_API_KEY || '').trim()
  );
}

export async function generateWithGeminiFallback(
  apiKey: string,
  contents: string,
  systemInstruction?: string
): Promise<{ text: string; model: string } | null> {
  const key = getActiveGeminiKey(apiKey);
  if (!key) return null;

  const ai = new GoogleGenAI({ apiKey: key });
  for (const model of GEMINI_MODELS) {
    try {
      const response = await ai.models.generateContent({
        model,
        contents,
        ...(systemInstruction ? { config: { systemInstruction } } : {}),
      });
      if (response.text) {
        return { text: response.text, model };
      }
    } catch {
      // Try next Gemini model on transient overload/deprecation
    }
  }
  return null;
}
