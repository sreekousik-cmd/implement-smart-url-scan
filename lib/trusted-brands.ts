export type TrustedBrand = {
  name: string
  primaryDomain: string
  approvedDomains: string[]
}

// Keep this list intentionally editable: every entry is a verified domain boundary,
// not a keyword that can grant trust to an unrelated hostname.
export const TRUSTED_BRANDS: TrustedBrand[] = [
  { name: 'Google', primaryDomain: 'google.com', approvedDomains: ['google.com'] },
  { name: 'YouTube', primaryDomain: 'youtube.com', approvedDomains: ['youtube.com', 'youtu.be'] },
  { name: 'Amazon', primaryDomain: 'amazon.com', approvedDomains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.co.jp', 'amazon.com.au'] },
  { name: 'Amazon India', primaryDomain: 'amazon.in', approvedDomains: ['amazon.in'] },
  { name: 'Flipkart', primaryDomain: 'flipkart.com', approvedDomains: ['flipkart.com'] },
  { name: 'ChatGPT', primaryDomain: 'chatgpt.com', approvedDomains: ['chatgpt.com'] },
  { name: 'OpenAI', primaryDomain: 'openai.com', approvedDomains: ['openai.com'] },
  { name: 'Gemini', primaryDomain: 'gemini.google.com', approvedDomains: ['gemini.google.com'] },
  { name: 'Microsoft', primaryDomain: 'microsoft.com', approvedDomains: ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com'] },
  { name: 'Instagram', primaryDomain: 'instagram.com', approvedDomains: ['instagram.com'] },
  { name: 'Facebook', primaryDomain: 'facebook.com', approvedDomains: ['facebook.com'] },
  { name: 'WhatsApp', primaryDomain: 'whatsapp.com', approvedDomains: ['whatsapp.com', 'whatsapp.net'] },
  { name: 'Netflix', primaryDomain: 'netflix.com', approvedDomains: ['netflix.com'] },
  { name: 'LinkedIn', primaryDomain: 'linkedin.com', approvedDomains: ['linkedin.com'] },
  { name: 'GitHub', primaryDomain: 'github.com', approvedDomains: ['github.com'] },
]

export const TRUSTED_BRAND_DOMAINS = TRUSTED_BRANDS.flatMap((brand) => brand.approvedDomains)
