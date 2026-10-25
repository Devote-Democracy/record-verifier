/**
 * RFC 8785 JSON Canonicalization Scheme (JCS). Every log entry is the UTF-8 of
 * canonicalize(envelope), so the same entry always hashes the same, in any language.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('JCS: numbers must be finite')
    // ECMAScript Number serialisation is what RFC 8785 specifies; JSON.stringify(-0) is "0".
    return JSON.stringify(value)
  }
  if (typeof value === 'string') {
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) throw new TypeError('JCS: lone surrogate in string')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v === undefined ? null : v)).join(',')}]`
  if (typeof value === 'object') {
    // Default sort compares UTF-16 code units, as RFC 8785 requires.
    const keys = Object.keys(value as object).filter((k) => (value as Record<string, unknown>)[k] !== undefined).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize((value as Record<string, unknown>)[k])}`).join(',')}}`
  }
  throw new TypeError(`JCS: unsupported value of type ${typeof value}`)
}

const encoder = new TextEncoder()
export const canonicalBytes = (value: unknown): Uint8Array => encoder.encode(canonicalize(value))
export const utf8 = (text: string): Uint8Array => encoder.encode(text)
