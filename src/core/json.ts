/**
 * True when any object of a JSON text has the same key twice (after decoding escapes, so `"a"` and
 * `"a"` are the same key). `JSON.parse` keeps the last of them silently and other languages keep
 * the first or fail, so a text entry point refuses such a text (see "Cross-language notes" in
 * `docs/wire-format.md`). The text must be valid JSON already (`JSON.parse` accepted it).
 */
export function hasDuplicateKeys(text: string): boolean {
  // One set of keys per open object; arrays have none.
  const stack: (Set<string> | null)[] = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const literal = text.slice(i, end + 1);
      i = end + 1;
      let next = i;
      while (next < text.length && ' \t\n\r'.includes(text[next] as string)) next += 1;
      const keys = stack[stack.length - 1];
      // A text followed by a colon is a key; values never are.
      if (text[next] === ':' && keys) {
        const key = JSON.parse(literal) as string;
        if (keys.has(key)) return true;
        keys.add(key);
      }
      continue;
    }
    if (ch === '{') stack.push(new Set());
    else if (ch === '[') stack.push(null);
    else if (ch === '}' || ch === ']') stack.pop();
    i += 1;
  }
  return false;
}
