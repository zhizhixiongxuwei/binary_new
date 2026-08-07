const UNSAFE_DISPLAY_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u

export function hasUnsafeDisplayCharacter(value: string): boolean {
  return UNSAFE_DISPLAY_CHARACTER.test(value)
}

export function neutralizeUnsafeDisplayCharacters(value: string): string {
  let safeValue = ''
  for (const character of value) {
    safeValue += hasUnsafeDisplayCharacter(character) ? ' ' : character
  }
  return safeValue
}
