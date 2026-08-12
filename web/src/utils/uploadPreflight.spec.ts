import { describe, expect, it } from 'vitest'

import { preflightUploadFile } from '@/utils/uploadPreflight'

function file(bytes: readonly number[], name = 'sample'): File {
  return new File([new Uint8Array(bytes)], name)
}

function tarFile(name = 'image'): File {
  const bytes = new Uint8Array(512)
  bytes.set(new TextEncoder().encode('ustar'), 257)
  return new File([bytes], name)
}

describe('upload magic preflight', () => {
  it('accepts an extensionless ELF only for the binary category', async () => {
    const extensionless = file([0x7f, 0x45, 0x4c, 0x46])

    await expect(
      preflightUploadFile(extensionless, 'binary'),
    ).resolves.toMatchObject({ accepted: true, detectedFormat: 'ELF' })
    await expect(
      preflightUploadFile(extensionless, 'archive'),
    ).resolves.toMatchObject({ accepted: false, detectedFormat: 'ELF' })
  })

  it('fails open for ZIP across binary and archive categories', async () => {
    const zip = file([0x50, 0x4b, 0x03, 0x04], 'ambiguous')

    await expect(preflightUploadFile(zip, 'binary')).resolves.toMatchObject({
      accepted: true,
    })
    await expect(preflightUploadFile(zip, 'archive')).resolves.toMatchObject({
      accepted: true,
    })
    await expect(preflightUploadFile(zip, 'container')).resolves.toMatchObject({
      accepted: false,
    })
  })

  it('fails open for TAR across archive and container categories', async () => {
    const tar = tarFile()

    await expect(preflightUploadFile(tar, 'archive')).resolves.toMatchObject({
      accepted: true,
    })
    await expect(preflightUploadFile(tar, 'container')).resolves.toMatchObject({
      accepted: true,
    })
    await expect(preflightUploadFile(tar, 'binary')).resolves.toMatchObject({
      accepted: false,
    })
  })

  it('allows unknown content for server-side authority', async () => {
    await expect(
      preflightUploadFile(file([1, 2, 3, 4]), 'container'),
    ).resolves.toEqual({ accepted: true })
  })
})
