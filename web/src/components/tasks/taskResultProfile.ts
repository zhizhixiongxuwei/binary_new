import {
  TASK_RESULT_TABS,
  type TaskResultTab,
} from '@/components/tasks/taskResultTypes'

const CONTAINER_IMAGE_FORMATS = new Set([
  'docker-tar',
  'docker-archive',
  'oci-tar',
  'oci-archive',
])

const DECOMPILE_FORMATS = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'mach-o',
  'mach-o32',
  'mach-o64',
  'class',
  'java-class',
  'jar',
  'war',
  'ear',
  'dex',
  'apk',
  'pyc',
  'python-bytecode',
])

const NATIVE_DECOMPILE_FORMATS = new Set([
  'pe',
  'pe32',
  'pe32+',
  'elf',
  'elf32',
  'elf64',
  'macho',
  'macho-thin',
  'mach-o',
  'mach-o32',
  'mach-o64',
])

const JAVA_DECOMPILE_FORMATS = new Set([
  'class',
  'java-class',
  'jar',
  'war',
  'ear',
  'dex',
  'apk',
])

const DECOMPILE_RESULT_TABS = [
  'files',
  'decompile',
  'reports',
] as const satisfies readonly TaskResultTab[]

const NATIVE_DECOMPILE_RESULT_TABS = [
  'files',
  'decompile',
  'c-analysis',
  'reports',
] as const satisfies readonly TaskResultTab[]

const JAVA_DECOMPILE_RESULT_TABS = [
  'files',
  'decompile',
  'java-analysis',
  'reports',
] as const satisfies readonly TaskResultTab[]

const CONTAINER_RESULT_TABS = [
  'files',
  'vulnerabilities',
  'reports',
] as const satisfies readonly TaskResultTab[]

function normalizeInputType(inputType: string): string {
  return inputType.trim().toLowerCase()
}

export function isContainerImageInputType(inputType: string): boolean {
  return CONTAINER_IMAGE_FORMATS.has(normalizeInputType(inputType))
}

export function taskResultTabsForInputType(
  inputType: string,
): readonly TaskResultTab[] {
  const normalized = normalizeInputType(inputType)
  if (CONTAINER_IMAGE_FORMATS.has(normalized)) return CONTAINER_RESULT_TABS
  if (NATIVE_DECOMPILE_FORMATS.has(normalized)) {
    return NATIVE_DECOMPILE_RESULT_TABS
  }
  if (JAVA_DECOMPILE_FORMATS.has(normalized)) {
    return JAVA_DECOMPILE_RESULT_TABS
  }
  if (DECOMPILE_FORMATS.has(normalized)) return DECOMPILE_RESULT_TABS

  // Generic archives may contain both executable and container-image targets.
  return TASK_RESULT_TABS
}
