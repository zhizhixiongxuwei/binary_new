import type * as Monaco from 'monaco-editor'

export type ReadOnlyCodeLanguage =
  | 'c'
  | 'java'
  | 'jvm-bytecode'
  | 'smali'
  | 'python-bytecode'

export type MonacoModule = typeof Monaco

interface MonacoEnvironment {
  getWorker: (_moduleId: string, _label: string) => Worker
}

const languageIds: Readonly<Record<ReadOnlyCodeLanguage, string>> = {
  c: 'cpp',
  java: 'java',
  'jvm-bytecode': 'jvm-bytecode',
  smali: 'smali',
  'python-bytecode': 'python-bytecode',
}

let monacoPromise: Promise<MonacoModule> | undefined

export function resolveMonacoLanguage(
  language: ReadOnlyCodeLanguage,
): string {
  return languageIds[language]
}

export function supportsMonacoRuntime(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof document !== 'undefined' &&
    typeof Worker !== 'undefined'
  )
}

function registerLanguage(
  monaco: MonacoModule,
  id: string,
  tokens: Monaco.languages.IMonarchLanguage,
): void {
  if (!monaco.languages.getLanguages().some((language) => language.id === id)) {
    monaco.languages.register({ id })
  }
  monaco.languages.setMonarchTokensProvider(id, tokens)
}

function registerBinaryAnalysisLanguages(monaco: MonacoModule): void {
  registerLanguage(monaco, 'jvm-bytecode', {
    defaultToken: '',
    tokenPostfix: '.jvm-bytecode',
    brackets: [
      { open: '{', close: '}', token: 'delimiter.curly' },
      { open: '[', close: ']', token: 'delimiter.square' },
    ],
    tokenizer: {
      root: [
        [/"(?:class_key|binary_name|methods|name|descriptor|bytecode_hex|offset_bytes|size_bytes|sha256)"(?=\s*:)/, 'keyword'],
        [/"(?:[^"\\]|\\.)*"/, 'string'],
        [/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/, 'number'],
        [/\b(?:true|false|null)\b/, 'constant'],
        [/[{}[\]]/, '@brackets'],
        [/[,:]/, 'delimiter'],
      ],
    },
  })

  registerLanguage(monaco, 'smali', {
    defaultToken: '',
    tokenPostfix: '.smali',
    keywords: [
      '.class',
      '.super',
      '.source',
      '.method',
      '.end',
      '.locals',
      '.registers',
      '.field',
      '.annotation',
      '.implements',
      'invoke-direct',
      'invoke-static',
      'invoke-virtual',
      'move-result',
      'return-void',
      'const-string',
      'new-instance',
    ],
    tokenizer: {
      root: [
        [/^\s*#.*$/, 'comment'],
        [/"([^"\\]|\\.)*$/, 'string.invalid'],
        [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
        [/[.:a-zA-Z_$][\w$./;-]*/, {
          cases: {
            '@keywords': 'keyword',
            '@default': 'identifier',
          },
        }],
        [/[{}()[\]]/, '@brackets'],
        [/-?\d+/, 'number'],
      ],
      string: [
        [/[^\\"]+/, 'string'],
        [/\\./, 'string.escape.invalid'],
        [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }],
      ],
    },
  })

  registerLanguage(monaco, 'python-bytecode', {
    defaultToken: '',
    tokenPostfix: '.python-bytecode',
    keywords: [
      'CACHE',
      'CALL',
      'COMPARE_OP',
      'CONTAINS_OP',
      'FOR_ITER',
      'GET_ITER',
      'JUMP_BACKWARD',
      'LOAD_ATTR',
      'LOAD_CONST',
      'LOAD_FAST',
      'LOAD_GLOBAL',
      'LOAD_METHOD',
      'POP_JUMP_FORWARD_IF_FALSE',
      'PRECALL',
      'RESUME',
      'RETURN_VALUE',
      'STORE_FAST',
    ],
    tokenizer: {
      root: [
        [/^\s*#.*$/, 'comment'],
        [/\b\d+\b/, 'number'],
        [/'([^'\\]|\\.)*'/, 'string'],
        [/"([^"\\]|\\.)*"/, 'string'],
        [/[A-Z][A-Z_]+/, {
          cases: {
            '@keywords': 'keyword',
            '@default': 'type.identifier',
          },
        }],
        [/[a-zA-Z_]\w*/, 'identifier'],
      ],
    },
  })
}

export function loadMonacoEditor(): Promise<MonacoModule> {
  if (!monacoPromise) {
    const pendingImport = Promise.all([
      import('@/components/code-editor/monacoWorkerFactory'),
      import('@/components/code-editor/monacoEntry'),
    ]).then(([workerModule, monaco]) => {
      const scope = globalThis as typeof globalThis & {
        MonacoEnvironment?: MonacoEnvironment
      }
      scope.MonacoEnvironment = {
        getWorker: () => workerModule.createEditorWorker(),
      }
      registerBinaryAnalysisLanguages(monaco)
      return monaco
    })
    monacoPromise = pendingImport.catch((error: unknown) => {
      monacoPromise = undefined
      throw error
    })
  }

  return monacoPromise
}
