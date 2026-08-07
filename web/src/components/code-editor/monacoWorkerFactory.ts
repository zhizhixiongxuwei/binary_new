import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker'

export function createEditorWorker(): Worker {
  return new EditorWorker()
}
