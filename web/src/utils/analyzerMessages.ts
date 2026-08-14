// Analyzer display translations, kept in sync with internal/report/messages.go.
// Checker messages are stored in English; the UI translates the stable
// rule/diagnostic codes to Chinese and keeps the original detail. Unknown
// codes fall back to the original message.

const cFindingTitles: Record<string, string> = {
  'cwe-242-gets': '使用 gets 读取输入，存在缓冲区溢出风险',
  'cwe-120-bounds': '缓冲区边界检查不足，存在溢出风险',
  'cwe-134-format': '不可信格式化字符串，存在格式串注入风险',
  'cwe-78-command': '命令注入风险（外部输入未净化）',
  'cwe-787-oob-write': '越界写入风险',
  'cwe-125-oob-read': '越界读取风险',
  'cwe-562-stack-address': '返回或泄露栈内存地址',
  'cwe-590-invalid-free': '无效的 free 调用（释放非堆内存）',
  'cwe-761-offset-free': '释放内存时使用错误偏移',
  'cwe-369-zero-divisor': '除零风险',
  'cwe-377-temp-file': '不安全的临时文件使用',
  'cwe-252-unchecked-return': '未检查函数返回值',
  'cwe-131-size-calculation': '尺寸计算错误导致整数溢出风险',
  'cwe-327-328-weak-crypto': '使用弱加密算法',
  'cwe-732-permissions': '不安全的文件权限设置',
}

const javaFindingTitles: Record<string, string> = {
  'java-weak-message-digest': '使用弱消息摘要算法',
  'java-weak-cipher': '使用弱加密算法',
  'java-legacy-tls': '使用过时或弱 TLS 配置',
  'java-hardcoded-crypto-key': '硬编码加密密钥',
  'java-trust-all-hostname-verifier': '信任所有主机名的验证器',
  'java-trust-all-x509-manager': '信任所有 X.509 证书的管理器',
  'java-xxe-enabled': '启用 XML 外部实体（XXE）风险',
  'java-unsafe-deserialization': '不安全的反序列化',
  'java-sql-injection': 'SQL 注入风险',
  'java-command-injection': '命令注入风险',
  'java-dynamic-code-execution': '动态代码执行风险',
  'java-overly-permissive-file': '文件权限过于宽松',
  'java-insecure-cookie': '不安全的 Cookie 配置',
}

const pythonFindingTitles: Record<string, string> = {
  'python-dynamic-code-execution': '动态执行代码风险',
  'python-command-injection': '命令注入风险',
  'python-unsafe-deserialization': '不安全的反序列化',
  'python-weak-message-digest': '使用弱消息摘要算法',
  'python-insecure-request': 'HTTP 请求关闭了证书校验',
}

const diagnosticTitles: Record<string, string> = {
  syntax_error: '源码语法错误',
  function_analysis_error: '函数分析失败',
  analysis_timeout: '分析超过时间限制',
  file_too_large: '文件超过单文件分析大小限制',
  parser_failed: '源码语法解析失败',
  parser_no_ast: '解析器未生成语法树',
  java_parse_problem: '源码解析存在问题',
  rule_evaluation_failed: '规则评估失败',
}

function displayMessage(
  titles: Record<string, string>,
  code: string,
  message: string,
): string {
  const title = titles[code]
  if (!title) return message
  const detail = message.trim()
  if (detail === '' || detail === title) return title
  return `${title} — ${detail}`
}

export function cFindingMessage(ruleId: string, message: string): string {
  return displayMessage(cFindingTitles, ruleId, message)
}

export function javaFindingMessage(ruleId: string, message: string): string {
  return displayMessage(javaFindingTitles, ruleId, message)
}

export function pythonFindingMessage(ruleId: string, message: string): string {
  return displayMessage(pythonFindingTitles, ruleId, message)
}

export function analyzerDiagnosticMessage(
  code: string,
  message: string,
): string {
  return displayMessage(diagnosticTitles, code, message)
}
