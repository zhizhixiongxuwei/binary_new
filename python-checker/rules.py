"""BinaryScan Python static analysis rules.

Rules inspect Python source with the standard-library ast module only, so the
checker image has zero third-party dependencies. Findings are reported by
stable rule ids with CWE and severity so the platform can translate them.

Every rule is a visitor over an ast.Module that appends Finding records.
"""

import ast

REQUEST_SCHEMA = "binaryscan-python-analysis-request/v1"
RESPONSE_SCHEMA = "binaryscan-python-analysis-response/v1"

SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"

_RISKY_CALLS = {
    "exec": ("python-dynamic-code-execution", "CWE-95", "HIGH",
             "动态执行代码（exec）"),
    "eval": ("python-dynamic-code-execution", "CWE-95", "HIGH",
             "动态执行代码（eval）"),
}

_SHELL_CALLS = {
    "system": ("python-command-injection", "CWE-78", "HIGH",
               "通过系统调用执行命令"),
    "popen": ("python-command-injection", "CWE-78", "HIGH",
              "通过管道执行命令"),
    "call": ("python-command-injection", "CWE-78", "HIGH",
             "通过 subprocess 执行命令"),
    "check_call": ("python-command-injection", "CWE-78", "HIGH",
                   "通过 subprocess 执行命令"),
    "check_output": ("python-command-injection", "CWE-78", "HIGH",
                     "通过 subprocess 执行命令"),
    "run": ("python-command-injection", "CWE-78", "HIGH",
            "通过 subprocess 执行命令"),
}

_UNSAFE_IMPORTS = {
    "pickle": ("python-unsafe-deserialization", "CWE-502", "HIGH",
               "使用 pickle 反序列化"),
    "shelve": ("python-unsafe-deserialization", "CWE-502", "HIGH",
               "使用 shelve 反序列化"),
}

_WEAK_DIGESTS = {
    "md5": ("python-weak-message-digest", "CWE-328", "MEDIUM",
            "使用弱消息摘要算法 md5"),
    "sha1": ("python-weak-message-digest", "CWE-328", "MEDIUM",
             "使用弱消息摘要算法 sha1"),
}

_MAX_FINDINGS = 1000
_MAX_DIAGNOSTICS = 100


class Finding:
    def __init__(self, rule_id, cwe, severity, message, logical_path, line):
        self.rule_id = rule_id
        self.cwe = cwe
        self.severity = severity
        self.message = message
        self.logical_path = logical_path
        self.line = line

    def to_dict(self):
        return {
            "ruleId": self.rule_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "message": self.message,
            "file": {"logicalPath": self.logical_path},
            "line": self.line,
        }


class _RuleVisitor(ast.NodeVisitor):
    def __init__(self, logical_path, findings, truncate):
        self.logical_path = logical_path
        self.findings = findings
        self.truncate = truncate

    def _add(self, rule_id, cwe, severity, message, node):
        if len(self.findings) >= _MAX_FINDINGS:
            self.truncate[0] = True
            return
        self.findings.append(
            Finding(rule_id, cwe, severity, message,
                    self.logical_path, getattr(node, "lineno", 0))
        )

    def _call_name(self, node):
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _module_of(self, node):
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return node.func.value.id
        return None

    def visit_Call(self, node):
        self.generic_visit(node)
        name = self._call_name(node)
        if name is None:
            return
        if name in _RISKY_CALLS:
            rule_id, cwe, severity, message = _RISKY_CALLS[name]
            self._add(rule_id, cwe, severity, message, node)
            return
        if name in _WEAK_DIGESTS and self._module_of(node) == "hashlib":
            rule_id, cwe, severity, message = _WEAK_DIGESTS[name]
            self._add(rule_id, cwe, severity, message, node)
            return
        if name in _SHELL_CALLS:
            module = self._module_of(node)
            if module in ("os", "subprocess"):
                rule_id, cwe, severity, message = _SHELL_CALLS[name]
                self._add(rule_id, cwe, severity, message, node)
            return
        if name == "loads" and self._module_of(node) in ("pickle", "yaml"):
            self._add("python-unsafe-deserialization", "CWE-502", "HIGH",
                      "使用不安全的反序列化 loads", node)
            return
        if name == "load" and self._module_of(node) == "pickle":
            self._add("python-unsafe-deserialization", "CWE-502", "HIGH",
                      "使用 pickle 反序列化 load", node)
            return
        if name == "get" and self._module_of(node) == "requests":
            for keyword in node.keywords:
                if keyword.arg == "verify" and _is_false(keyword.value):
                    self._add("python-insecure-request", "CWE-295", "MEDIUM",
                              "HTTP 请求关闭了证书校验（verify=False）", node)
            return
        if name == "check_shell" and self._module_of(node) == "subprocess":
            for keyword in node.keywords:
                if keyword.arg == "shell" and _is_true(keyword.value):
                    self._add("python-command-injection", "CWE-78", "HIGH",
                              "subprocess 启用了 shell 执行", node)
            return
        if name == "Popen" and self._module_of(node) == "subprocess":
            for keyword in node.keywords:
                if keyword.arg == "shell" and _is_true(keyword.value):
                    self._add("python-command-injection", "CWE-78", "HIGH",
                              "subprocess.Popen 启用了 shell 执行", node)

    def visit_Import(self, node):
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in _UNSAFE_IMPORTS:
                rule_id, cwe, severity, message = _UNSAFE_IMPORTS[top]
                self._add(rule_id, cwe, severity, message, node)

    def visit_ImportFrom(self, node):
        if node.module:
            top = node.module.split(".")[0]
            if top in _UNSAFE_IMPORTS:
                rule_id, cwe, severity, message = _UNSAFE_IMPORTS[top]
                self._add(rule_id, cwe, severity, message, node)


def _is_false(node):
    return isinstance(node, ast.Constant) and node.value is False


def _is_true(node):
    return isinstance(node, ast.Constant) and node.value is True


def analyze_file(source, logical_path):
    """Parse one source file and return (findings, diagnostics, truncated)."""
    findings = []
    diagnostics = []
    truncated = [False]
    try:
        tree = ast.parse(source, filename=logical_path)
    except (SyntaxError, ValueError) as error:
        diagnostics.append({
            "code": "python_parse_problem",
            "message": str(error),
            "severity": "ERROR",
            "file": {"logicalPath": logical_path},
            "line": getattr(error, "lineno", 0),
        })
        return findings, diagnostics, False
    visitor = _RuleVisitor(logical_path, findings, truncated)
    visitor.visit(tree)
    return findings, diagnostics, truncated[0]


def analyze_request(payload):
    """Validate and analyze a request payload. Returns (response, status)."""
    if not isinstance(payload, dict) or payload.get("schema") != REQUEST_SCHEMA:
        return {"error": {"code": "invalid_request",
                          "message": "request schema is invalid"}}, 400
    files = payload.get("files")
    if not isinstance(files, list) or not files or len(files) > 200:
        return {"error": {"code": "invalid_request",
                          "message": "files must be a non-empty list"}}, 400
    findings = []
    diagnostics = []
    truncated = False
    analyzed = 0
    for item in files:
        if not isinstance(item, dict):
            return {"error": {"code": "invalid_request",
                              "message": "file entry is invalid"}}, 400
        logical_path = item.get("logicalPath")
        content = item.get("content")
        if not isinstance(logical_path, str) or not logical_path or \
                not isinstance(content, str):
            return {"error": {"code": "invalid_request",
                              "message": "file entry fields are invalid"}}, 400
        file_findings, file_diagnostics, file_truncated = analyze_file(
            content, logical_path)
        findings.extend(file_findings)
        diagnostics.extend(file_diagnostics)
        truncated = truncated or file_truncated
        analyzed += 1
    return {
        "schema": RESPONSE_SCHEMA,
        "name": "binaryscan-python-checker",
        "version": "0.1.0",
        "analyzedFiles": analyzed,
        "findings": [finding.to_dict() for finding in findings],
        "diagnostics": diagnostics,
        "findingsTruncated": truncated,
        "diagnosticsTruncated": len(diagnostics) >= _MAX_DIAGNOSTICS,
    }, 200
