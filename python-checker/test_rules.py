"""Unit tests for the Python checker rules (stdlib unittest)."""

import unittest

import rules


class RuleTests(unittest.TestCase):
    def analyze(self, source, path="main.py"):
        findings, diagnostics, truncated = rules.analyze_file(source, path)
        return findings, diagnostics, truncated

    def rule_ids(self, source):
        findings, _, _ = self.analyze(source)
        return [finding.rule_id for finding in findings]

    def test_os_system_command_injection(self):
        self.assertIn(
            "python-command-injection",
            self.rule_ids("import os\nos.system(user_input)\n"),
        )

    def test_subprocess_shell_command_injection(self):
        self.assertIn(
            "python-command-injection",
            self.rule_ids(
                "import subprocess\n"
                "subprocess.call(user_input, shell=True)\n"
            ),
        )

    def test_pickle_deserialization(self):
        self.assertIn(
            "python-unsafe-deserialization",
            self.rule_ids("import pickle\npickle.loads(raw)\n"),
        )

    def test_weak_digest(self):
        self.assertIn(
            "python-weak-message-digest",
            self.rule_ids("import hashlib\nhashlib.md5(data).hexdigest()\n"),
        )

    def test_requests_verify_false(self):
        self.assertIn(
            "python-insecure-request",
            self.rule_ids(
                "import requests\nrequests.get(url, verify=False)\n"
            ),
        )

    def test_dynamic_code_execution(self):
        self.assertIn(
            "python-dynamic-code-execution",
            self.rule_ids("eval(user_input)\n"),
        )

    def test_safe_code_has_no_findings(self):
        self.assertEqual(
            self.rule_ids(
                "import os\n"
                "def run():\n"
                "    return os.path.join('a', 'b')\n"
            ),
            [],
        )

    def test_syntax_error_becomes_diagnostic(self):
        findings, diagnostics, _ = self.analyze("def broken(:\n")
        self.assertEqual(findings, [])
        self.assertEqual(diagnostics[0]["code"], "python_parse_problem")

    def test_parse_error_does_not_mask_other_files(self):
        response, status = rules.analyze_request({
            "schema": rules.REQUEST_SCHEMA,
            "files": [
                {"logicalPath": "a.py", "content": "import pickle\npickle.loads(x)\n"},
                {"logicalPath": "b.py", "content": "def broken(:\n"},
            ],
        })
        self.assertEqual(status, 200)
        self.assertIn(
            "python-unsafe-deserialization",
            [f["ruleId"] for f in response["findings"]],
        )
        self.assertEqual(response["diagnostics"][0]["code"],
                         "python_parse_problem")

    def test_request_validation(self):
        response, status = rules.analyze_request({"schema": "wrong"})
        self.assertEqual(status, 400)
        self.assertEqual(response["error"]["code"], "invalid_request")
        response, status = rules.analyze_request({
            "schema": rules.REQUEST_SCHEMA,
            "files": [{
                "logicalPath": "main.py",
                "content": "eval(x)\n",
            }],
        })
        self.assertEqual(status, 200)
        self.assertEqual(response["schema"], rules.RESPONSE_SCHEMA)
        self.assertIn("python-dynamic-code-execution",
                      [f["ruleId"] for f in response["findings"]])

    def test_finding_fields(self):
        findings, _, _ = self.analyze(
            "import os\nos.system(cmd)\n", path="src/a.py"
        )
        finding = findings[0]
        self.assertEqual(finding.cwe, "CWE-78")
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.logical_path, "src/a.py")
        self.assertGreaterEqual(finding.line, 1)


if __name__ == "__main__":
    unittest.main()
