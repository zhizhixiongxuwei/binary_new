package report

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Word export writes a minimal OOXML document (docx) using only the standard
// library: a docx package is a ZIP container whose main part is
// word/document.xml. Section layout mirrors the static HTML report so both
// formats stay equivalent.

const (
	wordContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`

	wordRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`</Relationships>`
)

type docxDocument struct {
	body bytes.Buffer
}

func (d *docxDocument) heading1(text string) {
	d.paragraph(text, 36, true)
}

func (d *docxDocument) heading2(text string) {
	d.paragraph(text, 28, true)
}

func (d *docxDocument) paragraph(text string, size int, bold bool) {
	d.body.WriteString(`<w:p><w:pPr><w:spacing w:before="120" w:after="120"/>`)
	if bold {
		d.body.WriteString(`<w:rPr><w:b/><w:sz w:val="` + strconv.Itoa(size) + `"/></w:rPr>`)
	}
	d.body.WriteString(`</w:pPr><w:r>`)
	if bold {
		d.body.WriteString(`<w:rPr><w:b/><w:sz w:val="` + strconv.Itoa(size) + `"/></w:rPr>`)
	}
	d.body.WriteString(`<w:t xml:space="preserve">` + escapeWordText(text) + `</w:t></w:r></w:p>`)
}

func (d *docxDocument) note(text string) {
	d.body.WriteString(`<w:p><w:pPr><w:spacing w:before="60" w:after="120"/>` +
		`<w:rPr><w:i/></w:rPr></w:pPr><w:r><w:rPr><w:i/></w:rPr>` +
		`<w:t xml:space="preserve">` + escapeWordText(text) + `</w:t></w:r></w:p>`)
}

func (d *docxDocument) table(headers []string, rows [][]string) {
	d.body.WriteString(`<w:tbl><w:tblPr>` +
		`<w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:left w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:right w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="auto"/>` +
		`<w:insideV w:val="single" w:sz="4" w:color="auto"/>` +
		`</w:tblBorders></w:tblPr>`)
	d.tableRow(headers, true)
	for _, row := range rows {
		d.tableRow(row, false)
	}
	d.body.WriteString(`</w:tbl>`)
}

func (d *docxDocument) tableRow(cells []string, header bool) {
	d.body.WriteString(`<w:tr>`)
	for _, cell := range cells {
		d.body.WriteString(`<w:tc><w:tcPr><w:tcW w:w="0" w:type="auto"/>`)
		if header {
			d.body.WriteString(`<w:shd w:val="clear" w:fill="EEF2F6"/>`)
		}
		d.body.WriteString(`</w:tcPr><w:p><w:r>`)
		if header {
			d.body.WriteString(`<w:rPr><w:b/></w:rPr>`)
		}
		d.body.WriteString(`<w:t xml:space="preserve">` + escapeWordText(cell) + `</w:t></w:r></w:p></w:tc>`)
	}
	d.body.WriteString(`</w:tr>`)
}

func escapeWordText(value string) string {
	var output bytes.Buffer
	if err := xml.EscapeText(&output, []byte(value)); err != nil {
		return ""
	}
	return output.String()
}

func renderWordDocument(writer io.Writer, data htmlReportData) error {
	document := &docxDocument{}
	document.heading1("BinaryScan 离线检测报告")
	document.note("Schema " + data.SchemaVersion +
		" · Report " + data.ReportID + " · Generated " + data.GeneratedAt)

	document.heading2("任务")
	document.table(
		[]string{"项目", "内容"},
		[][]string{
			{"ID", data.Task.ID},
			{"名称", data.Task.Name},
			{"状态", data.Task.Status},
			{"阶段", nullableText(data.Task.Stage)},
			{"风险", data.Task.RiskLevel},
			{"根格式", nullableText(data.Task.RootFormat)},
			{"错误", joinNullable(data.Task.ErrorCode, data.Task.ErrorMessage)},
			{"原始样本", data.SampleRelationMessage},
		},
	)

	document.heading2("输入")
	document.table(
		[]string{"项目", "内容"},
		[][]string{
			{"文件名", data.Task.Input.Filename},
			{"大小", strconv.FormatUint(data.Task.Input.SizeBytes, 10)},
			{"SHA-256", data.Task.Input.SHA256},
		},
	)

	if len(data.FileTypes) > 0 {
		document.heading2("文件类型")
		rows := make([][]string, 0, len(data.FileTypes))
		for _, fileType := range data.FileTypes {
			rows = append(rows, []string{
				fileType.Format,
				strconv.FormatUint(fileType.Count, 10),
				strconv.FormatUint(fileType.SizeBytes, 10),
			})
		}
		document.table([]string{"格式", "数量", "字节"}, rows)
	}

	if len(data.VulnerabilitySummary) > 0 {
		document.heading2("漏洞汇总")
		rows := make([][]string, 0, len(data.VulnerabilitySummary))
		for _, summary := range data.VulnerabilitySummary {
			rows = append(rows, []string{
				summary.Severity,
				strconv.FormatUint(summary.Count, 10),
				strconv.FormatUint(summary.Fixable, 10),
			})
		}
		document.table([]string{"严重度", "数量", "可修复"}, rows)
	}

	if len(data.Vulnerabilities) > 0 {
		document.heading2("漏洞明细")
		rows := make([][]string, 0, len(data.Vulnerabilities))
		for _, finding := range data.Vulnerabilities {
			rows = append(rows, []string{
				finding.VulnerabilityID,
				finding.Severity,
				finding.PackageName,
				nullableText(finding.InstalledVersion),
				nullableText(finding.FixedVersion),
				nullableText(finding.Title),
			})
		}
		document.table(
			[]string{"编号", "严重度", "软件包", "已装版本", "修复版本", "标题"},
			rows,
		)
		if data.VulnerabilitiesTruncated {
			document.note("漏洞明细超过展示上限，更多记录请查看 JSON 报告。")
		}
	}

	if len(data.CAnalysisRuns) > 0 {
		document.heading2("C 伪源码静态分析")
		rows := make([][]string, 0, len(data.CAnalysisRuns))
		for _, run := range data.CAnalysisRuns {
			rows = append(rows, []string{
				run.ID,
				run.AnalyzerName + " " + run.AnalyzerVersion,
				run.Status,
				strconv.FormatUint(run.FindingCount, 10),
				strconv.FormatUint(run.DiagnosticCount, 10),
			})
		}
		document.table([]string{"运行 ID", "分析器", "状态", "发现", "诊断"}, rows)
		if len(data.CAnalysisFindings) > 0 {
			findingRows := make([][]string, 0, len(data.CAnalysisFindings))
			for _, finding := range data.CAnalysisFindings {
				findingRows = append(findingRows, []string{
					finding.CWE,
					finding.RuleID,
					finding.Severity,
					finding.FunctionName,
					locationLabel(finding.StartLine, finding.StartColumn,
						finding.EndLine, finding.EndColumn),
					cFindingMessage(finding.RuleID, finding.Message),
				})
			}
			document.table(
				[]string{"CWE", "规则", "严重度", "函数", "位置", "检测结论"},
				findingRows,
			)
		}
		if data.CAnalysisFindingsTruncated {
			document.note("C 伪源码发现仅展示前 " +
				strconv.Itoa(data.CAnalysisFindingLimit) + " 项。")
		}
	}

	if len(data.JavaAnalysisRuns) > 0 {
		document.heading2("Java 反编译源码静态分析")
		rows := make([][]string, 0, len(data.JavaAnalysisRuns))
		for _, run := range data.JavaAnalysisRuns {
			rows = append(rows, []string{
				run.ID,
				run.AnalyzerName + " " + run.AnalyzerVersion,
				run.Status,
				strconv.FormatUint(run.SourceFileCount, 10),
				strconv.FormatUint(run.FindingCount, 10),
				strconv.FormatUint(run.DiagnosticCount, 10),
			})
		}
		document.table(
			[]string{"运行 ID", "分析器", "状态", "文件", "发现", "诊断"},
			rows,
		)
		if len(data.JavaAnalysisFindings) > 0 {
			findingRows := make([][]string, 0, len(data.JavaAnalysisFindings))
			for _, finding := range data.JavaAnalysisFindings {
				findingRows = append(findingRows, []string{
					finding.CWE,
					finding.RuleID,
					finding.Severity,
					finding.LogicalPath,
					finding.CallableName,
					locationLabel(finding.StartLine, finding.StartColumn,
						finding.EndLine, finding.EndColumn),
					javaFindingMessage(finding.RuleID, finding.Message),
				})
			}
			document.table(
				[]string{"CWE", "规则", "严重度", "文件", "可调用", "位置", "检测结论"},
				findingRows,
			)
		}
		if data.JavaAnalysisFindingsTruncated {
			document.note("Java 源码发现仅展示前 " +
				strconv.Itoa(data.JavaAnalysisFindingLimit) + " 项。")
		}
	}

	if len(data.PythonAnalysisRuns) > 0 {
		document.heading2("Python 反编译源码静态分析")
		rows := make([][]string, 0, len(data.PythonAnalysisRuns))
		for _, run := range data.PythonAnalysisRuns {
			rows = append(rows, []string{
				run.ID,
				run.AnalyzerName + " " + run.AnalyzerVersion,
				run.Status,
				strconv.FormatUint(run.SourceFileCount, 10),
				strconv.FormatUint(run.FindingCount, 10),
				strconv.FormatUint(run.DiagnosticCount, 10),
			})
		}
		document.table(
			[]string{"运行 ID", "分析器", "状态", "文件", "发现", "诊断"},
			rows,
		)
		if len(data.PythonAnalysisFindings) > 0 {
			findingRows := make([][]string, 0, len(data.PythonAnalysisFindings))
			for _, finding := range data.PythonAnalysisFindings {
				findingRows = append(findingRows, []string{
					finding.CWE,
					finding.RuleID,
					finding.Severity,
					finding.LogicalPath,
					locationLabel(finding.StartLine, finding.StartColumn,
						finding.EndLine, finding.EndColumn),
					pythonFindingMessage(finding.RuleID, finding.Message),
				})
			}
			document.table(
				[]string{"CWE", "规则", "严重度", "文件", "位置", "检测结论"},
				findingRows,
			)
		}
		if data.PythonAnalysisFindingsTruncated {
			document.note("Python 源码发现仅展示前 " +
				strconv.Itoa(data.PythonAnalysisFindingLimit) + " 项。")
		}
	}

	if len(data.Analyzers) > 0 {
		document.heading2("分析器")
		rows := make([][]string, 0, len(data.Analyzers))
		for _, analyzer := range data.Analyzers {
			rows = append(rows, []string{
				analyzer.AnalyzerName,
				analyzer.AnalyzerVersion,
				analyzer.Status,
				joinNullable(analyzer.ErrorCode, analyzer.ErrorMessage),
			})
		}
		document.table([]string{"分析器", "版本", "状态", "错误"}, rows)
	}

	if len(data.Decompilations) > 0 {
		document.heading2("反编译结果")
		rows := make([][]string, 0, len(data.Decompilations))
		for _, decompilation := range data.Decompilations {
			rows = append(rows, []string{
				decompilation.ID,
				decompilation.DisplayName,
				decompilation.SymbolKind,
				decompilation.Language,
				decompilation.Status,
			})
		}
		document.table(
			[]string{"结果 ID", "名称", "符号类型", "语言", "状态"},
			rows,
		)
	}

	if len(data.Databases) > 0 {
		document.heading2("数据库版本")
		rows := make([][]string, 0, len(data.Databases))
		for _, database := range data.Databases {
			rows = append(rows, []string{
				database.Version,
				database.TrivyDBVersion,
				database.TrivyJavaDBVersion,
				database.GeneratedAt.UTC().Format("2006-01-02 15:04:05"),
				database.ContentSHA256,
			})
		}
		document.table(
			[]string{"版本", "Trivy 库", "Java 库", "生成时间", "内容 SHA-256"},
			rows,
		)
	}

	if len(data.Issues) > 0 {
		document.heading2("诊断")
		rows := make([][]string, 0, len(data.Issues))
		for _, issue := range data.Issues {
			rows = append(rows, []string{
				issue.Category,
				issue.Code,
				nullableText(issue.Source),
				nullableText(issue.LogicalPath),
				diagnosticMessage(issue.Code, issue.Message),
			})
		}
		document.table(
			[]string{"类别", "代码", "来源", "路径", "诊断"},
			rows,
		)
	}

	document.body.WriteString(`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/></w:sectPr>`)

	body := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body>` + document.body.String() + `</w:body></w:document>`

	archive := zip.NewWriter(writer)
	files := map[string]string{
		"[Content_Types].xml": wordContentTypes,
		"_rels/.rels":         wordRels,
		"word/document.xml":   body,
	}
	for name, content := range files {
		entry, err := archive.Create(name)
		if err != nil {
			return fmt.Errorf("create docx part %s: %w", name, err)
		}
		if _, err := io.WriteString(entry, content); err != nil {
			return fmt.Errorf("write docx part %s: %w", name, err)
		}
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("close docx archive: %w", err)
	}
	return nil
}

func locationLabel(
	startLine uint64,
	startColumn uint64,
	endLine uint64,
	endColumn uint64,
) string {
	return strconv.FormatUint(startLine, 10) + ":" + strconv.FormatUint(startColumn, 10) +
		"-" + strconv.FormatUint(endLine, 10) + ":" + strconv.FormatUint(endColumn, 10)
}

func nullableText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func joinNullable(left *string, right *string) string {
	values := make([]string, 0, 2)
	if value := nullableText(left); value != "" {
		values = append(values, value)
	}
	if value := nullableText(right); value != "" {
		values = append(values, value)
	}
	return strings.Join(values, " ")
}

// WriteDOCXSnapshot renders the report as a Word document using the shared
// presentation snapshot.
func (r *MySQLRepository) WriteDOCXSnapshot(
	ctx context.Context,
	request SnapshotRequest,
	writer io.Writer,
) error {
	return r.withReadSnapshot(ctx, func(transaction *sql.Tx) error {
		data, dependencies, javaDependencies, _, err := loadHTMLReportData(
			ctx,
			transaction,
			request,
		)
		if err != nil {
			return err
		}
		var pythonDependencies []PythonAnalysisDependency
		if data.PythonAnalysisRuns != nil {
			for _, run := range data.PythonAnalysisRuns {
				pythonDependencies = append(pythonDependencies, PythonAnalysisDependency{
					RunID: run.ID, ProjectID: run.SourceProjectID,
					CompletedAt: run.CompletedAt,
					SourceManifestSHA256: run.SourceManifestSHA256,
					InputSHA256:          run.InputSHA256,
				})
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := renderWordDocument(writer, data); err != nil {
			return fmt.Errorf("render Word report: %w", err)
		}
		recordSnapshotDependencies(request, dependencies)
		recordJavaSnapshotDependencies(request, javaDependencies)
		recordPythonSnapshotDependencies(request, pythonDependencies)
		return nil
	})
}
