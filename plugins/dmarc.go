package plugins

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	dmarcReportMarkerHeader  = "X-MyMail-DMARC-Report"
	dmarcDefaultReportLimit  = 10 << 20
	dmarcDefaultMessageLimit = 25 << 20
	dmarcMaxMIMEParts        = 1000
	dmarcMaxMIMEDepth        = 20
	dmarcMaxZipEntries       = 100
	dmarcMaxInt64            = int64(^uint64(0) >> 1)
)

// DMARCReportProcessor adds a human-readable HTML attachment for each DMARC
// aggregate report found in a locally delivered message.
type DMARCReportProcessor struct {
	logger         *slog.Logger
	maxReportSize  int64
	maxMessageSize int64
}

// NewDMARCReportProcessor constructs the built-in DMARC report processor.
func NewDMARCReportProcessor(logger *slog.Logger) *DMARCReportProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	return &DMARCReportProcessor{
		logger:         logger,
		maxReportSize:  dmarcDefaultReportLimit,
		maxMessageSize: dmarcDefaultMessageLimit,
	}
}

// Name returns the processor name used in configuration.
func (p *DMARCReportProcessor) Name() string { return "dmarc" }

// Initialize applies optional positive byte limits for decompressed reports and
// total messages. The defaults are 10 MiB and 25 MiB respectively.
func (p *DMARCReportProcessor) Initialize(ctx context.Context, settings map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if p == nil {
		return errors.New("nil DMARC report processor")
	}
	for key, target := range map[string]*int64{
		"max_report_size":  &p.maxReportSize,
		"max_message_size": &p.maxMessageSize,
	} {
		value := strings.TrimSpace(settings[key])
		if value == "" {
			continue
		}
		limit, err := strconv.ParseInt(value, 10, 64)
		if err != nil || limit <= 0 || limit == dmarcMaxInt64 {
			return fmt.Errorf("invalid DMARC %s %q: must be a positive byte count", key, value)
		}
		*target = limit
	}
	return nil
}

// Process scans MIME attachments for DMARC aggregate XML and adds escaped HTML
// summaries. Invalid or unrelated candidate attachments are left untouched.
func (p *DMARCReportProcessor) Process(ctx context.Context, message *Message) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if p == nil {
		return Result{}, errors.New("nil DMARC report processor")
	}
	if message == nil {
		return Result{}, errors.New("nil message")
	}
	if int64(len(message.Data)) > p.maxMessageSize {
		return Result{Decision: Accept}, nil
	}
	top, body, separator, ok := splitRawMessage(message.Data)
	if !ok {
		return Result{Decision: Accept}, nil
	}
	parsed, err := mail.ReadMessage(bytes.NewReader(message.Data))
	if err != nil {
		return Result{Decision: Accept}, nil
	}
	if parsed.Header.Get(dmarcReportMarkerHeader) != "" {
		return Result{Decision: Accept}, nil
	}
	lineEnding := detectLineEnding(message.Data)

	var attachments []dmarcHTMLAttachment
	partCount := 0
	var scan func(mediaType, transferEncoding, filename string, data []byte, depth int) error
	scan = func(mediaType, transferEncoding, filename string, data []byte, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > dmarcMaxMIMEDepth {
			return errors.New("MIME nesting exceeds limit")
		}
		partCount++
		if partCount > dmarcMaxMIMEParts {
			return errors.New("MIME part count exceeds limit")
		}
		mediaType, params, parseErr := mime.ParseMediaType(mediaType)
		if parseErr != nil {
			mediaType = strings.ToLower(strings.TrimSpace(strings.SplitN(mediaType, ";", 2)[0]))
			params = nil
		}
		mediaType = strings.ToLower(mediaType)
		decoded, decodeErr := decodeMIMETransfer(data, transferEncoding, p.maxMessageSize)
		if decodeErr != nil {
			if isDMARCCandidate(mediaType, filename) {
				p.warnCandidate(filename, decodeErr)
			}
			return nil
		}
		if strings.HasPrefix(mediaType, "multipart/") {
			boundary := params["boundary"]
			if boundary == "" {
				return nil
			}
			reader := multipart.NewReader(bytes.NewReader(decoded), boundary)
			for {
				part, err := reader.NextRawPart()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return fmt.Errorf("read multipart content: %w", err)
				}
				partData, err := io.ReadAll(io.LimitReader(part, p.maxMessageSize+1))
				if err != nil {
					return fmt.Errorf("read MIME part: %w", err)
				}
				if int64(len(partData)) > p.maxMessageSize {
					return errors.New("MIME part exceeds message size limit")
				}
				partType := part.Header.Get("Content-Type")
				if partType == "" {
					partType = "text/plain"
				}
				_, dispositionParams, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
				_, typeParams, _ := mime.ParseMediaType(partType)
				partFilename := dispositionParams["filename"]
				if partFilename == "" {
					partFilename = typeParams["name"]
				}
				if err := scan(partType, part.Header.Get("Content-Transfer-Encoding"), partFilename, partData, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if !isDMARCCandidate(mediaType, filename) {
			return nil
		}
		reports, err := decodeDMARCReports(decoded, mediaType, filename, p.maxReportSize)
		if err != nil {
			p.warnCandidate(filename, err)
			return nil
		}
		for _, report := range reports {
			htmlBody, err := renderDMARCReport(report)
			if err != nil {
				p.warnCandidate(filename, err)
				continue
			}
			attachments = append(attachments, dmarcHTMLAttachment{
				name:   htmlAttachmentName(filename, report.Metadata.ReportID),
				body:   htmlBody,
				report: report,
			})
		}
		return nil
	}

	contentType := parsed.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}
	_, contentTypeParams, _ := mime.ParseMediaType(contentType)
	_, dispositionParams, _ := mime.ParseMediaType(parsed.Header.Get("Content-Disposition"))
	topFilename := dispositionParams["filename"]
	if topFilename == "" {
		topFilename = contentTypeParams["name"]
	}
	if err := scan(contentType, parsed.Header.Get("Content-Transfer-Encoding"), topFilename, body, 0); err != nil {
		p.logger.Warn("DMARC message MIME scan failed", "error", err)
		return Result{Decision: Accept}, nil
	}
	if len(attachments) == 0 {
		return Result{Decision: Accept}, nil
	}

	newBody := body
	newHeader := top
	mediaType, params, _ := mime.ParseMediaType(contentType)
	if strings.EqualFold(mediaType, "multipart/mixed") && isIdentityTransferEncoding(parsed.Header.Get("Content-Transfer-Encoding")) {
		boundary := params["boundary"]
		if boundary == "" {
			p.logger.Warn("DMARC message cannot be updated", "error", "multipart/mixed has no boundary")
			return Result{Decision: Accept}, nil
		}
		newBody, err = appendMultipartAttachments(body, boundary, attachments, lineEnding)
		if err != nil {
			p.logger.Warn("DMARC message cannot be updated", "error", err)
			return Result{Decision: Accept}, nil
		}
	} else {
		newBody, newHeader, err = wrapMessageAsMixed(top, body, separator, contentType, attachments, lineEnding)
		if err != nil {
			p.logger.Warn("DMARC message cannot be updated", "error", err)
			return Result{Decision: Accept}, nil
		}
		separator = []byte(lineEnding + lineEnding)
	}
	newHeader = appendHeader(newHeader, []byte(dmarcReportMarkerHeader+": summarized"), lineEnding)
	message.Data = make([]byte, 0, len(newHeader)+len(separator)+len(newBody))
	message.Data = append(message.Data, newHeader...)
	message.Data = append(message.Data, separator...)
	message.Data = append(message.Data, newBody...)
	for _, attachment := range attachments {
		p.logger.Info("DMARC report summarized",
			"org", attachment.report.Metadata.OrgName,
			"report_id", attachment.report.Metadata.ReportID,
			"domain", attachment.report.Policy.Domain,
			"records", len(attachment.report.Records),
			"messages", attachment.report.Totals.Messages,
			"filename", attachment.name)
	}
	return Result{Decision: Accept, StopChain: true}, nil
}

func (p *DMARCReportProcessor) warnCandidate(filename string, err error) {
	p.logger.Warn("DMARC report attachment could not be summarized", "filename", filename, "error", err)
}

type dmarcHTMLAttachment struct {
	name   string
	body   []byte
	report dmarcReport
}

type dmarcReport struct {
	Metadata struct {
		OrgName          string `xml:"org_name"`
		Email            string `xml:"email"`
		ExtraContactInfo string `xml:"extra_contact_info"`
		ReportID         string `xml:"report_id"`
		DateRange        struct {
			Begin int64 `xml:"begin"`
			End   int64 `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	Policy struct {
		Domain string `xml:"domain"`
		ADKIM  string `xml:"adkim"`
		ASPF   string `xml:"aspf"`
		Policy string `xml:"p"`
		SP     string `xml:"sp"`
		Pct    string `xml:"pct"`
		NP     string `xml:"np"`
		FO     string `xml:"fo"`
	} `xml:"policy_published"`
	Records []dmarcRecord `xml:"record"`
	XMLName xml.Name      `xml:"feedback"`
	Totals  dmarcTotals
}

type dmarcRecord struct {
	Row struct {
		SourceIP string `xml:"source_ip"`
		Count    int64  `xml:"count"`
		Policy   struct {
			Disposition string `xml:"disposition"`
			DKIM        string `xml:"dkim"`
			SPF         string `xml:"spf"`
			Reasons     []struct {
				Type    string `xml:"type"`
				Comment string `xml:"comment"`
			} `xml:"reason"`
		} `xml:"policy_evaluated"`
	} `xml:"row"`
	Identifiers struct {
		HeaderFrom   string `xml:"header_from"`
		EnvelopeFrom string `xml:"envelope_from"`
		EnvelopeTo   string `xml:"envelope_to"`
	} `xml:"identifiers"`
	AuthResults struct {
		DKIM []struct {
			Domain       string `xml:"domain"`
			Selector     string `xml:"selector"`
			Result       string `xml:"result"`
			HumanResults string `xml:"human_result"`
		} `xml:"dkim"`
		SPF []struct {
			Domain string `xml:"domain"`
			Scope  string `xml:"scope"`
			Result string `xml:"result"`
		} `xml:"spf"`
	} `xml:"auth_results"`
}

type dmarcTotals struct {
	Messages int64
	Pass     int64
	Fail     int64
}

func isDMARCCandidate(mediaType, filename string) bool {
	switch strings.ToLower(mediaType) {
	case "application/gzip", "application/x-gzip", "application/zip", "application/x-zip", "application/x-zip-compressed", "application/xml", "text/xml":
		return true
	case "application/octet-stream":
		lower := strings.ToLower(filename)
		return strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, ".xml.gz") || strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".zip")
	default:
		return false
	}
}

func decodeMIMETransfer(data []byte, encoding string, limit int64) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(data)
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
	case "base64":
		reader = base64.NewDecoder(base64.StdEncoding, reader)
	case "quoted-printable":
		reader = quotedPrintableReader(reader)
	default:
		return nil, fmt.Errorf("unsupported content-transfer-encoding %q", encoding)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(decoded)) > limit {
		return nil, fmt.Errorf("decoded MIME part exceeds %d bytes", limit)
	}
	return decoded, nil
}

func isIdentityTransferEncoding(encoding string) bool {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "7bit", "8bit", "binary":
		return true
	default:
		return false
	}
}

func quotedPrintableReader(reader io.Reader) io.Reader {
	return quotedprintable.NewReader(reader)
}

func decodeDMARCReports(data []byte, mediaType, filename string, maxSize int64) ([]dmarcReport, error) {
	lower := strings.ToLower(filename)
	if strings.Contains(mediaType, "gzip") || strings.HasSuffix(lower, ".gz") {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("open gzip report: %w", err)
		}
		decompressed, readErr := io.ReadAll(io.LimitReader(reader, maxSize+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("decompress gzip report: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close gzip report: %w", closeErr)
		}
		if int64(len(decompressed)) > maxSize {
			return nil, fmt.Errorf("decompressed report exceeds %d bytes", maxSize)
		}
		report, err := parseDMARCXML(decompressed)
		if err != nil {
			return nil, err
		}
		return []dmarcReport{report}, nil
	}
	if strings.Contains(mediaType, "zip") || strings.HasSuffix(lower, ".zip") {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("open ZIP report: %w", err)
		}
		if len(archive.File) > dmarcMaxZipEntries {
			return nil, fmt.Errorf("ZIP report contains more than %d entries", dmarcMaxZipEntries)
		}
		var reports []dmarcReport
		foundXML := false
		var totalXMLSize int64
		for _, file := range archive.File {
			if file.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(file.Name), ".xml") {
				continue
			}
			foundXML = true
			entry, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("open XML in ZIP report: %w", err)
			}
			remaining := maxSize - totalXMLSize
			xmlData, readErr := io.ReadAll(io.LimitReader(entry, remaining+1))
			closeErr := entry.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read XML in ZIP report: %w", readErr)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("close XML in ZIP report: %w", closeErr)
			}
			if int64(len(xmlData)) > remaining {
				return nil, fmt.Errorf("XML in ZIP report exceeds total limit of %d bytes", maxSize)
			}
			totalXMLSize += int64(len(xmlData))
			report, err := parseDMARCXML(xmlData)
			if err != nil {
				return nil, err
			}
			reports = append(reports, report)
		}
		if !foundXML {
			return nil, errors.New("ZIP report contains no XML entries")
		}
		return reports, nil
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("XML report exceeds %d bytes", maxSize)
	}
	report, err := parseDMARCXML(data)
	if err != nil {
		return nil, err
	}
	return []dmarcReport{report}, nil
}

func parseDMARCXML(data []byte) (dmarcReport, error) {
	var report dmarcReport
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = dmarcCharsetReader
	if err := decoder.Decode(&report); err != nil {
		return dmarcReport{}, fmt.Errorf("parse DMARC XML: %w", err)
	}
	if report.XMLName.Local != "feedback" || report.Metadata.ReportID == "" {
		return dmarcReport{}, errors.New("XML is not a DMARC feedback report")
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return dmarcReport{}, fmt.Errorf("parse trailing DMARC XML: %w", err)
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return dmarcReport{}, errors.New("unexpected text after DMARC feedback report")
			}
		case xml.Comment, xml.ProcInst:
		default:
			return dmarcReport{}, errors.New("unexpected XML content after DMARC feedback report")
		}
	}
	for _, record := range report.Records {
		count := record.Row.Count
		if count < 0 || report.Totals.Messages > dmarcMaxInt64-count {
			return dmarcReport{}, errors.New("invalid or overflowing DMARC record count")
		}
		report.Totals.Messages += count
		if strings.EqualFold(record.Row.Policy.DKIM, "pass") || strings.EqualFold(record.Row.Policy.SPF, "pass") {
			report.Totals.Pass += count
		} else {
			report.Totals.Fail += count
		}
	}
	return report, nil
}

func dmarcCharsetReader(charset string, input io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(strings.TrimSpace(charset)) {
	case "utf-8", "utf8", "us-ascii", "ascii":
		return bytes.NewReader(data), nil
	case "iso-8859-1", "latin1", "latin-1":
		var decoded strings.Builder
		decoded.Grow(len(data) * 2)
		for _, value := range data {
			decoded.WriteRune(rune(value))
		}
		return strings.NewReader(decoded.String()), nil
	default:
		return nil, fmt.Errorf("unsupported XML charset %q", charset)
	}
}

var dmarcHTMLTemplate = template.Must(template.New("dmarc-report").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>DMARC report {{.Metadata.ReportID}}</title>
<style>body{font-family:sans-serif;color:#222}table{border-collapse:collapse;width:100%;margin:1em 0}th,td{border:1px solid #bbb;padding:.4em;text-align:left;vertical-align:top}th{background:#eee}.pass{background:#e5f5e5}.fail{background:#fde8e8}h1,h2{margin-bottom:.3em}</style></head>
<body><h1>DMARC aggregate report</h1><table><tbody>
<tr><th>Organization</th><td>{{.Metadata.OrgName}}</td><th>Contact</th><td>{{.Metadata.Email}}</td></tr>
<tr><th>Extra contact</th><td>{{.Metadata.ExtraContactInfo}}</td><th>Report ID</th><td>{{.Metadata.ReportID}}</td></tr>
<tr><th>Period (UTC)</th><td>{{.BeginUTC}} – {{.EndUTC}}</td><th>Domain</th><td>{{.Policy.Domain}}</td></tr>
<tr><th>Published policy</th><td colspan="3">p={{.Policy.Policy}}; sp={{.Policy.SP}}; adkim={{.Policy.ADKIM}}; aspf={{.Policy.ASPF}}; pct={{.Policy.Pct}}; np={{.Policy.NP}}; fo={{.Policy.FO}}</td></tr>
</tbody></table><h2>Summary</h2><p>{{.Totals.Messages}} messages; {{.Totals.Pass}} DMARC pass; {{.Totals.Fail}} DMARC fail.</p>
<h2>Records</h2><table><thead><tr><th>Source IP</th><th>Count</th><th>Disposition</th><th>DKIM / SPF evaluated</th><th>Header from</th><th>Envelope from / to</th><th>Authentication results</th><th>Override reasons</th></tr></thead><tbody>
{{range .Records}}<tr class="{{if or (eq .Row.Policy.DKIM "pass") (eq .Row.Policy.SPF "pass")}}pass{{else}}fail{{end}}"><td>{{.Row.SourceIP}}</td><td>{{.Row.Count}}</td><td>{{.Row.Policy.Disposition}}</td><td>DKIM: {{.Row.Policy.DKIM}}<br>SPF: {{.Row.Policy.SPF}}</td><td>{{.Identifiers.HeaderFrom}}</td><td>{{.Identifiers.EnvelopeFrom}}<br>{{.Identifiers.EnvelopeTo}}</td><td>{{range .AuthResults.DKIM}}DKIM {{.Domain}} ({{.Selector}}): {{.Result}}{{if .HumanResults}} — {{.HumanResults}}{{end}}<br>{{end}}{{range .AuthResults.SPF}}SPF {{.Domain}} ({{.Scope}}): {{.Result}}<br>{{end}}</td><td>{{range .Row.Policy.Reasons}}{{.Type}}{{if .Comment}}: {{.Comment}}{{end}}<br>{{end}}</td></tr>{{end}}
</tbody></table></body></html>`))

func renderDMARCReport(report dmarcReport) ([]byte, error) {
	view := struct {
		dmarcReport
		BeginUTC string
		EndUTC   string
	}{dmarcReport: report}
	if report.Metadata.DateRange.Begin != 0 {
		view.BeginUTC = time.Unix(report.Metadata.DateRange.Begin, 0).UTC().Format(time.RFC3339)
	}
	if report.Metadata.DateRange.End != 0 {
		view.EndUTC = time.Unix(report.Metadata.DateRange.End, 0).UTC().Format(time.RFC3339)
	}
	var output bytes.Buffer
	if err := dmarcHTMLTemplate.Execute(&output, view); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func htmlAttachmentName(original, reportID string) string {
	name := filepath.Base(strings.TrimSpace(original))
	lower := strings.ToLower(name)
	for _, suffix := range []string{".xml.gz", ".xml.zip", ".gz", ".zip", ".xml"} {
		if strings.HasSuffix(lower, suffix) {
			name = name[:len(name)-len(suffix)]
			break
		}
	}
	if name == "" || name == "." {
		name = "dmarc-report-" + reportID
	}
	name = strings.Map(func(r rune) rune {
		if r < 32 || strings.ContainsRune(`/\\:*?"<>|`, r) {
			return '-'
		}
		return r
	}, name)
	return name + ".html"
}

func splitRawMessage(data []byte) (header, body, separator []byte, ok bool) {
	if index := bytes.Index(data, []byte("\r\n\r\n")); index >= 0 {
		return data[:index], data[index+4:], []byte("\r\n\r\n"), true
	}
	if index := bytes.Index(data, []byte("\n\n")); index >= 0 {
		return data[:index], data[index+2:], []byte("\n\n"), true
	}
	return nil, nil, nil, false
}

func detectLineEnding(data []byte) string {
	if bytes.Contains(data, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

func appendHeader(header, line []byte, lineEnding string) []byte {
	result := append([]byte(nil), header...)
	result = append(result, []byte(lineEnding)...)
	result = append(result, line...)
	return result
}

func appendMultipartAttachments(body []byte, boundary string, attachments []dmarcHTMLAttachment, lineEnding string) ([]byte, error) {
	closing, err := findClosingBoundary(body, boundary)
	if err != nil {
		return nil, err
	}
	parts := serializeHTMLParts(boundary, attachments, detectBoundaryLineEnding(body, boundary, lineEnding))
	result := make([]byte, 0, len(body)+len(parts))
	result = append(result, body[:closing]...)
	result = append(result, parts...)
	result = append(result, body[closing:]...)
	return result, nil
}

func detectBoundaryLineEnding(body []byte, boundary, fallback string) string {
	marker := []byte("--" + boundary)
	for offset := 0; offset < len(body); {
		end := bytes.IndexByte(body[offset:], '\n')
		if end < 0 {
			break
		}
		lineEnd := offset + end
		line := bytes.TrimSuffix(body[offset:lineEnd], []byte("\r"))
		if bytes.Equal(line, marker) || bytes.Equal(line, append(append([]byte(nil), marker...), '-', '-')) {
			if lineEnd > offset && body[lineEnd-1] == '\r' {
				return "\r\n"
			}
			return "\n"
		}
		offset = lineEnd + 1
	}
	return fallback
}

func findClosingBoundary(body []byte, boundary string) (int, error) {
	marker := []byte("--" + boundary + "--")
	for offset := 0; offset < len(body); {
		end := bytes.IndexByte(body[offset:], '\n')
		lineEnd := len(body)
		if end >= 0 {
			lineEnd = offset + end
		}
		line := bytes.TrimSuffix(body[offset:lineEnd], []byte("\r"))
		if bytes.Equal(line, marker) {
			return offset, nil
		}
		if end < 0 {
			break
		}
		offset = lineEnd + 1
	}
	return 0, errors.New("closing MIME boundary not found")
}

func serializeHTMLParts(boundary string, attachments []dmarcHTMLAttachment, lineEnding string) []byte {
	var output bytes.Buffer
	for _, attachment := range attachments {
		_, _ = fmt.Fprintf(&output, "--%s%s", boundary, lineEnding)
		_, _ = fmt.Fprintf(&output, "Content-Type: text/html; charset=utf-8%s", lineEnding)
		disposition := mime.FormatMediaType("attachment", map[string]string{"filename": attachment.name})
		_, _ = fmt.Fprintf(&output, "Content-Disposition: %s%s", disposition, lineEnding)
		_, _ = fmt.Fprintf(&output, "Content-Transfer-Encoding: base64%s%s", lineEnding, lineEnding)
		writeBase64Lines(&output, attachment.body, lineEnding)
		output.WriteString(lineEnding)
	}
	return output.Bytes()
}

func writeBase64Lines(output *bytes.Buffer, data []byte, lineEnding string) {
	encoded := base64.StdEncoding.EncodeToString(data)
	for len(encoded) > 76 {
		output.WriteString(encoded[:76])
		output.WriteString(lineEnding)
		encoded = encoded[76:]
	}
	if encoded != "" {
		output.WriteString(encoded)
		output.WriteString(lineEnding)
	}
}

func wrapMessageAsMixed(header, body, separator []byte, originalContentType string, attachments []dmarcHTMLAttachment, lineEnding string) ([]byte, []byte, error) {
	boundaryBytes := make([]byte, 24)
	if _, err := rand.Read(boundaryBytes); err != nil {
		return nil, nil, fmt.Errorf("create MIME boundary: %w", err)
	}
	boundary := "mymail-dmarc-" + hex.EncodeToString(boundaryBytes)
	for bytes.Contains(body, []byte("--"+boundary)) {
		if _, err := rand.Read(boundaryBytes); err != nil {
			return nil, nil, fmt.Errorf("create MIME boundary: %w", err)
		}
		boundary = "mymail-dmarc-" + hex.EncodeToString(boundaryBytes)
	}
	contentHeaders, otherHeaders := partitionContentHeaders(header)
	if len(contentHeaders) == 0 {
		contentHeaders = []byte("Content-Type: " + originalContentType)
	}
	newHeader := append([]byte(nil), bytes.TrimRight(otherHeaders, "\r\n")...)
	if !headerHasField(otherHeaders, "MIME-Version") {
		if len(newHeader) > 0 {
			newHeader = append(newHeader, []byte(lineEnding)...)
		}
		newHeader = append(newHeader, []byte("MIME-Version: 1.0")...)
	}
	if len(newHeader) > 0 {
		newHeader = append(newHeader, []byte(lineEnding)...)
	}
	newHeader = append(newHeader, []byte("Content-Type: multipart/mixed; boundary=\""+boundary+"\"")...)

	var newBody bytes.Buffer
	newBody.WriteString("--" + boundary + lineEnding)
	newBody.Write(contentHeaders)
	if !bytes.HasSuffix(contentHeaders, []byte("\n")) {
		newBody.WriteString(lineEnding)
	}
	newBody.WriteString(lineEnding)
	newBody.Write(body)
	if !bytes.HasSuffix(body, []byte("\n")) {
		newBody.WriteString(lineEnding)
	}
	newBody.Write(serializeHTMLParts(boundary, attachments, lineEnding))
	newBody.WriteString("--" + boundary + "--" + lineEnding)
	_ = separator
	return newBody.Bytes(), newHeader, nil
}

func partitionContentHeaders(header []byte) (content, other []byte) {
	lines := bytes.SplitAfter(header, []byte("\n"))
	var current [][]byte
	isContent := false
	flush := func() {
		if len(current) == 0 {
			return
		}
		destination := &other
		if isContent {
			destination = &content
		}
		for _, line := range current {
			*destination = append(*destination, line...)
		}
		current = nil
	}
	for _, line := range lines {
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == ' ' || trimmed[0] == '\t' {
			current = append(current, line)
			continue
		}
		flush()
		colon := bytes.IndexByte(trimmed, ':')
		isContent = colon > 0 && strings.HasPrefix(strings.ToLower(string(trimmed[:colon])), "content-")
		current = append(current, line)
	}
	flush()
	return content, other
}

func headerHasField(header []byte, wanted string) bool {
	for _, line := range bytes.Split(header, []byte("\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon > 0 && strings.EqualFold(string(bytes.TrimSpace(line[:colon])), wanted) {
			return true
		}
	}
	return false
}

var _ Processor = (*DMARCReportProcessor)(nil)
