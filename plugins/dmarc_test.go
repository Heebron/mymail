package plugins

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDMARCProcessorSummarizesSampleReports(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "dmarc-reports.mbox"))
	if err != nil {
		t.Fatal(err)
	}
	messages := splitTestMbox(data)
	if len(messages) != 7 {
		t.Fatalf("sample message count = %d, want 7", len(messages))
	}

	processor := NewDMARCReportProcessor(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := processor.Initialize(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	for index, original := range messages {
		t.Run(strconv.Itoa(index+1), func(t *testing.T) {
			inputFilename, mediaType, originalAttachment := findDMARCAttachment(t, original)
			expectedReports, err := decodeDMARCReports(originalAttachment, mediaType, inputFilename, dmarcDefaultReportLimit)
			if err != nil {
				t.Fatalf("decode sample report: %v", err)
			}
			message := &Message{Data: append([]byte(nil), original...)}
			originalPartCount := countTestMIMEParts(t, original)
			result, err := processor.Process(context.Background(), message)
			if err != nil || result.Decision != Accept || !result.StopChain {
				t.Fatalf("Process() = (%+v, %v), want accepted StopChain and nil", result, err)
			}
			if !bytes.Contains(message.Data, []byte(dmarcReportMarkerHeader+": summarized")) {
				t.Fatal("processed message lacks DMARC marker header")
			}
			parts := parseTestParts(t, message.Data)
			if len(parts) != originalPartCount+len(expectedReports) {
				t.Fatalf("output MIME part count = %d, want original parts plus %d HTML attachment(s)", len(parts), len(expectedReports))
			}
			var originalFound bool
			var htmlParts [][]byte
			var htmlNames []string
			for _, part := range parts {
				if strings.EqualFold(filepath.Ext(part.filename), ".html") {
					htmlParts = append(htmlParts, part.body)
					htmlNames = append(htmlNames, part.filename)
				}
				if part.filename == inputFilename {
					originalFound = true
					if !bytes.Equal(part.body, originalAttachment) {
						t.Fatal("original report attachment bytes changed")
					}
				}
			}
			if !originalFound {
				t.Fatalf("original report attachment %q not found in output", inputFilename)
			}
			if len(htmlParts) != len(expectedReports) {
				t.Fatalf("HTML attachment count = %d, want %d", len(htmlParts), len(expectedReports))
			}
			for reportIndex, report := range expectedReports {
				wantName := htmlAttachmentName(inputFilename, report.Metadata.ReportID)
				if htmlNames[reportIndex] != wantName {
					t.Errorf("HTML attachment filename = %q, want %q", htmlNames[reportIndex], wantName)
				}
				html := string(htmlParts[reportIndex])
				for _, value := range []string{report.Metadata.ReportID, report.Policy.Domain, report.Metadata.OrgName} {
					if value != "" && !strings.Contains(html, value) {
						t.Errorf("HTML attachment does not contain %q", value)
					}
				}
				for _, record := range report.Records {
					for _, value := range []string{record.Row.SourceIP, strconv.FormatInt(record.Row.Count, 10)} {
						if value != "" && !strings.Contains(html, value) {
							t.Errorf("HTML attachment does not contain record value %q", value)
						}
					}
				}
				if !strings.Contains(html, strconv.FormatInt(report.Totals.Messages, 10)+" messages") ||
					!strings.Contains(html, strconv.FormatInt(report.Totals.Pass, 10)+" DMARC pass") ||
					!strings.Contains(html, strconv.FormatInt(report.Totals.Fail, 10)+" DMARC fail") {
					t.Errorf("HTML attachment does not contain expected pass/fail totals: %d/%d/%d", report.Totals.Messages, report.Totals.Pass, report.Totals.Fail)
				}
				if report.Metadata.OrgName == "google.com" && (len(report.Records) != 2 || report.Totals.Pass != 1 || report.Totals.Fail != 1) {
					t.Errorf("Google sample summary = %d records, %d pass, %d fail; want 2, 1, 1", len(report.Records), report.Totals.Pass, report.Totals.Fail)
				}
				if strings.Contains(report.Metadata.ReportID, "260632") && (len(report.Records) != 2 || report.Totals.Pass != 0 || report.Totals.Fail != 2) {
					t.Errorf("Yahoo 260632 summary = %d records, %d pass, %d fail; want 2, 0, 2", len(report.Records), report.Totals.Pass, report.Totals.Fail)
				}
			}
		})
	}
}

func TestDMARCProcessorLeavesUnrelatedOrInvalidMessagesUnchanged(t *testing.T) {
	badZip := makeTestZip(t, "notes.txt", []byte("not a DMARC XML report"))
	badGzip := []byte("not a gzip stream")
	tests := []struct {
		name    string
		message []byte
	}{
		{name: "non DMARC", message: makeTestMessage("text/plain", "", "", []byte("hello world"), "\r\n")},
		{name: "zip without feedback", message: makeTestMessage("application/zip", "archive.zip", "base64", badZip, "\r\n")},
		{name: "corrupt gzip", message: makeTestMessage("application/gzip", "report.xml.gz", "base64", badGzip, "\r\n")},
		{name: "trailing XML", message: makeTestMessage("application/xml", "report.xml", "", append(validDMARCXML("Example Org", "trailing", "192.0.2.1", 1, "pass", "pass"), []byte("<unexpected/>")...), "\r\n")},
	}
	processor := NewDMARCReportProcessor(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message := &Message{Data: append([]byte(nil), test.message...)}
			result, err := processor.Process(context.Background(), message)
			if err != nil || result.Decision != Accept || result.StopChain {
				t.Fatalf("Process() = (%+v, %v), want Accept without StopChain and nil", result, err)
			}
			if !bytes.Equal(message.Data, test.message) {
				t.Fatal("message changed despite there being no valid DMARC report")
			}
		})
	}
}

func TestDMARCProcessorHandlesPlainAndMultipleXMLReports(t *testing.T) {
	firstXML := validDMARCXML("Example Org", "plain-report", "192.0.2.1", 1, "pass", "pass")
	plainMessage := &Message{Data: makeTestMessage("application/xml", "plain.xml", "", firstXML, "\r\n")}
	if _, err := NewDMARCReportProcessor(nil).Process(context.Background(), plainMessage); err != nil {
		t.Fatal(err)
	}
	plainParts := parseTestParts(t, plainMessage.Data)
	if len(plainParts) != 2 || !bytes.Equal(plainParts[0].body, firstXML) || !strings.Contains(string(plainParts[1].body), "plain-report") {
		t.Fatalf("plain XML result has %d parts or changed its original report", len(plainParts))
	}

	secondXML := validDMARCXML("Another Org", "second-report", "198.51.100.2", 2, "fail", "fail")
	archive := makeTestZipFiles(t, []struct {
		name string
		data []byte
	}{{name: "first.xml", data: firstXML}, {name: "second.xml", data: secondXML}})
	zipOriginal := makeTestMessage("application/zip", "reports.zip", "base64", archive, "\r\n")
	zipMessage := &Message{Data: append([]byte(nil), zipOriginal...)}
	if _, err := NewDMARCReportProcessor(nil).Process(context.Background(), zipMessage); err != nil {
		t.Fatal(err)
	}
	zipParts := parseTestParts(t, zipMessage.Data)
	if len(zipParts) != 3 || !bytes.Equal(zipParts[0].body, archive) {
		t.Fatalf("multiple-report ZIP result has %d parts or changed its original archive", len(zipParts))
	}
	firstReport := strings.Contains(string(zipParts[1].body), "plain-report") || strings.Contains(string(zipParts[2].body), "plain-report")
	secondReport := strings.Contains(string(zipParts[1].body), "second-report") || strings.Contains(string(zipParts[2].body), "second-report")
	if !firstReport || !secondReport {
		t.Fatal("ZIP XML entries did not each produce a report attachment")
	}
	limited := NewDMARCReportProcessor(nil)
	if err := limited.Initialize(context.Background(), map[string]string{"max_report_size": strconv.Itoa(len(firstXML) + 1)}); err != nil {
		t.Fatal(err)
	}
	limitedMessage := &Message{Data: append([]byte(nil), zipOriginal...)}
	if _, err := limited.Process(context.Background(), limitedMessage); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(limitedMessage.Data, zipOriginal) {
		t.Fatal("ZIP report exceeding the combined XML limit was not left unchanged")
	}
}

func TestDMARCProcessorSkipsMarkedMessages(t *testing.T) {
	original := makeTestMessage("application/gzip", "report.xml.gz", "base64", []byte("invalid gzip"), "\r\n")
	original = bytes.Replace(original, []byte("\r\n\r\n"), []byte("\r\n"+dmarcReportMarkerHeader+": already\r\n\r\n"), 1)
	message := &Message{Data: append([]byte(nil), original...)}
	processor := NewDMARCReportProcessor(nil)
	result, err := processor.Process(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.StopChain {
		t.Fatal("already-marked message requested that the chain stop")
	}
	if !bytes.Equal(message.Data, original) {
		t.Fatal("marked message was changed")
	}
}

func TestDMARCProcessorEscapesHTMLAndEnforcesReportSize(t *testing.T) {
	xmlData := validDMARCXML("&lt;script&gt;alert(1)&lt;/script&gt;", "xss-report", "198.51.100.10", 1, "pass", "fail")
	compressed := makeTestGzip(t, xmlData)
	messageData := makeTestMessage("application/gzip", "xss.xml.gz", "base64", compressed, "\r\n")
	processor := NewDMARCReportProcessor(nil)
	message := &Message{Data: append([]byte(nil), messageData...)}
	if _, err := processor.Process(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	parts := parseTestParts(t, message.Data)
	var html string
	for _, part := range parts {
		if strings.HasSuffix(part.filename, ".html") {
			html = string(part.body)
		}
	}
	if html == "" {
		t.Fatal("HTML report attachment was not added")
	}
	if strings.Contains(html, "<script>alert(1)</script>") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatalf("untrusted report value was not escaped: %s", html)
	}

	overLimit := NewDMARCReportProcessor(nil)
	if err := overLimit.Initialize(context.Background(), map[string]string{"max_report_size": "40"}); err != nil {
		t.Fatal(err)
	}
	oversized := &Message{Data: append([]byte(nil), messageData...)}
	if _, err := overLimit.Process(context.Background(), oversized); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oversized.Data, messageData) {
		t.Fatal("oversized decompressed report was not left unchanged")
	}
}

func TestDMARCProcessorUsesCRLFForInsertedContent(t *testing.T) {
	compressed := makeTestGzip(t, validDMARCXML("Example Org", "crlf-report", "203.0.113.8", 1, "pass", "pass"))
	original := makeTestMessage("application/gzip", "crlf.xml.gz", "base64", compressed, "\r\n")
	message := &Message{Data: append([]byte(nil), original...)}
	if _, err := NewDMARCReportProcessor(nil).Process(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message.Data, []byte("Content-Type: text/html; charset=utf-8\r\n")) {
		t.Fatal("inserted MIME headers do not use CRLF")
	}
}

func TestDMARCProcessorInitializeRejectsInvalidLimits(t *testing.T) {
	for key, value := range map[string]string{
		"max_report_size":  "0",
		"max_message_size": "not-a-number",
	} {
		t.Run(key, func(t *testing.T) {
			if err := NewDMARCReportProcessor(nil).Initialize(context.Background(), map[string]string{key: value}); err == nil {
				t.Fatalf("Initialize accepted %s=%q", key, value)
			}
		})
	}
}

type testMIMEPart struct {
	filename string
	body     []byte
}

func splitTestMbox(data []byte) [][]byte {
	var messages [][]byte
	var current bytes.Buffer
	for len(data) > 0 {
		lineEnd := bytes.IndexByte(data, '\n')
		if lineEnd < 0 {
			lineEnd = len(data)
		}
		line := data[:lineEnd]
		if strings.HasPrefix(string(line), "From ") {
			if current.Len() > 0 {
				messages = append(messages, bytes.Clone(bytes.TrimSpace(current.Bytes())))
				current.Reset()
			}
		} else {
			current.Write(data[:min(lineEnd+1, len(data))])
		}
		if lineEnd == len(data) {
			break
		}
		data = data[lineEnd+1:]
	}
	if current.Len() > 0 {
		messages = append(messages, bytes.Clone(bytes.TrimSpace(current.Bytes())))
	}
	return messages
}

func findDMARCAttachment(t *testing.T, data []byte) (string, string, []byte) {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		reader := multipart.NewReader(message.Body, params["boundary"])
		for {
			part, err := reader.NextRawPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			filename, partType, body, ok := readReportPart(t, part.Header, part)
			if ok {
				return filename, partType, body
			}
		}
	} else {
		filename := ""
		_, disposition, _ := mime.ParseMediaType(message.Header.Get("Content-Disposition"))
		filename = disposition["filename"]
		if filename == "" {
			filename = params["name"]
		}
		body, err := io.ReadAll(message.Body)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeMIMETransfer(body, message.Header.Get("Content-Transfer-Encoding"), dmarcDefaultMessageLimit)
		if err != nil {
			t.Fatal(err)
		}
		return filename, mediaType, decoded
	}
	t.Fatal("no gzip or ZIP DMARC attachment found")
	return "", "", nil
}

func readReportPart(t *testing.T, header textproto.MIMEHeader, reader io.Reader) (string, string, []byte, bool) {
	t.Helper()
	mediaType, typeParams, _ := mime.ParseMediaType(header.Get("Content-Type"))
	_, disposition, _ := mime.ParseMediaType(header.Get("Content-Disposition"))
	filename := disposition["filename"]
	if filename == "" {
		filename = typeParams["name"]
	}
	if !isDMARCCandidate(strings.ToLower(mediaType), filename) {
		return "", "", nil, false
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeMIMETransfer(body, header.Get("Content-Transfer-Encoding"), dmarcDefaultMessageLimit)
	if err != nil {
		t.Fatal(err)
	}
	return filename, mediaType, decoded, true
}

func countTestMIMEParts(t *testing.T, data []byte) int {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return 1
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	count := 0
	for {
		_, err := reader.NextRawPart()
		if err == io.EOF {
			return count
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
}

func parseTestParts(t *testing.T, data []byte) []testMIMEPart {
	t.Helper()
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		t.Fatalf("output media type = %q, want multipart", mediaType)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var parts []testMIMEPart
	for {
		part, err := reader.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read output MIME part: %v", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		body, err = decodeMIMETransfer(body, part.Header.Get("Content-Transfer-Encoding"), dmarcDefaultMessageLimit)
		if err != nil {
			t.Fatal(err)
		}
		_, disposition, _ := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		parts = append(parts, testMIMEPart{filename: disposition["filename"], body: body})
	}
	return parts
}

func makeTestMessage(mediaType, filename, transferEncoding string, payload []byte, newline string) []byte {
	var output bytes.Buffer
	output.WriteString("From: reports@example.test" + newline)
	output.WriteString("Subject: DMARC test" + newline)
	output.WriteString("MIME-Version: 1.0" + newline)
	if filename != "" {
		output.WriteString("Content-Disposition: attachment; filename=\"" + filename + "\"" + newline)
	}
	if strings.EqualFold(transferEncoding, "base64") {
		output.WriteString("Content-Transfer-Encoding: base64" + newline)
	}
	output.WriteString("Content-Type: " + mime.FormatMediaType(mediaType, map[string]string{"name": filename}) + newline + newline)
	if strings.EqualFold(transferEncoding, "base64") {
		encoded := base64.StdEncoding.EncodeToString(payload)
		for len(encoded) > 76 {
			output.WriteString(encoded[:76] + newline)
			encoded = encoded[76:]
		}
		output.WriteString(encoded + newline)
	} else {
		output.Write(payload)
	}
	return output.Bytes()
}

func makeTestGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeTestZip(t *testing.T, filename string, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	entry, err := writer.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeTestZipFiles(t *testing.T, files []struct {
	name string
	data []byte
}) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, file := range files {
		entry, err := writer.Create(file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func validDMARCXML(org, reportID, sourceIP string, count int, dkim, spf string) []byte {
	return []byte(`<feedback><report_metadata><org_name>` + org + `</org_name><email>reports@example.test</email><report_id>` + reportID + `</report_id><date_range><begin>1794268800</begin><end>1794355199</end></date_range></report_metadata><policy_published><domain>example.test</domain><adkim>r</adkim><aspf>r</aspf><p>reject</p><sp>quarantine</sp><pct>100</pct></policy_published><record><row><source_ip>` + sourceIP + `</source_ip><count>` + strconv.Itoa(count) + `</count><policy_evaluated><disposition>none</disposition><dkim>` + dkim + `</dkim><spf>` + spf + `</spf></policy_evaluated></row><identifiers><header_from>example.test</header_from></identifiers><auth_results><dkim><domain>example.test</domain><selector>mail</selector><result>pass</result></dkim><spf><domain>example.test</domain><scope>mfrom</scope><result>pass</result></spf></auth_results></record></feedback>`)
}
