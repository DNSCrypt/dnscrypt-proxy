package printers

import (
	"context"
	"encoding/xml"
	"fmt"

	"github.com/go-xmlfmt/xmlfmt"

	"github.com/golangci/golangci-lint/pkg/logutils"
	"github.com/golangci/golangci-lint/pkg/result"
)

type checkstyleOutput struct {
	XMLName xml.Name          `xml:"checkstyle"`
	Version string            `xml:"version,attr"`
	Files   []*checkstyleFile `xml:"file"`
}

type checkstyleFile struct {
	Name   string             `xml:"name,attr"`
	Errors []*checkstyleError `xml:"error"`
}

type checkstyleError struct {
	Column   int    `xml:"column,attr"`
	Line     int    `xml:"line,attr"`
	Message  string `xml:"message,attr"`
	Severity string `xml:"severity,attr"`
	Source   string `xml:"source,attr"`
}

const defaultCheckstyleSeverity = "error"

type Checkstyle struct{}

func NewCheckstyle() *Checkstyle {
	return &Checkstyle{}
}

func (Checkstyle) Print(ctx context.Context, issues []result.Issue) error {
	out := checkstyleOutput{
		Version: "5.0",
	}

	files := map[string]*checkstyleFile{}

	for i := range issues {
		issue := &issues[i]
		file, ok := files[issue.FilePath()]
		if !ok {
			file = &checkstyleFile{
				Name: issue.FilePath(),
			}

			files[issue.FilePath()] = file
		}

		severity := defaultCheckstyleSeverity
		if issue.Severity != "" {
			severity = issue.Severity
		}

		newError := &checkstyleError{
			Column:   issue.Column(),
			Line:     issue.Line(),
			Message:  issue.Text,
			Source:   issue.FromLinter,
			Severity: severity,
		}

		file.Errors = append(file.Errors, newError)
	}

	out.Files = make([]*checkstyleFile, 0, len(files))
	for _, file := range files {
		out.Files = append(out.Files, file)
	}

	data, err := xml.Marshal(&out)
	if err != nil {
		return err
	}

	fmt.Fprintf(logutils.StdOut, "%s%s\n", xml.Header, xmlfmt.FormatXML(string(data), "", "  "))
	return nil
}
