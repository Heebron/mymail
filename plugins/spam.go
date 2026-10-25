package plugins

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// KeywordSpamFilter is a small example processor that rejects messages
// containing any configured keyword. It is intended as a starting point for
// replacing the keyword check with a real spam-scoring service or library.
//
// The filter is immutable after construction and is safe for concurrent use.
type KeywordSpamFilter struct {
	keywords []string
}

// NewKeywordSpamFilter creates a spam filter for the supplied keywords.
// Empty keywords are ignored.
func NewKeywordSpamFilter(keywords ...string) *KeywordSpamFilter {
	filter := &KeywordSpamFilter{}
	for _, keyword := range keywords {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword != "" {
			filter.keywords = append(filter.keywords, keyword)
		}
	}
	return filter
}

func (f *KeywordSpamFilter) Name() string { return "keyword-spam-filter" }

func (f *KeywordSpamFilter) Initialize(context.Context) error { return nil }

func (f *KeywordSpamFilter) Process(ctx context.Context, message *Message) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if message == nil {
		return Result{}, errors.New("nil message")
	}
	content := strings.ToLower(string(message.Data))
	for _, keyword := range f.keywords {
		if strings.Contains(content, keyword) {
			return Result{
				Decision: Reject,
				Reason:   fmt.Sprintf("spam keyword detected: %s", keyword),
			}, nil
		}
	}
	return Result{Decision: Accept}, nil
}
