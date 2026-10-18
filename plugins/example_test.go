package plugins_test

import (
	"context"
	"fmt"

	"mymail/plugins"
)

func ExampleKeywordSpamFilter() {
	processors := plugins.New()
	if err := processors.Add(plugins.NewKeywordSpamFilter("buy now", "free money")); err != nil {
		panic(err)
	}

	result := processors.Process(context.Background(), &plugins.Message{
		Data:       []byte("Subject: Buy now\r\n\r\nLimited offer"),
		From:       "sender@example.test",
		Recipients: []string{"alice@example.test"},
	})
	fmt.Println(result.Decision == plugins.Reject, result.Reason)
	// Output:
	// true spam keyword detected: buy now
}
