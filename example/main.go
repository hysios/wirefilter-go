package main

import (
	"fmt"
	"log"

	"github.com/hysios/wirefilter"
)

func main() {
	// https://developers.cloudflare.com/firewall/cf-firewall-language/operators
	log.Print("wirefilter version: ", wirefilter.Version())

	schema := wirefilter.NewSchema()
	defer schema.Close()

	schema.AddFields(map[string]wirefilter.Type{
		"http.request.method": wirefilter.TYPE_BYTES,
		"http.user_agent":     wirefilter.TYPE_BYTES,
		"ip.src":              wirefilter.TYPE_IP,
		"ip.geoip.asnum":      wirefilter.TYPE_INT,
	})

	ctx := wirefilter.NewExecutionContext(schema)
	defer ctx.Close()

	ctx.SetFieldValue("http.request.method", "GET")
	ctx.SetFieldValue("http.user_agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36")
	//ctx.SetFieldValue("ip.src", net.ParseIP("1.1.1.1"))
	ctx.SetFieldValue("ip.geoip.asnum", 13335)

	rules := []string{
		`http.request.method eq "GET"`,
		`http.request.method eq "GET" and http.user_agent contains "Macintosh"`,
		`http.request.method eq "GET" and http.user_agent not contains "Macintosh"`,
		`http.request.method eq "GET" and not (http.user_agent contains "Macintosh")`,
		`ip.geoip.asnum in {888 9910, 299}`,
		`ip.geoip.asnum in {888 9910, 13335} and http.user_agent contains "Macintosh"`,
	}

	for _, rule := range rules {
		ast, err := schema.Parse(rule)

		if err != nil {
			fmt.Print(rule)
			fmt.Print(err)
			continue
		}

		filter := ast.Compile()

		fmt.Print(rule)
		fmt.Print(" => ")
		fmt.Print(filter.Execute(ctx))
		fmt.Print("\n")
	}
}
