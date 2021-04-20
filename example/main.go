package main

import (
	"fmt"
	"log"
	"github.com/hysios/wirefilter"
	"net"
)

func main() {
	// https://developers.cloudflare.com/firewall/cf-firewall-language/operators
	log.Print("wirefilter version: ", wirefilter.Version())

	schema := wirefilter.NewSchema()
	defer schema.Close()

	schema.AddFields(map[string]wirefilter.Type{
		"http.request.method": wirefilter.TYPE_BYTES,
		"http.user_agent":     wirefilter.TYPE_BYTES,
		"ip.src.ipv4":         wirefilter.TYPE_IP,
		"ip.src.ipv6":         wirefilter.TYPE_IP,
		"ip.geoip.asnum":      wirefilter.TYPE_INT,
	})

	ctx := wirefilter.NewExecutionContext(schema)
	defer ctx.Close()

	ctxMap := map[string]interface{}{
		"http.request.method": "GET",
		"http.user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36",
		"ip.src.ipv4": net.ParseIP("1.1.1.1"),
		"ip.src.ipv6": net.ParseIP("2400:cb00:2049:1::a29f:506"),
		"ip.geoip.asnum": 1111,
	}

	fmt.Println("Context:\n========")
	for key, value := range ctxMap {
		fmt.Print(key, ": ", value, "\n")
		ctx.SetFieldValue(key, value)
	}

	fmt.Println("\n\nResult:\n------")
	rules := []string{
		`http.request.method eq "GET"`,
		`http.request.method eq "POST"`,
		`http.user_agent contains "Macintosh"`,
		`http.user_agent contains "MSIE"`,
		`ip.src.ipv4 in {1.1.1.1}`,
		`ip.src.ipv4 in {1.1.1.0/24}`,
		`ip.src.ipv4 eq 1.1.1.1`,
		`ip.src.ipv4 == 1.1.1.1`,
		`ip.geoip.asnum == 1111`,
		`ip.geoip.asnum > 1111`,
		`ip.geoip.asnum > 1110`,
		`ip.geoip.asnum eq 1111`,
		`ip.geoip.asnum eq 1112`,
		`ip.geoip.asnum in {1111}`,
		`ip.geoip.asnum in {1112 1002}`,
		`not (ip.geoip.asnum in {1112 1002})`,
		`ip.src.ipv4 in {1.1.1.0..1.1.1.255}`,
		`ip.src.ipv6 in {2400:cb00::/32}`,
	}

	for _, rule := range rules {
		ast, err := schema.Parse(rule)

		if err != nil {
			fmt.Print(rule, "\n=> ", err, "\n\n")
			continue
		}

		filter := ast.Compile()
		// filter.Close() ?

		fmt.Print(rule, "\n=> ", filter.Execute(ctx), "\n\n")
	}
}