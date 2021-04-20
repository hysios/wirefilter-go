package wirefilter

import (
	"net"
	"testing"
)

func TestIP2IP(t *testing.T) {

	ip := net.ParseIP("1.2.3.4")
	t.Logf("ipov4 %v", IP2IP(ip))

}
