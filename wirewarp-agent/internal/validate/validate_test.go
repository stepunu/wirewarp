package validate

import "testing"

func TestNoControlChars(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"hello", true},
		{"1.2.3.4:51820", true},
		{"line\nPostUp = bad", false},
		{"x\rcr", false},
		{"\x00null", false},
	}
	for _, c := range cases {
		got := NoControlChars(c.in) == nil
		if got != c.want {
			t.Errorf("NoControlChars(%q) ok=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestInterface(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"wg0", true},
		{"wg1", true},
		{"wg-vpn0", true},
		{"wg-vpn12", true},
		{"", false},
		{"wg", false},
		{"wgX", false},
		{"../../etc/passwd", false},
		{"../tmp/x", false},
		{"wg0/x", false},
		{"wg0.conf", false},
		{"wg0 wg1", false},
		{"wg0\nPostUp", false},
		{"-wg0", false},
	}
	for _, c := range cases {
		got := Interface(c.in) == nil
		if got != c.want {
			t.Errorf("Interface(%q) ok=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestPublicIface(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"eth0", true},
		{"ens18", true},
		{"enp0s3", true},
		{"bond0.100", true},
		{"", false},
		{"eth0;rm -rf", false},
		{"eth0 eth1", false},
		{"eth0\nbad", false},
		{"verylonginterfacename", false}, // > 15
	}
	for _, c := range cases {
		got := PublicIface(c.in) == nil
		if got != c.want {
			t.Errorf("PublicIface(%q) ok=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestIPv4(t *testing.T) {
	good := []string{"10.21.0.1", "192.168.1.1", "0.0.0.0", "255.255.255.255"}
	bad := []string{"", "10.21.0.1/24", "::1", "10.21.0.1\nx", "10.21.0.1; rm", "abc"}
	for _, s := range good {
		if err := IPv4(s); err != nil {
			t.Errorf("IPv4(%q) unexpected err %v", s, err)
		}
	}
	for _, s := range bad {
		if err := IPv4(s); err == nil {
			t.Errorf("IPv4(%q) expected err", s)
		}
	}
}

func TestIPv4CIDR(t *testing.T) {
	good := []string{"10.21.0.0/24", "0.0.0.0/0", "192.168.1.0/16"}
	bad := []string{"10.21.0.1", "::/0", "", "10.21.0.0/24\nx"}
	for _, s := range good {
		if err := IPv4CIDR(s); err != nil {
			t.Errorf("IPv4CIDR(%q) unexpected err %v", s, err)
		}
	}
	for _, s := range bad {
		if err := IPv4CIDR(s); err == nil {
			t.Errorf("IPv4CIDR(%q) expected err", s)
		}
	}
}

func TestIPv4OrCIDR(t *testing.T) {
	good := []string{"10.21.0.1", "10.21.0.0/24"}
	bad := []string{"", "::1", "x.y.z.w"}
	for _, s := range good {
		if err := IPv4OrCIDR(s); err != nil {
			t.Errorf("IPv4OrCIDR(%q) unexpected err %v", s, err)
		}
	}
	for _, s := range bad {
		if err := IPv4OrCIDR(s); err == nil {
			t.Errorf("IPv4OrCIDR(%q) expected err", s)
		}
	}
}

func TestEndpoint(t *testing.T) {
	good := []string{"1.2.3.4:51820", "host.example.com:443", "h:1"}
	bad := []string{
		"",
		"1.2.3.4",
		"1.2.3.4:0",
		"1.2.3.4:65536",
		"1.2.3.4:port",
		"1.2.3.4:51820\nPostUp = bad",
		"1.2.3.4:51820\n\n[Interface]\nPostUp = x",
		"bad host:1",
	}
	for _, s := range good {
		if err := Endpoint(s); err != nil {
			t.Errorf("Endpoint(%q) unexpected err %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Endpoint(s); err == nil {
			t.Errorf("Endpoint(%q) expected err", s)
		}
	}
}

func TestWGKey(t *testing.T) {
	// 44-char base64 of a 32-byte key.
	good := "uK1n6gqWXJzKqYqXqYqXqYqXqYqXqYqXqYqXqYqXqQ="
	if err := WGKey(good); err != nil {
		t.Errorf("WGKey good: unexpected err %v", err)
	}
	bad := []string{
		"",
		"short",
		"uK1n6gqWXJzKqYqXqYqXqYqXqYqXqYqXqYqXqYqXqQ", // 43 chars
		"!!!n6gqWXJzKqYqXqYqXqYqXqYqXqYqXqYqXqYqXqQ=",
	}
	for _, s := range bad {
		if err := WGKey(s); err == nil {
			t.Errorf("WGKey(%q) expected err", s)
		}
	}
}

func TestWGKeyOpt(t *testing.T) {
	if err := WGKeyOpt(""); err != nil {
		t.Errorf("WGKeyOpt(\"\") unexpected err %v", err)
	}
	if err := WGKeyOpt("short"); err == nil {
		t.Errorf("WGKeyOpt(short) expected err")
	}
}

func TestPort(t *testing.T) {
	if err := Port(0); err == nil {
		t.Errorf("Port(0) expected err")
	}
	if err := Port(65536); err == nil {
		t.Errorf("Port(65536) expected err")
	}
	if err := Port(51820); err != nil {
		t.Errorf("Port(51820) unexpected err %v", err)
	}
}

func TestPeerName(t *testing.T) {
	if err := PeerName(""); err != nil {
		t.Errorf("PeerName(\"\") unexpected err %v", err)
	}
	if err := PeerName("alice's laptop"); err != nil {
		t.Errorf("PeerName ok unexpected err %v", err)
	}
	if err := PeerName("x\nPostUp = bad"); err == nil {
		t.Errorf("PeerName with newline expected err")
	}
}

func TestControlServerURL(t *testing.T) {
	good := []string{"https://wirewarp.example.com", "https://1.2.3.4:8100"}
	bad := []string{
		"",
		"http://wirewarp.example.com",
		"ws://wirewarp.example.com",
		"wss://wirewarp.example.com",
		"https://",
		"://x",
		"javascript:alert(1)",
	}
	for _, s := range good {
		if err := ControlServerURL(s); err != nil {
			t.Errorf("ControlServerURL(%q) unexpected err %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ControlServerURL(s); err == nil {
			t.Errorf("ControlServerURL(%q) expected err", s)
		}
	}
}
