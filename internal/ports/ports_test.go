package ports

import "testing"

func TestParseAndContains(t *testing.T) {
	set, err := Parse("80, 443, 1000-1002,1002-1004")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	cases := map[int]bool{
		79:    false,
		80:    true,
		443:   true,
		999:   false,
		1000:  true,
		1003:  true,
		1004:  true,
		1005:  false,
		65535: false,
	}
	for port, want := range cases {
		if got := set.Contains(port); got != want {
			t.Fatalf("Contains(%d)=%v want %v", port, got, want)
		}
	}
}
