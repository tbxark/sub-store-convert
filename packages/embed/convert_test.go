package embed

import (
	"strings"
	"testing"
)

const ss = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@1.2.3.4:8388#test"

func TestConvert(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for target, want := range map[string]string{"clash": "1.2.3.4", "surge": "test=ss,1.2.3.4,8388", "uri": "ss://"} {
		out, err := c.Convert(ss, target, nil)
		if err != nil || !strings.Contains(out, want) {
			t.Errorf("%s: %q %v", target, out, err)
		}
	}
	if _, err := c.Convert(ss, "nope", nil); err == nil {
		t.Error("expected error for unknown target")
	}
}
