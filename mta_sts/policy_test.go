package mta_sts

import "testing"

func TestParsePolicyValidation(t *testing.T) {
	valid := "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n"
	p, err := ParsePolicy(valid)
	if err != nil || p.MaxAge != 86400 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, bad := range []string{"version: STSv1\nmode: enforce\nmx: mx.example\n", "version: STSv1\nmode: enforce\nmax_age: 1\n", "version: STSv1\nversion: STSv1\nmode: none\nmax_age: 1\n", "# comment\nversion: STSv1\nmode: none\nmax_age: 1\n"} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("accepted invalid policy %q", bad)
		}
	}
}
