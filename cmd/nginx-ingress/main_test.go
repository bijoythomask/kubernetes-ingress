package main

import (
	"errors"
	"testing"
)

func TestValidateStatusPort(t *testing.T) {
	badPorts := []int{80, 443, 1, 1022, 65536}
	for _, badPort := range badPorts {
		err := validateStatusPort(badPort)
		if err == nil {
			t.Errorf("Expected error for port %v\n", badPort)
		}
	}

	goodPorts := []int{8080, 8081, 8082, 1023, 65535}
	for _, goodPort := range goodPorts {
		err := validateStatusPort(goodPort)
		if err != nil {
			t.Errorf("Error for valid port:  %v err: %v\n", goodPort, err)
		}
	}

}

func TestParseNginxStatusAllowCIDRs(t *testing.T) {
	var badCIDRs = []struct {
		input         string
		expected      []string
		expectedError error
	}{
		{
			"earth, ,,furball",
			[]string{},
			errors.New("invalid IP address: earth"),
		},
		{
			"127.0.0.1,10.0.1.0/24, ,,furball",
			[]string{"127.0.0.1", "10.0.1.0/24"},
			errors.New("invalid CIDR address: an empty string is an invalid CIDR block or IP address"),
		},
		{
			"false",
			[]string{},
			errors.New("invalid IP address: false"),
		},
	}
	for _, badCIDR := range badCIDRs {
		splitArray, err := parseNginxStatusAllowCIDRs(badCIDR.input)
		if err == nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned no error when it should have returned error %q", badCIDR.input, badCIDR.expectedError)
		} else if err.Error() != badCIDR.expectedError.Error() {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned error %q when it should have returned error %q", badCIDR.input, err, badCIDR.expectedError)
		}

		for _, expectedEntry := range badCIDR.expected {
			if !contains(splitArray, expectedEntry) {
				t.Errorf("parseNginxStatusAllowCIDRs(%q) did not include %q but returned %q", badCIDR.input, expectedEntry, splitArray)
			}
		}
	}

	var goodCIDRs = []struct {
		input    string
		expected []string
	}{
		{
			"127.0.0.1",
			[]string{"127.0.0.1"},
		},
		{
			"10.0.1.0/24",
			[]string{"10.0.1.0/24"},
		},
		{
			"127.0.0.1,10.0.1.0/24,68.121.233.214 , 24.24.24.24/32",
			[]string{"127.0.0.1", "10.0.1.0/24", "68.121.233.214", "24.24.24.24/32"},
		},
	}
	for _, goodCIDR := range goodCIDRs {
		splitArray, err := parseNginxStatusAllowCIDRs(goodCIDR.input)
		if err != nil {
			t.Errorf("parseNginxStatusAllowCIDRs(%q) returned an error when it should have returned no error: %q", goodCIDR.input, err)
		}

		for _, expectedEntry := range goodCIDR.expected {
			if !contains(splitArray, expectedEntry) {
				t.Errorf("parseNginxStatusAllowCIDRs(%q) did not include %q but returned %q", goodCIDR.input, expectedEntry, splitArray)
			}
		}
	}

}

func TestValidateCIDRorIP(t *testing.T) {
	badCIDRs := []string{"localhost", "thing", "~", "!!!", "", " ", "-1"}
	for _, badCIDR := range badCIDRs {
		err := validateCIDRorIP(badCIDR)
		if err == nil {
			t.Errorf(`Expected error for invalid CIDR "%v"\n`, badCIDR)
		}
	}

	goodCIDRs := []string{"0.0.0.0/32", "0.0.0.0/0", "127.0.0.1/32", "127.0.0.0/24", "23.232.65.42"}
	for _, goodCIDR := range goodCIDRs {
		err := validateCIDRorIP(goodCIDR)
		if err != nil {
			t.Errorf("Error for valid CIDR: %v err: %v\n", goodCIDR, err)
		}
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
