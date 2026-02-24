package main

import (
	"net/http"

	"github.com/stripe/smokescreen/cmd"
	"github.com/stripe/smokescreen/pkg/smokescreen"
)

func main() {
	conf, err := cmd.NewConfiguration(nil, nil)
	if err != nil {
		panic(err)
	}
	// Return the "default" role for all requests so the ACL policy applies
	// without requiring TLS client certificates.
	conf.RoleFromRequest = func(req *http.Request) (string, error) {
		return "default", nil
	}
	if err := smokescreen.StartWithConfig(conf, nil); err != nil {
		panic(err)
	}
}
