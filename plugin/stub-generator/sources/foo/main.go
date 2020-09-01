package main

import (
	"github.com/markliederbach/tflint-plugin-sdk/tflint"
	"github.com/markliederbach/tflint-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: tflint.RuleSet{
			Name:    "foo",
			Version: "0.1.0",
			Rules:   []tflint.Rule{},
		},
	})
}
