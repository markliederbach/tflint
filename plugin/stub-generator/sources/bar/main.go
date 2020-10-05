package main

import (
	"github.com/markliederbach/tflint-plugin-sdk/plugin"
	"github.com/markliederbach/tflint-plugin-sdk/tflint"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		RuleSet: tflint.RuleSet{
			Name:    "bar",
			Version: "0.1.0",
			Rules:   []tflint.Rule{},
		},
	})
}
