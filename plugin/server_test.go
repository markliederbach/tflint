package plugin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	hcl "github.com/hashicorp/hcl/v2"
	"github.com/markliederbach/tflint-plugin-sdk/terraform"
	client "github.com/markliederbach/tflint-plugin-sdk/tflint"
	tfplugin "github.com/markliederbach/tflint-plugin-sdk/tflint/client"
	"github.com/terraform-linters/tflint/tflint"
	"github.com/zclconf/go-cty/cty"
)

func Test_Attributes(t *testing.T) {
	source := `
resource "aws_instance" "foo" {
  instance_type = "t2.micro"
}`

	server := NewServer(tflint.TestRunner(t, map[string]string{"main.tf": source}), map[string][]byte{"main.tf": []byte(source)})
	req := &tfplugin.AttributesRequest{
		Resource:      "aws_instance",
		AttributeName: "instance_type",
	}
	var resp tfplugin.AttributesResponse

	err := server.Attributes(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	if resp.Err != nil {
		t.Fatalf("The response has an unexpected error: %s", resp.Err)
	}
	expected := []*tfplugin.Attribute{
		{
			Name: "instance_type",
			Expr: []byte(`"t2.micro"`),
			ExprRange: hcl.Range{
				Filename: "main.tf",
				Start:    hcl.Pos{Line: 3, Column: 19},
				End:      hcl.Pos{Line: 3, Column: 29},
			},
			Range: hcl.Range{
				Filename: "main.tf",
				Start:    hcl.Pos{Line: 3, Column: 3},
				End:      hcl.Pos{Line: 3, Column: 29},
			},
			NameRange: hcl.Range{
				Filename: "main.tf",
				Start:    hcl.Pos{Line: 3, Column: 3},
				End:      hcl.Pos{Line: 3, Column: 16},
			},
		},
	}
	opt := cmpopts.IgnoreFields(hcl.Pos{}, "Byte")
	if !cmp.Equal(expected, resp.Attributes, opt) {
		t.Fatalf("Attributes are not matched: %s", cmp.Diff(expected, resp.Attributes, opt))
	}
}

func Test_Blocks(t *testing.T) {
	source := `
resource "aws_instance" "foo" {
  ebs_block_device {
    volume_size = 10
  }
}`

	server := NewServer(tflint.TestRunner(t, map[string]string{"main.tf": source}), map[string][]byte{"main.tf": []byte(source)})
	req := &tfplugin.BlocksRequest{
		Resource:  "aws_instance",
		BlockType: "ebs_block_device",
	}
	var resp tfplugin.BlocksResponse

	err := server.Blocks(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	if resp.Err != nil {
		t.Fatalf("The response has an unexpected error: %s", resp.Err)
	}
	expected := []*tfplugin.Block{
		{
			Type:      "ebs_block_device",
			Body:      []byte(`volume_size = 10`),
			BodyRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 4, Column: 5}, End: hcl.Pos{Line: 4, Column: 21}},
			DefRange:  hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3, Column: 3}, End: hcl.Pos{Line: 3, Column: 19}},
			TypeRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3, Column: 3}, End: hcl.Pos{Line: 3, Column: 19}},
		},
	}
	opt := cmpopts.IgnoreFields(hcl.Pos{}, "Byte")
	if !cmp.Equal(expected, resp.Blocks, opt) {
		t.Fatalf("Blocks are not matched: %s", cmp.Diff(expected, resp.Blocks, opt))
	}
}

func Test_Resources(t *testing.T) {
	source := `
resource "aws_instance" "foo" {
  provider = aws.west
  count = 1

  instance_type = "t2.micro"

  connection {
    type = "ssh"
  }

  provisioner "local-exec" {
    command    = "chmod 600 ssh-key.pem"
    when       = destroy
    on_failure = continue

    connection {
      type = "ssh"
    }
  }

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
    ignore_changes        = all
  }
}

resource "aws_s3_bucket" "bar" {
  bucket = "my-tf-test-bucket"
  acl    = "private"
}`

	server := NewServer(tflint.TestRunner(t, map[string]string{"main.tf": source}), map[string][]byte{"main.tf": []byte(source)})
	req := &tfplugin.ResourcesRequest{Name: "aws_instance"}
	var resp tfplugin.ResourcesResponse

	err := server.Resources(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	if resp.Err != nil {
		t.Fatalf("The response has an unexpected error: %s", resp.Err)
	}

	expected := []*tfplugin.Resource{
		{
			Mode: terraform.ManagedResourceMode,
			Name: "foo",
			Type: "aws_instance",
			Config: []byte(`provider = aws.west
  count = 1

  instance_type = "t2.micro"

  connection {
    type = "ssh"
  }

  provisioner "local-exec" {
    command    = "chmod 600 ssh-key.pem"
    when       = destroy
    on_failure = continue

    connection {
      type = "ssh"
    }
  }

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
    ignore_changes        = all
  }`),
			ConfigRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3, Column: 3}, End: hcl.Pos{Line: 26, Column: 4}},
			Count:       []byte(`1`),
			CountRange:  hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 4, Column: 11}, End: hcl.Pos{Line: 4, Column: 12}},

			ProviderConfigRef: &terraform.ProviderConfigRef{
				Name:       "aws",
				NameRange:  hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3, Column: 14}, End: hcl.Pos{Line: 3, Column: 17}},
				Alias:      "west",
				AliasRange: &hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 3, Column: 17}, End: hcl.Pos{Line: 3, Column: 22}},
			},

			Managed: &tfplugin.ManagedResource{
				Connection: &tfplugin.Connection{
					Config:      []byte(`type = "ssh"`),
					ConfigRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 9, Column: 5}, End: hcl.Pos{Line: 9, Column: 17}},
					DeclRange:   hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 8, Column: 3}, End: hcl.Pos{Line: 8, Column: 13}},
				},
				Provisioners: []*tfplugin.Provisioner{
					{
						Type: "local-exec",
						Config: []byte(`command    = "chmod 600 ssh-key.pem"
    when       = destroy
    on_failure = continue

    connection {
      type = "ssh"
    }`),
						ConfigRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 13, Column: 5}, End: hcl.Pos{Line: 19, Column: 6}},
						Connection: &tfplugin.Connection{
							Config:      []byte(`type = "ssh"`),
							ConfigRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 18, Column: 7}, End: hcl.Pos{Line: 18, Column: 19}},
							DeclRange:   hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 17, Column: 5}, End: hcl.Pos{Line: 17, Column: 15}},
						},
						When:      terraform.ProvisionerWhenDestroy,
						OnFailure: terraform.ProvisionerOnFailureContinue,
						DeclRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 12, Column: 3}, End: hcl.Pos{Line: 12, Column: 27}},
						TypeRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 12, Column: 15}, End: hcl.Pos{Line: 12, Column: 27}},
					},
				},

				CreateBeforeDestroy:    true,
				PreventDestroy:         true,
				IgnoreAllChanges:       true,
				CreateBeforeDestroySet: true,
				PreventDestroySet:      true,
			},

			DeclRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 2, Column: 1}, End: hcl.Pos{Line: 2, Column: 30}},
			TypeRange: hcl.Range{Filename: "main.tf", Start: hcl.Pos{Line: 2, Column: 10}, End: hcl.Pos{Line: 2, Column: 24}},
		},
	}

	opt := cmpopts.IgnoreFields(hcl.Pos{}, "Byte")
	if !cmp.Equal(expected, resp.Resources, opt) {
		t.Fatalf("Resources are not matched: %s", cmp.Diff(expected, resp.Resources, opt))
	}
}

func Test_EvalExpr(t *testing.T) {
	source := `
variable "instance_type" {
  default = "t2.micro"
}`

	server := NewServer(tflint.TestRunner(t, map[string]string{"main.tf": source}), map[string][]byte{"main.tf": []byte(source)})
	req := &tfplugin.EvalExprRequest{
		Expr: []byte(`var.instance_type`),
		ExprRange: hcl.Range{
			Filename: "template.tf",
			Start:    hcl.Pos{Line: 1, Column: 1},
			End:      hcl.Pos{Line: 1, Column: 1},
		},
		Ret:      "", // string value
		WantType: cty.String,
	}
	var resp tfplugin.EvalExprResponse

	err := server.EvalExpr(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	if resp.Err != nil {
		t.Fatalf("The response has an unexpected error: %s", resp.Err)
	}
	expected := cty.StringVal("t2.micro")
	opts := []cmp.Option{
		cmpopts.IgnoreUnexported(cty.Type{}, cty.Value{}),
		cmpopts.IgnoreFields(hcl.Pos{}, "Byte"),
	}
	if !cmp.Equal(expected, resp.Val, opts...) {
		t.Fatalf("Value is not matched: %s", cmp.Diff(expected, resp.Val, opts...))
	}
}

func Test_EvalExpr_errors(t *testing.T) {
	source := `variable "instance_type" {}`

	server := NewServer(tflint.TestRunner(t, map[string]string{"main.tf": source}), map[string][]byte{"main.tf": []byte(source)})
	req := &tfplugin.EvalExprRequest{
		Expr: []byte(`var.instance_type`),
		ExprRange: hcl.Range{
			Filename: "template.tf",
			Start:    hcl.Pos{Line: 1, Column: 1},
			End:      hcl.Pos{Line: 1, Column: 1},
		},
		Ret:      "", // string value
		WantType: cty.String,
	}
	var resp tfplugin.EvalExprResponse

	err := server.EvalExpr(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	expected := client.Error{
		Code:    client.UnknownValueError,
		Level:   client.WarningLevel,
		Message: "Unknown value found in template.tf:1; Please use environment variables or tfvars to set the value",
		Cause:   nil,
	}
	if !cmp.Equal(expected, resp.Err) {
		t.Fatalf("Error it not matched: %s", cmp.Diff(expected, resp.Err))
	}
}

func Test_EmitIssue(t *testing.T) {
	runner := tflint.TestRunner(t, map[string]string{})
	rule := &tfplugin.Rule{
		Data: &tfplugin.RuleObject{
			Name:     "test_rule",
			Severity: client.ERROR,
		},
	}

	server := NewServer(runner, map[string][]byte{})
	req := &tfplugin.EmitIssueRequest{
		Rule:    rule,
		Message: "This is test rule",
		Location: hcl.Range{
			Filename: "main.tf",
			Start:    hcl.Pos{Line: 3, Column: 3},
			End:      hcl.Pos{Line: 3, Column: 30},
		},
		Expr: []byte("1"),
		ExprRange: hcl.Range{
			Filename: "template.tf",
			Start:    hcl.Pos{Line: 1, Column: 1},
			End:      hcl.Pos{Line: 1, Column: 1},
		},
	}
	var resp interface{}

	err := server.EmitIssue(req, &resp)
	if err != nil {
		t.Fatalf("Unexpected error occurred: %s", err)
	}

	expected := tflint.Issues{
		{
			Rule:    rule,
			Message: "This is test rule",
			Range: hcl.Range{
				Filename: "main.tf",
				Start:    hcl.Pos{Line: 3, Column: 3},
				End:      hcl.Pos{Line: 3, Column: 30},
			},
		},
	}
	if !cmp.Equal(expected, runner.Issues) {
		t.Fatalf("Issue are not matched: %s", cmp.Diff(expected, runner.Issues))
	}
}
