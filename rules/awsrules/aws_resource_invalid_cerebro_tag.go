package awsrules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/terraform/configs"
	"github.com/terraform-linters/tflint/rules/awsrules/tags"
	"github.com/terraform-linters/tflint/tflint"
	"github.com/zclconf/go-cty/cty"
)

// Cerebro Client helpers

// Void is merely a stub used to make void maps
type Void struct{}

var member Void

// Team is a single item in the list
// of teams returned by Cerebro. It only contains
// the fields we care about
type Team struct {
	// ID is the internal id of the team
	ID int64 `json:"id"`
	// Name is the Name of the team
	Name string `json:"name"`
	// Permalink is the cannonical name of the team
	Permalink string `json:"permalink"`
	// Billable describes whether resources can be
	// charged to this team
	Billable bool `json:"billable?"`
}

// TeamsCollection encapsulates the response for
// the corresponding Cerebro endpoint
type TeamsCollection struct {
	// Teams is the list of teams in a /teams response
	Teams []Team `json:"teams"`
}

// IndexByID indexes all teams by their ID field
func (t *TeamsCollection) IndexByID() map[int64]Team {
	result := make(map[int64]Team)
	for _, team := range t.Teams {
		result[team.ID] = team
	}
	return result
}

// Product is a single item in the list
// of products returned by Cerebro. It only contains
// the fields we care about
type Product struct {
	// ID is the internal id of the team
	ID int64 `json:"id"`
	// Name is the Name of the team
	Name string `json:"name"`
	// Permalink is the cannonical name of the team
	Permalink string `json:"permalink"`
	// TODO: Some attribute to describe child teams?
}

// ProductsCollection encapsulates the response for
// the corresponding Cerebro endpoint
type ProductsCollection struct {
	// Products is the list of products in a /products response
	Products []Product `json:"products"`
}

// ToCannonicalSet returns a unique set of cannonical names for the Cerebro items
func (p *ProductsCollection) ToCannonicalSet() map[string]Void {
	result := make(map[string]Void)
	for _, product := range p.Products {
		result[product.Permalink] = member
	}
	return result
}

// Service is a single item in the list
// of services returned by Cerebro. It only contains
// the fields we care about
type Service struct {
	// ID is the internal id of the team
	ID int64 `json:"id"`
	// Name is the Name of the team
	Name string `json:"name"`
	// Permalink is the cannonical name of the team
	Permalink string `json:"permalink"`
	// TODO: Some attribute to describe child teams?
}

// ServicesCollection encapsulates the response for
// the corresponding Cerebro endpoint
type ServicesCollection struct {
	// Services is the list of projects in a /projects response
	Services []Service `json:"projects"`
}

// ToCannonicalSet returns a unique set of cannonical names for the Cerebro items
func (s *ServicesCollection) ToCannonicalSet() map[string]Void {
	result := make(map[string]Void)
	for _, product := range s.Services {
		result[product.Permalink] = member
	}
	return result
}

// Endpoint encapsulates available API endpoints
type Endpoint string

const (
	baseURL string = "https://cerebro.zende.sk"

	teamsEndpoint    Endpoint = "teams"
	productsEndpoint Endpoint = "products"
	servicesEndpoint Endpoint = "projects"
)

// Cerebro is a client that pulls down and caches cerebro data.
// It also has functions to query against that data.
type Cerebro struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewCerebro returns a new instance of a Cerebro client,
// and also initiates the caches.
func NewCerebro() (*Cerebro, error) {
	cerebroToken, err := getToken()
	if err != nil {
		return &Cerebro{}, err
	}

	return &Cerebro{
		baseURL: baseURL,
		token:   cerebroToken,
		client:  &http.Client{},
	}, nil
}

func getToken() (string, error) {
	// TODO: This is preferred, but there's no
	// 		 way to pass this down from tflint
	if cerebroToken, ok := os.LookupEnv("CEREBRO_TOKEN"); ok {
		return cerebroToken, nil
	}

	log.Printf("[DEBUG] CEREBRO_TOKEN not set, checking .cerebro-token file")

	// Backup method is to look for a .cerebro-token in
	// the current directory (I hate this)
	cerebroToken, err := ioutil.ReadFile(".cerebro-token")
	if err != nil {
		return "", fmt.Errorf("Failed to read Cerebro token from .cerebro-token: %w", err)
	}
	return strings.TrimSpace(string(cerebroToken)), nil

}

func (c *Cerebro) buildURL(endpoint Endpoint, page int) string {
	return fmt.Sprintf("%s/%s.json?page=%v", c.baseURL, endpoint, page)
}

func (c *Cerebro) setHeaders(request *http.Request, headers map[string]string) {
	for key, value := range headers {
		request.Header.Set(key, value)
	}
}

func (c *Cerebro) get(url string) ([]byte, error) {
	var err error

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return []byte{}, err
	}

	c.setHeaders(request, map[string]string{
		"Authorization": fmt.Sprintf("Token %s", c.token),
	})

	response, err := c.client.Do(request)
	if err != nil {
		return []byte{}, err
	}

	if response.StatusCode != http.StatusOK {
		return []byte{}, fmt.Errorf("Response from Cerebro returned status: %s", response.Status)
	}

	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	return body, err
}

// GetTeams returns the unmarshaled dump of data for the given endpoint
func (c *Cerebro) GetTeams() (map[string]Void, error) {
	var (
		result              = make(map[string]Void)
		allTeams            = []Team{}
		pageTeamsCollection TeamsCollection
		page                int = 1
	)
	for {
		url := c.buildURL(teamsEndpoint, page)
		body, err := c.get(url)
		if err != nil {
			return result, err
		}

		if err := json.Unmarshal(body, &pageTeamsCollection); err != nil {
			return result, err
		}

		if len(pageTeamsCollection.Teams) == 0 {
			break
		}

		allTeams = append(allTeams, pageTeamsCollection.Teams...)

		page++
	}

	// Filter for only billable teams
	for _, team := range allTeams {
		if team.Billable {
			result[team.Permalink] = member
		}
	}

	log.Printf("[DEBUG] Found %v valid Cerebro teams", len(result))
	return result, nil
}

// GetProducts returns the unmarshaled dump of data for the given endpoint
func (c *Cerebro) GetProducts() (map[string]Void, error) {
	var (
		result           = make(map[string]Void)
		productsResponse ProductsCollection
		page             int = 1
	)
	for {
		url := c.buildURL(productsEndpoint, page)
		body, err := c.get(url)
		if err != nil {
			return result, err
		}

		if err := json.Unmarshal(body, &productsResponse); err != nil {
			return result, err
		}

		for cannonicalName, void := range productsResponse.ToCannonicalSet() {
			result[cannonicalName] = void
		}

		if len(productsResponse.Products) == 0 {
			break
		}
		page++
	}
	return result, nil
}

// GetServices returns the unmarshaled dump of data for the given endpoint
func (c *Cerebro) GetServices() (map[string]Void, error) {
	var (
		result           = make(map[string]Void)
		servicesResponse ServicesCollection
		page             int = 1
	)
	for {
		url := c.buildURL(servicesEndpoint, page)
		body, err := c.get(url)
		if err != nil {
			return result, err
		}

		if err := json.Unmarshal(body, &servicesResponse); err != nil {
			return result, err
		}

		for cannonicalName, void := range servicesResponse.ToCannonicalSet() {
			result[cannonicalName] = void
		}

		if len(servicesResponse.Services) == 0 {
			break
		}
		page++
	}
	return result, nil
}

// Rule logic
const (
	tagsName        string = "tags"
	tagName         string = "tag"
	asgResourceType string = "aws_autoscaling_group"
)

type awsResourceInvalidCerebroTagRuleConfig struct {
	Exclude []string `hcl:"exclude,optional"`
}

// CerebroSpec holds all available specs from the
// Cerebro data
type CerebroSpec struct {
	Teams    map[string]Void
	Products map[string]Void
	Services map[string]Void
}

// AwsResourceInvalidCerebroTagRule checks whether taggable resources
// use correct team/product tags that correspond to
// actual values in Cerebro.
type AwsResourceInvalidCerebroTagRule struct {
	Allowed   CerebroSpec
	InitError error
}

// NewAwsResourceInvalidCerebroTagRule returns a new instance of the rule
func NewAwsResourceInvalidCerebroTagRule() *AwsResourceInvalidCerebroTagRule {
	client, err := NewCerebro()
	if err != nil {
		return &AwsResourceInvalidCerebroTagRule{
			InitError: err,
		}
	}

	// TODO: this is all Cerebro teams, in memory. Look into caching
	allowedTeams, err := client.GetTeams()
	if err != nil {
		return &AwsResourceInvalidCerebroTagRule{
			InitError: err,
		}
	}

	allowedProducts, err := client.GetProducts()
	if err != nil {
		return &AwsResourceInvalidCerebroTagRule{
			InitError: err,
		}
	}

	allowedServices, err := client.GetServices()
	if err != nil {
		return &AwsResourceInvalidCerebroTagRule{
			InitError: err,
		}
	}
	return &AwsResourceInvalidCerebroTagRule{
		Allowed: CerebroSpec{
			Teams:    allowedTeams,
			Products: allowedProducts,
			Services: allowedServices,
		},
	}
}

// Name returns the rule name
func (r *AwsResourceInvalidCerebroTagRule) Name() string {
	return "aws_resource_invalid_cerebro_tag"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsResourceInvalidCerebroTagRule) Enabled() bool {
	return false
}

// Severity returns the rule severity
func (r *AwsResourceInvalidCerebroTagRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsResourceInvalidCerebroTagRule) Link() string {
	return "https://zendesk.atlassian.net/wiki/spaces/FSEC/pages/1344340350/Cloud+Resource+Tagging+Standard"
}

// Check performs the actual check on each resource
func (r *AwsResourceInvalidCerebroTagRule) Check(runner *tflint.Runner) error {
	if r.InitError != nil {
		return r.InitError
	}

	config := awsResourceInvalidCerebroTagRuleConfig{}
	if err := runner.DecodeRuleConfig(r.Name(), &config); err != nil {
		return err
	}

	// Iterate all resource types
	for _, resourceType := range tags.Resources {
		// Skip this resource if its type is excluded in configuration
		if r.stringInSlice(resourceType, config.Exclude) {
			continue
		}

		if resourceType == asgResourceType {
			err := r.checkAwsAutoScalingGroups(runner, r.Allowed)
			err = runner.EnsureNoError(err, func() error {
				return nil
			})
			if err != nil {
				return err
			}
			continue
		}

		for _, resource := range runner.LookupResourcesByType(resourceType) {
			body, _, diags := resource.Config.PartialContent(&hcl.BodySchema{
				Attributes: []hcl.AttributeSchema{
					{
						Name: tagsName,
					},
				},
			})
			if diags.HasErrors() {
				return diags
			}

			if attribute, ok := body.Attributes[tagsName]; ok {
				log.Printf("[DEBUG] Walk `%s` attribute", resource.Type+"."+resource.Name+"."+tagsName)
				err := runner.WithExpressionContext(attribute.Expr, func() error {
					var err error
					resourceTags := make(map[string]string)
					err = runner.EvaluateExpr(attribute.Expr, &resourceTags)
					return runner.EnsureNoError(err, func() error {
						r.emitIssue(runner, resourceTags, r.Allowed, attribute.Expr.Range())
						return nil
					})
				})
				if err != nil {
					return err
				}
			} else {
				log.Printf("[DEBUG] Walk `%s` resource", resource.Type+"."+resource.Name)
				r.emitIssue(runner, map[string]string{}, r.Allowed, resource.DeclRange)
			}
		}
	}
	return nil
}

// checkAwsAutoScalingGroups handles the special case for tags on AutoScaling Groups
// See: https://github.com/terraform-providers/terraform-provider-aws/blob/master/aws/autoscaling_tags.go
func (r *AwsResourceInvalidCerebroTagRule) checkAwsAutoScalingGroups(runner *tflint.Runner, allowed CerebroSpec) error {
	for _, resource := range runner.LookupResourcesByType(asgResourceType) {
		asgTagBlockTags, tagBlockLocation, err := r.checkAwsAutoScalingGroupsTag(runner, resource)
		if err != nil {
			return err
		}

		asgTagsAttributeTags, tagsAttributeLocation, err := r.checkAwsAutoScalingGroupsTags(runner, resource)
		if err != nil {
			return err
		}

		var location hcl.Range
		tags := make(map[string]string)
		switch {
		case len(asgTagBlockTags) > 0 && len(asgTagsAttributeTags) > 0:
			issue := fmt.Sprintf("Only tag block or tags attribute may be present, but found both")
			runner.EmitIssue(r, issue, resource.DeclRange)
			return nil
		case len(asgTagBlockTags) == 0 && len(asgTagsAttributeTags) == 0:
			r.emitIssue(runner, map[string]string{}, allowed, resource.DeclRange)
			return nil
		case len(asgTagBlockTags) > 0 && len(asgTagsAttributeTags) == 0:
			tags = asgTagBlockTags
			location = tagBlockLocation
		case len(asgTagBlockTags) == 0 && len(asgTagsAttributeTags) > 0:
			tags = asgTagsAttributeTags
			location = tagsAttributeLocation
		}

		err = runner.EnsureNoError(err, func() error {
			r.emitIssue(runner, tags, allowed, location)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// checkAwsAutoScalingGroupsTag checks tag{} blocks on aws_autoscaling_group resources
func (r *AwsResourceInvalidCerebroTagRule) checkAwsAutoScalingGroupsTag(runner *tflint.Runner, resource *configs.Resource) (map[string]string, hcl.Range, error) {
	tags := make(map[string]string)
	body, _, diags := resource.Config.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type: tagName,
			},
		},
	})
	if diags.HasErrors() {
		return tags, (hcl.Range{}), diags
	}

	for _, tagBlock := range body.Blocks {
		attributes, diags := tagBlock.Body.JustAttributes()
		if diags.HasErrors() {
			return tags, tagBlock.DefRange, diags
		}

		if _, ok := attributes["key"]; !ok {
			err := &tflint.Error{
				Code:  tflint.UnevaluableError,
				Level: tflint.WarningLevel,
				Message: fmt.Sprintf("Did not find expected field \"key\" in aws_autoscaling_group \"%s\" starting at line %d",
					resource.Name,
					resource.DeclRange.Start.Line,
				),
			}
			return tags, resource.DeclRange, err
		}

		// Check that the value of the tag is available
		if _, ok := attributes["value"]; !ok {
			err := &tflint.Error{
				Code:  tflint.UnevaluableError,
				Level: tflint.WarningLevel,
				Message: fmt.Sprintf("Did not find expected field \"value\" in %s \"%s\" starting at line %d",
					asgResourceType,
					resource.Name,
					resource.DeclRange.Start.Line,
				),
			}
			return tags, resource.DeclRange, err
		}

		var key string
		var value string
		if err := runner.EvaluateExpr(attributes["key"].Expr, &key); err != nil {
			return tags, tagBlock.DefRange, err
		}
		if err := runner.EvaluateExpr(attributes["value"].Expr, &value); err != nil {
			return tags, tagBlock.DefRange, err
		}
		tags[key] = value
	}
	return tags, resource.DeclRange, nil
}

// AwsASGTag is used by go-cty to evaluate tags in aws_autoscaling_group resources
// https://github.com/zclconf/go-cty/blob/master/docs/gocty.md#converting-to-and-from-structs
type AwsASGTag struct {
	Key               string `cty:"key"`
	Value             string `cty:"value"`
	PropagateAtLaunch bool   `cty:"propagate_at_launch"`
}

// checkAwsAutoScalingGroupsTag checks the tags attribute on aws_autoscaling_group resources
func (r *AwsResourceInvalidCerebroTagRule) checkAwsAutoScalingGroupsTags(runner *tflint.Runner, resource *configs.Resource) (map[string]string, hcl.Range, error) {
	tags := make(map[string]string)
	body, _, diags := resource.Config.PartialContent(&hcl.BodySchema{
		Attributes: []hcl.AttributeSchema{
			{
				Name: tagsAttributeName,
			},
		},
	})
	if diags.HasErrors() {
		return tags, (hcl.Range{}), diags
	}

	if attribute, ok := body.Attributes[tagsAttributeName]; ok {
		err := runner.WithExpressionContext(attribute.Expr, func() error {
			wantType := cty.List(cty.Object(map[string]cty.Type{
				"key":                 cty.String,
				"value":               cty.String,
				"propagate_at_launch": cty.Bool,
			}))
			var asgTags []AwsASGTag
			err := runner.EvaluateExprType(attribute.Expr, &asgTags, wantType)
			if err != nil {
				return err
			}
			for _, tag := range asgTags {
				tags[tag.Key] = tag.Value
			}
			return nil
		})
		if err != nil {
			return tags, attribute.Expr.Range(), err
		}
		return tags, attribute.Expr.Range(), nil
	}
	return tags, resource.DeclRange, nil
}

func (r *AwsResourceInvalidCerebroTagRule) emitIssue(runner *tflint.Runner, tags map[string]string, allowed CerebroSpec, location hcl.Range) {

	var issues []string

	// Check team
	if teamTag, tagValue, valid := r.checkTag("team", tags, allowed.Teams); !valid {
		issues = r.appendIssue(issues, teamTag, tagValue)
	}

	// Check product
	if productTag, tagValue, valid := r.checkTag("product", tags, allowed.Products); !valid {
		issues = r.appendIssue(issues, productTag, tagValue)
	}

	// Check service
	if serviceTag, tagValue, valid := r.checkTag("service", tags, allowed.Services); !valid {
		issues = r.appendIssue(issues, serviceTag, tagValue)
	}

	if len(issues) > 0 {
		sort.Strings(issues)
		joinedIssues := strings.Join(issues, ", ")
		issue := fmt.Sprintf("The resource has invalid values for Cerebro: %s", joinedIssues)
		runner.EmitIssue(r, issue, location)
	}
}

func (r *AwsResourceInvalidCerebroTagRule) appendIssue(issues []string, lookupTag string, tagValue string) []string {
	return append(issues, fmt.Sprintf("\"%s=%s\"", lookupTag, tagValue))
}

func (r *AwsResourceInvalidCerebroTagRule) checkTag(lookupTag string, tags map[string]string, allowedValues map[string]Void) (string, string, bool) {
	if value, ok := tags[lookupTag]; ok {
		_, exists := allowedValues[value]
		return lookupTag, value, exists
	}
	return lookupTag, "", true
}

func (r *AwsResourceInvalidCerebroTagRule) stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
