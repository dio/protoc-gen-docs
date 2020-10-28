package extensions

import (
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/pseudomuto/protoc-gen-doc/extensions"
	rbac_v2 "github.com/tetrateio/api/tsb/rbac/v2"
	types_v2 "github.com/tetrateio/api/tsb/types/v2"
	"google.golang.org/genproto/googleapis/api/annotations"
)

// HTTPRule represents a single HTTP rule from the (google.api.http) method option extension.
type HTTPRule struct {
	Method  string `json:"method"`
	Pattern string `json:"pattern"`
	Body    string `json:"body,omitempty"`
}

// HTTPExtension contains the rules set by the (google.api.http) method option extension.
type HTTPExtension struct {
	Rules []HTTPRule `json:"rules"`
}

func getRule(r *annotations.HttpRule) (rule HTTPRule) {
	switch r.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		rule.Method = http.MethodGet
		rule.Pattern = r.GetGet()
	case *annotations.HttpRule_Put:
		rule.Method = http.MethodPut
		rule.Pattern = r.GetPut()
	case *annotations.HttpRule_Post:
		rule.Method = http.MethodPost
		rule.Pattern = r.GetPost()
	case *annotations.HttpRule_Delete:
		rule.Method = http.MethodDelete
		rule.Pattern = r.GetDelete()
	case *annotations.HttpRule_Patch:
		rule.Method = http.MethodPatch
		rule.Pattern = r.GetPatch()
	case *annotations.HttpRule_Custom:
		custom := r.GetCustom()
		rule.Method = custom.GetKind()
		rule.Pattern = custom.GetPath()
	}
	rule.Body = r.GetBody()
	return
}

// Field ...
type Field struct {
	Behavior string `json:"behavior"`
}

// RbacRequires ...
type RbacRequires struct {
	Permissions                      string   `json:"permissions"`
	RawPermissions                   []string `json:"rawPermissions"`
	DeferPermissioCheckToApplication bool     `json:"deferPermissioCheckToApplication"`
}

// IstioObjectSpec ...
type IstioObjectSpec struct {
	AtType string `json:"@type"`
}

func init() {
	proto.RegisterExtension(&proto.ExtensionDesc{
		ExtendedType:  (*descriptor.FieldOptions)(nil),
		ExtensionType: rbac_v2.E_Requires.ExtensionType,
		Field:         rbac_v2.E_Requires.Field,
		Name:          rbac_v2.E_Requires.Name,
		Tag:           rbac_v2.E_Requires.Tag,
		Filename:      rbac_v2.E_Requires.Filename,
	})

	extensions.SetTransformer("google.api.field_behavior", func(payload interface{}) interface{} {
		behavior, ok := payload.([]annotations.FieldBehavior)
		if !ok || len(behavior) != 1 {
			return nil
		}
		return Field{Behavior: behavior[0].String()}
	})

	extensions.SetTransformer("google.api.http", func(payload interface{}) interface{} {
		var rules []HTTPRule
		rule, ok := payload.(*annotations.HttpRule)
		if !ok {
			return nil
		}

		rules = append(rules, getRule(rule))

		// NOTE: The option can only have one level of nested AdditionalBindings.
		for _, rule := range rule.AdditionalBindings {
			rules = append(rules, getRule(rule))
		}

		return HTTPExtension{Rules: rules}
	})

	extensions.SetTransformer("tetrateio.api.tsb.rbac.v2.requires", func(payload interface{}) interface{} {
		requires, ok := payload.(rbac_v2.RequiredPermission)
		if !ok {
			return nil
		}

		rbacRequires := RbacRequires{
			DeferPermissioCheckToApplication: requires.DeferPermissionCheckToApplication,
		}

		if len(requires.Permissions) > 0 {
			rbacRequires.Permissions = requires.Permissions[0].String()
		}

		rbacRequires.RawPermissions = requires.RawPermissions

		return rbacRequires
	})

	extensions.SetTransformer("tetrateio.api.tsb.rbac.v2.default_requires", func(payload interface{}) interface{} {
		requires, ok := payload.(rbac_v2.RequiredPermission)
		if !ok {
			return nil
		}

		rbacRequires := RbacRequires{
			DeferPermissioCheckToApplication: requires.DeferPermissionCheckToApplication,
		}

		if len(requires.Permissions) > 0 {
			rbacRequires.Permissions = requires.Permissions[0].String()
		}

		rbacRequires.RawPermissions = requires.RawPermissions

		return rbacRequires
	})

	extensions.SetTransformer("tetrateio.api.tsb.types.v2.spec", func(payload interface{}) interface{} {
		spec, ok := payload.(types_v2.IstioObjectSpec)
		if !ok {
			return nil
		}
		return IstioObjectSpec{
			AtType: "type.googleapis.com/" + spec.Type,
		}
	})
}
