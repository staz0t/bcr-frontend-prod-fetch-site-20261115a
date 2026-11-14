package bcr

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	bzpb "github.com/bazel-contrib/bcr-frontend/build/stack/bazel/registry/v1"
	"github.com/bazelbuild/bazel-gazelle/rule"
	"github.com/bazelbuild/buildtools/build"
)

const moduleTemplate = `module(name = "bcr_production_fetch_proof")

bazel_dep(name = "build_stack_rules_proto", version = "4.1.1", dev_dependency = True)

archive_override(
    module_name = "build_stack_rules_proto",
    sha256 = "c109fd8d2609f4029ddeb62099dc7b6c31364d8acd83147e6b4de2d6907c391b",
    strip_prefix = "rules_proto-c7c3ea2365197bc319c59cc55f44d2680be7677e",
    urls = ["https://github.com/stackb/rules_proto/archive/c7c3ea2365197bc319c59cc55f44d2680be7677e.tar.gz"],
)

starlark_repository = use_extension("@build_stack_rules_proto//extensions:starlark_repository.bzl", "starlark_repository", dev_dependency = True)
use_repo(starlark_repository, "bzl.proof---1.0.0")
`

type productionFetchReceipt struct {
	AttackModuleSHA256    string            `json:"attack_module_sha256"`
	AttackRuleSHA256      string            `json:"attack_rule_sha256"`
	ControlModuleSHA256   string            `json:"control_module_sha256"`
	ControlRuleSHA256     string            `json:"control_rule_sha256"`
	ExpectedSHA256        string            `json:"expected_sha256"`
	FrontendCommit        string            `json:"frontend_commit"`
	ModuleTargetLabel     string            `json:"module_target_label"`
	ProductionFunction    string            `json:"production_function"`
	ProductionHTTPSHasSHA bool              `json:"production_https_has_sha256"`
	RuleDifference        map[string]string `json:"rule_difference"`
	SourceURL             string            `json:"source_url"`
	StarlarkRepositoryPin string            `json:"starlark_repository_pin"`
}

func requiredEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func render(t *testing.T, template []byte, r *rule.Rule) []byte {
	t.Helper()
	ast, err := build.ParseModule("MODULE.bazel", template)
	if err != nil {
		t.Fatal(err)
	}
	f := rule.ScanAST("", ast)
	r.Insert(f)
	f.Sync()
	return f.Format()
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// TestEmitProductionFetchModules calls the exact pinned production function.
// The attack file is its unmodified HTTPS output. The control file differs by
// one attribute: it adds the reviewed sha256 to the same generated rule.
func TestEmitProductionFetchModules(t *testing.T) {
	url := requiredEnv(t, "PROOF_SOURCE_URL")
	integrity := requiredEnv(t, "PROOF_SOURCE_INTEGRITY")
	outputDir := requiredEnv(t, "PROOF_OUTPUT_DIR")
	frontendCommit := requiredEnv(t, "PROOF_FRONTEND_COMMIT")
	if !strings.HasPrefix(url, "https://") {
		t.Fatalf("source URL is not HTTPS: %s", url)
	}
	expectedSHA, ok := getSha256Integrity(integrity)
	if !ok || len(expectedSHA) != 64 {
		t.Fatalf("invalid reviewed SHA-256 integrity: %s", integrity)
	}
	module := &bzpb.ModuleVersion{Name: "proof", Version: "1.0.0"}
	source := &bzpb.ModuleSource{
		Url:         url,
		Integrity:   integrity,
		StripPrefix: "proof-1.0.0",
	}
	label := makeBzlRepositoryModulesLabel(module.Name, module.Version)
	makeAttackRule := func() *rule.Rule { return makeBzlRepository(label, module, source) }
	makeControlRule := func() *rule.Rule {
		r := makeBzlRepository(label, module, source)
		r.SetAttr("sha256", expectedSHA)
		return r
	}
	attackRule := makeAttackRule()
	if attackRule.Kind() != starlarkRepositoryArchiveKind {
		t.Fatalf("production kind = %q", attackRule.Kind())
	}
	if attackRule.AttrString("sha256") != "" {
		t.Fatalf("production HTTPS rule unexpectedly enforces sha256")
	}
	controlRule := makeControlRule()
	for _, attr := range []string{"urls", "type", "strip_prefix", "build_file_generation", "languages", "build_directives"} {
		if !reflect.DeepEqual(attackRule.Attr(attr), controlRule.Attr(attr)) {
			t.Fatalf("attack/control differ at %s", attr)
		}
	}
	attackModule := render(t, []byte(moduleTemplate), makeAttackRule())
	attackRuleBytes := render(t, nil, makeAttackRule())
	controlModule := render(t, []byte(moduleTemplate), makeControlRule())
	controlRuleBytes := render(t, nil, makeControlRule())
	if strings.Replace(string(controlRuleBytes), fmt.Sprintf("    sha256 = %q,\n", expectedSHA), "", 1) != string(attackRuleBytes) {
		t.Fatalf("control rule differs from production output by more than sha256")
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{
		"attack.MODULE.bazel":       attackModule,
		"attack-rule.MODULE.bazel":  attackRuleBytes,
		"control.MODULE.bazel":      controlModule,
		"control-rule.MODULE.bazel": controlRuleBytes,
	} {
		if err := os.WriteFile(filepath.Join(outputDir, name), payload, 0644); err != nil {
			t.Fatal(err)
		}
	}
	receipt := productionFetchReceipt{
		AttackModuleSHA256:    digest(attackModule),
		AttackRuleSHA256:      digest(attackRuleBytes),
		ControlModuleSHA256:   digest(controlModule),
		ControlRuleSHA256:     digest(controlRuleBytes),
		ExpectedSHA256:        expectedSHA,
		FrontendCommit:        frontendCommit,
		ModuleTargetLabel:     "@bzl.proof---1.0.0//:proof",
		ProductionFunction:    "language/bcr.makeBzlRepository",
		ProductionHTTPSHasSHA: false,
		RuleDifference:        map[string]string{"control_only": "sha256 = " + expectedSHA},
		SourceURL:             url,
		StarlarkRepositoryPin: "stackb/rules_proto@c7c3ea2365197bc319c59cc55f44d2680be7677e",
	}
	receiptBytes, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes = append(receiptBytes, '\n')
	if err := os.WriteFile(filepath.Join(outputDir, "emitter-receipt.json"), receiptBytes, 0644); err != nil {
		t.Fatal(err)
	}
}
