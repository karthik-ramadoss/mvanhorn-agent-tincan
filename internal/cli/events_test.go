package cli

import (
	"testing"
)

func TestDotsMigrationFlagsDefaultOff(t *testing.T) {
	f := relayFlags{}
	if len(f.directoryConfig().ServiceRoles) != 0 || len(f.relayConfig().RequireClaimOwnership) != 0 {
		t.Fatal("implicit migration")
	}
	cmd := relayCmd()
	for _, flag := range []string{"service-role", "require-claim-ownership", "gateway-events-only"} {
		if cmd.Flags().Lookup(flag) == nil {
			t.Fatal(flag)
		}
	}
}

func TestDotsMigrationRejectsUnsafeConfigurationBeforeStartup(t *testing.T) {
	for _, args := range [][]string{{"--service-role", "tag:codex-forgejo=openai-dots"}, {"--gateway-events-only", "openai-dots"}, {"--require-claim-ownership", "bad name"}} {
		cmd := relayCmd()
		if err := cmd.Flags().Parse(args); err != nil {
			t.Fatal(err)
		}
		if err := cmd.RunE(cmd, nil); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
