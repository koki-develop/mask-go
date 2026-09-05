package mask

import "slices"

// This file is the registry alone. A built-in pattern lives in a file of its
// own, builtin_<name>.go beside a builtin_<name>_test.go, so that adding one
// leaves the patterns already here untouched and none of them grows a file the
// others have to be read around. What more than one of them reads is in
// builtin_scan.go, and what all of them are held to is in builtins_test.go.

// AllBuiltinPatterns returns every built-in pattern:
//
//	m := mask.New(mask.WithPatterns(mask.AllBuiltinPatterns()...))
//
// The set grows as patterns are added to this package. The returned slice is
// freshly allocated and may be modified by the caller.
func AllBuiltinPatterns() []Pattern {
	return slices.Clone(builtins)
}

// builtins is every built-in pattern, in the order AllBuiltinPatterns reports
// them. A pattern added to this package is added here, and that is the one
// place which puts it in AllBuiltinPatterns and under the properties every
// built-in is held to in builtins_test.go. The pattern itself stays in the
// file it was declared in; only its name reaches this list.
//
// One name to a line, so that two patterns added at once are two insertions at
// different lines rather than two rewrites of one. A list written on a single
// line is one every addition conflicts with.
var builtins = []Pattern{
	ageSecretKey,
	airtablePersonalAccessToken,
	anthropicCredential,
	awsAccessKeyID,
	awsSecretAccessKey,
	buildkiteToken,
	circleCIAPIToken,
	cloudflareAPIKey,
	cloudflareAPIToken,
	cratesIOToken,
	databricksOAuthClientSecret,
	databricksPersonalAccessToken,
	digitalOceanToken,
	dockerPersonalAccessToken,
	dopplerAuthToken,
	dynatraceToken,
	flyIOAccessToken,
	githubToken,
	gitLabToken,
	googleAPIKey,
	grafanaServiceAccountToken,
	groqAPIKey,
	hashiCorpVaultToken,
	hcpTerraformAPIToken,
	herokuAPIToken,
	huggingFaceUserAccessToken,
	jsonWebToken,
	langSmithAPIKey,
	linearAPIKey,
	mailchimpAPIKey,
	mailerSendAPIToken,
	neonAPIKey,
	netlifyAuthToken,
	newRelicUserKey,
	notionAPIToken,
	npmAccessToken,
	onePasswordServiceAccountToken,
	openAIAPIKey,
	openRouterAPIKey,
	oryAPIKey,
	paddleAPIKey,
	perplexityAPIKey,
	pineconeAPIKey,
	planetScaleToken,
	postHogPersonalAPIKey,
	postmanAPIKey,
	privateKey,
	pulumiAccessToken,
	pypiAPIToken,
	renderAPIKey,
	replicateAPIToken,
	resendAPIKey,
	rubyGemsAPIKey,
	sendGridAPIKey,
	sentryAuthToken,
	shippoAPIToken,
	shopifyAccessToken,
	shopifyAppSecretKey,
	slackToken,
	sonarQubeToken,
	sourcegraphAccessToken,
	stripePublishableKey,
	stripeSecretKey,
	stripeWebhookSigningSecret,
	supabaseAccessToken,
	supabasePublishableKey,
	supabaseSecretKey,
	xaiAPIKey,
}
