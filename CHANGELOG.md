# Changelog

## 0.0.1 (2026-08-26)


### Features

* Group the built-ins by vendor and name them as their vendors do ([f956352](https://github.com/koki-develop/mask-go/commit/f9563528464f9aa783facb77b471da8ada8a2b54))
* Implement masking ([deed0c6](https://github.com/koki-develop/mask-go/commit/deed0c6ed31fb5500546301c432578c5f8c2bd8b))
* Locate a Cloudflare API key ([#17](https://github.com/koki-develop/mask-go/issues/17)) ([7428564](https://github.com/koki-develop/mask-go/commit/742856462d60180ed887d2bfc2785daba857b430))
* Locate a Cloudflare API token ([#15](https://github.com/koki-develop/mask-go/issues/15)) ([f87d3af](https://github.com/koki-develop/mask-go/commit/f87d3af13faded4a0e82548264c5b78beb482a94))
* Locate a GitLab token ([349cec4](https://github.com/koki-develop/mask-go/commit/349cec49a3c4c2c668ab766b7a157a4b4bc9e9e6))
* Locate a Google API key ([ca86b30](https://github.com/koki-develop/mask-go/commit/ca86b30b03d72f94ef1665c277edbcf47e32eeaf))
* Locate a Grafana service account token ([#10](https://github.com/koki-develop/mask-go/issues/10)) ([e0781a7](https://github.com/koki-develop/mask-go/commit/e0781a7a2b09681b47842fed64eb18bd8d847268))
* Locate a HashiCorp Vault token ([#9](https://github.com/koki-develop/mask-go/issues/9)) ([9308cee](https://github.com/koki-develop/mask-go/commit/9308cee2e19588a980a3e9a6957705d9842722f6))
* Locate a Linear API key ([#7](https://github.com/koki-develop/mask-go/issues/7)) ([6d1eff9](https://github.com/koki-develop/mask-go/commit/6d1eff9fc46be6089716dddc2502714255c98211))
* Locate a Notion API token ([#8](https://github.com/koki-develop/mask-go/issues/8)) ([6dc4f7f](https://github.com/koki-develop/mask-go/commit/6dc4f7f3202905fa8ad68d9e0d172ca9c8a6f242))
* Locate a private key ([#18](https://github.com/koki-develop/mask-go/issues/18)) ([1c27e1a](https://github.com/koki-develop/mask-go/commit/1c27e1af56d778edd73d4894e4ad72306d1be67c))
* Locate a PyPI API token ([#2](https://github.com/koki-develop/mask-go/issues/2)) ([d0c37bd](https://github.com/koki-develop/mask-go/commit/d0c37bd8855076431c20a99b1ab8ec11bb50883f))
* Locate a RubyGems API key ([#13](https://github.com/koki-develop/mask-go/issues/13)) ([ae73fbe](https://github.com/koki-develop/mask-go/commit/ae73fbec9234624f46edf5b216ea6a924cdff9ed))
* Locate a SendGrid API key ([#5](https://github.com/koki-develop/mask-go/issues/5)) ([baa320f](https://github.com/koki-develop/mask-go/commit/baa320fd276aaf3669449b151680948c77ae3ff4))
* Locate a Sentry auth token ([#6](https://github.com/koki-develop/mask-go/issues/6)) ([80a81c0](https://github.com/koki-develop/mask-go/commit/80a81c017e1a9a79e0db56542b9602f168a255a8))
* Locate a Slack token ([3dbdfd3](https://github.com/koki-develop/mask-go/commit/3dbdfd3a61f95c8e156afe0c156e7c7354d21360))
* Locate a Stripe API key ([#1](https://github.com/koki-develop/mask-go/issues/1)) ([a9b6938](https://github.com/koki-develop/mask-go/commit/a9b693830b41da53fdd50913123575f8068c2d73))
* Locate a Stripe webhook signing secret ([#16](https://github.com/koki-develop/mask-go/issues/16)) ([9ad3a6e](https://github.com/koki-develop/mask-go/commit/9ad3a6e4cd19e89edcbdb9ef10c2d0660c52987f))
* Locate a Supabase personal access token ([#12](https://github.com/koki-develop/mask-go/issues/12)) ([c67b269](https://github.com/koki-develop/mask-go/commit/c67b2698191a410deb1ecd84f58d8e4b99131712))
* Locate a user access token written in the stateless form ([00f9ec7](https://github.com/koki-develop/mask-go/commit/00f9ec7c9aa681bb076db58604936786d46dbc32))
* Locate an Anthropic API key ([c890cc3](https://github.com/koki-develop/mask-go/commit/c890cc3b7a8e959d2619da8c673d4abc4b940913))
* Locate an AWS access key ID ([aba8a53](https://github.com/koki-develop/mask-go/commit/aba8a5376d28e6f36ad6d8feb90bbfa19889663f))
* Locate an AWS secret access key ([b85d46c](https://github.com/koki-develop/mask-go/commit/b85d46cbfa09302f974cac5dc6d605ec5a08caf1))
* Locate an npm token ([#3](https://github.com/koki-develop/mask-go/issues/3)) ([4d9954e](https://github.com/koki-develop/mask-go/commit/4d9954eb0ab3c4c3daa7bda6e777a86209ddb614))
* Locate an OpenAI API key ([4e8a6d2](https://github.com/koki-develop/mask-go/commit/4e8a6d29ed741d47b72671f1d8b934699343fc5a))
* Locate an OpenRouter API key ([#14](https://github.com/koki-develop/mask-go/issues/14)) ([b4ece78](https://github.com/koki-develop/mask-go/commit/b4ece786bb9e8ded334332b82e5b71aa518b64d4))
* Mask text that arrives a piece at a time ([8027886](https://github.com/koki-develop/mask-go/commit/80278865ceed23466441aa0c215e57b66f8fa574))
* Release v0.0.1 ([969f1e1](https://github.com/koki-develop/mask-go/commit/969f1e1298eccb158f914d49c54cff80d9d95307))


### Bug Fixes

* Anchor a stateless token's JWT on what opens a JOSE header ([7d412eb](https://github.com/koki-develop/mask-go/commit/7d412ebab0b516a3ff6fe00b71696f3f4450d351))
* Ask a Slack token for a part in front of its secret ([03a0e70](https://github.com/koki-develop/mask-go/commit/03a0e708f8e56919c8f22d00e3137247e740f2d5))
* Locate a credential that begins inside another ([b274df3](https://github.com/koki-develop/mask-go/commit/b274df3c1e238e5991cac12a37c54dadc9d97706))
* Locate a JOSE header written with a space behind the brace ([5f56921](https://github.com/koki-develop/mask-go/commit/5f5692154308964c06d4c6138d552cbfdbda18da))
* Locate a JWT whose header does not open with a letter ([833e1ff](https://github.com/koki-develop/mask-go/commit/833e1ff155768a737cc8b1cb7159c5127d20535a))
* Locate a Stripe key written against the key in front of it ([c610bcd](https://github.com/koki-develop/mask-go/commit/c610bcdf092fda236f80093cedbe7044f2ab9955))
* Name the npm pattern what npm names the token ([#11](https://github.com/koki-develop/mask-go/issues/11)) ([cdf01da](https://github.com/koki-develop/mask-go/commit/cdf01daffde14627c709ac09524f5da52c06c43a))
* Read both counts GitLab writes for a pipeline trigger token ([657a170](https://github.com/koki-develop/mask-go/commit/657a1704833d72ce1fced284d33d26a414fb4993))
* Redact a stateless installation token whole ([aafe29d](https://github.com/koki-develop/mask-go/commit/aafe29d7655f38b8be37c3506908d08240b9ca02))
* Redact every group a pattern names mask ([8297cde](https://github.com/koki-develop/mask-go/commit/8297cde2b5d30f29a2a6fc422a9fd750bf054a20))
* Run the secret scan on the files a push carries ([4384500](https://github.com/koki-develop/mask-go/commit/438450063ebe8a1ef46a74c290efadb9d347b018))
* Say what a Stripe scan does now that a key may be written against a key ([acc5440](https://github.com/koki-develop/mask-go/commit/acc5440037c98d0dbfa7a1688afd5b0958a8fccd))
* Settle a regexp pattern's offset to the whole of the rule it states ([b6452de](https://github.com/koki-develop/mask-go/commit/b6452de77854b38c56dc580397991281e6c69e1c))


### Performance Improvements

* Locate GitHub tokens without a regular expression ([7ec18d9](https://github.com/koki-develop/mask-go/commit/7ec18d985a943b359661bdb2d4b780498fdb0367))
* Search for the rarest byte of a prefix rather than the prefix ([4445dc8](https://github.com/koki-develop/mask-go/commit/4445dc80272e604eda8c38a30ac9201c851df794))
