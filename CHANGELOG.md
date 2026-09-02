# Changelog

## [0.3.0](https://github.com/koki-develop/mask-go/compare/v0.2.0...v0.3.0) (2026-09-01)


### ⚠ BREAKING CHANGES

* AnthropicAPIKey is now AnthropicCredential, and the name it reports is "anthropic-credential" rather than "anthropic-api-key".

### Features

* Locate a Neon API key ([#67](https://github.com/koki-develop/mask-go/issues/67)) ([#113](https://github.com/koki-develop/mask-go/issues/113)) ([b37fda4](https://github.com/koki-develop/mask-go/commit/b37fda42c63b8c0314da505e23336b08a1164c35))
* Locate a Netlify authentication token ([#104](https://github.com/koki-develop/mask-go/issues/104)) ([#111](https://github.com/koki-develop/mask-go/issues/111)) ([746e984](https://github.com/koki-develop/mask-go/commit/746e98437f51e83b6010507c74ead229650923e3))
* Locate a Pinecone API key ([#65](https://github.com/koki-develop/mask-go/issues/65)) ([#112](https://github.com/koki-develop/mask-go/issues/112)) ([eeefc61](https://github.com/koki-develop/mask-go/commit/eeefc6155b084b2a92dcea3d0d0d8f7497ac8821))
* Locate a Render API key ([#103](https://github.com/koki-develop/mask-go/issues/103)) ([#121](https://github.com/koki-develop/mask-go/issues/121)) ([25e5bc3](https://github.com/koki-develop/mask-go/commit/25e5bc3b2e67f2bfb388e90e9286f477902f584b))
* Locate a Shippo API token ([#95](https://github.com/koki-develop/mask-go/issues/95)) ([#122](https://github.com/koki-develop/mask-go/issues/122)) ([2d0030a](https://github.com/koki-develop/mask-go/commit/2d0030a600bd8a32dfbd0d3f8c0a60f7885b204e))
* Locate an Ory API key ([#117](https://github.com/koki-develop/mask-go/issues/117)) ([#120](https://github.com/koki-develop/mask-go/issues/120)) ([5afd1c4](https://github.com/koki-develop/mask-go/commit/5afd1c4e73b1423b3e0d36013a0a55fac81508f2))
* Name the Anthropic pattern for the whole of what it locates ([cf3bc29](https://github.com/koki-develop/mask-go/commit/cf3bc29e319a0605c3e2e8288a994e3944316d56))
* Release v0.3.0 ([eea1f94](https://github.com/koki-develop/mask-go/commit/eea1f94009b29293c206c7d5dc248041eb8a2a6f))


### Bug Fixes

* Answer the generic rules betterleaks 1.8.1 added, one kind at a time ([#123](https://github.com/koki-develop/mask-go/issues/123)) ([5e1b3f9](https://github.com/koki-develop/mask-go/commit/5e1b3f99973705710bac52076e808f99e0ce2e74))
* Ask where the ordered run stands, not only that it stands ([14f0f80](https://github.com/koki-develop/mask-go/commit/14f0f80d9984cc4e10ba7b6f2beb2b43ec88f4cb))


### Performance Improvements

* Turn a pattern away on a text that holds none of its openings ([#135](https://github.com/koki-develop/mask-go/issues/135)) ([3ff2320](https://github.com/koki-develop/mask-go/commit/3ff232051d4d224314b400d9e973c5a8c7d405d5))

## [0.2.0](https://github.com/koki-develop/mask-go/compare/v0.1.0...v0.2.0) (2026-08-30)


### Features

* Add Regexp, which returns an error where MustRegexp panics ([6ec677f](https://github.com/koki-develop/mask-go/commit/6ec677f759b7bd9f350a2aba3c4ce8dab631f4ab))
* Locate a Buildkite token ([#70](https://github.com/koki-develop/mask-go/issues/70)) ([#107](https://github.com/koki-develop/mask-go/issues/107)) ([92f2d19](https://github.com/koki-develop/mask-go/commit/92f2d1954d2c4b97aae187defa93a2ec4ab6eb56))
* Locate a Dynatrace token ([#45](https://github.com/koki-develop/mask-go/issues/45)) ([#61](https://github.com/koki-develop/mask-go/issues/61)) ([59e32a5](https://github.com/koki-develop/mask-go/commit/59e32a59249aaf0deb1e5693391e4c551f298c99))
* Locate a Fly.io access token ([#76](https://github.com/koki-develop/mask-go/issues/76)) ([#100](https://github.com/koki-develop/mask-go/issues/100)) ([be16192](https://github.com/koki-develop/mask-go/commit/be1619203da33c5f87819b295ebe7f5bcfc529e7))
* Locate a Groq API key ([#62](https://github.com/koki-develop/mask-go/issues/62)) ([#71](https://github.com/koki-develop/mask-go/issues/71)) ([2e366d5](https://github.com/koki-develop/mask-go/commit/2e366d598e10f05cac4bfb13a28636e086bcc1ee))
* Locate a New Relic user key ([#74](https://github.com/koki-develop/mask-go/issues/74)) ([#94](https://github.com/koki-develop/mask-go/issues/94)) ([5a97261](https://github.com/koki-develop/mask-go/commit/5a97261eda0166973547d58a07c130706358eedf))
* Locate a Paddle API key ([#86](https://github.com/koki-develop/mask-go/issues/86)) ([#92](https://github.com/koki-develop/mask-go/issues/92)) ([5dc1172](https://github.com/koki-develop/mask-go/commit/5dc1172e1e508a7132f10ef9db227e1a78078f5b))
* Locate a PostHog personal API key ([#81](https://github.com/koki-develop/mask-go/issues/81)) ([#93](https://github.com/koki-develop/mask-go/issues/93)) ([6576392](https://github.com/koki-develop/mask-go/commit/6576392a9230810a6cf21e544fb1e6a38bde59a3))
* Locate a Replicate API token ([#46](https://github.com/koki-develop/mask-go/issues/46)) ([#58](https://github.com/koki-develop/mask-go/issues/58)) ([b428339](https://github.com/koki-develop/mask-go/commit/b428339cef7e63953a619aec975579698892be67))
* Locate a Resend API key ([#68](https://github.com/koki-develop/mask-go/issues/68)) ([#72](https://github.com/koki-develop/mask-go/issues/72)) ([5f46c15](https://github.com/koki-develop/mask-go/commit/5f46c158b4996814647f8b161a7aee842e3e56fd))
* Locate a SonarQube user token, analysis token and project badge token ([#50](https://github.com/koki-develop/mask-go/issues/50)) ([#59](https://github.com/koki-develop/mask-go/issues/59)) ([eee4a61](https://github.com/koki-develop/mask-go/commit/eee4a6102dca1d2ca021b9b02f71dc3ee1e23d1c))
* Locate an HCP Terraform API token ([#75](https://github.com/koki-develop/mask-go/issues/75)) ([#108](https://github.com/koki-develop/mask-go/issues/108)) ([c1f0ab9](https://github.com/koki-develop/mask-go/commit/c1f0ab9ee99309ea4a73b88b85d9f42d11435770))
* Locate an xAI API key and a management API key ([#63](https://github.com/koki-develop/mask-go/issues/63)) ([#73](https://github.com/koki-develop/mask-go/issues/73)) ([2f9cc6f](https://github.com/koki-develop/mask-go/commit/2f9cc6ff4d4dbb9d809a11b4143fdb699af7480f))


### Bug Fixes

* Release a rune whole or not at all, and state what giving up owes ([#110](https://github.com/koki-develop/mask-go/issues/110)) ([ac7e93d](https://github.com/koki-develop/mask-go/commit/ac7e93d85797dc77eaba398b6a60a7c8bb1fa2c6))

## [0.1.0](https://github.com/koki-develop/mask-go/compare/v0.0.1...v0.1.0) (2026-08-29)


### Features

* Locate a 1Password service account token ([#47](https://github.com/koki-develop/mask-go/issues/47)) ([#55](https://github.com/koki-develop/mask-go/issues/55)) ([daf4cdc](https://github.com/koki-develop/mask-go/commit/daf4cdc8e08c05e33d68de944c1f94ce80992694))
* Locate a CircleCI personal API token and a project API token ([#43](https://github.com/koki-develop/mask-go/issues/43)) ([308ccfb](https://github.com/koki-develop/mask-go/commit/308ccfbf44735d6bdeb294b500b71d4f7f181c29))
* Locate a crates.io API token and a Trusted Publishing token ([#25](https://github.com/koki-develop/mask-go/issues/25)) ([f1bf787](https://github.com/koki-develop/mask-go/commit/f1bf7873d8e8b2e0b94e5969317776c1dbe7ff90))
* Locate a Databricks OAuth client secret ([#30](https://github.com/koki-develop/mask-go/issues/30)) ([011abc4](https://github.com/koki-develop/mask-go/commit/011abc48309de02c83c0f17e20b3a9423576df7c))
* Locate a Databricks personal access token ([#28](https://github.com/koki-develop/mask-go/issues/28)) ([332c813](https://github.com/koki-develop/mask-go/commit/332c8132fd395e951b0434d76b7813db092be751))
* Locate a DigitalOcean personal access token, an OAuth token and a refresh token ([#26](https://github.com/koki-develop/mask-go/issues/26)) ([d2ba57e](https://github.com/koki-develop/mask-go/commit/d2ba57ebcf0109fdf3ee20c21af99804e8abfedc))
* Locate a Docker personal access token ([#52](https://github.com/koki-develop/mask-go/issues/52)) ([#56](https://github.com/koki-develop/mask-go/issues/56)) ([f631bb8](https://github.com/koki-develop/mask-go/commit/f631bb864727ec3d3f29d344a03e9d04e93e5dcf))
* Locate a Doppler auth token ([#40](https://github.com/koki-develop/mask-go/issues/40)) ([a572fb9](https://github.com/koki-develop/mask-go/commit/a572fb9f6785084bc7b9792d26033b987ab4fd84))
* Locate a Heroku API token ([#36](https://github.com/koki-develop/mask-go/issues/36)) ([a54575d](https://github.com/koki-develop/mask-go/commit/a54575d727f909becbf8a7a435a484c5fa2455e8))
* Locate a Hugging Face user access token ([#24](https://github.com/koki-develop/mask-go/issues/24)) ([2ae9c6a](https://github.com/koki-develop/mask-go/commit/2ae9c6a907206be54a4ef49685d4788395e54ca8))
* Locate a PlanetScale service token, an OAuth access token and a refresh token ([#32](https://github.com/koki-develop/mask-go/issues/32)) ([2d1dfb7](https://github.com/koki-develop/mask-go/commit/2d1dfb709aba2430429b655e4e54c17cc40f7945))
* Locate a Postman API key ([#27](https://github.com/koki-develop/mask-go/issues/27)) ([c0e7329](https://github.com/koki-develop/mask-go/commit/c0e7329f179dc374d2bdd899d0472376872c63cc))
* Locate a Pulumi access token ([#31](https://github.com/koki-develop/mask-go/issues/31)) ([1a64308](https://github.com/koki-develop/mask-go/commit/1a64308753f4a3bf23a8f22cd496fc2add2f24cf))
* Locate a Shopify access token and an app secret key ([#41](https://github.com/koki-develop/mask-go/issues/41)) ([9d9211f](https://github.com/koki-develop/mask-go/commit/9d9211f98a34d53629f5a326a1fb37618bf42683))
* Locate a Sourcegraph access token ([#34](https://github.com/koki-develop/mask-go/issues/34)) ([b29300a](https://github.com/koki-develop/mask-go/commit/b29300a74a2344479c0162e228ccf723c79d95df))
* Locate a Supabase publishable key and a Supabase secret key ([#22](https://github.com/koki-develop/mask-go/issues/22)) ([4f10b3e](https://github.com/koki-develop/mask-go/commit/4f10b3ebbfdbb03fe06fbc1ded5755a11733d83b))
* Locate an age secret key and a post-quantum hybrid one ([#54](https://github.com/koki-develop/mask-go/issues/54)) ([fea8089](https://github.com/koki-develop/mask-go/commit/fea80893fdc5b706ef52b618baafcd2e8ea52b6e))
* Locate an Airtable personal access token ([#35](https://github.com/koki-develop/mask-go/issues/35)) ([e38299d](https://github.com/koki-develop/mask-go/commit/e38299df6882cf8abf1eff5dc66049e4007e211b))


### Performance Improvements

* **ci:** divide the run under the race detector and take the repeated work out of it ([#53](https://github.com/koki-develop/mask-go/issues/53)) ([2cb26b3](https://github.com/koki-develop/mask-go/commit/2cb26b31d3438d1a30850fb9bb876a6ef026c0d3))

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
