// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightVersions from 'starlight-versions';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';

// https://astro.build/config
export default defineConfig({
	site: 'https://starfly.dev',
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Starfly',
			description: 'Non-human identity for the agentic fabric.',
			defaultLocale: 'root',
			locales: {
				root: {
					label: 'English',
					lang: 'en',
				},
			},
			customCss: ['./src/styles/starfly.css'],
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/raygj/project-starfly-fabrics',
				},
			],
			plugins: [
				starlightVersions({
					versions: [{ slug: '1.0', label: 'v1.0' }],
				}),
				starlightOpenAPI([
					{
						base: 'api',
						schema: './openapi.yaml',
						sidebar: { label: 'REST API' },
					},
				]),
			],
			sidebar: [
				{
					label: 'Start',
					items: [
						{ label: 'Documentation hub', slug: 'docs' },
						{ label: 'Getting started', slug: 'docs/getting-started' },
						{ label: 'Playground', link: '/play/' },
					],
				},
				{
					label: 'Explanation',
					items: [
						{ label: 'Glossary', slug: 'docs/glossary' },
						{ label: 'Trust domains', slug: 'docs/concepts/trust-domains' },
						{ label: 'Exchange', slug: 'docs/concepts/exchange' },
						{ label: 'Revocation', slug: 'docs/concepts/revocation' },
					],
				},
				{
					label: 'Integrators',
					items: [
						{ label: 'Token exchange', slug: 'docs/integrators/token-exchange' },
						{ label: 'Credential patterns', slug: 'docs/integrators/credential-patterns' },
						{ label: 'MCP security', slug: 'docs/integrators/mcp' },
						{ label: 'UTC (multi-protocol tools)', slug: 'docs/integrators/utc' },
						{ label: 'Operations dashboard', slug: 'docs/integrators/dashboard' },
						{ label: 'Starfly Graph', slug: 'docs/integrators/starfly-graph' },
					],
				},
				{
					label: 'Terraform',
					items: [
						{ label: 'Overview', slug: 'terraform' },
						{ label: 'Quick start', slug: 'terraform/quickstart' },
						{ label: 'Resources', slug: 'terraform/resources' },
						{ label: 'Authentication', slug: 'terraform/auth' },
					],
				},
				...openAPISidebarGroups,
			],
			head: [
				{
					tag: 'link',
					attrs: {
						rel: 'canonical',
						href: 'https://starfly.dev/',
					},
				},
			],
		}),
	],
});
