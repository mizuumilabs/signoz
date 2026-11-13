/**
 * AI-owned. Generated and maintained by the `signoz-page-story` skill.
 * Do not hand-edit: regenerate instead.
 */

import type {
	ServiceAccountOIDCBinding,
	ServiceAccountOIDCSettings,
} from 'components/ServiceAccountDrawer/useServiceAccountOIDC';

export const KEYCLOAK_BINDING: ServiceAccountOIDCBinding = {
	issuer: 'https://keycloak.example.com/realms/platform',
	clientId: 'ci-pipeline',
	subject: 'c9946353-f0e4-4d7c-9090-7b3c8253ef51',
};

export function serviceAccountOIDCResponse(
	enabled: boolean,
	binding: ServiceAccountOIDCBinding | null,
): { status: 'success'; data: ServiceAccountOIDCSettings } {
	return {
		status: 'success',
		data: {
			enabled,
			issuer: 'https://keycloak.example.com/realms/platform',
			audience: 'signoz-api',
			binding,
		},
	};
}
