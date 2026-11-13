import {
	buildSAReadPermission,
	buildSAUpdatePermission,
} from 'lib/authz/hooks/useAuthZ/permissions/service-account.permissions';
import {
	setupAuthzAdmin,
	setupAuthzDeny,
} from 'lib/authz/utils/authz-test-utils';
import { rest, server } from 'mocks-server/server';
import { render, screen, userEvent, waitFor } from 'tests/test-utils';

import OverviewTab from '../OverviewTab';

const ENDPOINT = '*/api/v1/service_accounts/:id/oidc';
const ISSUER = 'https://keycloak.example.com/realms/platform';

function overview(id = 'sa-1', status = 'ACTIVE'): JSX.Element {
	return (
		<OverviewTab
			account={{
				id,
				status,
				name: 'CI Bot',
				email: 'ci@example.com',
				createdAt: null,
				updatedAt: null,
			}}
			localName="CI Bot"
			onNameChange={jest.fn()}
			localRoles={[]}
			onRolesChange={jest.fn()}
			isDisabled={status === 'DELETED'}
			availableRoles={[]}
		/>
	);
}

describe('Service account Keycloak authentication', () => {
	beforeEach(() => {
		server.use(setupAuthzAdmin());
	});

	it('loads the existing client binding and shows issuer and audience without secrets', async () => {
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: {
								issuer: ISSUER,
								clientId: 'existing-client',
								subject: 'keycloak-service-account-subject',
							},
						},
					}),
				),
			),
		);
		render(overview());
		await expect(screen.findByTestId('sa-oidc-client-id')).resolves.toHaveValue(
			'existing-client',
		);
		expect(screen.getByTestId('sa-oidc-subject')).toHaveValue(
			'keycloak-service-account-subject',
		);
		expect(screen.getByTestId('sa-oidc-issuer')).toHaveValue(ISSUER);
		expect(screen.getByTestId('sa-oidc-issuer')).toHaveAttribute('readonly');
		expect(screen.getByTestId('sa-oidc-audience')).toHaveValue('signoz-api');
		expect(screen.queryByLabelText(/client secret/i)).not.toBeInTheDocument();
		expect(document.querySelector('input[type="password"]')).toBeNull();
	});

	it('saves only the existing client ID and subject, then removes the binding', async () => {
		const user = userEvent.setup({ pointerEventsCheck: 0 });
		let binding: { clientId: string; subject: string } | null = null;
		let savedBody: object | null = null;
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: binding ? { ...binding, issuer: ISSUER } : null,
						},
					}),
				),
			),
			rest.put(ENDPOINT, async (req, res, ctx) => {
				const body = await req.json<{ clientId: string; subject: string }>();
				savedBody = body;
				binding = body;
				return res(ctx.status(204));
			}),
			rest.delete(ENDPOINT, (_, res, ctx) => {
				binding = null;
				return res(ctx.status(204));
			}),
		);
		render(overview());
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-client-id')).not.toBeDisabled(),
		);
		await user.type(
			await screen.findByTestId('sa-oidc-client-id'),
			' existing-client ',
		);
		await user.type(
			screen.getByTestId('sa-oidc-subject'),
			' service-account-subject ',
		);
		await user.click(screen.getByTestId('sa-oidc-save'));
		await expect(screen.findByTestId('sa-oidc-saved')).resolves.toHaveTextContent(
			'Keycloak authentication saved.',
		);
		expect(savedBody).toStrictEqual({
			clientId: 'existing-client',
			subject: 'service-account-subject',
		});
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-remove')).toHaveAttribute(
				'aria-disabled',
				'false',
			),
		);
		await user.click(screen.getByTestId('sa-oidc-remove'));
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-client-id')).toHaveValue(''),
		);
		expect(binding).toBeNull();
	});

	it('does not fetch a binding without service-account read permission', async () => {
		const reads: string[] = [];
		server.use(
			setupAuthzDeny(buildSAReadPermission('sa-2')),
			rest.get(ENDPOINT, (req, res, ctx) => {
				reads.push(String(req.params.id));
				return res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: null,
						},
					}),
				);
			}),
		);
		const { rerender } = render(overview('sa-1'));
		await expect(screen.findByTestId('sa-oidc-client-id')).resolves.toHaveValue(
			'',
		);
		rerender(overview('sa-2'));
		await expect(
			screen.findByText(/read:serviceaccount:sa-2/),
		).resolves.toBeInTheDocument();
		expect(reads).toStrictEqual(['sa-1']);
		expect(screen.queryByTestId('sa-oidc-client-id')).not.toBeInTheDocument();
	});

	it('allows reading but prevents editing when update permission is denied', async () => {
		server.use(
			setupAuthzDeny(buildSAUpdatePermission('sa-1')),
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: {
								issuer: ISSUER,
								clientId: 'existing-client',
								subject: 'subject-1',
							},
						},
					}),
				),
			),
		);
		render(overview());
		await expect(
			screen.findByTestId('sa-oidc-client-id'),
		).resolves.toBeDisabled();
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-save')).toHaveAttribute(
				'aria-disabled',
				'true',
			),
		);
		expect(screen.getByTestId('sa-oidc-remove')).toHaveAttribute(
			'aria-disabled',
			'true',
		);
	});

	it('allows removing an existing binding while token authentication is disabled', async () => {
		const user = userEvent.setup({ pointerEventsCheck: 0 });
		let binding: { clientId: string; subject: string } | null = {
			clientId: 'old-client',
			subject: 'old-subject',
		};
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: false,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: binding ? { ...binding, issuer: ISSUER } : null,
						},
					}),
				),
			),
			rest.delete(ENDPOINT, (_, res, ctx) => {
				binding = null;
				return res(ctx.status(204));
			}),
		);
		render(overview());
		await expect(
			screen.findByTestId('sa-oidc-status'),
		).resolves.toHaveTextContent('Disabled');
		expect(screen.queryByTestId('sa-oidc-save')).not.toBeInTheDocument();
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-remove')).toHaveAttribute(
				'aria-disabled',
				'false',
			),
		);
		await user.click(screen.getByTestId('sa-oidc-remove'));
		await waitFor(() =>
			expect(screen.queryByTestId('sa-oidc-remove')).not.toBeInTheDocument(),
		);
		expect(binding).toBeNull();
	});

	it('does not offer mutations for a deleted account', async () => {
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: {
								issuer: ISSUER,
								clientId: 'existing-client',
								subject: 'subject-1',
							},
						},
					}),
				),
			),
		);
		render(overview('sa-1', 'DELETED'));
		await expect(
			screen.findByTestId('sa-oidc-client-id'),
		).resolves.toBeDisabled();
		expect(screen.getByTestId('sa-oidc-save')).toHaveAttribute(
			'aria-disabled',
			'true',
		);
		expect(screen.getByTestId('sa-oidc-remove')).toHaveAttribute(
			'aria-disabled',
			'true',
		);
	});

	it('keeps bindings and drafts separate when switching accounts', async () => {
		server.use(
			rest.get(ENDPOINT, (req, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: {
								issuer: ISSUER,
								clientId: `client-${String(req.params.id)}`,
								subject: `subject-${String(req.params.id)}`,
							},
						},
					}),
				),
			),
		);
		const { rerender } = render(overview('sa-1'));
		await expect(screen.findByTestId('sa-oidc-client-id')).resolves.toHaveValue(
			'client-sa-1',
		);
		rerender(overview('sa-2'));
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-client-id')).toHaveValue('client-sa-2'),
		);
		expect(screen.getByTestId('sa-oidc-subject')).toHaveValue('subject-sa-2');
	});

	it('keeps the draft and displays an error when saving fails', async () => {
		const user = userEvent.setup({ pointerEventsCheck: 0 });
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: null,
						},
					}),
				),
			),
			rest.put(ENDPOINT, (_, res, ctx) => res(ctx.status(500))),
		);
		render(overview());
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-client-id')).not.toBeDisabled(),
		);
		await user.type(
			await screen.findByTestId('sa-oidc-client-id'),
			'existing-client',
		);
		await user.type(screen.getByTestId('sa-oidc-subject'), 'subject-1');
		await user.click(screen.getByTestId('sa-oidc-save'));
		await expect(screen.findByTestId('sa-oidc-error')).resolves.toHaveTextContent(
			'Unable to save Keycloak authentication. Try again.',
		);
		expect(screen.getByTestId('sa-oidc-client-id')).toHaveValue(
			'existing-client',
		);
	});

	it('requires explicit removal of a binding from a previous issuer', async () => {
		const user = userEvent.setup({ pointerEventsCheck: 0 });
		let removed = false;
		server.use(
			rest.get(ENDPOINT, (_, res, ctx) =>
				res(
					ctx.json({
						data: {
							enabled: true,
							issuer: ISSUER,
							audience: 'signoz-api',
							binding: {
								issuer: 'https://old-keycloak.example.com/realms/old',
								clientId: 'old-client',
								subject: 'old-subject',
							},
						},
					}),
				),
			),
			rest.delete(ENDPOINT, (_, res, ctx) => {
				removed = true;
				return res(ctx.status(204));
			}),
		);
		render(overview());
		await expect(screen.findByTestId('sa-oidc-stale')).resolves.toHaveTextContent(
			'Remove it before saving a new binding.',
		);
		expect(screen.getByTestId('sa-oidc-bound-issuer')).toHaveValue(
			'https://old-keycloak.example.com/realms/old',
		);
		expect(screen.getByTestId('sa-oidc-save')).toHaveAttribute(
			'aria-disabled',
			'true',
		);
		await waitFor(() =>
			expect(screen.getByTestId('sa-oidc-remove')).toHaveAttribute(
				'aria-disabled',
				'false',
			),
		);
		await user.click(screen.getByTestId('sa-oidc-remove'));
		await waitFor(() =>
			expect(screen.queryByTestId('sa-oidc-stale')).not.toBeInTheDocument(),
		);
		expect(removed).toBe(true);
	});
});
