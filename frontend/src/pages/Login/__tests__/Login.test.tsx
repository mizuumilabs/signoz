import { rest, server } from 'mocks-server/server';
import { render, screen, userEvent, waitFor } from 'tests/test-utils';

import Login from '../index';

const CONFIG_ENDPOINT = '*/api/v2/sessions/oidc';
const LOGIN_URL = '/signoz/api/v2/sessions/oidc/login';

describe('Instance OIDC login', () => {
	beforeEach(() => {
		localStorage.clear();
		server.use(
			rest.get(CONFIG_ENDPOINT, (_, res, ctx) =>
				res(ctx.json({ data: { enabled: true, loginURL: LOGIN_URL } })),
			),
		);
	});

	it('replaces email and password login with Keycloak', async () => {
		render(<Login />, undefined, { initialRoute: '/login?password=Y' });

		await expect(screen.findByTestId('oidc-login')).resolves.toHaveTextContent(
			'Continue with Keycloak',
		);
		expect(screen.queryByTestId('email')).not.toBeInTheDocument();
		expect(screen.queryByTestId('password')).not.toBeInTheDocument();
	});

	it('uses the deployment-prefixed login URL', async () => {
		const user = userEvent.setup({ pointerEventsCheck: 0 });
		const originalLocation = window.location;
		Object.defineProperty(window, 'location', {
			value: { href: 'http://localhost/login', origin: 'http://localhost' },
			writable: true,
		});

		try {
			render(<Login />);
			await user.click(await screen.findByTestId('oidc-login'));
			expect(window.location.href).toBe(LOGIN_URL);
		} finally {
			Object.defineProperty(window, 'location', { value: originalLocation });
		}
	});

	it('keeps the existing login form when OIDC is disabled', async () => {
		server.use(
			rest.get(CONFIG_ENDPOINT, (_, res, ctx) =>
				res(ctx.json({ data: { enabled: false } })),
			),
		);

		render(<Login />);
		await expect(screen.findByTestId('email')).resolves.toBeInTheDocument();
		expect(screen.queryByTestId('oidc-login')).not.toBeInTheDocument();
	});

	it('fails closed when authentication configuration is unavailable', async () => {
		server.use(rest.get(CONFIG_ENDPOINT, (_, res, ctx) => res(ctx.status(503))));

		render(<Login />);
		await expect(
			screen.findByTestId('oidc-config-error'),
		).resolves.toHaveTextContent('Unable to load sign-in settings. Try again.');
		expect(screen.queryByTestId('email')).not.toBeInTheDocument();
	});

	it('exchanges the browser handoff once without tokens in the URL', async () => {
		let exchanges = 0;
		server.use(
			rest.post('*/api/v2/sessions/oidc/session', (_, res, ctx) => {
				exchanges += 1;
				return res(
					ctx.json({
						data: { accessToken: 'oidc-access', refreshToken: 'oidc-refresh' },
					}),
				);
			}),
		);

		render(<Login />, undefined, { initialRoute: '/login?oidcComplete=true' });
		await waitFor(() => {
			expect(localStorage.getItem('AUTH_TOKEN')).toBe('oidc-access');
			expect(localStorage.getItem('REFRESH_AUTH_TOKEN')).toBe('oidc-refresh');
		});
		expect(exchanges).toBe(1);
	});

	it('shows a retryable error after a failed handoff', async () => {
		server.use(
			rest.post('*/api/v2/sessions/oidc/session', (_, res, ctx) =>
				res(ctx.status(403)),
			),
		);

		render(<Login />, undefined, { initialRoute: '/login?oidcComplete=true' });
		await expect(
			screen.findByTestId('oidc-login-error'),
		).resolves.toHaveTextContent(
			'Unable to sign in with Keycloak. Please try again.',
		);
		expect(screen.getByTestId('oidc-login')).toHaveTextContent(
			'Continue with Keycloak',
		);
		expect(localStorage.getItem('AUTH_TOKEN')).toBeNull();
	});

	it('shows a generic callback error without reflecting provider details', async () => {
		render(<Login />, undefined, {
			initialRoute: '/login?oidcError=sensitive-provider-details',
		});

		await expect(
			screen.findByTestId('oidc-login-error'),
		).resolves.toHaveTextContent(
			'Unable to sign in with Keycloak. Please try again.',
		);
		expect(
			screen.queryByText('sensitive-provider-details'),
		).not.toBeInTheDocument();
	});
});
