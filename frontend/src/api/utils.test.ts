import ROUTES from 'constants/routes';
import { getCurrentLocation } from 'lib/router/navigation';

import { Logout } from './utils';
import deleteSession from './v2/sessions/delete';

jest.mock('./v2/sessions/delete');

describe('Logout', () => {
	const assign = jest.fn();
	const originalLocation = window.location;

	beforeAll(() => {
		Object.defineProperty(window, 'location', {
			configurable: true,
			value: { assign },
		});
	});

	afterAll(() => {
		Object.defineProperty(window, 'location', {
			configurable: true,
			value: originalLocation,
		});
	});

	beforeEach(() => {
		jest.clearAllMocks();
		localStorage.setItem('AUTH_TOKEN', 'access-token');
	});

	it('requests provider logout on an explicit sign-out and follows its URL', async () => {
		jest.mocked(deleteSession).mockResolvedValue({
			httpStatusCode: 200,
			data: { logoutURL: 'https://keycloak.example.com/logout?client_id=signoz' },
		});
		await Logout(true);
		expect(deleteSession).toHaveBeenCalledWith(true);
		expect(localStorage.getItem('AUTH_TOKEN')).toBeNull();
		expect(assign).toHaveBeenCalledWith(
			'https://keycloak.example.com/logout?client_id=signoz',
		);
	});

	it('keeps automatic session cleanup local', async () => {
		jest
			.mocked(deleteSession)
			.mockResolvedValue({ httpStatusCode: 204, data: null });
		await Logout();
		expect(deleteSession).toHaveBeenCalledWith(false);
		expect(assign).not.toHaveBeenCalled();
		expect(getCurrentLocation().pathname).toBe(ROUTES.LOGIN);
	});

	it('still clears local credentials if the logout request fails', async () => {
		const error = jest
			.spyOn(console, 'error')
			.mockImplementation(() => undefined);
		jest
			.mocked(deleteSession)
			.mockRejectedValue(new Error('provider unavailable'));
		await Logout(true);
		expect(localStorage.getItem('AUTH_TOKEN')).toBeNull();
		expect(assign).not.toHaveBeenCalled();
		expect(getCurrentLocation().pathname).toBe(ROUTES.LOGIN);
		error.mockRestore();
	});
});
