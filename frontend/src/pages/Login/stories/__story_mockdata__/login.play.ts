/**
 * AI-owned. Generated and maintained by the `signoz-page-story` skill.
 * Do not hand-edit: regenerate instead.
 */

import { expect, userEvent, waitFor, within } from 'storybook/test';

import { LOGIN_EMAIL } from './login';

export async function showSignInStep({
	canvasElement,
	args,
}: {
	canvasElement: HTMLElement;
	args: { oidc: boolean; orgs: number; authN: string; dataState?: string };
}): Promise<void> {
	const canvas = within(canvasElement);
	if (args.dataState && args.dataState !== 'loaded') {
		return;
	}
	if (args.oidc) {
		await expect(await canvas.findByTestId('oidc-login')).toBeVisible();
		return;
	}
	const email = await canvas.findByTestId('email');
	await waitFor(() => expect(email).toBeEnabled());
	await userEvent.type(email, LOGIN_EMAIL);
	await userEvent.click(canvas.getByTestId('initiate_login'));
	if (args.orgs > 1) {
		await expect(await canvas.findByTestId('orgId')).toBeVisible();
	} else if (args.orgs === 1) {
		await expect(
			await canvas.findByTestId(
				args.authN === 'sso' ? 'callback_authn_submit' : 'password',
			),
		).toBeVisible();
	}
}
