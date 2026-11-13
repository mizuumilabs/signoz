import type { Meta, StoryObj } from '@storybook/react-vite';

import { storyMocks } from '@/storybook/controls/defineStoryMocks';
import type { PageStoryArgs } from '@/storybook/runtime/resolveStory';

import { showSignInStep } from './__story_mockdata__/login.play';
import Login from '../index';
import { loginMocks } from './Login.stories.mocks';

type LoginArgs = PageStoryArgs<typeof loginMocks>;

const pageStory = storyMocks(loginMocks, { layout: 'app' });

/**
 * The login page: the auth methods the org offers, the SSO redirect, and what a
 * failed callback leaves behind.
 *
 * Route: `/login`.
 */
const meta = {
	title: 'Pages/Auth/Login',
	tags: ['play'],
	component: Login,
	...pageStory,
	parameters: { ...pageStory.parameters },
} satisfies Meta<LoginArgs>;

export default meta;

type Story = StoryObj<LoginArgs>;

/** The first step: the email, which is what decides how the user signs in. */
export const Default: Story = {};

/** The email resolved to one password workspace, so the password field is next. */
export const PasswordStep: Story = {
	play: showSignInStep,
};

/** An email in three workspaces: the organization has to be picked first. */
export const MultipleOrganizations: Story = {
	args: { orgs: 3 },
	play: showSignInStep,
};

/** A workspace behind an identity provider: no password, a hand-off instead. */
export const SingleSignOn: Story = {
	args: { authN: 'sso' },
	play: showSignInStep,
};

/** Instance-wide Keycloak authentication replaces the local credential form. */
export const Keycloak: Story = {
	args: { oidc: true },
};

/** Redirected back from the provider with the assertion rejected. */
export const CallbackFailed: Story = {
	args: { callbackError: true },
};
