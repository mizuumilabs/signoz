import { Button } from '@signozhq/ui/button';
import { Typography } from '@signozhq/ui/typography';
import AuthPageContainer from 'components/AuthPageContainer';
import LoginContainer from 'container/Login';

import { useInstanceOIDC } from './useInstanceOIDC';

import './Login.styles.scss';

function Login(): JSX.Element {
	const { settings, login, completing, failed } = useInstanceOIDC();

	return (
		<AuthPageContainer>
			<div className="auth-form-card">
				{settings.isLoading && (
					<Typography.Text testId="oidc-settings-loading">
						Loading sign-in settings…
					</Typography.Text>
				)}
				{settings.isError && (
					<div className="login-form-card">
						<Typography.Text testId="oidc-config-error" role="alert" color="danger">
							Unable to load sign-in settings. Try again.
						</Typography.Text>
						<Button
							size="md"
							variant="solid"
							color="primary"
							testId="oidc-settings-retry"
							onClick={(): void => {
								void settings.refetch();
							}}
						>
							Try again
						</Button>
					</div>
				)}
				{settings.isSuccess && !settings.data.enabled && <LoginContainer />}
				{settings.isSuccess && settings.data.enabled && (
					<div className="login-form-card">
						<Typography.Title level={4}>Sign in to your workspace</Typography.Title>
						<Typography.Text>Use your Keycloak account to continue.</Typography.Text>
						{failed && (
							<Typography.Text testId="oidc-login-error" role="alert" color="danger">
								Unable to sign in with Keycloak. Please try again.
							</Typography.Text>
						)}
						<Button
							size="md"
							variant="solid"
							color="primary"
							width="100%"
							testId="oidc-login"
							loading={completing}
							disabled={!settings.data.loginURL}
							disabledTooltip="The sign-in provider is not configured."
							onClick={login}
						>
							{completing ? 'Signing in…' : 'Continue with Keycloak'}
						</Button>
					</div>
				)}
			</div>
		</AuthPageContainer>
	);
}

export default Login;
