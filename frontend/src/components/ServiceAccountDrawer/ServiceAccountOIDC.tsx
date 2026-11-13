import { Button } from '@signozhq/ui/button';
import { Input } from '@signozhq/ui/input';
import { Typography } from '@signozhq/ui/typography';
import AuthZButton from 'lib/authz/components/AuthZButton/AuthZButton';
import { withAuthZContent } from 'lib/authz/components/withAuthZ/withAuthZContent';
import {
	buildSAReadPermission,
	buildSAUpdatePermission,
} from 'lib/authz/hooks/useAuthZ/permissions/service-account.permissions';

import { useServiceAccountOIDC } from './useServiceAccountOIDC';
import styles from './ServiceAccountOIDC.module.css';

function ServiceAccountOIDC({
	accountId,
	deleted = false,
}: {
	accountId: string;
	deleted?: boolean;
}): JSX.Element {
	const {
		settings,
		draft,
		canEdit,
		pending,
		saved,
		stale,
		error,
		changeClientId,
		changeSubject,
		save,
		remove,
	} = useServiceAccountOIDC(accountId, deleted);
	const checks = [
		buildSAReadPermission(accountId),
		buildSAUpdatePermission(accountId),
	];
	const incomplete = !draft.clientId.trim() || !draft.subject.trim();

	return (
		<section
			className={styles.section}
			aria-label="Keycloak authentication"
			data-testid="sa-oidc-section"
		>
			<Typography.Title level={5}>Keycloak authentication</Typography.Title>
			{settings.isLoading && (
				<Typography.Text testId="sa-oidc-loading">
					Loading Keycloak authentication…
				</Typography.Text>
			)}
			{settings.isError && (
				<>
					<Typography.Text role="alert" color="danger">
						Unable to load Keycloak authentication.
					</Typography.Text>
					<Button
						size="sm"
						variant="outlined"
						color="secondary"
						testId="sa-oidc-retry"
						onClick={(): void => {
							void settings.refetch();
						}}
					>
						Try again
					</Button>
				</>
			)}
			{settings.data && (
				<>
					<Typography.Text testId="sa-oidc-status">
						{settings.data.enabled ? 'Enabled' : 'Disabled'}
					</Typography.Text>
					<Typography.Text color="muted">
						Use an existing Keycloak client with service accounts enabled. Enter its
						service-account user subject (sub). Client credentials stay in Keycloak.
					</Typography.Text>
					{!settings.data.enabled && (
						<Typography.Text>
							Keycloak token authentication is disabled. Ask an administrator to enable
							identn.oidc on the server.
						</Typography.Text>
					)}
					{stale && (
						<>
							<Typography.Text testId="sa-oidc-stale" color="warning">
								This binding belongs to a different issuer. Remove it before saving a
								new binding.
							</Typography.Text>
							<div className={styles.field}>
								<label htmlFor={`sa-oidc-bound-issuer-${accountId}`}>
									Binding issuer
								</label>
								<Input
									id={`sa-oidc-bound-issuer-${accountId}`}
									testId="sa-oidc-bound-issuer"
									readOnly
									value={settings.data.binding?.issuer ?? ''}
								/>
							</div>
						</>
					)}
					<div className={styles.field}>
						<label htmlFor={`sa-oidc-issuer-${accountId}`}>Issuer</label>
						<Input
							id={`sa-oidc-issuer-${accountId}`}
							testId="sa-oidc-issuer"
							readOnly
							value={settings.data.issuer || 'Not configured'}
						/>
					</div>
					<div className={styles.field}>
						<label htmlFor={`sa-oidc-audience-${accountId}`}>Audience</label>
						<Input
							id={`sa-oidc-audience-${accountId}`}
							testId="sa-oidc-audience"
							readOnly
							value={settings.data.audience || 'Not configured'}
						/>
					</div>
					<div className={styles.field}>
						<label htmlFor={`sa-oidc-client-${accountId}`}>Client ID</label>
						<Input
							id={`sa-oidc-client-${accountId}`}
							testId="sa-oidc-client-id"
							value={draft.clientId}
							disabled={!canEdit}
							maxLength={255}
							autoComplete="off"
							onChange={(event): void => changeClientId(event.target.value)}
						/>
					</div>
					<div className={styles.field}>
						<label htmlFor={`sa-oidc-subject-${accountId}`}>
							Service-account subject (sub)
						</label>
						<Input
							id={`sa-oidc-subject-${accountId}`}
							testId="sa-oidc-subject"
							value={draft.subject}
							disabled={!canEdit}
							maxLength={255}
							autoComplete="off"
							onChange={(event): void => changeSubject(event.target.value)}
						/>
					</div>
					<div className={styles.actions}>
						{settings.data.enabled && (
							<AuthZButton
								checks={checks}
								size="sm"
								variant="solid"
								color="primary"
								testId="sa-oidc-save"
								disabled={deleted || pending || incomplete || stale}
								disabledTooltip={
									deleted
										? 'Service account deleted'
										: stale
											? 'Remove the binding from the previous issuer first'
											: pending
												? 'A change is being saved'
												: incomplete
													? 'Enter the client ID and service-account subject'
													: undefined
								}
								loading={pending}
								onClick={save}
							>
								Save Keycloak authentication
							</AuthZButton>
						)}
						{settings.data.binding && (
							<AuthZButton
								checks={checks}
								size="sm"
								variant="outlined"
								color="secondary"
								testId="sa-oidc-remove"
								disabled={deleted || pending}
								disabledTooltip={
									deleted
										? 'Service account deleted'
										: pending
											? 'A change is being saved'
											: undefined
								}
								onClick={remove}
							>
								Remove binding
							</AuthZButton>
						)}
					</div>
					{saved && (
						<Typography.Text as="div" testId="sa-oidc-saved">
							Keycloak authentication saved.
						</Typography.Text>
					)}
					{error && (
						<Typography.Text role="alert" testId="sa-oidc-error" color="danger">
							{error}
						</Typography.Text>
					)}
				</>
			)}
		</section>
	);
}

export default withAuthZContent(ServiceAccountOIDC, {
	checks: (props): ReturnType<typeof buildSAReadPermission>[] => [
		buildSAReadPermission(props.accountId),
	],
});
