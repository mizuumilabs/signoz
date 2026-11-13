import { useCallback, useState } from 'react';
import {
	useMutation,
	useQuery,
	useQueryClient,
	UseQueryResult,
} from 'react-query';
import api from 'api';
import {
	buildSAReadPermission,
	buildSAUpdatePermission,
} from 'lib/authz/hooks/useAuthZ/permissions/service-account.permissions';
import { useAuthZ } from 'lib/authz/hooks/useAuthZ/useAuthZ';

export type ServiceAccountOIDCBinding = {
	issuer: string;
	clientId: string;
	subject: string;
};

export type ServiceAccountOIDCInput = Pick<
	ServiceAccountOIDCBinding,
	'clientId' | 'subject'
>;

export type ServiceAccountOIDCSettings = {
	enabled: boolean;
	issuer: string;
	audience: string;
	binding: ServiceAccountOIDCBinding | null;
};

export function useServiceAccountOIDC(
	accountId: string,
	deleted: boolean,
): {
	settings: UseQueryResult<ServiceAccountOIDCSettings>;
	draft: ServiceAccountOIDCInput;
	canEdit: boolean;
	pending: boolean;
	saved: boolean;
	stale: boolean;
	error: string;
	changeClientId: (value: string) => void;
	changeSubject: (value: string) => void;
	save: () => void;
	remove: () => void;
} {
	const read = useAuthZ([buildSAReadPermission(accountId)]);
	const update = useAuthZ([buildSAUpdatePermission(accountId)]);
	const queryClient = useQueryClient();
	const queryKey = ['service-account-oidc', accountId];
	const endpoint = `/service_accounts/${encodeURIComponent(accountId)}/oidc`;
	const [draft, setDraft] = useState<ServiceAccountOIDCInput | null>(null);
	const settings = useQuery({
		queryKey,
		queryFn: async ({ signal }): Promise<ServiceAccountOIDCSettings> => {
			const response = await api.get<{ data: ServiceAccountOIDCSettings }>(
				endpoint,
				{ signal },
			);
			return response.data.data;
		},
		enabled: Boolean(accountId) && read.allowed,
		retry: false,
		refetchOnWindowFocus: false,
		onSuccess: (data): void => {
			setDraft(
				(current) => current ?? data.binding ?? { clientId: '', subject: '' },
			);
		},
	});
	const canUpdate = read.allowed && update.allowed && !deleted;
	const stale = Boolean(
		settings.data?.binding &&
		settings.data.binding.issuer !== settings.data.issuer,
	);
	const saveMutation = useMutation({
		mutationFn: async (binding: ServiceAccountOIDCInput): Promise<void> => {
			if (!canUpdate || !settings.data?.enabled || stale) {
				throw new Error('Permission denied');
			}
			await api.put(endpoint, binding);
		},
		onSuccess: (_, binding): void => {
			setDraft(binding);
			if (settings.data) {
				queryClient.setQueryData<ServiceAccountOIDCSettings>(queryKey, {
					...settings.data,
					binding: { ...binding, issuer: settings.data.issuer },
				});
			}
		},
	});
	const removeMutation = useMutation({
		mutationFn: async (): Promise<void> => {
			if (!canUpdate) {
				throw new Error('Permission denied');
			}
			await api.delete(endpoint);
		},
		onSuccess: (): void => {
			setDraft({ clientId: '', subject: '' });
			if (settings.data) {
				queryClient.setQueryData<ServiceAccountOIDCSettings>(queryKey, {
					...settings.data,
					binding: null,
				});
			}
		},
	});
	const value = draft ?? settings.data?.binding ?? { clientId: '', subject: '' };
	const pending = saveMutation.isLoading || removeMutation.isLoading;
	const changeClientId = useCallback(
		(clientId: string): void => {
			setDraft((current) => ({
				clientId,
				subject: current?.subject ?? settings.data?.binding?.subject ?? '',
			}));
			saveMutation.reset();
			removeMutation.reset();
		},
		[saveMutation, removeMutation, settings.data?.binding?.subject],
	);
	const changeSubject = useCallback(
		(subject: string): void => {
			setDraft((current) => ({
				clientId: current?.clientId ?? settings.data?.binding?.clientId ?? '',
				subject,
			}));
			saveMutation.reset();
			removeMutation.reset();
		},
		[saveMutation, removeMutation, settings.data?.binding?.clientId],
	);

	return {
		settings,
		draft: value,
		canEdit: canUpdate && Boolean(settings.data?.enabled) && !pending && !stale,
		pending,
		saved: saveMutation.isSuccess,
		stale,
		error: saveMutation.isError
			? 'Unable to save Keycloak authentication. Try again.'
			: removeMutation.isError
				? 'Unable to remove Keycloak authentication. Try again.'
				: '',
		changeClientId,
		changeSubject,
		save: (): void => {
			if (
				canUpdate &&
				settings.data?.enabled &&
				!pending &&
				!stale &&
				value.clientId.trim() &&
				value.subject.trim()
			) {
				removeMutation.reset();
				saveMutation.mutate({
					clientId: value.clientId.trim(),
					subject: value.subject.trim(),
				});
			}
		},
		remove: (): void => {
			if (canUpdate && settings.data?.binding && !pending) {
				saveMutation.reset();
				removeMutation.mutate();
			}
		},
	};
}
