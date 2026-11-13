import { useCallback, useEffect, useRef } from 'react';
import { useMutation, useQuery, UseQueryResult } from 'react-query';
import { ApiV2Instance } from 'api';
import afterLogin from 'AppRoutes/utils';
import { parseAsBoolean, parseAsString, useQueryStates } from 'nuqs';
import { withBasePath } from 'utils/basePath';

type OIDCSettings = {
	enabled: boolean;
	loginURL?: string;
};

type OIDCSession = {
	accessToken: string;
	refreshToken: string;
};

export function useInstanceOIDC(): {
	settings: UseQueryResult<OIDCSettings>;
	login: () => void;
	completing: boolean;
	failed: boolean;
} {
	const [callback, setCallback] = useQueryStates({
		oidcComplete: parseAsBoolean.withDefault(false),
		oidcError: parseAsString.withDefault(''),
	});
	const exchanged = useRef(false);
	const settings = useQuery({
		queryKey: ['instance-oidc-settings'],
		queryFn: async ({ signal }): Promise<OIDCSettings> => {
			const response = await ApiV2Instance.get<{ data: OIDCSettings }>(
				'/sessions/oidc',
				{ signal },
			);
			return response.data.data;
		},
		retry: false,
		refetchOnWindowFocus: false,
	});
	const session = useMutation({
		mutationFn: async (): Promise<OIDCSession> => {
			const response = await ApiV2Instance.post<{ data: OIDCSession }>(
				'/sessions/oidc/session',
			);
			return response.data.data;
		},
		onSuccess: ({ accessToken, refreshToken }) => {
			afterLogin(accessToken, refreshToken);
		},
		retry: false,
	});
	const { mutate } = session;

	useEffect(() => {
		if (!settings.data?.enabled || !callback.oidcComplete || exchanged.current) {
			return;
		}
		exchanged.current = true;
		void setCallback({ oidcComplete: null });
		mutate();
	}, [settings.data?.enabled, callback.oidcComplete, setCallback, mutate]);

	const login = useCallback((): void => {
		if (settings.data?.loginURL) {
			window.location.href = withBasePath(settings.data.loginURL);
		}
	}, [settings.data?.loginURL]);

	return {
		settings,
		login,
		completing: session.isLoading || session.isSuccess,
		failed: Boolean(callback.oidcError) || session.isError,
	};
}
