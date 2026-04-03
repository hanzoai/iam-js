/**
 * React bindings for @hanzo/iam.
 *
 * Provides a context provider, auth hooks, and org/project switching
 * that can be dropped into any React application.
 *
 * @example
 * ```tsx
 * import { IamProvider, useIam, useOrganizations } from '@hanzo/iam/react'
 *
 * function App() {
 *   return (
 *     <IamProvider config={{
 *       serverUrl: 'https://iam.hanzo.ai',
 *       clientId: 'my-app',
 *       redirectUri: `${window.location.origin}/auth/callback`,
 *     }}>
 *       <MyApp />
 *     </IamProvider>
 *   )
 * }
 *
 * function MyApp() {
 *   const { user, isAuthenticated, login, logout } = useIam()
 *   const { organizations, currentOrg, switchOrg } = useOrganizations()
 *
 *   if (!isAuthenticated) return <button onClick={() => login()}>Log in</button>
 *   return <div>Welcome, {user?.displayName}</div>
 * }
 * ```
 *
 * @packageDocumentation
 */

import {
  createContext,
  createElement,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { ReactNode } from "react";
import { BrowserIamSdk } from "./browser.js";
import type { BrowserIamConfig } from "./browser.js";
import { IamClient } from "./client.js";
import type { IamUser, IamOrganization, IamInvitation, IamProject, TokenResponse } from "./types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IamProviderProps {
  /** Browser IAM SDK configuration. */
  config: BrowserIamConfig;
  /** Auto-initialize on mount (check stored tokens). Default: true. */
  autoInit?: boolean;
  /** Called when authentication state changes. */
  onAuthChange?: (authenticated: boolean) => void;
  children: ReactNode;
}

export interface IamContextValue {
  /** The underlying BrowserIamSdk instance for advanced use. */
  sdk: BrowserIamSdk;
  /** The IAM configuration. */
  config: BrowserIamConfig;
  /** Authenticated user (null if not logged in). */
  user: IamUser | null;
  /** Whether the user is currently authenticated. */
  isAuthenticated: boolean;
  /** Whether initial auth check is in progress. */
  isLoading: boolean;
  /** Current access token (null if not authenticated). */
  accessToken: string | null;
  /** Redirect to IAM login page. */
  login: (params?: { additionalParams?: Record<string, string> }) => Promise<void>;
  /** Open IAM login in a popup. */
  loginPopup: (params?: { width?: number; height?: number }) => Promise<void>;
  /** Handle OAuth callback — call on your /auth/callback route. */
  handleCallback: (callbackUrl?: string) => Promise<TokenResponse>;
  /** Log out and clear all tokens. */
  logout: () => void;
  /** Last auth error, if any. */
  error: Error | null;
}

export interface OrgState {
  /** All organizations the user belongs to. */
  organizations: IamOrganization[];
  /** Currently selected organization. */
  currentOrg: IamOrganization | null;
  /** Currently selected org ID. */
  currentOrgId: string | null;
  /** Switch to a different organization. */
  switchOrg: (orgId: string) => void;
  /** All projects for the current organization. */
  projects: IamProject[];
  /** Currently selected project. */
  currentProject: IamProject | null;
  /** Currently selected project ID within the org. */
  currentProjectId: string | null;
  /** Switch to a different project (null to clear). */
  switchProject: (projectId: string | null) => void;
  /** Whether organizations are loading. */
  isLoading: boolean;
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const IamContext = createContext<IamContextValue | null>(null);
IamContext.displayName = "HanzoIamContext";

// Storage keys for tenant persistence
const STORAGE_ORG_KEY = "hanzo_iam_current_org";
const STORAGE_PROJECT_KEY = "hanzo_iam_current_project";
const STORAGE_EXPIRES_KEY = "hanzo_iam_expires_at";

// ---------------------------------------------------------------------------
// IamProvider
// ---------------------------------------------------------------------------

/**
 * Root provider for Hanzo IAM in React applications.
 *
 * Wrap your app (or a subtree) with this provider to enable IAM auth.
 * Manages the BrowserIamSdk instance, token lifecycle, and auth state.
 */
export function IamProvider(props: IamProviderProps) {
  const { config, autoInit = true, onAuthChange, children } = props;

  const sdk = useMemo(
    () => new BrowserIamSdk(config),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [config.serverUrl, config.clientId, config.redirectUri],
  );

  const [user, setUser] = useState<IamUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(autoInit);
  const [accessToken, setAccessToken] = useState<string | null>(
    sdk.getAccessToken(),
  );
  const [error, setError] = useState<Error | null>(null);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Schedule token refresh ~60s before expiry
  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    if (sdk.isTokenExpired()) return;

    const storage = config.storage ?? sessionStorage;
    const expiresAtStr = storage.getItem(STORAGE_EXPIRES_KEY);
    if (!expiresAtStr) return;

    const msUntilRefresh = Number(expiresAtStr) - Date.now() - 60_000;
    if (msUntilRefresh <= 0) {
      sdk
        .refreshAccessToken()
        .then((tokens) => {
          setAccessToken(tokens.access_token);
          scheduleRefresh();
        })
        .catch(() => {
          setIsAuthenticated(false);
          setUser(null);
          setAccessToken(null);
        });
      return;
    }

    refreshTimerRef.current = setTimeout(async () => {
      try {
        const tokens = await sdk.refreshAccessToken();
        setAccessToken(tokens.access_token);
        scheduleRefresh();
      } catch {
        setIsAuthenticated(false);
        setUser(null);
        setAccessToken(null);
      }
    }, msUntilRefresh);
  }, [sdk, config.storage]);

  // Auto-init: check stored tokens on mount
  useEffect(() => {
    if (!autoInit) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;

    const init = async () => {
      try {
        const token = await sdk.getValidAccessToken();
        if (cancelled) return;
        if (token) {
          setAccessToken(token);
          setIsAuthenticated(true);
          try {
            const info = await sdk.getUserInfo();
            if (!cancelled) setUser(info as unknown as IamUser);
          } catch {
            // Token valid but userinfo failed — still authenticated
          }
          scheduleRefresh();
          onAuthChange?.(true);
        } else {
          onAuthChange?.(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error(String(err)));
          onAuthChange?.(false);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    init();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sdk, autoInit]);

  // Cleanup refresh timer on unmount
  useEffect(() => {
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    };
  }, []);

  // Complete authentication after login/callback
  const completeAuth = useCallback(
    async (tokens: TokenResponse) => {
      setAccessToken(tokens.access_token);
      setIsAuthenticated(true);
      try {
        const info = await sdk.getUserInfo();
        setUser(info as unknown as IamUser);
      } catch {
        // ok — token valid, userinfo is optional
      }
      scheduleRefresh();
      onAuthChange?.(true);
    },
    [sdk, scheduleRefresh, onAuthChange],
  );

  const login = useCallback(
    async (params?: { additionalParams?: Record<string, string> }) => {
      setError(null);
      await sdk.signinRedirect(params);
    },
    [sdk],
  );

  const loginPopup = useCallback(
    async (params?: { width?: number; height?: number }) => {
      setError(null);
      try {
        const tokens = await sdk.signinPopup(params);
        await completeAuth(tokens);
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      }
    },
    [sdk, completeAuth],
  );

  const handleCallback = useCallback(
    async (callbackUrl?: string) => {
      setError(null);
      try {
        const tokens = await sdk.handleCallback(callbackUrl);
        await completeAuth(tokens);
        return tokens;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      }
    },
    [sdk, completeAuth],
  );

  const logout = useCallback(() => {
    sdk.clearTokens();
    setUser(null);
    setIsAuthenticated(false);
    setAccessToken(null);
    setError(null);
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
    try {
      localStorage.removeItem(STORAGE_ORG_KEY);
      localStorage.removeItem(STORAGE_PROJECT_KEY);
    } catch {
      /* ok */
    }
    onAuthChange?.(false);
  }, [sdk, onAuthChange]);

  const value = useMemo<IamContextValue>(
    () => ({
      sdk,
      config,
      user,
      isAuthenticated,
      isLoading,
      accessToken,
      login,
      loginPopup,
      handleCallback,
      logout,
      error,
    }),
    [
      sdk,
      config,
      user,
      isAuthenticated,
      isLoading,
      accessToken,
      login,
      loginPopup,
      handleCallback,
      logout,
      error,
    ],
  );

  return createElement(IamContext.Provider, { value }, children);
}

// ---------------------------------------------------------------------------
// useIam
// ---------------------------------------------------------------------------

/**
 * Access Hanzo IAM auth state and methods.
 * Must be used within an `<IamProvider>`.
 */
export function useIam(): IamContextValue {
  const ctx = useContext(IamContext);
  if (!ctx) {
    throw new Error("useIam() must be used within an <IamProvider>");
  }
  return ctx;
}

// ---------------------------------------------------------------------------
// useOrganizations
// ---------------------------------------------------------------------------

/**
 * Manage organization and project switching.
 *
 * Fetches the user's organizations from IAM and provides
 * `switchOrg` / `switchProject` to change the active tenant.
 * Selection is persisted to localStorage.
 */
export function useOrganizations(): OrgState {
  const { config, isAuthenticated, accessToken } = useIam();
  const [organizations, setOrganizations] = useState<IamOrganization[]>([]);
  const [projects, setProjects] = useState<IamProject[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const [currentOrgId, setCurrentOrgId] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_ORG_KEY);
    } catch {
      return null;
    }
  });

  const [currentProjectId, setCurrentProjectId] = useState<string | null>(
    () => {
      try {
        return localStorage.getItem(STORAGE_PROJECT_KEY);
      } catch {
        return null;
      }
    },
  );

  // Fetch organizations when authenticated
  useEffect(() => {
    if (!isAuthenticated || !accessToken) {
      setOrganizations([]);
      setProjects([]);
      return;
    }

    let cancelled = false;

    const fetchOrgs = async () => {
      setIsLoading(true);

      // 1. Parse JWT claims for user's workspace org (immediate, no API call)
      // The user's "owner" is the signup org (for auth). Their personal org
      // (name == username) is their actual workspace.
      try {
        let b64 = accessToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4) b64 += "=";
        const payload = JSON.parse(atob(b64));

        const userOwner = (payload.owner as string) ?? "";
        const userName = (payload.name as string) ?? "";
        const sub = (payload.sub as string) ?? "";
        const isAdmin = !!payload.isAdmin;

        // Personal org is the default workspace
        const workspaceOrg = (userName && userName !== userOwner)
          ? userName
          : userOwner || (sub.includes("/") ? sub.split("/")[0] : "");

        if (workspaceOrg && !cancelled) {
          const immediateOrgs: IamOrganization[] = [
            { owner: "admin", name: workspaceOrg, displayName: workspaceOrg },
          ];
          // Admin users also see their signup org (they manage it)
          if (isAdmin && userOwner && userOwner !== workspaceOrg) {
            immediateOrgs.push({ owner: "admin", name: userOwner, displayName: userOwner });
          }
          setOrganizations(immediateOrgs);
          if (!currentOrgId) {
            setCurrentOrgId(workspaceOrg);
            try {
              localStorage.setItem(STORAGE_ORG_KEY, workspaceOrg);
            } catch {
              /* ok */
            }
          }
        }
      } catch {
        // Invalid token format — skip JWT parsing
      }

      // 2. Try to fetch full org list from API (may fail for non-admin users)
      try {
        const client = new IamClient({
          serverUrl: config.serverUrl,
          clientId: config.clientId,
        });
        const orgs = await client.getOrganizations(accessToken);
        if (!cancelled && orgs.length > 0) {
          setOrganizations(orgs);
          if (!currentOrgId && orgs.length > 0) {
            const firstOrg = orgs[0].name;
            setCurrentOrgId(firstOrg);
            try {
              localStorage.setItem(STORAGE_ORG_KEY, firstOrg);
            } catch {
              /* ok */
            }
          }
        }
      } catch {
        // API call failed — keep JWT-derived org
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    fetchOrgs();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken, config.serverUrl, config.clientId]);

  // Fetch projects when currentOrgId changes
  useEffect(() => {
    if (!isAuthenticated || !accessToken || !currentOrgId) {
      setProjects([]);
      return;
    }

    let cancelled = false;

    const fetchProjects = async () => {
      try {
        const client = new IamClient({
          serverUrl: config.serverUrl,
          clientId: config.clientId,
        });
        const orgProjects = await client.getOrganizationProjects(
          currentOrgId,
          accessToken,
        );
        if (!cancelled) {
          setProjects(orgProjects);
          // Auto-select default project if none selected
          if (!currentProjectId && orgProjects.length > 0) {
            const defaultProject =
              orgProjects.find((p) => p.isDefault) ?? orgProjects[0];
            setCurrentProjectId(defaultProject.name);
            try {
              localStorage.setItem(STORAGE_PROJECT_KEY, defaultProject.name);
            } catch {
              /* ok */
            }
          }
        }
      } catch {
        // Projects API may not be available yet — that's ok
        if (!cancelled) setProjects([]);
      }
    };

    fetchProjects();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken, currentOrgId, config.serverUrl, config.clientId]);

  const currentOrg = useMemo(
    () => organizations.find((o) => o.name === currentOrgId) ?? null,
    [organizations, currentOrgId],
  );

  const currentProject = useMemo(
    () => projects.find((p) => p.name === currentProjectId) ?? null,
    [projects, currentProjectId],
  );

  const switchOrg = useCallback((orgId: string) => {
    setCurrentOrgId(orgId);
    setCurrentProjectId(null);
    setProjects([]);
    try {
      localStorage.setItem(STORAGE_ORG_KEY, orgId);
      localStorage.removeItem(STORAGE_PROJECT_KEY);
    } catch {
      /* ok */
    }
  }, []);

  const switchProject = useCallback((projectId: string | null) => {
    setCurrentProjectId(projectId);
    try {
      if (projectId) {
        localStorage.setItem(STORAGE_PROJECT_KEY, projectId);
      } else {
        localStorage.removeItem(STORAGE_PROJECT_KEY);
      }
    } catch {
      /* ok */
    }
  }, []);

  return {
    organizations,
    currentOrg,
    currentOrgId,
    switchOrg,
    projects,
    currentProject,
    currentProjectId,
    switchProject,
    isLoading,
  };
}

// ---------------------------------------------------------------------------
// useIamToken
// ---------------------------------------------------------------------------

/**
 * Hook that provides a valid access token with auto-refresh capability.
 * Returns null while loading or if not authenticated.
 */
export function useIamToken(): {
  token: string | null;
  isValid: boolean;
  refresh: () => Promise<string | null>;
} {
  const { sdk, accessToken, isAuthenticated } = useIam();

  const refresh = useCallback(async () => {
    try {
      return await sdk.getValidAccessToken();
    } catch {
      return null;
    }
  }, [sdk]);

  return {
    token: accessToken,
    isValid: isAuthenticated && !!accessToken && !sdk.isTokenExpired(),
    refresh,
  };
}

// ---------------------------------------------------------------------------
// useOrgManagement
// ---------------------------------------------------------------------------

export interface OrgManagementState {
  /** Create a new organization. */
  createOrg: (org: Partial<IamOrganization>) => Promise<void>;
  /** Update an existing organization. */
  updateOrg: (org: Partial<IamOrganization>) => Promise<void>;
  /** Delete an organization by owner and name. */
  deleteOrg: (org: { owner: string; name: string }) => Promise<void>;
  /** Whether a mutation is in progress. */
  isLoading: boolean;
}

/**
 * Manage organization CRUD operations.
 *
 * Provides create, update, and delete methods that call the IAM API
 * using the current user's access token.
 */
export function useOrgManagement(): OrgManagementState {
  const { config, accessToken } = useIam();
  const [isLoading, setIsLoading] = useState(false);

  const client = useMemo(
    () =>
      new IamClient({
        serverUrl: config.serverUrl,
        clientId: config.clientId,
      }),
    [config.serverUrl, config.clientId],
  );

  const createOrg = useCallback(
    async (org: Partial<IamOrganization>) => {
      setIsLoading(true);
      try {
        await client.createOrganization(org, accessToken ?? undefined);
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken],
  );

  const updateOrg = useCallback(
    async (org: Partial<IamOrganization>) => {
      setIsLoading(true);
      try {
        await client.updateOrganization(org, accessToken ?? undefined);
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken],
  );

  const deleteOrg = useCallback(
    async (org: { owner: string; name: string }) => {
      setIsLoading(true);
      try {
        await client.deleteOrganization(org, accessToken ?? undefined);
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken],
  );

  return { createOrg, updateOrg, deleteOrg, isLoading };
}

// ---------------------------------------------------------------------------
// useInvitations
// ---------------------------------------------------------------------------

export interface InvitationsState {
  /** All invitations for the organization. */
  invitations: IamInvitation[];
  /** Create a new invitation. */
  createInvite: (invitation: Partial<IamInvitation>) => Promise<void>;
  /** Send an existing invitation. */
  sendInvite: (invitation: { owner: string; name: string }) => Promise<void>;
  /** Verify an invitation code. */
  verifyInvite: (code: string) => Promise<IamInvitation | null>;
  /** Whether invitations are loading. */
  isLoading: boolean;
  /** Re-fetch the invitations list. */
  refresh: () => Promise<void>;
}

/**
 * Manage invitations for an organization.
 *
 * Fetches the invitation list on mount and provides create, send,
 * and verify methods using the current user's access token.
 */
export function useInvitations(orgName: string): InvitationsState {
  const { config, accessToken, isAuthenticated } = useIam();
  const [invitations, setInvitations] = useState<IamInvitation[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const client = useMemo(
    () =>
      new IamClient({
        serverUrl: config.serverUrl,
        clientId: config.clientId,
      }),
    [config.serverUrl, config.clientId],
  );

  const fetchInvitations = useCallback(async () => {
    if (!isAuthenticated || !accessToken || !orgName) return;
    setIsLoading(true);
    try {
      const data = await client.getInvitations(orgName, accessToken);
      setInvitations(data);
    } catch {
      setInvitations([]);
    } finally {
      setIsLoading(false);
    }
  }, [client, orgName, accessToken, isAuthenticated]);

  // Fetch invitations on mount and when orgName changes
  useEffect(() => {
    if (!isAuthenticated || !accessToken || !orgName) {
      setInvitations([]);
      return;
    }

    let cancelled = false;

    const load = async () => {
      setIsLoading(true);
      try {
        const data = await client.getInvitations(orgName, accessToken);
        if (!cancelled) setInvitations(data);
      } catch {
        if (!cancelled) setInvitations([]);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    load();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAuthenticated, accessToken, orgName, config.serverUrl, config.clientId]);

  const createInvite = useCallback(
    async (invitation: Partial<IamInvitation>) => {
      setIsLoading(true);
      try {
        await client.createInvitation(invitation, accessToken ?? undefined);
        await fetchInvitations();
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken, fetchInvitations],
  );

  const sendInvite = useCallback(
    async (invitation: { owner: string; name: string }) => {
      setIsLoading(true);
      try {
        await client.sendInvitation(invitation, accessToken ?? undefined);
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken],
  );

  const verifyInvite = useCallback(
    async (code: string): Promise<IamInvitation | null> => {
      setIsLoading(true);
      try {
        const resp = await client.verifyInvitation(code, accessToken ?? undefined);
        return resp.data ?? null;
      } finally {
        setIsLoading(false);
      }
    },
    [client, accessToken],
  );

  return { invitations, createInvite, sendInvite, verifyInvite, isLoading, refresh: fetchInvitations };
}

// Re-export context for advanced use
export { IamContext };

// ---------------------------------------------------------------------------
// OrgProjectSwitcher component
// ---------------------------------------------------------------------------

export interface OrgProjectSwitcherProps {
  organizations: Array<{ name: string; displayName?: string; owner?: string }>;
  currentOrgId: string | null;
  switchOrg: (orgId: string) => void;
  projects?: Array<{ name: string; displayName?: string; organization?: string; isDefault?: boolean }>;
  currentProjectId?: string | null;
  switchProject?: (projectId: string | null) => void;
  onTenantChange?: (orgId: string | null, projectId: string | null) => void;
  environment?: string | null;
  className?: string;
  alwaysShow?: boolean;
}

/**
 * Organization and project switcher component.
 *
 * @example
 * ```tsx
 * import { useOrganizations, OrgProjectSwitcher } from '@hanzo/iam/react'
 *
 * function Nav() {
 *   const orgState = useOrganizations()
 *   return <OrgProjectSwitcher {...orgState} />
 * }
 * ```
 */
export function OrgProjectSwitcher({
  organizations,
  currentOrgId,
  switchOrg,
  projects = [],
  currentProjectId = null,
  switchProject,
  onTenantChange,
  environment,
  className = "",
  alwaysShow = false,
}: OrgProjectSwitcherProps) {
  useEffect(() => {
    onTenantChange?.(currentOrgId, currentProjectId ?? null);
  }, [currentOrgId, currentProjectId, onTenantChange]);

  const handleOrgChange = useCallback(
    (e: { target: { value: string } }) => switchOrg(e.target.value),
    [switchOrg],
  );

  const handleProjectChange = useCallback(
    (e: { target: { value: string } }) => switchProject?.(e.target.value || null),
    [switchProject],
  );

  if (!alwaysShow && organizations.length <= 1 && projects.length <= 1) {
    if (organizations.length === 1) {
      const org = organizations[0];
      return createElement(
        "div",
        { className: `flex items-center gap-2 text-sm ${className}` },
        createElement("span", { className: "font-medium" }, org.displayName || org.name),
        projects.length === 1
          ? [
              createElement("span", { className: "text-muted-foreground", key: "sep" }, "/"),
              createElement("span", { key: "proj" }, projects[0].displayName || projects[0].name),
            ]
          : null,
        environment
          ? createElement(
              "span",
              { className: "rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground" },
              environment,
            )
          : null,
      );
    }
    return null;
  }

  return createElement(
    "div",
    { className: `flex items-center gap-2 ${className}` },
    createElement(
      "select",
      {
        value: currentOrgId ?? "",
        onChange: handleOrgChange,
        className:
          "h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring",
        "aria-label": "Switch organization",
      },
      ...organizations.map((org) =>
        createElement("option", { key: org.name, value: org.name }, org.displayName || org.name),
      ),
    ),
    projects.length > 0 && switchProject
      ? [
          createElement("span", { className: "text-muted-foreground", key: "sep" }, "/"),
          createElement(
            "select",
            {
              key: "proj-select",
              value: currentProjectId ?? "",
              onChange: handleProjectChange,
              className:
                "h-8 rounded-md border border-border bg-background px-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring",
              "aria-label": "Switch project",
            },
            ...projects.map((proj) =>
              createElement("option", { key: proj.name, value: proj.name }, proj.displayName || proj.name),
            ),
          ),
        ]
      : null,
    environment
      ? createElement(
          "span",
          { className: "rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground" },
          environment,
        )
      : null,
  );
}

// ---------------------------------------------------------------------------
// UserOrgMenu — shared org switcher + user menu for all Hanzo apps
// ---------------------------------------------------------------------------

export interface UserOrgMenuProps {
  /** Additional CSS class for the outer container. */
  className?: string;
  /** Called when org changes. Use to sync external state (e.g., tenantStore). */
  onOrgChange?: (orgId: string) => void;
  /** Called when user clicks logout. */
  onLogout?: () => void;
  /** Whether to show the "Create Organization" option. Defaults to true. */
  showCreateOrg?: boolean;
  /** Optional endpoint for org creation (defaults to IAM's /api/add-organization). */
  createOrgEndpoint?: string;
}

/**
 * Shared user menu + organization switcher for all Hanzo apps.
 *
 * Shows current user info (name, email, avatar), a dropdown with org list,
 * "Create Organization" option, and logout button. Uses only `@hanzo/iam`
 * hooks — no external UI library required.
 *
 * @example
 * ```tsx
 * import { UserOrgMenu } from '@hanzo/iam/react'
 *
 * function TopBar() {
 *   return (
 *     <nav>
 *       <UserOrgMenu
 *         onOrgChange={(orgId) => myStore.setOrg(orgId)}
 *         onLogout={() => router.push('/login')}
 *       />
 *     </nav>
 *   )
 * }
 * ```
 */
export function UserOrgMenu({
  className = "",
  onOrgChange,
  onLogout,
  showCreateOrg = true,
  createOrgEndpoint,
}: UserOrgMenuProps) {
  const { config, isAuthenticated, accessToken, user, logout } = useIam();
  const orgState = useOrganizations();
  const [open, setOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newOrgName, setNewOrgName] = useState("");
  const [newOrgDisplay, setNewOrgDisplay] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleSwitchOrg = useCallback(
    (orgId: string) => {
      orgState.switchOrg(orgId);
      onOrgChange?.(orgId);
      setOpen(false);
    },
    [orgState, onOrgChange],
  );

  const handleLogout = useCallback(() => {
    setOpen(false);
    if (onLogout) {
      onLogout();
    } else {
      logout?.();
    }
  }, [onLogout, logout]);

  const handleCreateOrg = useCallback(async () => {
    const name = newOrgName.trim();
    if (!name) return;

    setCreating(true);
    setError(null);

    try {
      const client = new IamClient({
        serverUrl: config.serverUrl,
        clientId: config.clientId,
      });

      if (createOrgEndpoint) {
        // Use custom endpoint (e.g., playground's /v1/orgs)
        const res = await fetch(createOrgEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
          },
          body: JSON.stringify({
            name,
            displayName: newOrgDisplay.trim() || name,
          }),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.error || body.msg || `HTTP ${res.status}`);
        }
      } else {
        // Use IAM directly
        await client.createOrganization(
          { owner: "admin", name, displayName: newOrgDisplay.trim() || name },
          accessToken ?? undefined,
        );
      }

      // Switch to new org
      orgState.switchOrg(name);
      onOrgChange?.(name);
      setNewOrgName("");
      setNewOrgDisplay("");
      setCreateOpen(false);
      setOpen(false);

      // Reload to refresh org list
      window.location.reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setCreating(false);
    }
  }, [newOrgName, newOrgDisplay, config, accessToken, createOrgEndpoint, orgState, onOrgChange]);

  if (!isAuthenticated) return null;

  const orgs = orgState.organizations ?? [];
  const currentLabel =
    orgs.find((o) => o.name === orgState.currentOrgId)?.displayName ??
    orgState.currentOrgId ??
    "Select org";

  const userName = user?.displayName || user?.name || user?.email || "User";
  const userEmail = user?.email || "";
  const userAvatar = user?.avatar || "";

  // Inline styles (no external CSS dependencies)
  const menuStyle: React.CSSProperties = {
    position: "absolute",
    top: "100%",
    right: 0,
    marginTop: 4,
    minWidth: 240,
    borderRadius: 8,
    border: "1px solid var(--border, #333)",
    background: "var(--popover, #1a1a1a)",
    color: "var(--popover-foreground, #fff)",
    boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
    zIndex: 50,
    overflow: "hidden",
  };

  const itemStyle: React.CSSProperties = {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "8px 12px",
    fontSize: 13,
    cursor: "pointer",
    transition: "background 0.1s",
    width: "100%",
    border: "none",
    background: "transparent",
    color: "inherit",
    textAlign: "left",
  };

  const activeItemStyle: React.CSSProperties = {
    ...itemStyle,
    background: "var(--accent, #2a2a2a)",
  };

  const separatorStyle: React.CSSProperties = {
    height: 1,
    background: "var(--border, #333)",
    margin: "4px 0",
  };

  const labelStyle: React.CSSProperties = {
    padding: "6px 12px",
    fontSize: 11,
    fontWeight: 600,
    textTransform: "uppercase" as const,
    letterSpacing: "0.05em",
    color: "var(--muted-foreground, #888)",
  };

  return createElement(
    "div",
    { ref: menuRef, className: `relative ${className}`, style: { position: "relative" } },

    // Trigger button
    createElement(
      "button",
      {
        onClick: () => setOpen(!open),
        style: {
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 10px",
          borderRadius: 6,
          border: "none",
          background: "transparent",
          cursor: "pointer",
          color: "inherit",
          fontSize: 13,
          fontWeight: 500,
        },
        "aria-label": "User menu",
      },
      userAvatar
        ? createElement("img", {
            src: userAvatar,
            alt: userName,
            style: { width: 24, height: 24, borderRadius: "50%", objectFit: "cover" as const },
          })
        : createElement(
            "div",
            {
              style: {
                width: 24,
                height: 24,
                borderRadius: "50%",
                background: "var(--primary, #3b82f6)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 11,
                fontWeight: 600,
                color: "#fff",
              },
            },
            userName.charAt(0).toUpperCase(),
          ),
      createElement("span", { style: { maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const } }, currentLabel),
      createElement("span", { style: { fontSize: 10, opacity: 0.5 } }, open ? "\u25B2" : "\u25BC"),
    ),

    // Dropdown menu
    open &&
      createElement(
        "div",
        { style: menuStyle },

        // User info section
        createElement(
          "div",
          { style: { padding: "10px 12px", borderBottom: "1px solid var(--border, #333)" } },
          createElement("div", { style: { fontSize: 13, fontWeight: 600 } }, userName),
          userEmail && createElement("div", { style: { fontSize: 11, opacity: 0.6, marginTop: 2 } }, userEmail),
        ),

        // Organization section
        createElement("div", { style: labelStyle }, "Organization"),
        ...orgs.map((org) =>
          createElement(
            "button",
            {
              key: org.name,
              onClick: () => handleSwitchOrg(org.name),
              style: org.name === orgState.currentOrgId ? activeItemStyle : itemStyle,
              onMouseEnter: (e: React.MouseEvent<HTMLButtonElement>) => { (e.target as HTMLElement).style.background = "var(--accent, #2a2a2a)"; },
              onMouseLeave: (e: React.MouseEvent<HTMLButtonElement>) => { if (org.name !== orgState.currentOrgId) (e.target as HTMLElement).style.background = "transparent"; },
            },
            org.name === orgState.currentOrgId ? "\u2713 " : "  ",
            org.displayName || org.name,
          ),
        ),

        // Create org option
        showCreateOrg &&
          createElement(
            "div",
            null,
            createElement("div", { style: separatorStyle }),
            !createOpen
              ? createElement(
                  "button",
                  {
                    onClick: () => setCreateOpen(true),
                    style: itemStyle,
                    onMouseEnter: (e: React.MouseEvent<HTMLButtonElement>) => { (e.target as HTMLElement).style.background = "var(--accent, #2a2a2a)"; },
                    onMouseLeave: (e: React.MouseEvent<HTMLButtonElement>) => { (e.target as HTMLElement).style.background = "transparent"; },
                  },
                  "+ Create Organization",
                )
              : createElement(
                  "div",
                  { style: { padding: "8px 12px" } },
                  createElement("input", {
                    type: "text",
                    placeholder: "org-name",
                    value: newOrgName,
                    onChange: (e: React.ChangeEvent<HTMLInputElement>) => setNewOrgName(e.target.value),
                    style: {
                      width: "100%",
                      padding: "6px 8px",
                      fontSize: 12,
                      borderRadius: 4,
                      border: "1px solid var(--border, #333)",
                      background: "var(--background, #111)",
                      color: "inherit",
                      marginBottom: 4,
                    },
                    disabled: creating,
                  }),
                  createElement("input", {
                    type: "text",
                    placeholder: "Display Name",
                    value: newOrgDisplay,
                    onChange: (e: React.ChangeEvent<HTMLInputElement>) => setNewOrgDisplay(e.target.value),
                    style: {
                      width: "100%",
                      padding: "6px 8px",
                      fontSize: 12,
                      borderRadius: 4,
                      border: "1px solid var(--border, #333)",
                      background: "var(--background, #111)",
                      color: "inherit",
                      marginBottom: 4,
                    },
                    disabled: creating,
                  }),
                  error && createElement("div", { style: { fontSize: 11, color: "#ef4444", marginBottom: 4 } }, error),
                  createElement(
                    "div",
                    { style: { display: "flex", gap: 4 } },
                    createElement(
                      "button",
                      {
                        onClick: handleCreateOrg,
                        disabled: creating || !newOrgName.trim(),
                        style: {
                          flex: 1,
                          padding: "5px 8px",
                          fontSize: 12,
                          borderRadius: 4,
                          border: "none",
                          background: "var(--primary, #3b82f6)",
                          color: "#fff",
                          cursor: creating ? "wait" : "pointer",
                          opacity: creating || !newOrgName.trim() ? 0.5 : 1,
                        },
                      },
                      creating ? "Creating..." : "Create",
                    ),
                    createElement(
                      "button",
                      {
                        onClick: () => { setCreateOpen(false); setError(null); },
                        style: {
                          padding: "5px 8px",
                          fontSize: 12,
                          borderRadius: 4,
                          border: "1px solid var(--border, #333)",
                          background: "transparent",
                          color: "inherit",
                          cursor: "pointer",
                        },
                      },
                      "Cancel",
                    ),
                  ),
                ),
          ),

        // Logout
        createElement("div", { style: separatorStyle }),
        createElement(
          "button",
          {
            onClick: handleLogout,
            style: { ...itemStyle, color: "var(--destructive, #ef4444)" },
            onMouseEnter: (e: React.MouseEvent<HTMLButtonElement>) => { (e.target as HTMLElement).style.background = "var(--accent, #2a2a2a)"; },
            onMouseLeave: (e: React.MouseEvent<HTMLButtonElement>) => { (e.target as HTMLElement).style.background = "transparent"; },
          },
          "Sign out",
        ),
      ),
  );
}
