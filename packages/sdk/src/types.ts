export type PlatformKind = "web" | "macos" | "windows" | "linux" | "android" | "ios";

export type SovereignRole =
  | "SUPER_ADMIN"
  | "DEPARTMENT_HEAD"
  | "STAFF"
  | "AUDITOR"
  | "CISO"
  | "SECURITY_ANALYST"
  | "EXECUTIVE"
  | "VIEWER";

export interface DeviceContext {
  deviceId: string;
  platform: PlatformKind;
  appVersion: string;
  deviceName?: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: string;
  refreshExpiresAt?: string;
}

export interface SessionUser {
  sub: string;
  email: string;
  role: SovereignRole;
  tenantId: string;
  department?: string;
  forcePasswordChange?: boolean;
}

export interface LoginRequest {
  email: string;
  password: string;
  device: DeviceContext;
}

export interface LoginResponse {
  tokens: TokenSet;
  user: SessionUser;
  device_session?: DeviceSession;
  access_token?: string;
  refresh_token?: string;
  token_type?: "bearer";
}

export interface DeviceSession {
  id: string;
  tenant_id: string;
  device_id?: string;
  device_name?: string;
  platform?: PlatformKind;
  app_version?: string;
  started_at?: string;
  ended_at?: string | null;
  revoked_at?: string | null;
}

export interface RiskActor {
  actor_hash: string;
  risk_score: number;
  pii_attempts_last_hour?: number;
  injection_attempts_last_hour?: number;
  semantic_hits_last_hour?: number;
  quarantined?: boolean;
  quarantine_review_required?: boolean;
  quarantine_reason?: string | null;
  labels?: string[];
}

export interface RiskHeatmap {
  actors: RiskActor[];
  quarantined_users?: number;
  quarantine_review_users?: number;
}

export interface AuditEntry {
  timestamp: string;
  actor_hash?: string;
  action?: string;
  policy_triggered?: string;
  signature?: string;
  previous_hash?: string;
}

export interface EvidenceReportResponse {
  status: string;
  file?: string;
  certificate?: string;
  sha256?: string;
}

export interface ControlRoomSnapshot {
  generated_at: string;
  gateway: {
    status: string;
    service?: string;
    engine?: string;
    deployment_mode?: string;
    startup_completed_at?: string | null;
  };
  summary?: Record<string, unknown>;
  readiness?: {
    score?: number;
    status?: string;
  };
  risk?: RiskHeatmap;
  alerts?: {
    total?: number;
    items?: Array<Record<string, unknown>>;
  };
  quarantine?: {
    total?: number;
    actors?: RiskActor[];
  };
  ledger?: Record<string, unknown>;
  operations?: Record<string, unknown>;
  recent_events?: Array<Record<string, unknown>>;
  live_stream_url?: string;
}

export interface SDKStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
