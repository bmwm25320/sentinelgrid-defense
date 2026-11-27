export interface Telemetry {
  status: string;
  uptime_seconds: number;
  cpu_percent: number;
  memory_percent: number;
  memory_used_gb: number;
  memory_total_gb: number;
  process_count: number;
  scanned_file_count: number;
  canary_status: 'ARMED' | 'ALERT' | 'DISABLED' | string;
  defcon_level: number;
  database_version?: string;
  total_threats_blocked: number;
  layers: {
    layer1_yara: boolean;
    layer2_canary: boolean;
    layer3_anomaly_threshold: number;
    layer4_network_guard: boolean;
  };
}

export interface AlertItem {
  id: string;
  timestamp: string;
  threat_name: string;
  simple_title?: string;
  simple_description?: string;
  technical_details?: {
    mitre_id?: string;
    mitre_technique?: string;
    process_name?: string;
    pid?: number | string;
    sha256?: string;
    detection_layer?: string;
    reaction_time_ms?: string;
    command_line?: string;
  };
  mitre_id: string;
  mitre_technique: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  process_name: string;
  pid: number | string;
  file_path: string;
  reaction_time_ms: string;
  detection_layer: string;
  action_taken: string;
  sha256: string;
  command_line?: string;
  status: string;
}

export interface QuarantineItem {
  id: string;
  filename: string;
  isolated_filename: string;
  original_path: string;
  quarantine_path: string;
  sha256: string;
  file_size: number;
  threat_name: string;
  simple_title?: string;
  simple_description?: string;
  detection_layer: string;
  mitre_id: string;
  quarantined_at: string;
  status: 'QUARANTINED' | 'RESTORED' | 'SHREDDED' | string;
  file_exists?: boolean;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'INFO' | 'WARNING' | 'CRITICAL' | 'SUCCESS' | string;
  layer: string;
  message: string;
  details?: Record<string, unknown>;
}

export interface ShieldConfig {
  layer1_yara: boolean;
  layer2_canary: boolean;
  layer3_anomaly_threshold: number;
  layer4_network_guard: boolean;
}

export interface VulnerabilityItem {
  id: string;
  title: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  description: string;
  remediation: string;
}

export interface ProcessItem {
  pid: number;
  name: string;
  exe: string;
  cpu_percent: number;
  memory_mb: number;
  status: string;
  user: string;
  is_immune: boolean;
  reason?: string;
}

export interface NetworkConnectionItem {
  local_port: number;
  remote_ip: string;
  remote_port: number;
  pid: number;
  process: string;
  status: string;
}

export interface ListeningPortItem {
  port: number;
  ip: string;
  process: string;
  pid: number;
  is_risky: boolean;
  risk_desc: string;
}

export interface StartupItem {
  name: string;
  command: string;
  hive: string;
  location: string;
  suspicious: boolean;
}

export interface DeviceAudit {
  timestamp: string;
  security_score: number;
  security_rating: 'EXCELLENT' | 'GOOD' | 'VULNERABLE' | string;
  system: {
    hostname: string;
    os_name: string;
    os_release: string;
    os_version: string;
    os_platform: string;
    processor: string;
    cpu_count: number;
    cpu_percent: number;
    ram_total_gb: number;
    ram_used_gb: number;
    ram_percent: number;
    disk_total_gb: number;
    disk_free_gb: number;
    disk_percent: number;
    boot_time: string;
    database_version: string;
    agent_status: string;
  };
  process_audit: {
    total_count: number;
    top_processes: ProcessItem[];
    suspicious_processes: ProcessItem[];
  };
  network_audit: {
    listening_ports_count: number;
    listening_ports: ListeningPortItem[];
    established_count: number;
    foreign_connections_count: number;
    foreign_connections: NetworkConnectionItem[];
    flagged_ports: {
      port: number;
      service: string;
      process: string;
      pid: number;
    }[];
  };
  startup_audit: {
    entries_count: number;
    entries: StartupItem[];
  };
  vulnerabilities: VulnerabilityItem[];
  canary_shield: {
    status: string;
    tripwire_file: string;
    path: string;
  };
}

export interface SmartScanState {
  status: 'IDLE' | 'SCANNING' | 'COMPLETED';
  scan_type: string;
  stage: string;
  progress: number;
  current_target: string;
  items_scanned: number;
  threats_detected: any[];
  vulnerabilities_detected: VulnerabilityItem[];
  started_at: string | null;
  finished_at: string | null;
  duration_seconds: number;
  security_score?: number;
}

export interface UrlCheckResult {
  url: string;
  domain: string;
  status: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  risk_score: number;
  verdict_title: string;
  explanation: string;
  reasons: string[];
}

export interface ExclusionsResponse {
  exclusions: string[];
}

export interface DndStatusResponse {
  dnd_enabled: boolean;
  mode: string;
}

export interface AuthUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  isDemo?: boolean;
}

export interface RamAppItem {
  pid: number;
  name: string;
  memory_mb: number;
  can_safely_close: boolean;
  is_useless_bloat?: boolean;
  category: string;
}

export interface GroupedRamAppItem {
  name: string;
  pids: number[];
  instance_count: number;
  total_memory_mb: number;
  can_safely_close: boolean;
  is_useless_bloat: boolean;
  category: string;
}

export interface RamDiagnostics {
  total_gb: number;
  used_gb: number;
  available_gb: number;
  percent: number;
  recommended_reclaim_mb: number;
  useless_bloat_mb?: number;
  useless_bloat_count?: number;
  safe_count: number;
  top_apps: RamAppItem[];
  grouped_apps?: GroupedRamAppItem[];
}

export interface RamOptimizeResponse {
  status: string;
  reclaimed_mb: number;
  trimmed_processes_count?: number;
  closed_pids: number[];
  closed_names: string[];
  new_used_gb: number;
  new_percent: number;
}

export interface FastLaptopScanState {
  status: 'IDLE' | 'SCANNING' | 'COMPLETED';
  stage: string;
  stage_index: number;
  total_stages: number;
  progress: number;
  items_scanned: number;
  threats_found: any[];
  issues_fixed: number;
  started_at: string | null;
  finished_at: string | null;
  elapsed_seconds: number;
  estimated_remaining_seconds: number;
  summary: {
    memory_integrity?: string;
    startup_persistence?: string;
    user_folders_status?: string;
    network_firewall?: string;
    security_verdict?: string;
  };
}

export interface VaultAccountItem {
  id?: string;
  service_name: string;
  url?: string;
  username: string;
  password: string;
  category?: string;
  notes?: string;
  updated_at?: string;
  user_id?: string;
}

export interface VaultVerifyResponse {
  status: 'initialized' | 'unlocked';
  is_new: boolean;
  count?: number;
  message?: string;
}

export interface VaultStatusResponse {
  is_configured: boolean;
  encryption: string;
  vault_file: string;
}

export interface LoginAuditLog {
  id?: string;
  uid: string;
  email: string;
  full_name: string;
  photo_url: string | null;
  event_type: 'NEW_ACCOUNT_SIGNUP' | 'USER_LOGIN';
  login_date: string;
  login_time: string;
  iso_timestamp: string;
  platform: 'Windows Desktop' | 'Web Portal' | 'Android Mobile';
}

export interface AuditStats {
  total_users: number;
  total_logins: number;
  logins_today: number;
  platforms: {
    windows: number;
    android: number;
    web: number;
  };
  event_types: {
    signups: number;
    logins: number;
  };
}

export interface AuditLogsResponse {
  logs: LoginAuditLog[];
  total: number;
  admin_authorized: boolean;
}

export interface VaultPinResetRequest {
  id?: string;
  uid: string;
  email: string;
  full_name?: string;
  status: 'pending' | 'approved' | 'rejected';
  requestedAt: string;
  approvedAt?: string;
  approvedBy?: string;
}

export interface VaultBreachEntryResult {
  id?: string;
  service_name: string;
  username: string;
  breached: boolean;
  leak_count: number;
  reused: boolean;
  strength: 'WEAK' | 'GOOD' | 'STRONG' | string;
  checked_online: boolean;
}

export interface VaultBreachReport {
  total_entries: number;
  breached_count: number;
  reused_count: number;
  weak_count: number;
  hibp_reachable: boolean;
  checked_at: string;
  results: VaultBreachEntryResult[];
}

export interface BlockedIpItem {
  ip: string;
  reason: string;
  rule_name: string;
  firewall_enforced: boolean;
  enforcement_note: string;
  blocked_at: string;
}

export interface ArpMitmStatus {
  status: 'SAFE' | 'ALERT' | 'UNKNOWN' | string;
  anomalies: {
    interface: string;
    mac_address: string;
    conflicting_ips: string[];
    description: string;
  }[];
  entries_checked: number;
  checked_at?: string;
}

export interface HardwarePrivacyApp {
  app: string;
  path: string;
  active: boolean;
}

export interface HardwarePrivacyStatus {
  webcam_in_use: boolean;
  webcam_active_apps: HardwarePrivacyApp[];
  recent_webcam_apps: HardwarePrivacyApp[];
  microphone_in_use: boolean;
  microphone_active_apps: HardwarePrivacyApp[];
  recent_microphone_apps: HardwarePrivacyApp[];
  guard_status: string;
  checked_at: string;
}

export interface NetworkShieldStatus {
  blocked_ips: BlockedIpItem[];
  arp_mitm: ArpMitmStatus;
  hardware_privacy: HardwarePrivacyStatus;
}

export interface UsbDriveItem {
  mountpoint: string;
  fstype: string;
  total_gb: number;
}

export interface UsbScanResult {
  target_path: string;
  files_scanned: number;
  threats_found: number;
  threats: AlertItem[];
  status: string;
  scanned_at: string;
}

export interface UsbShieldStatus {
  status: string;
  connected_drives: UsbDriveItem[];
  last_scan: UsbScanResult | null;
}

export interface ActiveAppInfo {
  process_name: string;
  window_title: string;
  pid: number;
  exe?: string;
  detected_at: string;
}

export interface GeminiContextState {
  background_enabled: boolean;
  hotkey: string;
  current_app: ActiveAppInfo;
  last_external_app: ActiveAppInfo | null;
  recent_apps: ActiveAppInfo[];
  summon_counter: number;
}

export interface GeminiTaskOption {
  id: string;
  title: string;
  description: string;
  impact: 'SAFE' | 'FAST' | 'DEEP' | string;
  action_type: string;
  params?: Record<string, any>;
}

export interface GeminiTaskPlan {
  task: string;
  used_gemini_llm: boolean;
  active_app: ActiveAppInfo | Record<string, any>;
  analysis: string;
  options: GeminiTaskOption[];
  planned_at: string;
}

export interface GeminiExecuteResult {
  status: string;
  action_type: string;
  summary: string;
  navigate_to?: string;
  details?: Record<string, any>;
}

export interface DiskJunkCategory {
  id: string;
  label: string;
  path: string;
  file_count: number;
  size_mb: number;
}

export interface DiskJunkScanResult {
  total_files: number;
  total_mb: number;
  categories: DiskJunkCategory[];
  scanned_at: string;
}

export interface DiskJunkCleanResult {
  status: string;
  deleted_files: number;
  skipped_locked: number;
  freed_mb: number;
  cleaned_at: string;
}

export interface ManagedStartupItem {
  name: string;
  command: string;
  hive: string;
  enabled: boolean;
  protected: boolean;
  suspicious: boolean;
}

export interface OutdatedSoftwareItem {
  name: string;
  id: string;
  current_version: string;
  available_version: string;
  severity: 'HIGH' | 'MEDIUM' | string;
}

export interface SoftwareScanResult {
  winget_available: boolean;
  outdated_count: number;
  high_severity_count?: number;
  packages: OutdatedSoftwareItem[];
  scanned_at: string;
  error?: string;
}

export interface SafeMoneySite {
  name: string;
  url: string;
  category: string;
}

export interface SafeMoneyLaunchResult {
  safe_money: {
    status: string;
    url: string;
    isolation_mode: string;
    clipboard_cleared: boolean;
    extensions_disabled: boolean;
    launched_at: string;
  };
  url_verdict: UrlCheckResult;
}

export interface ProcessThreatItem {
  pid: number;
  name: string;
  cmdline: string;
  exe: string;
  risk_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | string;
  mitre_id?: string;
  reasons: string[];
}

export interface ProcessHuntResult {
  status: 'ALERT' | 'CLEAN' | string;
  processes_inspected: number;
  threats_found: number;
  threats: ProcessThreatItem[];
  scanned_at: string;
}

export interface ScheduledTaskItem {
  task_name: string;
  command: string;
  author: string;
  status: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | string;
}

export interface ScheduledTasksResult {
  supported: boolean;
  suspicious_count: number;
  tasks: ScheduledTaskItem[];
  error?: string | null;
  scanned_at: string;
}

export interface DnsShieldStatus {
  enabled: boolean;
  hosts_enforced?: boolean;
  domains_count: number;
  sample_domains?: string[];
  note?: string;
}

export interface SnapshotItem {
  name: string;
  size_kb: number;
}

export interface SnapshotBackupResult {
  status: string;
  snapshot_name: string;
  files_backed_up: number;
  size_kb: number;
  created_at: string;
}

export interface HoneyTokenTrapItem {
  name: string;
  category: string;
  mitre_id: string;
  expected_sha256: string;
  actual_sha256: string;
  intact: boolean;
  size_bytes: number;
  path: string;
}

export interface HoneyTokenBreachRecord {
  trap_name: string;
  category: string;
  mitre_id: string;
  event_type: string;
  healed: boolean;
  restored_sha256: string;
  reaction_ms: number;
  timestamp: string;
}

export interface DeceptionGridStatus {
  armed: boolean;
  traps_dir: string;
  traps_count: number;
  intact_count: number;
  repaired_now: number;
  auto_heal_count: number;
  last_deployed_at?: string | null;
  traps: HoneyTokenTrapItem[];
  breaches: HoneyTokenBreachRecord[];
}

export interface SimulateDeceptionResult {
  status: string;
  trap_name: string;
  tampered_sha256: string;
  restored_sha256: string;
  healed: boolean;
  reaction_ms: number;
  mitre_id: string;
  summary: string;
}

export interface BinarySignatureItem {
  process_name: string;
  exe: string;
  signature_status: string;
  signer: string;
  trust_level: 'TRUSTED' | 'UNSIGNED' | 'HIGH_RISK_UNSIGNED' | 'TAMPERED' | 'UNVERIFIED' | string;
  risk_score: number;
}

export interface BinarySignatureAuditResult {
  supported: boolean;
  checked_count: number;
  signed_valid_count: number;
  unsigned_or_risky_count: number;
  binaries: BinarySignatureItem[];
  checked_at: string;
}




