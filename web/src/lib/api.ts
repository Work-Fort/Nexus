function getBaseUrl(): string {
  const match = location.pathname.match(/^\/forts\/([^/]+)/);
  if (match) {
    return `/forts/${match[1]}/api/nexus/v1`;
  }
  return '/v1';
}

const base = getBaseUrl();

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${method} ${path}: ${res.status} ${text}`);
  }
  return res.json();
}

export interface VM {
  id: string;
  name: string;
  tags: string[];
  state: string;
  image: string;
  runtime: string;
  ip?: string;
  gateway?: string;
  dns?: { servers?: string[]; search?: string[] };
  root_size?: string;
  restart_policy: string;
  restart_strategy: string;
  shell?: string;
  init: boolean;
  env?: Record<string, string>;
  template_id?: string;
  created_at: string;
  started_at?: string;
  stopped_at?: string;
}

export interface Drive {
  id: string;
  name: string;
  size_bytes: number;
  mount_path: string;
  vm_id?: string;
  created_at: string;
}

export interface Device {
  id: string;
  name: string;
  host_path: string;
  container_path: string;
  permissions: string;
  gid: number;
  vm_id?: string;
  created_at: string;
}

export const api = {
  listVMs: (tag?: string[], tagMatch?: string) => {
    const params = new URLSearchParams();
    tag?.forEach((t) => params.append('tag', t));
    if (tagMatch) params.set('tag_match', tagMatch);
    const qs = params.toString();
    return request<VM[]>('GET', `/vms${qs ? `?${qs}` : ''}`);
  },
  getVM: (id: string) => request<VM>('GET', `/vms/${id}`),
  startVM: (id: string) => request<void>('POST', `/vms/${id}/start`),
  stopVM: (id: string) => request<void>('POST', `/vms/${id}/stop`),
  restartVM: (id: string) => request<void>('POST', `/vms/${id}/restart`),
  deleteVM: (id: string) => request<void>('DELETE', `/vms/${id}`),
  listDrives: () => request<Drive[]>('GET', '/drives'),
  listDevices: () => request<Device[]>('GET', '/devices'),
};
