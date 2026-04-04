<template>
  <div class="vm-overview">
    <div class="vm-overview-row">
      <span class="label">Status</span>
      <span><wf-status-dot :status="stateToStatus(vm.state)" /> {{ vm.state }}</span>
    </div>
    <div class="vm-overview-row"><span class="label">ID</span><span>{{ vm.id }}</span></div>
    <div class="vm-overview-row"><span class="label">Name</span><span>{{ vm.name }}</span></div>
    <div class="vm-overview-row"><span class="label">Image</span><span>{{ vm.image }}</span></div>
    <div class="vm-overview-row"><span class="label">Runtime</span><span>{{ vm.runtime }}</span></div>
    <div class="vm-overview-row" v-if="vm.shell"><span class="label">Shell</span><span>{{ vm.shell }}</span></div>
    <div class="vm-overview-row" v-if="vm.ip"><span class="label">IP</span><span>{{ vm.ip }}</span></div>
    <div class="vm-overview-row" v-if="vm.gateway"><span class="label">Gateway</span><span>{{ vm.gateway }}</span></div>
    <div class="vm-overview-row" v-if="vm.dns">
      <span class="label">DNS</span>
      <span>
        <span v-if="vm.dns.servers">Servers: {{ vm.dns.servers.join(', ') }}</span>
        <span v-if="vm.dns.search"> Search: {{ vm.dns.search.join(', ') }}</span>
      </span>
    </div>
    <div class="vm-overview-row" v-if="vm.root_size"><span class="label">Root Size</span><span>{{ vm.root_size }}</span></div>
    <div class="vm-overview-row"><span class="label">Restart Policy</span><span>{{ vm.restart_policy }}</span></div>
    <div class="vm-overview-row"><span class="label">Restart Strategy</span><span>{{ vm.restart_strategy }}</span></div>
    <div class="vm-overview-row"><span class="label">Init</span><span>{{ vm.init ? 'Yes' : 'No' }}</span></div>
    <div class="vm-overview-row" v-if="vm.template_id"><span class="label">Template</span><span>{{ vm.template_id }}</span></div>
    <div class="vm-overview-row" v-if="vm.env && Object.keys(vm.env).length > 0">
      <span class="label">Environment</span>
      <ul class="env-list">
        <li v-for="(val, key) in vm.env" :key="key">{{ key }}={{ val }}</li>
      </ul>
    </div>

    <div v-if="drives.length > 0">
      <h4>Drives</h4>
      <div v-for="d in drives" :key="d.id" class="vm-overview-row">
        <span class="label">{{ d.name }}</span>
        <span>{{ d.mount_path }} ({{ formatBytes(d.size_bytes) }})</span>
      </div>
    </div>

    <div v-if="devices.length > 0">
      <h4>Devices</h4>
      <div v-for="d in devices" :key="d.id" class="vm-overview-row">
        <span class="label">{{ d.name }}</span>
        <span>{{ d.host_path }} → {{ d.container_path }}</span>
      </div>
    </div>

    <div class="vm-overview-row"><span class="label">Created</span><span>{{ vm.created_at }}</span></div>
    <div class="vm-overview-row" v-if="vm.started_at"><span class="label">Started</span><span>{{ vm.started_at }}</span></div>
    <div class="vm-overview-row" v-if="vm.stopped_at"><span class="label">Stopped</span><span>{{ vm.stopped_at }}</span></div>

    <div class="vm-overview-actions">
      <button v-if="vm.state !== 'running'" @click="doStart">Start</button>
      <button v-if="vm.state === 'running'" @click="doStop">Stop</button>
      <button @click="doRestart">Restart</button>
    </div>

    <div v-if="actionError" class="vm-overview-error">{{ actionError }}</div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api, type VM, type Drive, type Device } from '../lib/api';

const props = defineProps<{ vm: VM }>();
const emit = defineEmits<{ (e: 'refresh'): void }>();

const drives = ref<Drive[]>([]);
const devices = ref<Device[]>([]);
const actionError = ref('');

onMounted(async () => {
  try {
    const [allDrives, allDevices] = await Promise.all([api.listDrives(), api.listDevices()]);
    drives.value = allDrives.filter((d) => d.vm_id === props.vm.id);
    devices.value = allDevices.filter((d) => d.vm_id === props.vm.id);
  } catch {
    // Non-critical — drives/devices section just stays empty.
  }
});

function stateToStatus(state: string): string {
  if (state === 'running') return 'online';
  if (state === 'stopped') return 'offline';
  return 'away';
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${bytes} B`;
}

async function doStart() {
  try { await api.startVM(props.vm.id); emit('refresh'); } catch (e) { actionError.value = String(e); }
}

async function doStop() {
  try { await api.stopVM(props.vm.id); emit('refresh'); } catch (e) { actionError.value = String(e); }
}

async function doRestart() {
  try { await api.restartVM(props.vm.id); emit('refresh'); } catch (e) { actionError.value = String(e); }
}
</script>

<style scoped>
.vm-overview-row {
  display: flex;
  gap: 1rem;
  margin-bottom: 0.4rem;
}
.label {
  font-weight: bold;
  min-width: 140px;
}
.env-list {
  margin: 0;
  padding-left: 1rem;
  list-style: none;
  font-family: monospace;
}
.vm-overview-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 1rem;
}
.vm-overview-error {
  color: var(--wf-color-error, red);
  margin-top: 0.5rem;
}
</style>
