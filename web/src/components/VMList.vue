<template>
  <div class="vm-list">
    <div class="vm-list-toolbar">
      <wf-text-input
        placeholder="Search VMs..."
        :value="search"
        @input="search = ($event.target as HTMLInputElement).value"
      />
      <select v-model="refreshRate" class="refresh-select">
        <option :value="2000">2s</option>
        <option :value="5000">5s</option>
        <option :value="10000">10s</option>
        <option :value="30000">30s</option>
      </select>
    </div>

    <div v-if="error" class="vm-list-error">{{ error }}</div>

    <div v-for="vm in filteredVMs" :key="vm.id" class="vm-list-item" @click="goToVM(vm.id)">
      <wf-list-item>
        <span slot="leading">
          <wf-status-dot :status="stateToStatus(vm.state)" />
        </span>
        <span>{{ vm.name }}</span>
        <span slot="trailing" class="vm-ip">{{ vm.ip ?? '—' }}</span>
        <div slot="actions" @click.stop>
          <button v-if="vm.state !== 'running'" @click="doStart(vm.id)">Start</button>
          <button v-if="vm.state === 'running'" @click="doStop(vm.id)">Stop</button>
          <button @click="doRestart(vm.id)">Restart</button>
          <button class="btn-danger" @click="doDelete(vm.id)">Delete</button>
        </div>
      </wf-list-item>
    </div>

    <div v-if="!error && filteredVMs.length === 0" class="vm-list-empty">No VMs found.</div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue';
import { useRouter } from 'vue-router';
import { api, type VM } from '../lib/api';

const router = useRouter();
const vms = ref<VM[]>([]);
const search = ref('');
const refreshRate = ref(5000);
const error = ref('');
let timer: ReturnType<typeof setInterval> | null = null;

const filteredVMs = computed(() =>
  vms.value.filter((vm) =>
    vm.name.toLowerCase().includes(search.value.toLowerCase()),
  ),
);

function stateToStatus(state: string): string {
  if (state === 'running') return 'online';
  if (state === 'stopped') return 'offline';
  return 'away';
}

async function loadVMs() {
  try {
    vms.value = await api.listVMs();
    error.value = '';
  } catch (e) {
    error.value = String(e);
  }
}

function startPolling() {
  if (timer !== null) clearInterval(timer);
  timer = setInterval(loadVMs, refreshRate.value);
}

watch(refreshRate, () => {
  startPolling();
});

onMounted(async () => {
  await loadVMs();
  startPolling();
});

onUnmounted(() => {
  if (timer !== null) clearInterval(timer);
});

function goToVM(id: string) {
  router.push(`/vms/${id}`);
}

async function doStart(id: string) {
  try { await api.startVM(id); await loadVMs(); } catch (e) { error.value = String(e); }
}

async function doStop(id: string) {
  try { await api.stopVM(id); await loadVMs(); } catch (e) { error.value = String(e); }
}

async function doRestart(id: string) {
  try { await api.restartVM(id); await loadVMs(); } catch (e) { error.value = String(e); }
}

async function doDelete(id: string) {
  if (!confirm(`Delete VM ${id}?`)) return;
  try { await api.deleteVM(id); await loadVMs(); } catch (e) { error.value = String(e); }
}
</script>

<style scoped>
.vm-list-toolbar {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 1rem;
}
.refresh-select {
  padding: 0.25rem 0.5rem;
}
.vm-list-item {
  cursor: pointer;
}
.vm-ip {
  font-size: 0.85em;
  opacity: 0.7;
}
.vm-list-error {
  color: var(--wf-color-error, red);
  margin-bottom: 0.5rem;
}
.vm-list-empty {
  opacity: 0.6;
}
.btn-danger {
  color: var(--wf-color-error, red);
}
</style>
