<template>
  <div class="vm-detail">
    <div class="vm-detail-header">
      <button @click="router.push('/')">← Back</button>
      <h2>{{ vm?.name ?? route.params.id }}</h2>
    </div>

    <div class="vm-detail-tabs">
      <button
        :class="{ active: activeTab === 'overview' }"
        @click="setTab('overview')"
      >Overview</button>
      <button
        :class="{ active: activeTab === 'terminal' }"
        @click="setTab('terminal')"
      >Terminal</button>
    </div>

    <div v-if="error" class="vm-detail-error">{{ error }}</div>

    <div v-if="vm">
      <VMOverview v-if="activeTab === 'overview'" :vm="vm" @refresh="loadVM" />
      <Terminal v-if="activeTab === 'terminal'" :vm-id="vm.id" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { api, type VM } from '../lib/api';
import VMOverview from './VMOverview.vue';
import Terminal from './Terminal.vue';

const route = useRoute();
const router = useRouter();
const vm = ref<VM | null>(null);
const error = ref('');

const activeTab = ref<'overview' | 'terminal'>(
  route.path.endsWith('/terminal') ? 'terminal' : 'overview',
);

async function loadVM() {
  try {
    vm.value = await api.getVM(route.params.id as string);
    error.value = '';
  } catch (e) {
    error.value = String(e);
  }
}

onMounted(loadVM);

watch(
  () => route.path,
  (path) => {
    activeTab.value = path.endsWith('/terminal') ? 'terminal' : 'overview';
  },
);

function setTab(tab: 'overview' | 'terminal') {
  activeTab.value = tab;
  const id = route.params.id as string;
  if (tab === 'terminal') {
    router.push(`/vms/${id}/terminal`);
  } else {
    router.push(`/vms/${id}`);
  }
}
</script>

<style scoped>
.vm-detail-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
}
.vm-detail-tabs {
  display: flex;
  gap: 0.25rem;
  margin-bottom: 1rem;
  border-bottom: 1px solid var(--wf-color-border, #ccc);
}
.vm-detail-tabs button {
  padding: 0.4rem 1rem;
  background: none;
  border: none;
  cursor: pointer;
  border-bottom: 2px solid transparent;
}
.vm-detail-tabs button.active {
  border-bottom-color: var(--wf-color-primary, #005fcc);
  font-weight: bold;
}
.vm-detail-error {
  color: var(--wf-color-error, red);
  margin-bottom: 0.5rem;
}
</style>
