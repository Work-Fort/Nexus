<template>
  <div class="terminal-container" ref="containerEl">
    <div ref="terminalEl" class="terminal-inner" />
    <div v-if="exited" class="terminal-overlay">
      <p>Process exited (code {{ exitCode }})</p>
      <button @click="reconnect">Reconnect</button>
    </div>
    <div v-if="disconnected && !exited" class="terminal-overlay">
      <p>Disconnected</p>
      <button @click="reconnect">Reconnect</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import 'xterm/css/xterm.css';
import { connectConsole } from '../lib/console';

const props = defineProps<{ vmId: string }>();

const terminalEl = ref<HTMLElement | null>(null);
const containerEl = ref<HTMLElement | null>(null);
const exited = ref(false);
const exitCode = ref(0);
const disconnected = ref(false);

let term: Terminal | null = null;
let fitAddon: FitAddon | null = null;
let consoleConn: { send: (d: string) => void; resize: (c: number, r: number) => void; close: () => void } | null = null;
let observer: ResizeObserver | null = null;

function setupTerminal() {
  if (!terminalEl.value) return;

  exited.value = false;
  disconnected.value = false;

  term = new Terminal({ cursorBlink: true });
  fitAddon = new FitAddon();
  term.loadAddon(fitAddon);
  term.loadAddon(new WebLinksAddon());
  term.open(terminalEl.value);
  fitAddon.fit();

  const { cols, rows } = term;
  consoleConn = connectConsole({
    vmId: props.vmId,
    cols,
    rows,
    onData: (data) => term?.write(new Uint8Array(data)),
    onExit: (code) => {
      exitCode.value = code;
      exited.value = true;
      consoleConn?.close();
    },
    onClose: () => {
      if (!exited.value) disconnected.value = true;
    },
  });

  term.onData((data) => consoleConn?.send(data));

  observer = new ResizeObserver(() => {
    fitAddon?.fit();
    if (term) consoleConn?.resize(term.cols, term.rows);
  });
  if (containerEl.value) observer.observe(containerEl.value);
}

function teardown() {
  observer?.disconnect();
  observer = null;
  consoleConn?.close();
  consoleConn = null;
  term?.dispose();
  term = null;
  fitAddon = null;
}

function reconnect() {
  teardown();
  setupTerminal();
}

onMounted(setupTerminal);
onUnmounted(teardown);
</script>

<style scoped>
.terminal-container {
  position: relative;
  width: 100%;
  height: 100%;
  min-height: 400px;
  display: flex;
  flex-direction: column;
}
.terminal-inner {
  flex: 1;
  width: 100%;
  height: 100%;
}
.terminal-overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  background: rgba(0, 0, 0, 0.6);
  color: #fff;
  gap: 0.75rem;
}
</style>
