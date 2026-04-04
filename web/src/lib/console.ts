export interface ConsoleOptions {
  vmId: string;
  cols: number;
  rows: number;
  onData: (data: ArrayBuffer) => void;
  onExit: (exitCode: number) => void;
  onClose: () => void;
}

export function getConsoleUrl(vmId: string, cols: number, rows: number): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const match = location.pathname.match(/^\/forts\/([^/]+)/);
  const base = match
    ? `/forts/${match[1]}/api/nexus/v1`
    : '/v1';
  return `${proto}//${location.host}${base}/vms/${vmId}/console?cols=${cols}&rows=${rows}`;
}

export function connectConsole(opts: ConsoleOptions): {
  send: (data: string) => void;
  resize: (cols: number, rows: number) => void;
  close: () => void;
} {
  const url = getConsoleUrl(opts.vmId, opts.cols, opts.rows);
  const ws = new WebSocket(url);
  ws.binaryType = 'arraybuffer';

  ws.onmessage = (ev) => {
    if (ev.data instanceof ArrayBuffer) {
      opts.onData(ev.data);
    } else {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'exit') {
          opts.onExit(msg.exit_code);
        }
      } catch {
        // Not JSON — treat as text stdout (shouldn't happen per protocol).
      }
    }
  };

  ws.onclose = () => opts.onClose();

  return {
    send: (data: string) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    },
    resize: (cols: number, rows: number) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'resize', cols, rows }));
      }
    },
    close: () => ws.close(),
  };
}
