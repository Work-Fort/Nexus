import { createApp, type App } from 'vue';
import AppComponent from './App.vue';

const apps = new WeakMap<HTMLElement, App>();

export function mount(el: HTMLElement, props: { connected: boolean }) {
  const app = createApp(AppComponent, { connected: props.connected });
  app.mount(el);
  apps.set(el, app);
}

export function unmount(el: HTMLElement) {
  const app = apps.get(el);
  if (app) {
    app.unmount();
    apps.delete(el);
  }
}

export const manifest = {
  name: 'nexus',
  label: 'Nexus',
  route: '/nexus',
  display: 'menu' as const,
};
