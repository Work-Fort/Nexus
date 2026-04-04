import { createApp, type App } from 'vue';
import { createRouter, createMemoryHistory } from 'vue-router';
import AppComponent from './App.vue';
import VMList from './components/VMList.vue';

// VMDetail is loaded lazily so Task 7 can add it without breaking Task 6.
const VMDetail = () => import('./components/VMDetail.vue');

const apps = new WeakMap<HTMLElement, App>();

function createNexusRouter() {
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: VMList },
      { path: '/vms/:id', component: VMDetail },
      { path: '/vms/:id/terminal', component: VMDetail },
    ],
  });
}

export function mount(el: HTMLElement, props: { connected: boolean }) {
  const router = createNexusRouter();
  const app = createApp(AppComponent, { connected: props.connected });
  app.use(router);
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
