import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'

import AppShell from '@/layouts/AppShell.vue'
import { useSessionStore } from '@/stores/session'

function narrowMatchMedia(): MediaQueryList {
  return {
    matches: true,
    media: '(max-width: 840px)',
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }
}

async function mountShell() {
  vi.stubGlobal('matchMedia', vi.fn(() => narrowMatchMedia()))
  const pinia = createPinia()
  setActivePinia(pinia)
  const session = useSessionStore()
  session.user = {
    id: 'user-a',
    username: 'admin',
    display_name: '本地管理员',
    role: 'administrator',
    must_change_password: false,
  }

  const EmptyRoute = { template: '<div>route</div>' }
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: EmptyRoute },
      { path: '/tasks', component: EmptyRoute },
      { path: '/tasks/new', component: EmptyRoute },
      { path: '/system', component: EmptyRoute },
    ],
  })
  await router.push('/')
  await router.isReady()

  return mount(AppShell, {
    attachTo: document.body,
    global: {
      plugins: [pinia, router],
    },
  })
}

describe('AppShell', () => {
  afterEach(() => {
    document.body.style.overflow = ''
    vi.unstubAllGlobals()
  })

  it('exposes the active route and localized account role', async () => {
    const wrapper = await mountShell()

    expect(wrapper.get('.nav-item[href="/"]').attributes('aria-current')).toBe('page')
    expect(wrapper.text()).toContain('系统管理员')
    expect(wrapper.get('.brand').attributes('aria-label')).toBe(
      '库博二进制代码静态分析工具系统V1.0',
    )
    expect(wrapper.get('.brand-copy').text()).toContain('库博')
    expect(wrapper.get('.brand-copy').text()).toContain('二进制代码静态分析工具系统V1.0')

    wrapper.unmount()
  })

  it('opens and closes the mobile navigation with keyboard-safe state', async () => {
    const wrapper = await mountShell()
    const menuButton = wrapper.get<HTMLButtonElement>('.mobile-menu')

    expect(wrapper.get('.sidebar').attributes('aria-hidden')).toBe('true')
    await menuButton.trigger('click')
    await nextTick()

    expect(menuButton.attributes('aria-expanded')).toBe('true')
    expect(wrapper.get('.main-area').attributes('aria-hidden')).toBe('true')
    expect(document.body.style.overflow).toBe('hidden')

    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await nextTick()

    expect(menuButton.attributes('aria-expanded')).toBe('false')
    expect(document.body.style.overflow).toBe('')
    expect(document.activeElement).toBe(menuButton.element)

    wrapper.unmount()
  })
})
