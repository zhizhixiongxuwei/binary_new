import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { defineComponent, nextTick } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from '@/api/client'
import LoginView from '@/views/LoginView.vue'

const routerMocks = vi.hoisted(() => ({
  replace: vi.fn(),
}))

vi.mock('vue-router', () => ({
  useRoute: () => ({ query: {} }),
  useRouter: () => ({ replace: routerMocks.replace }),
}))

vi.mock('@/api/runtime', () => ({
  isDemoMode: false,
}))

const LoginFormStub = defineComponent({
  name: 'LoginForm',
  props: {
    loading: Boolean,
    errorMessage: { type: String, default: '' },
    retryAfterSeconds: { type: Number, default: 0 },
  },
  emits: ['submit'],
  template: `
    <button
      type="button"
      :disabled="loading || retryAfterSeconds > 0"
      @click="$emit('submit', { username: 'unknown-user', password: 'private-value' })"
    >
      submit
    </button>
  `,
})

describe('LoginView', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    routerMocks.replace.mockReset()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('在登录页展示统一的库博平台名称', () => {
    const wrapper = mount(LoginView, {
      global: { stubs: { LoginForm: LoginFormStub } },
    })

    expect(wrapper.get('h1').text()).toBe('库博二进制静态分析平台')
    expect(wrapper.get('.login-footer').text()).toContain(
      '库博二进制静态分析平台',
    )
  })

  it('uses bounded retry metadata and automatically restores the form', async () => {
    vi.spyOn(api, 'login').mockRejectedValue(
      new ApiError(
        'backend wording is not rendered',
        429,
        { code: 'login_rate_limited' },
        { retryAfterSeconds: 3 },
      ),
    )
    const wrapper = mount(LoginView, {
      global: { stubs: { LoginForm: LoginFormStub } },
    })

    await wrapper.get('button').trigger('click')
    await flushPromises()

    const form = wrapper.findComponent(LoginFormStub)
    expect(form.props('retryAfterSeconds')).toBe(3)
    expect(form.props('errorMessage')).toBe('')
    expect(wrapper.text()).not.toContain('backend wording')
    expect(routerMocks.replace).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(3_000)
    await nextTick()
    expect(form.props('retryAfterSeconds')).toBe(0)
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
  })

  it('falls back to one second and unifies credential failures', async () => {
    const login = vi
      .spyOn(api, 'login')
      .mockRejectedValueOnce(
        new ApiError('backend throttle wording', 429, {
          code: 'login_rate_limited',
        }),
      )
      .mockRejectedValueOnce(
        new ApiError('unknown account', 401, {
          code: 'invalid_credentials',
        }),
      )
    const wrapper = mount(LoginView, {
      global: { stubs: { LoginForm: LoginFormStub } },
    })
    const form = wrapper.findComponent(LoginFormStub)

    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(form.props('retryAfterSeconds')).toBe(1)

    await vi.advanceTimersByTimeAsync(1_000)
    await nextTick()
    await wrapper.get('button').trigger('click')
    await flushPromises()

    expect(login).toHaveBeenCalledTimes(2)
    expect(form.props('errorMessage')).toBe('用户名或密码错误')
    expect(wrapper.text()).not.toContain('unknown account')
    expect(wrapper.text()).not.toContain('unknown-user')
  })
})
