import { fireEvent, render, screen } from '@testing-library/vue'
import { describe, expect, it } from 'vitest'

import LogoutErrorAlert from '@/components/auth/LogoutErrorAlert.vue'

describe('LogoutErrorAlert', () => {
  it('announces the error and emits dismiss', async () => {
    const { emitted } = render(LogoutErrorAlert, {
      props: { message: '退出登录失败' },
    })

    expect(screen.getByRole('alert').textContent).toContain('退出登录失败')
    await fireEvent.click(screen.getByRole('button', { name: '关闭退出错误' }))
    expect(emitted().dismiss).toHaveLength(1)
  })
})
