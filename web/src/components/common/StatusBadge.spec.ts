import { render, screen } from '@testing-library/vue'
import { describe, expect, it } from 'vitest'

import StatusBadge from '@/components/common/StatusBadge.vue'

describe('StatusBadge', () => {
  it('renders an execution status label', () => {
    const { container } = render(StatusBadge, {
      props: { kind: 'status', value: 'running' },
    })

    expect(screen.getByText('执行中')).toBeTruthy()
    expect(screen.getByLabelText('执行状态：执行中')).toBeTruthy()
    expect(container.firstElementChild?.classList.contains('status-badge--running')).toBe(
      true,
    )
  })

  it('renders a risk level independently from status', () => {
    const { container } = render(StatusBadge, {
      props: { kind: 'risk', value: 'medium' },
    })

    expect(screen.getByText('中危')).toBeTruthy()
    expect(screen.getByLabelText('风险等级：中危')).toBeTruthy()
    expect(container.firstElementChild?.classList.contains('status-badge--medium')).toBe(
      true,
    )
  })

  it('uses the active tone for uploading', () => {
    const { container } = render(StatusBadge, {
      props: { kind: 'status', value: 'UPLOADING' },
    })

    expect(container.firstElementChild?.classList.contains('status-badge--running')).toBe(
      true,
    )
  })
})
