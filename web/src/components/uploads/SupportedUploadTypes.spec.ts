import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import SupportedUploadTypes from '@/components/uploads/SupportedUploadTypes.vue'

describe('SupportedUploadTypes', () => {
  it('groups inputs by the analysis workflow they start', () => {
    const wrapper = mount(SupportedUploadTypes)
    const groups = wrapper.findAll('.supported-types__group')

    expect(groups).toHaveLength(2)
    expect(groups[0]?.text()).toContain('反编译分析')
    expect(groups[0]?.text()).toContain('EXE、DLL、SYS')
    expect(groups[0]?.text()).toContain('CLASS、JAR、WAR、EAR')
    expect(groups[1]?.text()).toContain('镜像漏洞扫描')
    expect(groups[1]?.text()).toContain('Docker Save TAR')
    expect(groups[1]?.text()).toContain('OCI Image Layout TAR')
    expect(wrapper.attributes('aria-label')).toBe('支持的检测文件类型')
  })
})
