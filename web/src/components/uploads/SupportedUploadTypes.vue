<script setup lang="ts">
import { Box, CodeXml } from 'lucide-vue-next'
</script>

<template>
  <div class="supported-types" aria-label="支持的检测文件类型">
    <div class="supported-types__group">
      <CodeXml :size="17" aria-hidden="true" />
      <div>
        <strong>反编译分析</strong>
        <p>EXE、DLL、SYS、ELF、Mach-O、CLASS、JAR、WAR、EAR、PYC</p>
        <small>原生程序输出类 C 代码；Java 归档优先输出 Java 源码，源码引擎不可用时降级为类与字节码结构。</small>
      </div>
    </div>
    <div class="supported-types__group">
      <Box :size="17" aria-hidden="true" />
      <div>
        <strong>镜像漏洞扫描</strong>
        <p>Docker Save TAR、OCI Image Layout TAR</p>
        <small>普通 TAR 不是容器镜像；漏洞检测使用部署时预装的离线 Trivy 漏洞库。</small>
      </div>
    </div>
  </div>
</template>

<style scoped>
.supported-types {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0;
  margin-bottom: 14px;
  border-block: 1px solid var(--line);
  background: #f7f9f9;
}

.supported-types__group {
  display: grid;
  min-width: 0;
  grid-template-columns: 24px minmax(0, 1fr);
  gap: 8px;
  padding: 12px 14px;
  color: var(--teal-strong);
}

.supported-types__group + .supported-types__group {
  border-left: 1px solid var(--line);
}

.supported-types__group svg {
  margin-top: 1px;
}

.supported-types__group strong,
.supported-types__group p,
.supported-types__group small {
  display: block;
  margin: 0;
}

.supported-types__group strong {
  color: var(--ink-800);
  font-size: 12px;
}

.supported-types__group p {
  margin-top: 3px;
  color: var(--ink-800);
  font-size: 11px;
  line-height: 1.55;
  overflow-wrap: anywhere;
}

.supported-types__group small {
  margin-top: 3px;
  color: var(--ink-600);
  font-size: 10px;
  line-height: 1.5;
}

@media (max-width: 700px) {
  .supported-types {
    grid-template-columns: 1fr;
  }

  .supported-types__group + .supported-types__group {
    border-top: 1px solid var(--line);
    border-left: 0;
  }
}
</style>
