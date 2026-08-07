<script setup lang="ts">
defineProps<{
  title: string
  description?: string
  eyebrow?: string
}>()
</script>

<template>
  <header class="page-header">
    <div class="page-header__copy">
      <span v-if="eyebrow" class="page-header__eyebrow mono">{{ eyebrow }}</span>
      <h1 class="page-header__title">{{ title }}</h1>
      <p v-if="description" class="page-header__description">{{ description }}</p>
    </div>
    <div v-if="$slots.actions" class="page-header__actions">
      <slot name="actions" />
    </div>
  </header>
</template>

<style scoped>
.page-header {
  display: flex;
  min-height: 70px;
  align-items: flex-end;
  justify-content: space-between;
  gap: 24px;
  margin-bottom: 20px;
}

.page-header__copy {
  min-width: 0;
}

.page-header__eyebrow {
  display: block;
  margin-bottom: 8px;
  color: var(--teal-strong);
  font-size: 10px;
  font-weight: 700;
}

.page-header__title {
  margin: 0;
  color: var(--ink-950);
  font-family: "DIN Alternate", "Noto Sans SC", sans-serif;
  font-size: 28px;
  font-weight: 700;
  line-height: 1.2;
  overflow-wrap: anywhere;
}

.page-header__description {
  margin: 8px 0 0;
  color: var(--ink-600);
  font-size: 13px;
  line-height: 1.6;
}

.page-header__actions {
  display: flex;
  min-width: 0;
  flex: 0 0 auto;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
}

@media (max-width: 620px) {
  .page-header {
    min-height: 0;
    align-items: stretch;
    flex-direction: column;
    gap: 14px;
    margin-bottom: 18px;
  }

  .page-header__title {
    font-size: 24px;
  }

  .page-header__actions {
    width: 100%;
  }

  .page-header__actions :deep(.el-button) {
    flex: 1;
    margin-left: 0;
  }
}
</style>
