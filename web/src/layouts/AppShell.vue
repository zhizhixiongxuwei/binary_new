<script setup lang="ts">
import {
  Binary,
  ChevronLeft,
  ChevronRight,
  CircleGauge,
  FileScan,
  LogOut,
  Menu,
  Plus,
  ServerCog,
  X,
} from 'lucide-vue-next'
import {
  computed,
  nextTick,
  onMounted,
  onScopeDispose,
  shallowRef,
  useTemplateRef,
  watch,
} from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { ApiError } from '@/api/client'
import LogoutErrorAlert from '@/components/auth/LogoutErrorAlert.vue'
import {
  PRODUCT_DESCRIPTION,
  PRODUCT_NAME,
  PRODUCT_SHORT_NAME,
} from '@/config/branding'
import { useSessionStore } from '@/stores/session'

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const collapsed = shallowRef(false)
const mobileOpen = shallowRef(false)
const narrowLayout = shallowRef(false)
const loggingOut = shallowRef(false)
const logoutError = shallowRef('')
const mobileMenuButton = useTemplateRef<HTMLButtonElement>('mobileMenuButton')
const mobileCloseButton = useTemplateRef<HTMLButtonElement>('mobileCloseButton')
let mobileMediaQuery: MediaQueryList | null = null

const navigation = computed(() => {
  if (session.user?.must_change_password) return []
  const entries = [
    { label: '系统概览', to: '/', icon: CircleGauge, adminOnly: false },
    { label: '检测任务', to: '/tasks', icon: FileScan, adminOnly: false },
    { label: '新建任务', to: '/tasks/new', icon: Plus, adminOnly: false, operatorOnly: true },
    { label: '系统维护', to: '/system', icon: ServerCog, adminOnly: true },
  ]
  return entries.filter((entry) => {
    if (entry.adminOnly) return session.user?.role === 'administrator'
    if (entry.operatorOnly) return session.user?.role !== 'reader'
    return true
  })
})

const displayName = computed(
  () => session.user?.display_name || session.user?.username || '当前用户',
)
const roleLabel = computed(() => {
  const labels = {
    administrator: '系统管理员',
    operator: '操作员',
    reader: '只读用户',
  } as const
  return session.user ? labels[session.user.role] : '未登录'
})
const drawerHidden = computed(() => narrowLayout.value && !mobileOpen.value)

function isActive(path: string): boolean {
  if (path === '/') return route.path === '/'
  return route.path === path || route.path.startsWith(`${path}/`)
}

function openMobileNavigation(): void {
  mobileOpen.value = true
  void nextTick(() => mobileCloseButton.value?.focus())
}

function closeMobileNavigation(restoreFocus = false): void {
  if (!mobileOpen.value) return
  mobileOpen.value = false
  if (restoreFocus) {
    void nextTick(() => mobileMenuButton.value?.focus())
  }
}

function syncNarrowLayout(event: MediaQueryList | MediaQueryListEvent): void {
  narrowLayout.value = event.matches
  if (!event.matches) mobileOpen.value = false
}

function handleKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape' && mobileOpen.value) {
    closeMobileNavigation(true)
  }
}

async function handleLogout(): Promise<void> {
  loggingOut.value = true
  logoutError.value = ''
  try {
    await session.logout()
    await router.replace({ name: 'login' })
  } catch (error) {
    logoutError.value =
      error instanceof ApiError ? error.message : '无法退出登录，请稍后重试'
  } finally {
    loggingOut.value = false
  }
}

watch(
  () => route.fullPath,
  () => {
    mobileOpen.value = false
  },
)

watch(
  () => mobileOpen.value && narrowLayout.value,
  (locked, _, onCleanup) => {
    if (!locked) return
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    onCleanup(() => {
      document.body.style.overflow = previousOverflow
    })
  },
)

onMounted(() => {
  document.addEventListener('keydown', handleKeydown)
  if (typeof window.matchMedia === 'function') {
    mobileMediaQuery = window.matchMedia('(max-width: 840px)')
    syncNarrowLayout(mobileMediaQuery)
    mobileMediaQuery.addEventListener('change', syncNarrowLayout)
  }
})

onScopeDispose(() => {
  document.removeEventListener('keydown', handleKeydown)
  mobileMediaQuery?.removeEventListener('change', syncNarrowLayout)
})
</script>

<template>
  <div class="app-shell" :class="{ 'app-shell--collapsed': collapsed }">
    <a class="skip-link" href="#main-content">跳到主要内容</a>
    <button
      ref="mobileMenuButton"
      class="mobile-menu"
      type="button"
      aria-label="打开主导航"
      title="打开主导航"
      aria-controls="primary-sidebar"
      :aria-expanded="mobileOpen"
      @click="openMobileNavigation"
    >
      <Menu :size="20" aria-hidden="true" />
    </button>

    <div
      v-if="mobileOpen"
      class="sidebar-scrim"
      aria-hidden="true"
      @click="closeMobileNavigation(true)"
    />

    <aside
      id="primary-sidebar"
      class="sidebar"
      :class="{ 'sidebar--mobile-open': mobileOpen }"
      :aria-hidden="drawerHidden"
      :inert="drawerHidden"
    >
      <div class="brand" :aria-label="PRODUCT_NAME">
        <span class="brand-mark" aria-hidden="true"><Binary :size="22" /></span>
        <div v-show="!collapsed" class="brand-copy">
          <strong>{{ PRODUCT_SHORT_NAME }}</strong>
          <span>{{ PRODUCT_DESCRIPTION }}</span>
        </div>
        <button
          ref="mobileCloseButton"
          class="mobile-close"
          type="button"
          aria-label="关闭主导航"
          title="关闭主导航"
          @click="closeMobileNavigation(true)"
        >
          <X :size="18" aria-hidden="true" />
        </button>
      </div>

      <div v-show="!collapsed" class="environment">
        <span class="environment-dot" aria-hidden="true" />
        <span>OFFLINE / LOCAL</span>
      </div>

      <nav class="primary-nav" aria-label="主导航">
        <RouterLink
          v-for="item in navigation"
          :key="item.to"
          :to="item.to"
          class="nav-item"
          :class="{ 'nav-item--active': isActive(item.to) }"
          :aria-current="isActive(item.to) ? 'page' : false"
          :aria-label="item.label"
          :title="collapsed ? item.label : ''"
          @click="closeMobileNavigation()"
        >
          <component :is="item.icon" :size="19" aria-hidden="true" />
          <span v-show="!collapsed">{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar-bottom">
        <div class="account" :title="collapsed ? displayName : ''">
          <span class="account-avatar">{{ displayName.slice(0, 1).toUpperCase() }}</span>
          <span v-show="!collapsed" class="account-copy">
            <strong>{{ displayName }}</strong>
            <small>{{ roleLabel }}</small>
          </span>
          <button
            v-show="!collapsed"
            class="icon-command"
            type="button"
            aria-label="退出登录"
            title="退出登录"
            :disabled="loggingOut"
            @click="handleLogout"
          >
            <LogOut :size="17" aria-hidden="true" />
          </button>
        </div>
        <button
          class="collapse-command"
          type="button"
          :aria-label="collapsed ? '展开导航' : '收起导航'"
          :title="collapsed ? '展开导航' : '收起导航'"
          @click="collapsed = !collapsed"
        >
          <ChevronRight v-if="collapsed" :size="17" aria-hidden="true" />
          <ChevronLeft v-else :size="17" aria-hidden="true" />
          <span v-show="!collapsed">收起导航</span>
        </button>
      </div>
    </aside>

    <main
      id="main-content"
      class="main-area"
      tabindex="-1"
      :aria-hidden="mobileOpen && narrowLayout"
      :inert="mobileOpen && narrowLayout"
    >
      <header class="topbar">
        <span class="topbar-caption">{{ PRODUCT_NAME }} / LOCAL NODE</span>
        <LogoutErrorAlert
          v-if="logoutError"
          :message="logoutError"
          @dismiss="logoutError = ''"
        />
      </header>
      <div class="content">
        <RouterView />
      </div>
    </main>
  </div>
</template>

<style scoped>
.skip-link {
  position: fixed;
  z-index: 200;
  top: 8px;
  left: 12px;
  padding: 8px 12px;
  border: 1px solid var(--line-strong);
  border-radius: 4px;
  color: var(--ink-950);
  background: var(--surface);
  box-shadow: 0 4px 14px rgb(23 36 39 / 14%);
  font-size: 12px;
  transform: translateY(-160%);
}

.skip-link:focus {
  transform: translateY(0);
}

.app-shell {
  min-height: 100vh;
  padding-left: var(--sidebar-width);
  transition: padding-left 180ms ease;
}

.app-shell--collapsed {
  --sidebar-width: 76px;
}

.sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  z-index: 30;
  display: flex;
  width: var(--sidebar-width);
  flex-direction: column;
  border-right: 1px solid #26363a;
  background: #152326;
  color: #dbe4e5;
  transition: width 180ms ease, transform 180ms ease;
}

.brand {
  display: flex;
  min-height: 76px;
  align-items: center;
  gap: 11px;
  padding: 0 18px;
  border-bottom: 1px solid #2b3a3e;
}

.brand-mark {
  display: grid;
  width: 40px;
  height: 40px;
  flex: 0 0 40px;
  place-items: center;
  border: 1px solid #3c5558;
  border-radius: 5px;
  color: #4fd1c5;
  background: #1d3033;
}

.brand-copy {
  min-width: 0;
}

.brand-copy strong,
.brand-copy span {
  display: block;
  white-space: nowrap;
}

.brand-copy strong {
  color: #fff;
  font-family: "DIN Alternate", "Noto Sans SC", sans-serif;
  font-size: 17px;
}

.brand-copy span {
  margin-top: 2px;
  color: #8fa2a6;
  font-size: 11px;
}

.environment {
  display: flex;
  height: 37px;
  align-items: center;
  gap: 8px;
  padding: 0 21px;
  border-bottom: 1px solid #26363a;
  color: #8fa2a6;
  font-family: "IBM Plex Mono", Consolas, monospace;
  font-size: 10px;
  white-space: nowrap;
}

.environment-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #45b7ac;
  box-shadow: 0 0 0 3px rgb(69 183 172 / 12%);
}

.primary-nav {
  display: grid;
  min-height: 0;
  flex: 1;
  align-content: start;
  gap: 4px;
  padding: 14px 10px;
  overflow-y: auto;
}

.nav-item {
  display: flex;
  min-height: 42px;
  align-items: center;
  gap: 13px;
  padding: 0 13px;
  border: 1px solid transparent;
  border-radius: 4px;
  color: #9dafb2;
  font-size: 14px;
  white-space: nowrap;
}

.nav-item span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}

.nav-item:hover {
  color: #f0f6f6;
  background: #1d3033;
}

.nav-item--active {
  border-color: #345154;
  color: #fff;
  background: #22383b;
  box-shadow: inset 3px 0 #35aaa0;
}

.sidebar-bottom {
  margin-top: auto;
  border-top: 1px solid #2b3a3e;
}

.account {
  display: flex;
  min-height: 66px;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
}

.account-avatar {
  display: grid;
  width: 34px;
  height: 34px;
  flex: 0 0 34px;
  place-items: center;
  border-radius: 4px;
  color: #eaf7f6;
  background: #087f78;
  font-size: 13px;
  font-weight: 700;
}

.account-copy {
  min-width: 0;
  flex: 1;
}

.account-copy strong,
.account-copy small {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.account-copy strong {
  color: #e7eeee;
  font-size: 13px;
}

.account-copy small {
  margin-top: 3px;
  color: #809397;
  font-size: 11px;
  text-transform: uppercase;
}

.icon-command,
.collapse-command,
.mobile-menu,
.mobile-close {
  border: 0;
  color: inherit;
  background: transparent;
  cursor: pointer;
}

.icon-command {
  display: grid;
  width: 32px;
  height: 32px;
  place-items: center;
  border-radius: 4px;
  color: #8fa2a6;
}

.icon-command:hover {
  color: #fff;
  background: #273b3f;
}

.icon-command:disabled {
  color: #64777b;
  cursor: wait;
}

.collapse-command {
  display: flex;
  width: 100%;
  min-height: 40px;
  align-items: center;
  gap: 12px;
  padding: 0 19px;
  border-top: 1px solid #26363a;
  color: #819497;
  font-size: 12px;
}

.collapse-command:hover {
  color: #dbe4e5;
}

.main-area {
  min-width: 0;
  min-height: 100vh;
}

.topbar {
  display: flex;
  height: 48px;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 0 28px;
  border-bottom: 1px solid var(--line);
  background: rgb(255 255 255 / 92%);
}

.topbar-caption {
  min-width: 0;
  overflow: hidden;
  color: var(--ink-400);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.content {
  min-width: 0;
  padding: 26px 28px 48px;
}

.mobile-menu,
.mobile-close {
  display: none;
}

@media (max-width: 840px) {
  .app-shell,
  .app-shell--collapsed {
    padding-left: 0;
  }

  .sidebar {
    width: min(284px, 86vw);
    box-shadow: 14px 0 30px rgb(9 18 20 / 20%);
    transform: translateX(-100%);
  }

  .sidebar--mobile-open {
    transform: translateX(0);
  }

  .sidebar .brand-copy,
  .sidebar .environment,
  .sidebar .nav-item span,
  .sidebar .account-copy,
  .sidebar .icon-command {
    display: block !important;
  }

  .sidebar .collapse-command {
    display: none;
  }

  .mobile-menu {
    position: fixed;
    z-index: 20;
    top: 8px;
    left: 12px;
    display: grid;
    width: 34px;
    height: 34px;
    place-items: center;
    border: 1px solid var(--line);
    border-radius: 5px;
    color: var(--ink-800);
    background: #fff;
    box-shadow: 0 1px 3px rgb(23 36 39 / 10%);
  }

  .mobile-close {
    display: grid;
    width: 34px;
    height: 34px;
    margin-left: auto;
    place-items: center;
  }

  .sidebar-scrim {
    position: fixed;
    z-index: 25;
    inset: 0;
    background: rgb(9 18 20 / 42%);
  }

  .topbar {
    padding-left: 58px;
  }

  .content {
    padding: 20px 16px 36px;
  }
}

@media (max-width: 520px) {
  .topbar {
    padding-right: 14px;
  }

  .topbar-caption {
    font-size: 10px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .app-shell,
  .sidebar {
    transition: none;
  }
}
</style>
