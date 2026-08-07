import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import type { UserRole } from '@/api/types'
import { passwordRouteRedirect } from '@/router/guards'
import { useSessionStore } from '@/stores/session'

declare module 'vue-router' {
  interface RouteMeta {
    public?: boolean
    roles?: UserRole[]
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('@/layouts/AppShell.vue'),
    children: [
      {
        path: '',
        name: 'overview',
        component: () => import('@/views/OverviewView.vue'),
      },
      {
        path: 'tasks',
        name: 'tasks',
        component: () => import('@/views/TasksView.vue'),
      },
      {
        path: 'change-password',
        name: 'change-password',
        component: () => import('@/views/ChangePasswordView.vue'),
      },
      {
        path: 'tasks/new',
        name: 'task-create',
        component: () => import('@/views/CreateTaskView.vue'),
        meta: { roles: ['administrator', 'operator'] },
      },
      {
        path: 'tasks/:id',
        name: 'task-detail',
        component: () => import('@/views/TaskDetailView.vue'),
      },
      {
        path: 'system',
        name: 'system',
        component: () => import('@/views/SystemView.vue'),
        meta: { roles: ['administrator'] },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
    meta: { public: true },
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

router.beforeEach(async (to) => {
  const session = useSessionStore()
  try {
    await session.restore()
  } catch {
    if (to.meta.public) return true
    return { name: 'login', query: { redirect: to.fullPath, reason: 'session' } }
  }

  const passwordRedirect = passwordRouteRedirect(session.user, to.name)
  if (passwordRedirect) return { name: passwordRedirect }

  if (to.meta.public) {
    if (session.isAuthenticated && to.name === 'login') return { name: 'overview' }
    return true
  }

  if (!session.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  if (to.meta.roles && !session.hasRole(to.meta.roles)) {
    return { name: 'overview' }
  }

  return true
})

export default router
