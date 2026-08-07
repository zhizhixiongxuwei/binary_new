import 'element-plus/dist/index.css'
import '@/assets/main.css'

import ElementPlus from 'element-plus'
import { createPinia } from 'pinia'
import { createApp } from 'vue'

import App from '@/App.vue'
import { configureRuntimeApi } from '@/api/runtime'
import router from '@/router'

async function bootstrap(): Promise<void> {
  await configureRuntimeApi()
  createApp(App)
    .use(createPinia())
    .use(router)
    .use(ElementPlus)
    .mount('#app')
}

void bootstrap()
