
import { createRouter, createWebHistory } from 'vue-router'
import Home from '@/pages/Home.vue';
import Shop from '@/pages/Shop.vue';

const router = createRouter({
    history: createWebHistory(),
    routes : [
        { path: '/', name: "Home", component: Home },
        { path: '/shop', name: "Shop", component: Shop },
        // { path: '/input', name: "Input", component: Input },
        // { path: '/input2', name: "Input2", component: Input2 },
        // { path: '/update', name: "Update", component: Update },
    ]
});

export default router;