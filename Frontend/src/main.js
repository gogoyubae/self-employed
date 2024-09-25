import './assets/main.css';
import 'bootstrap/dist/css/bootstrap.css';
import 'vue-awesome-paginate/dist/style.css';
import './assets/css/main.css';
import './assets/css/utility.css';
import 'bootstrap-icons/font/bootstrap-icons.css';
// Popper.js
import 'bootstrap/dist/js/bootstrap.bundle.min.js';
import { createApp } from 'vue';
import { createPinia } from 'pinia';
import VueAwesomePaginate from 'vue-awesome-paginate';

import App from './App.vue';
import router from './router/index';

const app = createApp(App);

app.use(VueAwesomePaginate);
app.use(createPinia());
app.use(router);

app.mount('#app');
