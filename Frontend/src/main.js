import "./assets/main.css";
import "bootstrap/dist/css/bootstrap.css";
import "vue-awesome-paginate/dist/style.css";
import "./assets/css/main.css";
import "./assets/css/utility.css";
import 'bootstrap-icons/font/bootstrap-icons.css';

import { createApp } from "vue";
import { createPinia } from "pinia";
import VueAwesomePaginate from "vue-awesome-paginate";

import App from "./App.vue";
import router from "./router";

const app = createApp(App);

app.use(VueAwesomePaginate);
app.use(createPinia());
app.use(router);

app.mount("#app");
