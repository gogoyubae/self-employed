<template lang="">
    <div>
      <!-- 계좌 정보 -->
      <div class="card-body pb-2">
        <div class="mb-2 d-flex align-items-center">
          <h5>{{ title }}</h5>
        </div>

        <div class="vstack gap-2 mx-n3" v-for="item in items">
          <div class="position-relative d-flex align-items-center p-3 rounded-3 bg-body-secondary-hover">
            <div class="flex-none">
              <img src="data:image/png;base64,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" class="w-rem-16 w-md-20 rounded" alt="..." />
            </div>
            <div class="ms-3 ms-md-4 flex-fill">
              <div class="stretched-link text-limit text-sm text-heading fw-semibold" role="button" data-bs-toggle="offcanvas" data-bs-target="#cardDetailsOffcanvas" aria-controls="cardDetailsOffcanvas">
                John Snow - Metal
              </div>
              <div class="d-block text-xs gap-2 mt-1">
                <span>**4291 - Exp: 12/26</span>
              </div>
            </div>
            <div class="d-none d-sm-block ms-auto text-end">
              <span class="badge bg-body-secondary text-success">Active</span>
              <div class="d-none d-sm-block text-xs text-muted mt-2">
                Last used: 2 hrs ago
              </div>
            </div>
          </div>
        </div>
        
        <div class="vstack gap-2 mx-n3">
          <div class="position-relative d-flex align-items-center p-3 rounded-3 bg-body-secondary-hover">
            <div class="flex-none">
              <img src="https://i.namu.wiki/i/NNWZwf6TI6Yt57NGvIUQ7qdiPC1XFFYv-NUbAUbj31NTgktZymNJunFOhZOJi6lKx7VK0-PgxYkwM8B_5OUGeg.webp" class="w-rem-16 w-md-20 rounded" alt="..." />
            </div>
            <div class="ms-3 ms-md-4 flex-fill">
              <div class="stretched-link text-limit text-sm text-heading fw-semibold" role="button" data-bs-toggle="offcanvas" data-bs-target="#cardDetailsOffcanvas" aria-controls="cardDetailsOffcanvas">
                John Snow - Metal
              </div>
              <div class="d-block text-xs gap-2 mt-1">
                <span>**4291 - Exp: 12/26</span>
              </div>
            </div>
            <div class="d-none d-sm-block ms-auto text-end">
              <span class="badge bg-body-secondary text-success">Active</span>
              <div class="d-none d-sm-block text-xs text-muted mt-2">
                Last used: 2 hrs ago
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
</template>

<script>
import { ref } from 'vue';

const items = ref([{ message: 'Foo' }, { message: 'Bar' }])

export default {
  name: 'Account',
  props: ['title'],
  components: {
  },
  setup() {
    return {
    };
  }
};
</script>
<style lang="">

</style>