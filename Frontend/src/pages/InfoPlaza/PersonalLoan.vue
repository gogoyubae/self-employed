<template>
  <div>
    <InfoPlazaHeader />
    <div class="container mw-screen-xl">
      <LoanHeader class="mb-10" />
      <div class="list-group list-group-flush gap-2 ms-10 me-5 col-1">
        <div
          class="list-group-item gap-3 text-center p-3 bg-body-secondary-hover"
        >
          <div class="icon flex-none">
            <div class="icon flex-none">
              <img
                src="@/assets/img/infoplaza/popular.png"
                class="w-rem-8 h-rem-8"
                alt="..."
              />
            </div>
          </div>
          <div class="align-items-center flex-fill">
            <div>
              <a href="#" class="stretched-link text-heading text-sm fw-bold"
                >개인신용</a
              >
            </div>
          </div>
        </div>
        <div
          class="list-group-item gap-3 text-center p-3 bg-body-secondary-hover"
        >
          <div class="icon flex-none">
            <img
              src="@/assets/img/infoplaza/storeinfo.png"
              class="w-rem-8 h-rem-8"
              alt="..."
            />
          </div>
          <div class="align-items-center flex-fill">
            <div>
              <a href="#" class="stretched-link text-heading text-sm fw-bold"
                >전세자금</a
              >
            </div>
          </div>
        </div>
        <div
          class="list-group-item gap-3 text-center p-3 bg-body-secondary-hover"
        >
          <div class="icon flex-none">
            <img
              src="@/assets/img/infoplaza/storeinfo.png"
              class="w-rem-8 h-rem-8"
              alt="..."
            />
          </div>
          <div class="align-items-center flex-fill">
            <div>
              <a href="#" class="stretched-link text-heading text-sm fw-bold"
                >주택담보</a
              >
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
import LoanHeader from '@/components/infoplaza/PersonalLoanHeader.vue';
</script>

<style></style>
