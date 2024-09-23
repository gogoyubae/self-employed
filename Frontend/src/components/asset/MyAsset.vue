<template lang="">
  <div class="container">
    <h2 class="mb-2">현재 자산</h2>
    <h4 class="mt-2 mb-2">등록한 계좌 정보</h4>
    <div class="row g-3 g-xl-6">
      <!-- 계좌 연결 정보 -->
      <div class="col-xl-6 col-sm-6 d-flex">
        <div class="card w-100 d-flex flex-column">
          <div class="card-body p-0">
            <Account title="계좌"/>
          </div>
        </div>
      </div>

      <!-- 카드 연결 정보 -->
      <div class="col-xl-6 col-sm-6 d-flex">
        <div class="card w-100 d-flex flex-column">
          <div class="card-body p-0">
            <Account title="카드"/>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import Account from './Account.vue';

export default {
  components: {
    Account
  }
}
</script>
<style lang="">

</style>