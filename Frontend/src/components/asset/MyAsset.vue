<template lang="">
  <div class="mb-10">
    <div class="d-flex justify-content-between  gap-2">
      <div>
        <h2 class="mb-2">현재 자산</h2>
        <h4 class="mb-2">등록한 계좌 정보</h4>
      </div>
      <div class="d-flex align-items-center gap-2">
        <router-link to="/asset/assetreg"><button type="button" class="btn btn-sm btn-primary mb-5 mt-5 col-12 m-0">자산 등록</button></router-link>
      </div>
    </div>
    
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