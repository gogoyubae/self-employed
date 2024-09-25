<template lang="">
  <div>
    <AssetHeader />

    <div class="container">
      <div class="mb-7">
        <h2 class="mb-2">정보 이용 동의</h2>
        <h4 class="gray fw-lighter mb-2">내 자산 목록을 가져옵니다. 아래를 읽고 동의해 주세요.</h4>
      </div> 
      <div class="mb-5">
        <h4 class="mb-1">가입상품목록 전송 요구</h4>
        <span>본인은 본 금융기관이 제공하는 다양한 금융 상품에 대한 정보를 요청하며, 해당 상품 목록이 제 이메일 또는 SMS로 전송되는 것에 동의합니다.</span>
    </div>
    <div class="mb-5">
      <h4 class="mb-1">개인신용정보 수집 및 이용 동의</h4>
      <span>본인은 본 금융기관이 금융상품 가입 및 서비스 제공을 위해 필요한 개인신용정보(신용등급, 대출 내역, 결제 이력 등)를 수집하고 이용하는 것에 동의합니다. <br/>수집된 개인신용정보는 상품 추천, 신용 평가 및 리스크 관리 목적으로만 사용됩니다.
      </span>
      </div>
      <div class="mb-5">
        <h4 class="mb-1">정보 제공 및 공유 동의</h4>
      <span>본인은 수집된 개인신용정보가 본 금융기관의 제휴 금융기관 또는 관련 기관에 제공될 수 있으며, 이는 금융상품의 가입 및 서비스 제공에 필요한 최소한의 범위로 한정된다는 것에 동의합니다.
      </span>
      </div>
      <div class="mb-5">
        <h4 class="mb-1">동의 철회 권리</h4>
      <span>본인은 본 동의를 언제든지 철회할 수 있는 권리가 있으며, 동의 철회 시 금융 서비스 이용에 제한이 있을 수 있음을 이해합니다. 동의 철회는 고객센터를 통해 가능하며, 즉시 반영될 것입니다.
      </span>
      </div>
      <div class="mb-5">
        <h4 class="mb-1">개인정보 보호</h4>
      <span>본 금융기관은 본인의 개인정보를 안전하게 보호하며, 관련 법령에 따라 개인정보 보호에 최선을 다할 것을 약속합니다.
      </span>
      </div>
      <router-link to="/asset/AssetSelect"><button type="button" class="btn btn-sm btn-primary mb-5 mt-5 col-12 m-0">동의하고 진행하기</button></router-link>
    </div>
  </div>
</template>

<script setup>
import AssetHeader from '@/components/asset/AssetHeader.vue';


</script>

<style scoped>
.gray{
  color: gray;
}

</style>
