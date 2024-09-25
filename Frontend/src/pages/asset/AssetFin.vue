
<template>
  <div class="">
    <AssetHeader class="mb-12"/>
    <div class="container text-center">
      <div class="mb-12">
      <h2 class="mb-4 fw-bold">자산 연동이 완료되었습니다.</h2>
      <img src="@/assets/img/asset/assetfin.png" class="rounded-circle mb-4 asset-image" />
    </div>
      <router-link to="/asset">
        <button type="button" class="btn btn-sm btn-primary mb-5 mt-5 col-12 m-0">가계관리로 돌아가기</button>
      </router-link>
    </div>
  </div>
</template>
<script setup>
import AssetHeader from '@/components/asset/AssetHeader.vue';

</script>

<style>
.asset-image {
  width: 150px; /* Adjust the size as needed */
  height: 150px; /* Adjust the size as needed */
  max-width: 100%;
}
</style>
