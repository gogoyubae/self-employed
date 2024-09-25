<template>
  <div>
    <AssetHeader />
    <div class="container">
      <router-link to="/asset/InfoAgree"><button type="button" class="btn btn-sm btn-primary mb-5 mt-5 col-12 m-0">연결하기</button></router-link>
    </div>
  </div>
</template>
<script setup>
import AssetHeader from '@/components/asset/AssetHeader.vue';

</script>

<style>
.btn-primary {
  margin: 0px 0px 0px 20px;
}
.btn-cls {
  display: flex;
  width: 18%;
  padding: 0.5% 0% 0% 20%;
}
.div-input {
  width: 40%;
}
.gray{
  color: gray;
}
</style>
