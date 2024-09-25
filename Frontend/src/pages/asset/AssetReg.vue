<template>
  <div>
    <AssetHeader />
    <div class="container">
      <div class="mb-7">
        <h2 class="mb-2">자산 등록</h2>
        <h4 class="gray fw-lighter mb-2">연결할 계좌 정보를 선택해 주세요.</h4>
      </div>
      <div class="row d-flex justify-content-center">
        <div class="asset_width d-flex flex-wrap justify-content-center">
          <div 
            class="col-2" 
            v-for="(asset, index) in assets" 
            :key="index"
          >
            <div class="form-item-checkable">
              <input 
                class="form-item-check" 
                type="radio" 
                name="asset-type" 
                :id="'asset-type-' + index" 
                :value="asset.name"
                v-model="selectedAsset"
              >
              <label 
                class="form-item cursor-pointer" 
                :for="'asset-type-' + index"
              >
                <span 
                  class="form-item-click d-inline-flex flex-column gap-3 align-items-center justify-content-center form-control w-rem-24 h-rem-24 text-center text-muted"
                >
                  <i :class="'bi bi-' + asset.icon + ' text-xl'"></i>
                  <span class="fw-semibold text-xs">{{ asset.name }}</span>
                </span>
              </label>
            </div>
          </div>
        </div>
      </div>

      <div class="mb-12 mt-12">
        <h2 class="mb-2">인증서 선택</h2>
        <h4 class="gray fw-lighter mb-2">사용할 인증서를 선택해 주세요.</h4>
      </div>

      <div class="d-flex flex-wrap justify-content-center">
        <div 
          class="card card-pricing text-bg-primary border-0 shadow-4 shadow-6-hover mx-2 mb-3" 
          v-for="(certificate, index) in certificates" 
          :key="index"
          style="width: 12rem;" 
        >
          <div class="p-6 pt-12">
            <h3 class="text-reset ls-tight text-sm mb-1">{{ certificate.title }}</h3>
            <div class="d-flex align-items-center my-5">
              <span class="d-block text-md text-reset">{{ certificate.name }}</span>
            </div>
            <div class="mb-2 d-flex justify-content-between align-items-center">
              <span class="text-sm fw-semibold">{{ certificate.expirationDate }}</span>
              <a href="#" class="btn btn-sm btn-square btn-dark stretched-link">
                <i class="bi bi-arrow-right"></i>
              </a>
            </div>
          </div>
        </div>
      </div>

      <router-link to="/asset/InfoAgree">
        <button 
          type="button" 
          class="btn btn-sm btn-primary mb-5 mt-12 col-12 m-0"
        >
          연결하기
        </button>
      </router-link>
    </div>
  </div>
</template>

<script setup>
import AssetHeader from '@/components/asset/AssetHeader.vue';
import { ref } from 'vue';

const selectedAsset = ref('');

const assets = ref([
  { name: 'KB국민은행', icon: 'bank' },
  { name: 'IM뱅크', icon: 'bank' },
  { name: '토스뱅크', icon: 'bank' },
  { name: '농협은행', icon: 'bank' },
  { name: '우체국', icon: 'bank' },
  { name: '국민은행', icon: 'bank' },
  { name: '국민은행', icon: 'bank' },
  { name: '국민은행', icon: 'bank' },
  { name: '우리은행', icon: 'bank' },
  { name: '농협은행', icon: 'bank' },
  { name: '케이뱅크', icon: 'bank' },
  { name: '신한은행', icon: 'bank' },
  { name: '하나은행', icon: 'bank' },
  { name: '기업은행', icon: 'bank' },
  { name: 'SC제일은행', icon: 'bank' },
  { name: '한국씨티은행', icon: 'bank' },
  { name: '제주은행', icon: 'bank' },
  { name: '부산은행', icon: 'bank' },
]);

const certificates = ref([
  { title: '뱅크샐러드 인증서', name: '이름1', expirationDate: '2027-07-29' },
  { title: 'KB국민은행 인증서', name: '이름2', expirationDate: '2028-07-29' },
  { title: '신한은행 인증서', name: '이름3', expirationDate: '2029-07-29' },
]);
</script>

<style>
.div-input {
  width: 40%;
}
.gray {
  color: gray;
}
.form-item-checkable {
  display: flex;
  justify-content: center;
  align-items: center;
}
.form-item-click {
  width: 100px; /* Adjust as needed */
  height: 100px; /* Adjust as needed */
}
.asset_width {
  width: 55%; /* Set the height of the row */
  overflow-y: auto; /* Optional: adds scroll if content exceeds height */
}
</style>
