<template>
  <div>
    <AssetHeader />
    <div class="container">
      <div class="mb-7">
        <h2 class="mb-2">연결할 자산 선택</h2>
        <h4 class="gray fw-lighter mb-2">1개 기관의 자산을 불러왔습니다.</h4>
      </div>
      <div class="table-responsive">
        <table class="table table-nowrap table-flush mb-10">
          <thead>
            <tr class="">
              <th scope="col">
                <div class="d-flex justify-content-between align-items-center">
                  <span class="fw-bold select-all-text">전체 선택</span>
                  <div class="form-check select-all-check me-3">
                    <input 
                      class="form-check-input" 
                      type="checkbox" 
                      v-model="selectAll" 
                      @change="toggleAllCheckboxes" 
                    />
                  </div>
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="asset in assets" :key="asset.id">
              <td>
                <div class="d-flex align-items-center gap-3 ps-1">
                  <div class="me-1 icon icon-shape w-rem-10 h-rem-10 rounded-circle text-sm bg-primary bg-opacity-25 text-tertiary">
                    <img src="@/assets/img/asset/Kbank_ci.png" class="rounded-circle" />
                  </div>
                  <div>
                    <span class="d-block text-heading fw-bold text-md">{{ asset.title }}</span>
                    <span class="text-sm">{{ asset.category }}</span>
                  </div>
                  <div class="form-check select-all-check ms-auto me-3">
                    <input 
                      class="form-check-input" 
                      type="checkbox" 
                      v-model="asset.selected" 
                      @change="updateSelectAllState" 
                    />
                  </div>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
        <router-link to="/asset/AssetFin"><button type="button" class="btn btn-sm btn-primary mb-5 mt-5 col-12 m-0">계좌 연결하기</button></router-link>
      </div>
    </div>
  </div>
</template>
<script setup>
import AssetHeader from '@/components/asset/AssetHeader.vue';
import { ref } from 'vue';


const assets = ref([
  {
          id: 1,
          title: '플러스박스',
          category: '케이뱅크',
          status: '',
        },
        {
          id: 2,
          title: '생활통장',
          category: '케이뱅크',
          status: '',
        },
        
  {
          id: 3,
          title: '듀얼K 입출금통장',
          category: '케이뱅크',
          status: '',
        },]);

const selectAll = ref(false);

const toggleAllCheckboxes = () => {
  assets.value.forEach(asset => {
    asset.selected = selectAll.value;
  });
};

const updateSelectAllState = () => {
  selectAll.value = assets.value.every(asset => asset.selected);
};
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
.select-all-text {
  font-size: 1.25rem; /* Increase as needed */
}
.select-all-check .form-check-input {
  border-radius: 50%;
  width: 1.5rem; /* Increase as needed */
  height: 1.5rem; /* Increase as needed */
}
</style>
