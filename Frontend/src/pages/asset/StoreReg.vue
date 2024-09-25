<template>
  <AssetHeader />
  <div class="container">
    <h3 style="text-align: center">내 가게 등록</h3>
    <h4 class="title">가게 주소</h4>
    <p>등록할 가게 주소를 입력해 주세요</p>
    <div class="row mb-3">
      <div class="col-sm-4">
        <input
          type="text"
          class="form-control"
          placeholder="도로명, 지번, 건물명 검색"
        />
      </div>
    </div>
    <div class="col-sm-6">
      <input type="text" class="form-control" placeholder="상세주소" />
    </div>

    <h4 class="title">가게 정보</h4>
    <p>가게 권리금 및 투자액을 입력해 주세요</p>
    <div class="row mb-3">
      <div class="col-sm-4">
        <input
          type="text"
          class="form-control"
          placeholder="도로명, 지번, 건물명 검색"
        />
      </div>
    </div>
    <div class="col-sm-6">
      <input type="text" class="form-control" placeholder="상세주소" />
    </div>
  </div>
</template>

<script>
import AssetHeader from '@/components/asset/AssetHeader.vue';
export default {
  components: {
    AssetHeader,
  },
};
</script>

<style>
p {
  opacity: 0.5;
}
.title {
  margin-top: 3%;
}
</style>
