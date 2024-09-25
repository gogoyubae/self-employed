<template>
  <div>
    <InfoPlazaHeader />
    <div class="container">
      <div class="row align-items-center">
        <!-- 헤딩 -->
        <div class="col-md-6">
          <h1
            class="h3 position-relative pb-sm-2 pb-md-3"
            style="z-index: 1021"
          >
            전체 지역에서 핫한 인기 사업 아이템
          </h1>
        </div>

        <!-- 검색창 -->
        <div class="col-md-6">
          <div class="position-relative w-100 d-flex justify-content-md-end">
            <input
              type="search"
              class="form-control form-control-lg rounded-pill"
              placeholder="Search for products"
              aria-label="Search"
            />
            <button
              type="button"
              class="btn btn-icon btn-ghost fs-lg text-bo border-0 position-absolute top-0 end-0 rounded-circle mt-1 me-1"
              aria-label="Search button"
            >
              <i class="fa-solid fa-magnifying-glass"></i>
            </button>
          </div>
        </div>
      </div>
      <br />
      <br />

      <div class="row">
        <!-- 지역 검색(구) -->
        <div class="col-md-3">
          <select
            class="form-select round-corner"
            aria-label="Default select example"
          >
            <option selected disabled hidden>구 선택</option>
            <option value="1">One</option>
            <option value="2">Two</option>
            <option value="3">Three</option>
          </select>
        </div>

        <!-- 지역 검색(동) -->
        <div class="col-md-3">
          <select
            class="form-select round-corner"
            aria-label="Default select example"
          >
            <option selected disabled hidden>동 선택</option>
            <option value="1">One</option>
            <option value="2">Two</option>
            <option value="3">Three</option>
          </select>
        </div>

        <!-- 상위 서비스 업종 -->
        <div class="col-md-3">
          <select
            class="form-select round-corner"
            aria-label="Default select example"
          >
            <option selected disabled hidden>상위 서비스 업종</option>
            <option value="1">One</option>
            <option value="2">Two</option>
            <option value="3">Three</option>
          </select>
        </div>

        <!-- 하위 서비스 업종 -->
        <div class="col-md-3">
          <select
            class="form-select round-corner"
            aria-label="Default select example"
          >
            <option selected disabled hidden>하위 서비스 업종</option>
            <option value="1">One</option>
            <option value="2">Two</option>
            <option value="3">Three</option>
          </select>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import InfoPlazaHeader from '@/components/infoplaza/InfoPlazaHeader.vue';
</script>

<style scoped>
.round-corner {
  border-radius: 20px;
}
</style>
