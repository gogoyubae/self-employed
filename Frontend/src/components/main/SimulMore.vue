<template>
  <div class="container">
    <div class="row justify-content-center mb-10">
      <!-- Row to contain cards -->
      <div class="col-4">
        <div class="card none_border">
          <div class="d-flex">
            <img
              src="@/assets/img/media/img-1.jpg"
              class="rounded card-img-left"
              alt="Card image"
            />
            <div class="card-body">
              <h4 class="mb-3">강서구 카페</h4>
              <div class="d-flex justify-content-between">
                <h5 class="mb-1">보증금</h5>
                <h4 class="mb-0">1억</h4>
              </div>
              <div class="d-flex justify-content-between">
                <h5 class="mb-0">월세</h5>
                <h4 class="mb-0">500만</h4>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-4">
        <div class="card none_border">
          <div class="d-flex">
            <img
              src="@/assets/img/media/img-1.jpg"
              class="rounded card-img-left"
              alt="Card image"
            />
            <div class="card-body">
              <h4 class="mb-3">강서구 카페</h4>
              <div class="d-flex justify-content-between">
                <h5 class="mb-1">보증금</h5>
                <h4 class="mb-0">1억</h4>
              </div>
              <div class="d-flex justify-content-between">
                <h5 class="mb-0">월세</h5>
                <h4 class="mb-0">500만</h4>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="col-2 d-flex align-items-center justify-content-center">
        <a href="/simul/report">
          <button type="button" class="btn btn-sm btn-primary p-5">
            더 많은 리포트<br /> 보러가기 >
          </button>
        </a>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>

<style scoped>
.card-img-left {
  height: 150px; /* 원하는 높이로 조정 */
  width: 250px; /* 원하는 너비로 조정 (필요에 따라 변경) */
  object-fit: cover; /* 이미지 비율 유지하면서 잘리도록 설정 */
}
.none_border {
  border: none;
  box-shadow: none;
}
</style>
