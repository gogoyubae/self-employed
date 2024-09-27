<template>
  <div class="container mt-20">
    <div class="simul-area">
      <div class="container">
        <div class="mt-5" style="display: flex; align-items: flex-end">
          <h2 style="font-weight: bold">시뮬레이션</h2>
          <p style="margin-left: 20px">
            시뮬레이션을 완료하면 받을 수 있는 리포트의 견본입니다.
          </p>
        </div>
        <hr />
        <div class="row mb-10" style="display: flex;">
          <div class="col-6" style="display: flex; align-items: stretch;">
            <img src="@/assets/img/report/clothes.png" alt="" class="full-image" />
          </div>
          <div class="col-6" style="display: flex; flex-direction: column; justify-content: space-between;">
            <h2 class="mb-2" style="font-weight: 800">강남구 유통업</h2>
            <div class="row">
              <div class="col-6">
                <div class="d-flex justify-content-between align-items-end">
                  <h4 style="font-weight: 400" class="mb-2">보증금</h4>
                  <h1 style="font-weight: 600;">1억</h1>
                </div>

                <div class="d-flex justify-content-between align-items-end">
                  <h4 style="font-weight: 400;" class="mb-2">월세</h4>
                  <h1 style="font-weight: 600;">600만</h1>
                </div>
              </div>
              <div class="col-6 mt-1">
                <div class="d-flex justify-content-between align-items-center">
                  <h4 class="mb-2 fw-light">중분류</h4>
                  <h4 class="mb-2 me-5">편의점</h4>
                </div>

                <div class="d-flex justify-content-between align-items-center">
                  <h4 class="mb-2 fw-light">유형</h4>
                  <h4 class="mb-2 me-5">편의점</h4>
                </div>

                <div class="d-flex justify-content-between align-items-center">
                  <h4 class="mb-2 fw-light">거주지</h4>
                  <h4 class="mb-2 me-5">편의점</h4>
                </div>

                <div class="d-flex justify-content-between align-items-center">
                  <h4 class="mb-2 fw-light">교육</h4>
                  <h4 class="mb-2 me-5">편의점</h4>
                </div>

                <div class="d-flex justify-content-between align-items-center">
                  <h4 class="mb-2 fw-light">대출 계획</h4>
                  <h4 class="mb-2 me-5">편의점</h4>
                </div>
              </div>
            </div>
          </div>
        </div>
        <Location class="mb-10"/>
        <ReportGraph />
      </div>
      <Loan class="mb-10" />
    </div>
  </div>
</template>

<script setup>
import Location from '@/components/report/Location.vue';
import ReportGraph from '@/components/main/ReportGraph.vue';
import Loan from '@/components/report/Loan.vue';
</script>

<style>
.simul-area {
  background-color: #f6f4f9;
  border-radius: 10px;
  margin: 30px 0px;
  padding: 20px;
}

.full-image {
  width: 100%;
  height: auto;
  object-fit: cover;
  align-self: stretch;
}
</style>
