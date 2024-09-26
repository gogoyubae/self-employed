<template>
  <div class="container">
    <div class="simul-area">
      <div style="display: flex; align-items: flex-end">
        <h2 style="font-weight: bold">시뮬레이션</h2>
        <p style="margin-left: 20px">
          시뮬레이션을 완료하면 받을 수 있는 리포트의 견본입니다.
        </p>
      </div>
      <hr />
      <div class="row">
        <div class="col-6">
          <img src="@/assets/img/report/clothes.png" alt="" />
        </div>
        <div class="col-6">
          <h1 class="mb-2">강남구 유통업</h1>
          <div class="row">
            <div class="col-6">
              <div class="d-flex justify-content-between align-items-center mb-3">
                <h4 class="">보증금</h4>
              <h1 class="me-5">1억</h1>
              </div>
              <div class="d-flex justify-content-between align-items-center">
                <h4 class="">월세</h4>
              <h1 class="me-5">600만</h1>
              </div>
            </div>
            <div class="col-6">
            
              <div class="d-flex justify-content-between align-items-center">
                <h4 class="mb-2">중분류</h4>
              <h4 class="mb-2 me-5">편의점</h4>
            </div>

            <div class="d-flex justify-content-between align-items-center">
              <h4 class="mb-2">유형</h4>
            <h4 class="mb-2 me-5">편의점</h4>
          </div>

          <div class="d-flex justify-content-between align-items-center">
            <h4 class="mb-2">거주지</h4>
            <h4 class="mb-2 me-5">편의점</h4>
          </div>

          <div class="d-flex justify-content-between align-items-center">
            <h4 class="mb-2">교육</h4>
            <h4 class="mb-2 me-5">편의점</h4>
          </div>

          <div class="d-flex justify-content-between align-items-center">
            <h4 class="mb-2">대출 계획</h4>
            <h4 class="mb-2 me-5">편의점</h4>
        </div>
      </div>
      </div>
    </div>
      </div>
      <Location/>
      <Bar/>
      <Loan/>
      <h3>시뮬레이션</h3>
    </div>
  </div>
</template>
<script setup>
import Location from '@/components/report/Location.vue';
import Bar from '@/components/report/Bar.vue';
import Loan from '@/components/report/Loan.vue';

</script>
<style>
.simul-area {
  background-color: #f6f4f9;
  border-radius: 10px;
  margin: 30px 0px;
  padding: 20px;
}
</style>
