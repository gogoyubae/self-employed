<template>
  <div>
    <!-- 헤더 -->
    <Result />

    <div class="container">
      <!-- 추천 위치 -->
      <Location />
    </div>

      <!-- 그래프 -->
    <Bar />

      <!-- 교육정보 -->
    <div class="container">
        <Education  />
    </div>
    <!-- 대출 -->
    <div style="background-color: #f6f4f9; padding: 20px;"> <!-- 배경색과 패딩 추가 -->
      <Loan />
    </div>
  </div>
</template>

<script setup>
import Result from '@/components/report/Result.vue';
import Location from '@/components/report/Location.vue';
import Bar from '@/components/report/Bar.vue';
import Education from '@/components/report/Education.vue';
import Loan from '@/components/report/Loan.vue';
</script>

<style>
.title {
  font-size: 25px;
  font-weight: bold;
}
</style>
