<template>
  <!-- 분석 결과 -->
  <Result />
  <!-- 추천위치 -->
  <Location />
  <!-- 그래프 -->
  <Bar />
  <!-- 교육정보 -->
  <Education />
  <!-- 대출 -->
  <Loan />
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
