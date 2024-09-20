<template>
  <div class="container">
    <div class="row">
      <div class="col-6">
        <canvas id="bar-chart" style="height: 200px"></canvas>
      </div>
      <div class="col-6">
        <Doughnut
          :data="doughnutData"
          :options="options"
          style="height: 200px"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { Chart } from 'chart.js/auto';
import { data_bar, data_doughnut, options } from '@/chartConfig'; // data_doughnut 추가
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from 'chart.js';
import { Doughnut } from 'vue-chartjs';

// Chart.js에서 도넛 차트 관련 요소 등록
ChartJS.register(ArcElement, Tooltip, Legend);

// 바 차트 관련 코드
let chartInstance = ref(null);

onMounted(() => {
  const ctx = document.getElementById('bar-chart').getContext('2d');

  // 바 차트 생성
  chartInstance.value = new Chart(ctx, {
    type: 'bar',
    data: data_bar, // bar 차트 데이터 사용
    options,
  });
});

// 도넛 차트 데이터
const doughnutData = data_doughnut; // chartConfig.js에서 가져온 도넛 차트 데이터
</script>

<style scoped>
canvas {
  max-width: 100%;
  height: auto;
}
</style>
