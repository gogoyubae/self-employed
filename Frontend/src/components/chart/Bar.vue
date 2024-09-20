<template>
  <div class="container">
    <div class="row">
      <div class="col-6">
        <canvas id="bar-chart" class="chart" />
      </div>
      <div class="col-6">
        <Doughnut
          :data="doughnutData"
          :options="doughnutOptions"
          class="chart"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { Chart } from 'chart.js/auto';
import {
  data_bar,
  data_doughnut,
  barOptions,
  doughnutOptions,
} from '@/chartConfig.js'; // 옵션 가져오기
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
    options: barOptions, // 바 차트 전용 옵션 사용
  });
});

// 도넛 차트 데이터
const doughnutData = data_doughnut; // chartConfig.js에서 가져온 도넛 차트 데이터
</script>

<style scoped>
.chart {
  max-width: 100%;
  height: 200px; /* 높이 설정 */
}
</style>
