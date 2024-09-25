<template>
<div>

  <div class="row">

  <div class="col-6">
    <div>
      <h4 class="mb-2">대출 상환 현황</h4>
    </div> 
    <div class="p-5">
      <canvas id="doughnut-chart" style="height: 200px"></canvas>
    </div>
  </div>
  <div class="col-6">
    <div>
      <h4 class="mb-2">가게 자산 현황</h4>
    </div> 
    <div class="p-5">
      <canvas id="bar-chart" style="height: 200px"></canvas>
    </div>
    </div>
  </div>
</div>
</template>

<script setup>
import { onMounted, ref } from 'vue';
import { Chart } from 'chart.js/auto';
import {
  asset_data_bar,
  asset_data_doughnut,
  asset_barOptions,
  asset_doughnutoptions,
} from '@/assets/js/assetChart.js';

let barChartInstance = ref(null); // 막대 차트 인스턴스
let doughnutChartInstance = ref(null); // 도넛 차트 인스턴스

onMounted(() => {
  const barCtx = document.getElementById('bar-chart').getContext('2d');
  const doughnutCtx = document
    .getElementById('doughnut-chart')
    .getContext('2d');

  // Chart.js를 사용하여 바 차트 생성
  barChartInstance.value = new Chart(barCtx, {
    type: 'bar',
    data: asset_data_bar,
    options: asset_barOptions,
  });

  // Chart.js를 사용하여 도넛 차트 생성
  doughnutChartInstance.value = new Chart(doughnutCtx, {
    type: 'doughnut',
    data: asset_data_doughnut,
    options: asset_doughnutoptions,
  });
});
</script>

<style scoped>
canvas {
  max-width: 100%;
  height: auto;
}

</style>
